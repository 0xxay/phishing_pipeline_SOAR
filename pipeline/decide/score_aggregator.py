"""Multi-signal verdict engine.

Pipeline:
  1. Hard signals  — VirusTotal, AbuseIPDB, URLScan give deterministic threat scores
  2. AI analysis   — LLM analyzes email content + enrichment context
  3. Merge         — Hard signals can override AI; AI alone cannot call MALICIOUS
                     without at least one corroborating hard signal

Override rules (applied in order, first match wins):
  - 2+ independent hard-MALICIOUS signals            → MALICIOUS  (ignore AI)
  - 1 hard-MALICIOUS + AI says MALICIOUS             → MALICIOUS  (confirmed)
  - 1 hard-MALICIOUS + AI says CLEAN/SUSPICIOUS      → SUSPICIOUS (conflict)
  - 0 hard signals   + AI says MALICIOUS             → SUSPICIOUS (AI alone insufficient)
  - hard-SUSPICIOUS  + AI says MALICIOUS             → SUSPICIOUS (elevated)
  - everything CLEAN                                 → CLEAN
"""
import json
import asyncio
from typing import List, Tuple
from models import Email, IOCs, EnrichmentResult, Verdict, VerdictType
from utils import log_info, log_error, log_debug
import config


# ─── Hard signal thresholds ──────────────────────────────────────────────────

def _hard_signals(enrichments: List[EnrichmentResult]) -> Tuple[int, int, str]:
    """
    Returns (malicious_count, suspicious_count, signal_summary) based purely
    on deterministic threat intel — no AI involved.
    """
    mal = 0
    sus = 0
    notes = []

    for e in enrichments:
        if e.source == "virustotal":
            vt_mal = e.details.get("malicious", 0) if e.details else 0
            vt_sus = e.details.get("suspicious", 0) if e.details else 0
            if vt_mal >= config.VT_DETECTION_THRESHOLD:
                mal += 1
                notes.append(f"VT: {vt_mal} malicious detections on {e.ioc[:40]}")
            elif vt_mal > 0 or vt_sus >= 3:
                sus += 1
                notes.append(f"VT: {vt_mal}M/{vt_sus}S detections on {e.ioc[:40]}")

        elif e.source == "abuseipdb":
            score = (e.details or {}).get("confidence_score") or e.score or 0
            reports = (e.details or {}).get("total_reports", 0)
            if score >= config.ABUSEIPDB_CONFIDENCE_THRESHOLD:
                mal += 1
                notes.append(f"AbuseIPDB: {score}% confidence ({reports} reports) on {e.ioc}")
            elif score >= 25:
                sus += 1
                notes.append(f"AbuseIPDB: {score}% confidence on {e.ioc}")

        elif e.source == "urlscan":
            v = (e.verdict or "").lower()
            if v == "malicious":
                mal += 1
                notes.append(f"URLScan: malicious on {e.ioc[:40]}")
            elif v == "suspicious":
                sus += 1
                notes.append(f"URLScan: suspicious on {e.ioc[:40]}")

    return mal, sus, "; ".join(notes) if notes else "No threat intel hits"


def _merge_verdict(
    hard_mal: int,
    hard_sus: int,
    hard_notes: str,
    ai_verdict: VerdictType,
    ai_confidence: float,
    ai_reasoning: str,
    ai_mitre: str,
) -> Verdict:
    """Apply override rules and produce final verdict."""

    if hard_mal >= 2:
        # Multiple independent sources confirm malicious — AI cannot override
        verdict = VerdictType.MALICIOUS
        confidence = min(95, 60 + hard_mal * 12)
        reasoning = (
            f"CONFIRMED MALICIOUS — {hard_mal} independent threat intel sources flagged this. "
            f"Signals: {hard_notes}. AI context: {ai_reasoning}"
        )

    elif hard_mal == 1 and ai_verdict == VerdictType.MALICIOUS:
        # One hard signal corroborated by AI
        verdict = VerdictType.MALICIOUS
        confidence = min(90, 55 + ai_confidence * 0.3)
        reasoning = (
            f"MALICIOUS — Threat intel confirms: {hard_notes}. "
            f"AI analysis agrees: {ai_reasoning}"
        )

    elif hard_mal == 1:
        # Hard signal says malicious but AI disagrees or is uncertain — be cautious
        verdict = VerdictType.SUSPICIOUS
        confidence = 65
        reasoning = (
            f"SUSPICIOUS — Threat intel flagged: {hard_notes}. "
            f"AI verdict was {ai_verdict.value} ({ai_confidence:.0f}% confidence): {ai_reasoning}. "
            f"Treat as suspicious pending manual review."
        )

    elif hard_sus > 0 and ai_verdict == VerdictType.MALICIOUS:
        # Suspicious hard signals + AI says malicious — elevate to suspicious
        verdict = VerdictType.SUSPICIOUS
        confidence = 70
        reasoning = (
            f"SUSPICIOUS (elevated) — Threat intel: {hard_notes}. "
            f"AI flags as malicious: {ai_reasoning}"
        )

    elif hard_sus > 0:
        verdict = VerdictType.SUSPICIOUS
        confidence = min(75, 40 + hard_sus * 10)
        reasoning = (
            f"SUSPICIOUS — {hard_sus} suspicious indicator(s): {hard_notes}. "
            f"AI context: {ai_reasoning}"
        )

    elif ai_verdict == VerdictType.MALICIOUS:
        # AI alone says malicious with zero hard signals — downgrade to suspicious
        verdict = VerdictType.SUSPICIOUS
        confidence = min(60, ai_confidence * 0.6)
        reasoning = (
            f"SUSPICIOUS — AI flagged as malicious ({ai_confidence:.0f}% confidence) but no "
            f"threat intel sources confirmed it. {ai_reasoning} — Manual review recommended."
        )

    elif ai_verdict == VerdictType.SUSPICIOUS:
        verdict = VerdictType.SUSPICIOUS
        confidence = min(55, ai_confidence * 0.7)
        reasoning = f"SUSPICIOUS (AI only, no hard signals) — {ai_reasoning}"

    else:
        verdict = VerdictType.CLEAN
        confidence = min(85, 70 + (1 if hard_mal == 0 and hard_sus == 0 else 0) * 15)
        reasoning = f"CLEAN — No threat intel hits. AI: {ai_reasoning}"

    return Verdict(
        value=verdict,
        confidence=confidence,
        reasoning=reasoning,
        mitre_tactic=ai_mitre,
    )


# ─── Main aggregator ─────────────────────────────────────────────────────────

class ScoreAggregator:

    @staticmethod
    async def aggregate_score(
        email: Email,
        iocs: IOCs,
        enrichments: List[EnrichmentResult],
    ) -> Verdict:
        # Step 1: deterministic hard signals
        hard_mal, hard_sus, hard_notes = _hard_signals(enrichments)

        # Step 2: AI analysis (with full enrichment context)
        ai_verdict, ai_confidence, ai_reasoning, ai_mitre = (
            await ScoreAggregator._ai_analyze(email, iocs, enrichments, hard_mal, hard_sus, hard_notes)
        )

        # Step 3: merge with override rules
        return _merge_verdict(hard_mal, hard_sus, hard_notes,
                              ai_verdict, ai_confidence, ai_reasoning, ai_mitre)


    @staticmethod
    async def _ai_analyze(
        email: Email,
        iocs: IOCs,
        enrichments: List[EnrichmentResult],
        hard_mal: int,
        hard_sus: int,
        hard_notes: str,
    ) -> Tuple[VerdictType, float, str, str]:
        """Call LLM and return (verdict_type, confidence, reasoning, mitre_tactic).
        Falls back to heuristic if LLM unavailable."""
        try:
            if config.LLM_PROVIDER == "gemini" and config.GOOGLE_API_KEY:
                text = await ScoreAggregator._gemini_call(
                    ScoreAggregator._build_prompt(email, iocs, enrichments, hard_mal, hard_sus, hard_notes)
                )
            elif config.LLM_PROVIDER == "openai" and config.OPENAI_API_KEY:
                text = await ScoreAggregator._openai_call(
                    ScoreAggregator._build_prompt(email, iocs, enrichments, hard_mal, hard_sus, hard_notes)
                )
            else:
                raise RuntimeError("No LLM configured")

            # Strip markdown fences if present
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            text = text.strip()

            d = json.loads(text)
            v_str = d.get("verdict", "SUSPICIOUS").upper()
            try:
                v = VerdictType[v_str]
            except KeyError:
                v = VerdictType.SUSPICIOUS

            return v, float(d.get("confidence", 50)), d.get("reasoning", ""), d.get("mitre_tactic") or "T1566"

        except Exception as e:
            log_debug(f"LLM analysis failed: {e} — using heuristic")
            return ScoreAggregator._heuristic_ai_fallback(hard_mal, hard_sus, hard_notes)


    @staticmethod
    def _build_prompt(
        email: Email,
        iocs: IOCs,
        enrichments: List[EnrichmentResult],
        hard_mal: int,
        hard_sus: int,
        hard_notes: str,
    ) -> str:
        enrich_summary = _summarize_enrichments(enrichments)
        return f"""You are a security analyst. Your role is to analyze the EMAIL CONTENT and HEADERS for phishing signals.
Threat intel scores are already computed separately — your job is email content analysis, not re-scoring the IOCs.

NOTE: Threat intel pre-scan found {hard_mal} malicious and {hard_sus} suspicious signals: {hard_notes}

EMAIL:
Subject: {email.subject}
From: {email.sender}
Reply-To: {email.reply_to or 'N/A'}
Body (first 800 chars):
{email.body[:800]}

EXTRACTED IOCs:
URLs: {', '.join(iocs.urls[:5]) or 'None'}
IPs: {', '.join(iocs.ips[:5]) or 'None'}
Domains: {', '.join(iocs.domains[:5]) or 'None'}

THREAT INTEL RESULTS:
{enrich_summary}

Analyze: urgency language, sender spoofing, suspicious links, credential harvesting patterns, brand impersonation.
Return ONLY valid JSON (no markdown):
{{
    "verdict": "MALICIOUS|SUSPICIOUS|CLEAN",
    "confidence": 0-100,
    "reasoning": "2-3 sentence analysis of the EMAIL CONTENT signals",
    "mitre_tactic": "T1566.001 or T1566.002 or null"
}}"""


    @staticmethod
    def _heuristic_ai_fallback(
        hard_mal: int, hard_sus: int, hard_notes: str
    ) -> Tuple[VerdictType, float, str, str]:
        """Used when LLM is unavailable — returns a neutral AI signal so hard signals still drive verdict."""
        if hard_mal > 0:
            return VerdictType.SUSPICIOUS, 50.0, "LLM unavailable — based on threat intel only", "T1566"
        elif hard_sus > 0:
            return VerdictType.SUSPICIOUS, 40.0, "LLM unavailable — suspicious indicators present", "T1566"
        return VerdictType.CLEAN, 70.0, "LLM unavailable — no threat intel hits", None


    @staticmethod
    async def _gemini_call(prompt: str) -> str:
        from google import genai
        from google.genai import types
        client = genai.Client(api_key=config.GOOGLE_API_KEY)
        response = await asyncio.to_thread(
            client.models.generate_content,
            model=config.GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(temperature=0.1, max_output_tokens=600),
        )
        return response.text.strip()


    @staticmethod
    async def _openai_call(prompt: str) -> str:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=config.OPENAI_API_KEY)
        response = await client.chat.completions.create(
            model=config.OPENAI_MODEL,
            max_tokens=600,
            messages=[
                {"role": "system", "content": "You are a security analyst. Return only valid JSON."},
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content.strip()


def _summarize_enrichments(enrichments: List[EnrichmentResult]) -> str:
    if not enrichments:
        return "No threat intel data"
    lines = []
    for e in enrichments[:15]:
        ioc = e.ioc[:40] + "..." if len(e.ioc) > 40 else e.ioc
        if e.source == "virustotal":
            mal = (e.details or {}).get("malicious", 0)
            sus = (e.details or {}).get("suspicious", 0)
            lines.append(f"  VT  | {ioc} | {mal}M {sus}S detections | verdict: {e.verdict}")
        elif e.source == "abuseipdb":
            conf = (e.details or {}).get("confidence_score", e.score or 0)
            lines.append(f"  ABUSE | {ioc} | {conf}% abuse confidence | verdict: {e.verdict}")
        elif e.source == "urlscan":
            lines.append(f"  URLSCAN | {ioc} | verdict: {e.verdict}")
    return "\n".join(lines)
