"""Multi-signal verdict engine with detailed line-by-line reasoning.

Pipeline:
  1. Hard signals  — VT / AbuseIPDB / URLScan → deterministic threat scores
  2. AI analysis   — LLM reads email content → content_signals bullet list
  3. Merge         — override rules combine both layers into final verdict
  4. Reasoning     — structured, section-by-section explanation of every decision

Override rules (first match wins):
  - 2+ hard-MALICIOUS               → MALICIOUS  (AI cannot override)
  - 1 hard-MALICIOUS + AI MALICIOUS → MALICIOUS  (corroborated)
  - 1 hard-MALICIOUS + AI disagrees → SUSPICIOUS  (conflict, be cautious)
  - 0 hard signals + AI MALICIOUS   → SUSPICIOUS  (AI alone insufficient)
  - hard-SUSPICIOUS + AI MALICIOUS  → SUSPICIOUS  (elevated)
  - everything CLEAN                → CLEAN
"""
import json
import asyncio
from typing import List, Tuple, Optional
from models import Email, IOCs, EnrichmentResult, Verdict, VerdictType
from utils import log_debug
import config


# ─── Hard signal evaluation ──────────────────────────────────────────────────

def _eval_hard_signals(enrichments: List[EnrichmentResult]):
    """
    Returns (mal_count, sus_count, signal_lines) where signal_lines
    is a list of bullet strings ready to embed in the reasoning block.
    """
    mal = 0
    sus = 0
    lines = []

    for e in enrichments:
        ioc = e.ioc[:50] + "..." if len(e.ioc) > 50 else e.ioc
        d = e.details or {}

        if e.source == "virustotal":
            vt_mal = d.get("malicious", 0)
            vt_sus = d.get("suspicious", 0)
            total  = d.get("total", 0)
            if vt_mal >= config.VT_DETECTION_THRESHOLD:
                mal += 1
                lines.append(
                    f"• VirusTotal │ {ioc} │ {vt_mal}/{total} engines flagged malicious"
                    f" (threshold {config.VT_DETECTION_THRESHOLD}) → MALICIOUS"
                )
            elif vt_mal > 0 or vt_sus >= 3:
                sus += 1
                lines.append(
                    f"• VirusTotal │ {ioc} │ {vt_mal}M / {vt_sus}S detections"
                    f" (below threshold) → SUSPICIOUS"
                )
            else:
                lines.append(f"• VirusTotal │ {ioc} │ {vt_mal}M / {vt_sus}S detections → NEUTRAL")

        elif e.source == "abuseipdb":
            conf    = d.get("confidence_score") or e.score or 0
            reports = d.get("total_reports", 0)
            if conf >= config.ABUSEIPDB_CONFIDENCE_THRESHOLD:
                mal += 1
                lines.append(
                    f"• AbuseIPDB │ {ioc} │ {conf}% abuse confidence,"
                    f" {reports} reports (threshold {config.ABUSEIPDB_CONFIDENCE_THRESHOLD}%) → MALICIOUS"
                )
            elif conf >= 25:
                sus += 1
                lines.append(
                    f"• AbuseIPDB │ {ioc} │ {conf}% abuse confidence,"
                    f" {reports} reports → SUSPICIOUS"
                )
            else:
                lines.append(f"• AbuseIPDB │ {ioc} │ {conf}% confidence → NEUTRAL")

        elif e.source == "urlscan":
            v = (e.verdict or "unknown").lower()
            if v == "malicious":
                mal += 1
                lines.append(f"• URLScan   │ {ioc} │ scan verdict: malicious → MALICIOUS")
            elif v == "suspicious":
                sus += 1
                lines.append(f"• URLScan   │ {ioc} │ scan verdict: suspicious → SUSPICIOUS")
            else:
                lines.append(f"• URLScan   │ {ioc} │ scan verdict: {v} → NEUTRAL")

    if not lines:
        lines.append("• No threat intel results — all enrichment sources returned no data")

    return mal, sus, lines


# ─── Verdict merge + reasoning builder ──────────────────────────────────────

def _build_verdict(
    hard_mal: int,
    hard_sus: int,
    hard_lines: List[str],
    ai_verdict: VerdictType,
    ai_confidence: float,
    ai_signals: List[str],
    ai_mitre: Optional[str],
) -> Verdict:

    # ── Decision logic ────────────────────────────────────────────────────
    if hard_mal >= 2:
        final     = VerdictType.MALICIOUS
        confidence = min(95, 60 + hard_mal * 12)
        rule = (
            f"• {hard_mal} independent threat intel sources confirmed MALICIOUS — "
            f"hard-signal majority overrides AI"
        )
        ai_corr = "YES" if ai_verdict == VerdictType.MALICIOUS else "NO (AI disagreed but overridden)"

    elif hard_mal == 1 and ai_verdict == VerdictType.MALICIOUS:
        final      = VerdictType.MALICIOUS
        confidence = min(90, 55 + ai_confidence * 0.3)
        rule = (
            "• 1 hard-MALICIOUS signal corroborated by AI content analysis → MALICIOUS confirmed"
        )
        ai_corr = "YES"

    elif hard_mal == 1:
        final      = VerdictType.SUSPICIOUS
        confidence = 65
        rule = (
            f"• 1 hard-MALICIOUS signal found but AI verdict is {ai_verdict.value} — "
            f"conflict → escalated to SUSPICIOUS pending review"
        )
        ai_corr = f"CONFLICT (AI said {ai_verdict.value})"

    elif hard_sus > 0 and ai_verdict == VerdictType.MALICIOUS:
        final      = VerdictType.SUSPICIOUS
        confidence = 70
        rule = (
            "• Suspicious hard signals + AI flags MALICIOUS → elevated to SUSPICIOUS "
            "(insufficient hard evidence for MALICIOUS)"
        )
        ai_corr = "ELEVATED"

    elif hard_sus > 0:
        final      = VerdictType.SUSPICIOUS
        confidence = min(75, 40 + hard_sus * 10)
        rule = (
            f"• {hard_sus} suspicious indicator(s) from threat intel, no confirmed malicious → SUSPICIOUS"
        )
        ai_corr = f"AI said {ai_verdict.value}"

    elif ai_verdict == VerdictType.MALICIOUS:
        final      = VerdictType.SUSPICIOUS
        confidence = min(60, ai_confidence * 0.6)
        rule = (
            "• AI flagged MALICIOUS but zero hard threat intel signals confirm it → "
            "downgraded to SUSPICIOUS (AI alone cannot confirm MALICIOUS)"
        )
        ai_corr = "DOWNGRADED — no corroborating hard signal"

    elif ai_verdict == VerdictType.SUSPICIOUS:
        final      = VerdictType.SUSPICIOUS
        confidence = min(55, ai_confidence * 0.7)
        rule = "• AI flagged SUSPICIOUS content patterns, no hard signals → SUSPICIOUS"
        ai_corr = "YES"

    else:
        final      = VerdictType.CLEAN
        confidence = 82
        rule = "• No hard threat intel signals and AI content analysis found no phishing indicators → CLEAN"
        ai_corr = "YES"

    # ── Build structured reasoning block ─────────────────────────────────
    lines = []
    lines.append(f"VERDICT: {final.value}  ({confidence:.0f}% confidence)")
    lines.append("")
    lines.append("── THREAT INTELLIGENCE SIGNALS ──")
    lines.extend(hard_lines)
    lines.append(f"• Summary: {hard_mal} MALICIOUS signal(s), {hard_sus} SUSPICIOUS signal(s)")
    lines.append("")
    lines.append("── AI CONTENT ANALYSIS ──")
    if ai_signals:
        lines.extend([f"• {s}" for s in ai_signals])
    else:
        lines.append("• No content signals extracted")
    lines.append(f"• AI verdict: {ai_verdict.value} ({ai_confidence:.0f}% confidence)")
    lines.append("")
    lines.append("── DECISION LOGIC ──")
    lines.append(rule)
    lines.append(f"• AI corroboration: {ai_corr}")
    lines.append(f"• Final verdict: {final.value}")
    lines.append("")
    if ai_mitre:
        lines.append("── MITRE ATT&CK ──")
        lines.append(f"• {ai_mitre}")

    reasoning = "\n".join(lines)

    return Verdict(
        value=final,
        confidence=confidence,
        reasoning=reasoning,
        mitre_tactic=ai_mitre,
    )


# ─── LLM calls ───────────────────────────────────────────────────────────────

def _build_prompt(email: Email, iocs: IOCs, enrichments: List[EnrichmentResult],
                  hard_mal: int, hard_sus: int) -> str:
    enrich_text = _summarize_enrichments(enrichments)
    return f"""You are a security analyst reviewing an email for phishing.
Threat intel pre-scan: {hard_mal} MALICIOUS signal(s), {hard_sus} SUSPICIOUS signal(s).
Your task: analyze the EMAIL CONTENT (not the IOC scores — those are handled separately).

EMAIL:
Subject : {email.subject}
From    : {email.sender}
Reply-To: {email.reply_to or 'N/A'}
Body (first 1000 chars):
{email.body[:1000]}

EXTRACTED IOCs: URLs={iocs.urls[:5]}  IPs={iocs.ips[:5]}  Domains={iocs.domains[:5]}

THREAT INTEL (for context):
{enrich_text}

Look for: urgency/fear language, sender spoofing, typosquatting, credential harvesting,
brand impersonation, suspicious links, grammar anomalies, unexpected requests.

Return ONLY valid JSON (no markdown fences):
{{
  "verdict": "MALICIOUS|SUSPICIOUS|CLEAN",
  "confidence": 0-100,
  "content_signals": [
    "signal description 1",
    "signal description 2"
  ],
  "mitre_tactic": "T1566.001 or T1566.002 or null"
}}"""


def _summarize_enrichments(enrichments: List[EnrichmentResult]) -> str:
    if not enrichments:
        return "None"
    lines = []
    for e in enrichments[:12]:
        ioc = e.ioc[:40]
        d = e.details or {}
        if e.source == "virustotal":
            lines.append(f"  VT      | {ioc} | {d.get('malicious',0)}M {d.get('suspicious',0)}S | {e.verdict}")
        elif e.source == "abuseipdb":
            lines.append(f"  ABUSE   | {ioc} | {d.get('confidence_score', e.score or 0)}% | {e.verdict}")
        elif e.source == "urlscan":
            lines.append(f"  URLSCAN | {ioc} | {e.verdict}")
    return "\n".join(lines)


async def _call_llm(prompt: str) -> str:
    if config.LLM_PROVIDER == "gemini" and config.GOOGLE_API_KEY:
        from google import genai
        from google.genai import types
        client = genai.Client(api_key=config.GOOGLE_API_KEY)
        resp = await asyncio.to_thread(
            client.models.generate_content,
            model=config.GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(temperature=0.1, max_output_tokens=700),
        )
        return resp.text.strip()
    elif config.LLM_PROVIDER == "openai" and config.OPENAI_API_KEY:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=config.OPENAI_API_KEY)
        resp = await client.chat.completions.create(
            model=config.OPENAI_MODEL,
            max_tokens=700,
            messages=[
                {"role": "system", "content": "You are a security analyst. Return only valid JSON."},
                {"role": "user", "content": prompt},
            ],
        )
        return resp.choices[0].message.content.strip()
    raise RuntimeError("No LLM configured")


async def _ai_analyze(email, iocs, enrichments, hard_mal, hard_sus):
    """Returns (verdict, confidence, content_signals, mitre_tactic)."""
    try:
        text = await _call_llm(_build_prompt(email, iocs, enrichments, hard_mal, hard_sus))

        # Strip markdown fences if model wrapped anyway
        if "```" in text:
            parts = text.split("```")
            text = parts[1] if len(parts) > 1 else parts[0]
            if text.startswith("json"):
                text = text[4:]
        text = text.strip()

        d = json.loads(text)
        v_str = d.get("verdict", "SUSPICIOUS").upper()
        try:
            v = VerdictType[v_str]
        except KeyError:
            v = VerdictType.SUSPICIOUS

        signals = d.get("content_signals") or []
        if isinstance(signals, str):
            signals = [signals]

        return v, float(d.get("confidence", 50)), signals, d.get("mitre_tactic")

    except Exception as e:
        log_debug(f"LLM analysis failed: {e} — using fallback")
        # Neutral fallback — hard signals still drive the verdict
        if hard_mal > 0:
            return VerdictType.SUSPICIOUS, 50.0, ["LLM unavailable — verdict driven by threat intel"], "T1566"
        elif hard_sus > 0:
            return VerdictType.SUSPICIOUS, 40.0, ["LLM unavailable — suspicious indicators present"], "T1566"
        return VerdictType.CLEAN, 65.0, ["LLM unavailable — no threat intel hits detected"], None


# ─── Public interface ─────────────────────────────────────────────────────────

class ScoreAggregator:

    @staticmethod
    async def aggregate_score(
        email: Email,
        iocs: IOCs,
        enrichments: List[EnrichmentResult],
    ) -> Verdict:
        # Step 1: deterministic hard signals
        hard_mal, hard_sus, hard_lines = _eval_hard_signals(enrichments)

        # Step 2: AI content analysis
        ai_verdict, ai_conf, ai_signals, ai_mitre = await _ai_analyze(
            email, iocs, enrichments, hard_mal, hard_sus
        )

        # Step 3: merge with override rules → structured verdict + reasoning
        return _build_verdict(
            hard_mal, hard_sus, hard_lines,
            ai_verdict, ai_conf, ai_signals, ai_mitre,
        )
