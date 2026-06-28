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
import re
import asyncio
from typing import List, Tuple, Optional
from models import Email, IOCs, EnrichmentResult, Verdict, VerdictType
from utils import log_debug
import config


# ─── Header signal analysis ──────────────────────────────────────────────────

def _eval_header_signals(email: Email) -> Tuple[int, int, List[str]]:
    """
    Check email authentication headers and metadata for red flags.
    Returns (mal_count, sus_count, signal_lines).
    """
    mal = 0
    sus = 0
    lines = []
    h = {k.lower(): str(v) for k, v in (email.headers or {}).items()}

    # SPF check
    spf_raw = h.get("received-spf", h.get("x-spf-status", ""))
    auth_results = h.get("authentication-results", "")
    if re.search(r"\bfail\b", spf_raw, re.I) or re.search(r"spf=fail", auth_results, re.I):
        mal += 1
        lines.append("• SPF: FAIL — sender IP not authorized by domain → MALICIOUS")
    elif re.search(r"\bsoftfail\b|\bneutral\b|\bnone\b", spf_raw, re.I):
        sus += 1
        lines.append(f"• SPF: {spf_raw.strip()[:60]} — weak/missing authorization → SUSPICIOUS")
    elif re.search(r"\bpass\b", spf_raw, re.I) or re.search(r"spf=pass", auth_results, re.I):
        lines.append("• SPF: PASS → NEUTRAL")
    else:
        sus += 1
        lines.append("• SPF: header absent — cannot verify sender authorization → SUSPICIOUS")

    # DKIM check
    if re.search(r"dkim=fail", auth_results, re.I):
        mal += 1
        lines.append("• DKIM: FAIL — email signature invalid, likely forged → MALICIOUS")
    elif re.search(r"dkim=pass", auth_results, re.I):
        lines.append("• DKIM: PASS → NEUTRAL")
    elif not h.get("dkim-signature"):
        sus += 1
        lines.append("• DKIM: no signature present — sender identity unverified → SUSPICIOUS")

    # DMARC check
    if re.search(r"dmarc=fail", auth_results, re.I):
        mal += 1
        lines.append("• DMARC: FAIL — domain policy violated, high spoofing risk → MALICIOUS")
    elif re.search(r"dmarc=pass", auth_results, re.I):
        lines.append("• DMARC: PASS → NEUTRAL")

    # Reply-To domain mismatch
    from_raw = email.sender or ""
    reply_raw = email.reply_to or ""
    from_domain = re.search(r"@([\w.\-]+)", from_raw)
    reply_domain = re.search(r"@([\w.\-]+)", reply_raw)
    if from_domain and reply_domain:
        fd = from_domain.group(1).lower().rstrip(">")
        rd = reply_domain.group(1).lower().rstrip(">")
        if fd != rd:
            sus += 1
            lines.append(
                f"• Reply-To domain mismatch: From=@{fd} vs Reply-To=@{rd}"
                f" — responses go to a different domain → SUSPICIOUS"
            )

    # Display name / From domain mismatch (e.g. "PayPal <attacker@evil.com>")
    display_match = re.match(r'^"?([^"<]+)"?\s*<', from_raw)
    if display_match:
        display_name = display_match.group(1).strip().lower()
        from_dom = from_domain.group(1).lower() if from_domain else ""
        # Check if display name looks like a brand but domain doesn't match
        for brand in ["paypal", "amazon", "google", "microsoft", "apple", "bank", "netflix", "fedex", "dhl"]:
            if brand in display_name and brand not in from_dom:
                sus += 1
                lines.append(
                    f"• Display name impersonation: '{display_match.group(1).strip()}' "
                    f"uses brand name '{brand}' but sender domain is '{from_dom}' → SUSPICIOUS"
                )
                break

    if not lines:
        lines.append("• Header analysis: no authentication headers found → SUSPICIOUS")
        sus += 1

    return mal, sus, lines


# ─── IOC signal analysis ─────────────────────────────────────────────────────

def _eval_ioc_signals(iocs: IOCs) -> Tuple[int, int, List[str]]:
    """Check IOC patterns for inherent red flags."""
    mal = 0
    sus = 0
    lines = []

    # Suspicious TLDs in URLs/domains
    suspicious_tlds = {".ru", ".cn", ".tk", ".xyz", ".top", ".pw", ".cc", ".su", ".to"}
    all_domains = iocs.domains + [
        re.search(r"https?://([^/]+)", u).group(1) for u in iocs.urls
        if re.search(r"https?://([^/]+)", u)
    ]
    for domain in all_domains:
        for tld in suspicious_tlds:
            if domain.lower().endswith(tld):
                sus += 1
                lines.append(f"• Suspicious TLD: {domain} uses '{tld}' — high-abuse TLD → SUSPICIOUS")
                break

    # IP-based URLs (no domain)
    ip_urls = [u for u in iocs.urls if re.search(r"https?://\d{1,3}\.\d{1,3}\.", u)]
    if ip_urls:
        sus += 1
        lines.append(f"• IP-based URL(s): {ip_urls[0][:60]} — legitimate sites rarely use raw IPs → SUSPICIOUS")

    # URL shorteners
    shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "tiny.cc", "rb.gy"]
    for url in iocs.urls:
        if any(s in url for s in shorteners):
            sus += 1
            lines.append(f"• URL shortener detected: {url[:60]} — hides true destination → SUSPICIOUS")
            break

    # Total IOC count
    total = len(iocs.all_iocs())
    if total >= 5:
        sus += 1
        lines.append(f"• High IOC density: {total} indicators extracted — unusual for legitimate email → SUSPICIOUS")
    elif total > 0:
        lines.append(f"• IOC count: {total} indicator(s) extracted → NEUTRAL")

    if not lines:
        lines.append("• IOC pattern analysis: no inherently suspicious patterns detected → NEUTRAL")

    return mal, sus, lines


# ─── Threat intel signal evaluation ──────────────────────────────────────────

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
    header_mal: int,
    header_sus: int,
    header_lines: List[str],
    ioc_mal: int,
    ioc_sus: int,
    ioc_lines: List[str],
    ai_verdict: VerdictType,
    ai_confidence: float,
    ai_signals: List[str],
    ai_mitre: Optional[str],
) -> Verdict:
    # Combine all hard + structural signals
    total_mal = hard_mal + header_mal + ioc_mal
    total_sus = hard_sus + header_sus + ioc_sus

    # ── Decision logic (uses combined total_mal / total_sus) ─────────────
    if total_mal >= 2:
        final      = VerdictType.MALICIOUS
        confidence = min(95, 55 + total_mal * 10)
        rule = (
            f"• {total_mal} independent signals confirmed MALICIOUS across threat intel "
            f"and header/IOC analysis — hard-signal majority overrides AI"
        )
        ai_corr = "YES" if ai_verdict == VerdictType.MALICIOUS else "NO (AI disagreed but overridden by hard signals)"

    elif total_mal == 1 and ai_verdict == VerdictType.MALICIOUS:
        final      = VerdictType.MALICIOUS
        confidence = min(88, 52 + ai_confidence * 0.3)
        rule = "• 1 confirmed MALICIOUS signal corroborated by AI content analysis → MALICIOUS"
        ai_corr = "YES"

    elif total_mal == 1:
        final      = VerdictType.SUSPICIOUS
        confidence = min(72, 55 + total_sus * 3)
        rule = (
            f"• 1 MALICIOUS signal found but AI verdict is {ai_verdict.value} — "
            f"conflict → SUSPICIOUS pending manual review"
        )
        ai_corr = f"CONFLICT (AI said {ai_verdict.value})"

    elif total_sus >= 3 and ai_verdict == VerdictType.MALICIOUS:
        final      = VerdictType.MALICIOUS
        confidence = min(82, 50 + total_sus * 6)
        rule = (
            f"• {total_sus} SUSPICIOUS signals + AI flags MALICIOUS → converging evidence → MALICIOUS"
        )
        ai_corr = "ELEVATED TO MALICIOUS"

    elif total_sus > 0 and ai_verdict in (VerdictType.MALICIOUS, VerdictType.SUSPICIOUS):
        final      = VerdictType.SUSPICIOUS
        confidence = min(78, 38 + total_sus * 8)
        rule = (
            f"• {total_sus} suspicious indicator(s) across signals + AI agrees → SUSPICIOUS"
        )
        ai_corr = f"YES (AI: {ai_verdict.value})"

    elif total_sus > 0:
        final      = VerdictType.SUSPICIOUS
        confidence = min(65, 35 + total_sus * 6)
        rule = f"• {total_sus} suspicious indicator(s) detected, no confirmed malicious → SUSPICIOUS"
        ai_corr = f"AI said {ai_verdict.value}"

    elif ai_verdict == VerdictType.MALICIOUS:
        final      = VerdictType.SUSPICIOUS
        confidence = min(58, ai_confidence * 0.55)
        rule = (
            "• AI flagged MALICIOUS but zero hard/header/IOC signals confirm it → "
            "downgraded to SUSPICIOUS (AI alone cannot confirm MALICIOUS)"
        )
        ai_corr = "DOWNGRADED — no corroborating signals"

    elif ai_verdict == VerdictType.SUSPICIOUS:
        final      = VerdictType.SUSPICIOUS
        confidence = min(52, ai_confidence * 0.65)
        rule = "• AI flagged SUSPICIOUS content patterns with no hard signals → SUSPICIOUS"
        ai_corr = "YES"

    else:
        final      = VerdictType.CLEAN
        confidence = min(88, 72 + max(0, 5 - total_sus) * 3)
        rule = "• No MALICIOUS or SUSPICIOUS signals detected across all layers → CLEAN"
        ai_corr = "YES"

    # ── Build structured reasoning block ─────────────────────────────────
    out = []
    out.append(f"VERDICT: {final.value}  ({confidence:.0f}% confidence)")
    out.append("")

    out.append("── THREAT INTELLIGENCE SIGNALS ──")
    out.extend(hard_lines)
    out.append(f"• Sub-total: {hard_mal} MALICIOUS, {hard_sus} SUSPICIOUS from threat intel APIs")
    out.append("")

    out.append("── EMAIL HEADER ANALYSIS ──")
    out.extend(header_lines)
    out.append(f"• Sub-total: {header_mal} MALICIOUS, {header_sus} SUSPICIOUS from header checks")
    out.append("")

    out.append("── IOC PATTERN ANALYSIS ──")
    out.extend(ioc_lines)
    out.append(f"• Sub-total: {ioc_mal} MALICIOUS, {ioc_sus} SUSPICIOUS from IOC patterns")
    out.append("")

    out.append("── AI CONTENT ANALYSIS ──")
    if ai_signals:
        out.extend([f"• {s}" for s in ai_signals])
    else:
        out.append("• No content signals extracted by AI")
    out.append(f"• AI verdict: {ai_verdict.value} ({ai_confidence:.0f}% confidence)")
    out.append("")

    out.append("── DECISION LOGIC ──")
    out.append(f"• Combined signals: {total_mal} MALICIOUS, {total_sus} SUSPICIOUS across all layers")
    out.append(rule)
    out.append(f"• AI corroboration: {ai_corr}")
    out.append(f"• Final verdict: {final.value}")
    out.append("")

    if ai_mitre:
        out.append("── MITRE ATT&CK ──")
        out.append(f"• {ai_mitre}")

    return Verdict(
        value=final,
        confidence=confidence,
        reasoning="\n".join(out),
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
        # Step 1a: threat intel hard signals (VT / AbuseIPDB / URLScan)
        hard_mal, hard_sus, hard_lines = _eval_hard_signals(enrichments)

        # Step 1b: email header authentication signals (SPF / DKIM / DMARC / Reply-To)
        header_mal, header_sus, header_lines = _eval_header_signals(email)

        # Step 1c: IOC pattern signals (suspicious TLDs / IP URLs / shorteners)
        ioc_mal, ioc_sus, ioc_lines = _eval_ioc_signals(iocs)

        total_mal = hard_mal + header_mal + ioc_mal
        total_sus = hard_sus + header_sus + ioc_sus

        # Step 2: AI content analysis (with full context)
        ai_verdict, ai_conf, ai_signals, ai_mitre = await _ai_analyze(
            email, iocs, enrichments, total_mal, total_sus
        )

        # Step 3: merge all layers → structured verdict + reasoning
        return _build_verdict(
            hard_mal, hard_sus, hard_lines,
            header_mal, header_sus, header_lines,
            ioc_mal, ioc_sus, ioc_lines,
            ai_verdict, ai_conf, ai_signals, ai_mitre,
        )
