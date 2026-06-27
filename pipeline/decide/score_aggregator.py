"""LLM-powered score aggregation and verdict decision.
Supports both Google Gemini and OpenAI models, configurable via LLM_PROVIDER."""
import json
import asyncio
from typing import List, Tuple
from models import Email, IOCs, EnrichmentResult, Verdict, VerdictType
from utils import log_info, log_error, log_debug, logger
import config


class ScoreAggregator:
    """Aggregates enrichment scores and uses configured LLM (Gemini or OpenAI) for final verdict."""

    @staticmethod
    async def aggregate_score(
        email: Email,
        iocs: IOCs,
        enrichments: List[EnrichmentResult],
    ) -> Verdict:
        """
        Analyze all enrichment data and return a verdict using configured LLM provider.
        Falls back to heuristic scoring if LLM is unavailable.
        """

        # Try LLM analysis first
        if config.LLM_PROVIDER == "gemini" and config.GOOGLE_API_KEY:
            try:
                verdict = await ScoreAggregator._llm_analyze(
                    email, iocs, enrichments
                )
                return verdict
            except Exception as e:
                log_debug(f"Gemini analysis failed: {str(e)}, falling back to heuristic")
        elif config.LLM_PROVIDER == "openai" and config.OPENAI_API_KEY:
            try:
                verdict = await ScoreAggregator._llm_analyze(
                    email, iocs, enrichments
                )
                return verdict
            except Exception as e:
                log_debug(f"OpenAI analysis failed: {str(e)}, falling back to heuristic")

        # Fallback to heuristic scoring
        return ScoreAggregator._heuristic_score(email, iocs, enrichments)

    @staticmethod
    async def _llm_analyze(
        email: Email,
        iocs: IOCs,
        enrichments: List[EnrichmentResult],
    ) -> Verdict:
        """Use configured LLM (Gemini or OpenAI) to analyze email and enrichment data."""
        # Build context for LLM
        enrichment_summary = ScoreAggregator._summarize_enrichments(enrichments)

        full_prompt = f"""You are a security analyst. Analyze this phishing email and threat intelligence data. Return ONLY valid JSON (no markdown, no explanation).

EMAIL DETAILS:
Subject: {email.subject}
From: {email.sender}
Reply-To: {email.reply_to or 'N/A'}

EXTRACTED IOCs:
URLs: {', '.join(iocs.urls[:5]) or 'None'}
IPs: {', '.join(iocs.ips[:5]) or 'None'}
Domains: {', '.join(iocs.domains[:5]) or 'None'}
Hashes: {', '.join(iocs.hashes[:3]) or 'None'}

THREAT INTELLIGENCE:
{enrichment_summary}

Return ONLY valid JSON:
{{
    "verdict": "MALICIOUS|SUSPICIOUS|CLEAN",
    "confidence": 0-100,
    "reasoning": "2-3 sentence summary",
    "mitre_tactic": "T1566 or null"
}}"""

        try:
            if config.LLM_PROVIDER == "gemini":
                response_text = await ScoreAggregator._gemini_call(full_prompt)
            else:  # openai
                response_text = await ScoreAggregator._openai_call(full_prompt)

            # Parse JSON response
            # Handle case where response is wrapped in markdown code blocks
            if response_text.startswith("```"):
                response_text = response_text.split("```")[1]
                if response_text.startswith("json"):
                    response_text = response_text[4:]
                response_text = response_text.strip()

            verdict_data = json.loads(response_text)

            # Map string verdict to VerdictType
            verdict_str = verdict_data.get("verdict", "SUSPICIOUS").upper()
            try:
                verdict_type = VerdictType[verdict_str]
            except KeyError:
                verdict_type = VerdictType.SUSPICIOUS

            return Verdict(
                value=verdict_type,
                confidence=float(verdict_data.get("confidence", 50)),
                reasoning=verdict_data.get("reasoning", "LLM analysis"),
                mitre_tactic=verdict_data.get("mitre_tactic"),
            )

        except json.JSONDecodeError as e:
            log_debug(f"Failed to parse LLM response: {str(e)}")
            raise
        except Exception as e:
            log_debug(f"LLM API error: {str(e)}")
            raise

    @staticmethod
    async def _gemini_call(prompt: str) -> str:
        """Call Gemini API using the new google-genai SDK."""
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=config.GOOGLE_API_KEY)
        response = await asyncio.to_thread(
            client.models.generate_content,
            model=config.GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.1,
                max_output_tokens=500,
            ),
        )
        return response.text.strip()

    @staticmethod
    async def _openai_call(prompt: str) -> str:
        """Call OpenAI API asynchronously."""
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=config.OPENAI_API_KEY)
        response = await client.chat.completions.create(
            model=config.OPENAI_MODEL,
            max_tokens=500,
            messages=[
                {
                    "role": "system",
                    "content": "You are a security analyst analyzing phishing emails.",
                },
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content.strip()

    @staticmethod
    def _heuristic_score(
        email: Email,
        iocs: IOCs,
        enrichments: List[EnrichmentResult],
    ) -> Verdict:
        """Heuristic scoring without GPT-4o."""
        malicious_count = 0
        suspicious_count = 0
        confidence = 0

        # Check VirusTotal results
        vt_results = [e for e in enrichments if e.source == "virustotal"]
        for result in vt_results:
            if result.verdict == "malicious":
                if result.details.get("malicious", 0) > config.VT_DETECTION_THRESHOLD:
                    malicious_count += 1
                else:
                    suspicious_count += 1
            elif result.verdict == "suspicious":
                suspicious_count += 1

        # Check AbuseIPDB results
        abuse_results = [e for e in enrichments if e.source == "abuseipdb"]
        for result in abuse_results:
            score = result.score or 0
            if score > config.ABUSEIPDB_CONFIDENCE_THRESHOLD:
                malicious_count += 1
            elif score > 25:
                suspicious_count += 1

        # Check URLScan results
        urlscan_results = [e for e in enrichments if e.source == "urlscan"]
        for result in urlscan_results:
            if result.verdict == "malicious":
                malicious_count += 1
            elif result.verdict == "suspicious":
                suspicious_count += 1

        # Determine verdict
        if malicious_count > 0:
            verdict = VerdictType.MALICIOUS
            confidence = min(100, 50 + (malicious_count * 15))
        elif suspicious_count > 1:
            verdict = VerdictType.SUSPICIOUS
            confidence = min(100, 40 + (suspicious_count * 10))
        else:
            verdict = VerdictType.CLEAN
            confidence = min(100, 80)

        reasoning = f"Heuristic analysis: {malicious_count} malicious indicators, {suspicious_count} suspicious indicators"

        return Verdict(
            value=verdict,
            confidence=confidence,
            reasoning=reasoning,
            mitre_tactic="T1566.002",  # Spearphishing Link
        )

    @staticmethod
    def _summarize_enrichments(enrichments: List[EnrichmentResult]) -> str:
        """Summarize enrichment results for GPT context."""
        if not enrichments:
            return "No threat intelligence data available"

        summary_lines = []

        for result in enrichments[:20]:  # Limit to 20 results
            ioc = result.ioc
            if len(ioc) > 40:
                ioc = ioc[:37] + "..."

            verdict = result.verdict or "unknown"
            score = result.score or "N/A"
            details = result.details or {}

            if result.source == "virustotal":
                malicious = details.get("malicious", 0)
                suspicious = details.get("suspicious", 0)
                summary_lines.append(
                    f"- {result.source}: {ioc} | Verdict: {verdict} | Score: {score} | "
                    f"Malicious: {malicious}, Suspicious: {suspicious}"
                )
            elif result.source == "abuseipdb":
                confidence = details.get("confidence_score", 0)
                reports = details.get("total_reports", 0)
                summary_lines.append(
                    f"- {result.source}: {ioc} | Verdict: {verdict} | Confidence: {confidence}% | "
                    f"Reports: {reports}"
                )
            elif result.source == "urlscan":
                summary_lines.append(
                    f"- {result.source}: {ioc} | Verdict: {verdict} | Scan ID: {details.get('scan_id', 'N/A')}"
                )

        return "\n".join(summary_lines)
