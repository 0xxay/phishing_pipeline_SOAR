"""TheHive v5 API client for case creation."""
import aiohttp
from typing import Optional
from models import PhishingCase, VerdictType
from utils import log_info, log_error, log_debug
import config
import json


class TheHiveClient:
    """Creates cases in TheHive v5."""

    def __init__(self):
        self.url = config.THEHIVE_URL
        self.api_key = config.THEHIVE_API_KEY
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def create_case(self, case: PhishingCase) -> Optional[str]:
        """Create a case in TheHive."""
        if not self.api_key:
            log_debug("TheHive API key not configured")
            return None

        # Map verdict to severity
        severity_map = {
            VerdictType.MALICIOUS: 3,  # High
            VerdictType.SUSPICIOUS: 2,  # Medium
            VerdictType.CLEAN: 1,  # Low (usually not created for clean)
        }

        case_data = {
            "title": f"Phishing: {case.email.subject}",
            "description": f"""
Email Analysis Report

FROM: {case.email.sender}
SUBJECT: {case.email.subject}
VERDICT: {case.verdict.value.value} (Confidence: {case.verdict.confidence:.1f}%)
REASONING: {case.verdict.reasoning}

MITRE ATT&CK: {case.verdict.mitre_tactic or 'T1566'}

IOCs EXTRACTED:
- URLs: {len(case.iocs.urls)}
- IPs: {len(case.iocs.ips)}
- Domains: {len(case.iocs.domains)}
- Hashes: {len(case.iocs.hashes)}

ENRICHMENT RESULTS:
- Total Enrichments: {len(case.enrichments)}
""",
            "severity": severity_map.get(case.verdict.value, 2),
            "tags": ["phishing", case.verdict.mitre_tactic or "T1566"],
            "flag": case.verdict.value == VerdictType.MALICIOUS,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.url}/api/v1/case",
                    json=case_data,
                    headers=self.headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    if response.status in [200, 201]:
                        result = await response.json()
                        case_id = result.get("_id")
                        log_info(f"TheHive case created: {case_id}")

                        # Add observables
                        await self._add_observables(session, case_id, case)

                        return case_id
                    else:
                        error_text = await response.text()
                        log_error(
                            f"Failed to create TheHive case: {response.status} - {error_text}"
                        )
                        return None

        except asyncio.TimeoutError:
            log_error("TheHive timeout when creating case")
            return None
        except Exception as e:
            log_error(f"Error creating TheHive case: {str(e)}")
            return None

    async def _add_observables(
        self, session: aiohttp.ClientSession, case_id: str, case: PhishingCase
    ):
        """Add observables (IOCs) to the case."""
        observables = []

        # Add URLs
        for url in case.iocs.urls:
            observables.append(
                {
                    "dataType": "url",
                    "data": url,
                    "tags": ["phishing", "extracted"],
                }
            )

        # Add IPs
        for ip in case.iocs.ips:
            observables.append(
                {
                    "dataType": "ip",
                    "data": ip,
                    "tags": ["phishing", "extracted"],
                }
            )

        # Add Domains
        for domain in case.iocs.domains:
            observables.append(
                {
                    "dataType": "domain",
                    "data": domain,
                    "tags": ["phishing", "extracted"],
                }
            )

        # Add Hashes
        for hash_val in case.iocs.hashes:
            # Determine hash type by length
            if len(hash_val) == 32:
                hash_type = "hash"
            elif len(hash_val) == 40:
                hash_type = "hash"
            elif len(hash_val) == 64:
                hash_type = "hash"
            else:
                continue

            observables.append(
                {
                    "dataType": hash_type,
                    "data": hash_val,
                    "tags": ["phishing", "extracted"],
                }
            )

        # Add each observable
        for observable in observables[:50]:  # Limit to 50 to avoid overwhelming
            try:
                async with session.post(
                    f"{self.url}/api/v1/case/{case_id}/observable",
                    json=observable,
                    headers=self.headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    if response.status not in [200, 201]:
                        log_debug(f"Failed to add observable: {response.status}")

            except Exception as e:
                log_debug(f"Error adding observable: {str(e)}")


import asyncio
