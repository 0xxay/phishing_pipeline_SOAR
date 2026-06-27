"""AbuseIPDB enrichment via API v2."""
import aiohttp
import asyncio
from typing import List, Optional
from models import IOCs, EnrichmentResult
from utils import log_info, log_error, log_debug
import config


class AbuseIPDBEnricher:
    """Queries AbuseIPDB API v2 for IP address reputation."""

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"
    HEADERS = {
        "Key": config.ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    @staticmethod
    async def check_ip(session: aiohttp.ClientSession, ip: str) -> Optional[EnrichmentResult]:
        """Check IP reputation on AbuseIPDB."""
        if not config.ABUSEIPDB_API_KEY:
            return None

        try:
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": "",
            }

            async with session.get(
                AbuseIPDBEnricher.BASE_URL,
                params=params,
                headers=AbuseIPDBEnricher.HEADERS,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    data = result.get("data", {})
                    confidence = data.get("abuseConfidenceScore", 0)
                    total_reports = data.get("totalReports", 0)

                    # Determine verdict based on confidence score
                    if confidence >= 75:
                        verdict = "malicious"
                    elif confidence >= 25:
                        verdict = "suspicious"
                    else:
                        verdict = "clean"

                    return EnrichmentResult(
                        ioc=ip,
                        source="abuseipdb",
                        score=confidence,
                        verdict=verdict,
                        details={
                            "confidence_score": confidence,
                            "total_reports": total_reports,
                            "usage_type": data.get("usageType", ""),
                            "isp": data.get("isp", ""),
                            "country": data.get("countryCode", ""),
                        },
                        raw=result,
                    )
                else:
                    log_debug(f"AbuseIPDB check failed: {response.status}")
                    return None

        except asyncio.TimeoutError:
            log_debug(f"AbuseIPDB timeout for IP: {ip}")
            return None
        except Exception as e:
            log_debug(f"AbuseIPDB check error: {str(e)}")
            return None

    @staticmethod
    async def enrich(iocs: IOCs) -> List[EnrichmentResult]:
        """Enrich IOCs using AbuseIPDB."""
        results = []

        if not config.ABUSEIPDB_API_KEY:
            log_info("AbuseIPDB API key not configured, skipping")
            return results

        async with aiohttp.ClientSession() as session:
            tasks = []

            # Check IPs
            for ip in iocs.ips[:10]:  # Limit to 10 to avoid rate limiting
                tasks.append(AbuseIPDBEnricher.check_ip(session, ip))

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for response in responses:
                if isinstance(response, EnrichmentResult):
                    results.append(response)
                elif isinstance(response, Exception):
                    log_debug(f"AbuseIPDB enrichment error: {str(response)}")

        return results
