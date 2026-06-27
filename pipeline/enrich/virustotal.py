"""VirusTotal enrichment via API v3."""
import aiohttp
import asyncio
from typing import List, Optional
from models import IOCs, EnrichmentResult
from utils import log_info, log_error, log_debug
import config


class VirusTotalEnricher:
    """Queries VirusTotal API v3 for URL and hash analysis."""

    BASE_URL = "https://www.virustotal.com/api/v3"
    HEADERS = {"x-apikey": config.VIRUSTOTAL_API_KEY}

    @staticmethod
    async def check_url(session: aiohttp.ClientSession, url: str) -> Optional[EnrichmentResult]:
        """Check URL reputation on VirusTotal."""
        if not config.VIRUSTOTAL_API_KEY:
            return None

        try:
            # VirusTotal expects URLs to be POST-encoded
            data = {"url": url}
            async with session.post(
                f"{VirusTotalEnricher.BASE_URL}/urls",
                data=data,
                headers=VirusTotalEnricher.HEADERS,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    analysis_stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = analysis_stats.get("malicious", 0)
                    suspicious = analysis_stats.get("suspicious", 0)

                    # Calculate score based on detections
                    score = min(100, (malicious * 10 + suspicious * 5))
                    verdict = "malicious" if malicious > 0 else "suspicious" if suspicious > 0 else "clean"

                    return EnrichmentResult(
                        ioc=url,
                        source="virustotal",
                        score=score,
                        verdict=verdict,
                        details={
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "undetected": analysis_stats.get("undetected", 0),
                        },
                        raw=result,
                    )
                elif response.status == 404:
                    return EnrichmentResult(
                        ioc=url,
                        source="virustotal",
                        score=0,
                        verdict="unknown",
                        details={"message": "URL not in VirusTotal database"},
                    )
                else:
                    log_debug(f"VirusTotal URL check failed: {response.status}")
                    return None

        except asyncio.TimeoutError:
            log_debug(f"VirusTotal timeout for URL: {url}")
            return None
        except Exception as e:
            log_debug(f"VirusTotal URL check error: {str(e)}")
            return None

    @staticmethod
    async def check_hash(session: aiohttp.ClientSession, hash_val: str) -> Optional[EnrichmentResult]:
        """Check file hash on VirusTotal."""
        if not config.VIRUSTOTAL_API_KEY:
            return None

        try:
            async with session.get(
                f"{VirusTotalEnricher.BASE_URL}/files/{hash_val}",
                headers=VirusTotalEnricher.HEADERS,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    analysis_stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = analysis_stats.get("malicious", 0)
                    suspicious = analysis_stats.get("suspicious", 0)

                    score = min(100, (malicious * 10 + suspicious * 5))
                    verdict = "malicious" if malicious > 0 else "suspicious" if suspicious > 0 else "clean"

                    return EnrichmentResult(
                        ioc=hash_val,
                        source="virustotal",
                        score=score,
                        verdict=verdict,
                        details={
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "undetected": analysis_stats.get("undetected", 0),
                        },
                        raw=result,
                    )
                elif response.status == 404:
                    return EnrichmentResult(
                        ioc=hash_val,
                        source="virustotal",
                        score=0,
                        verdict="unknown",
                        details={"message": "Hash not in VirusTotal database"},
                    )
                else:
                    log_debug(f"VirusTotal hash check failed: {response.status}")
                    return None

        except asyncio.TimeoutError:
            log_debug(f"VirusTotal timeout for hash: {hash_val}")
            return None
        except Exception as e:
            log_debug(f"VirusTotal hash check error: {str(e)}")
            return None

    @staticmethod
    async def enrich(iocs: IOCs) -> List[EnrichmentResult]:
        """Enrich IOCs using VirusTotal."""
        results = []

        if not config.VIRUSTOTAL_API_KEY:
            log_info("VirusTotal API key not configured, skipping")
            return results

        async with aiohttp.ClientSession() as session:
            tasks = []

            # Check URLs
            for url in iocs.urls[:10]:  # Limit to 10 to avoid rate limiting
                tasks.append(VirusTotalEnricher.check_url(session, url))

            # Check hashes
            for hash_val in iocs.hashes[:10]:  # Limit to 10
                tasks.append(VirusTotalEnricher.check_hash(session, hash_val))

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for response in responses:
                if isinstance(response, EnrichmentResult):
                    results.append(response)
                elif isinstance(response, Exception):
                    log_debug(f"VirusTotal enrichment error: {str(response)}")

        return results
