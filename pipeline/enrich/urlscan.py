"""URLScan.io enrichment API."""
import aiohttp
import asyncio
from typing import List, Optional
from models import IOCs, EnrichmentResult
from utils import log_info, log_error, log_debug
import config
import time


class URLScanEnricher:
    """Queries URLScan.io API for URL and screenshot analysis."""

    BASE_URL = "https://urlscan.io/api/v1"
    HEADERS = {"API-Key": config.URLSCAN_API_KEY}

    @staticmethod
    async def submit_url(session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """Submit URL for scanning on URLScan.io."""
        if not config.URLSCAN_API_KEY:
            return None

        try:
            data = {
                "url": url,
                "visibility": "unlisted",
            }

            async with session.post(
                f"{URLScanEnricher.BASE_URL}/scan/",
                json=data,
                headers=URLScanEnricher.HEADERS,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    scan_id = result.get("uuid")
                    return scan_id
                elif response.status == 429:
                    log_debug("URLScan rate limit reached")
                    return None
                else:
                    body = await response.text()
                    log_debug(f"URLScan submit failed: {response.status} — {body[:200]}")
                    return None

        except asyncio.TimeoutError:
            log_debug(f"URLScan submit timeout for URL: {url}")
            return None
        except Exception as e:
            log_debug(f"URLScan submit error: {str(e)}")
            return None

    @staticmethod
    async def get_scan_result(session: aiohttp.ClientSession, scan_id: str) -> Optional[dict]:
        """Retrieve scan results from URLScan.io."""
        if not config.URLSCAN_API_KEY:
            return None

        try:
            # Wait a bit for scan to complete
            await asyncio.sleep(2)

            async with session.get(
                f"{URLScanEnricher.BASE_URL}/result/{scan_id}/",
                headers=URLScanEnricher.HEADERS,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    return result
                elif response.status == 404:
                    log_debug(f"Scan result not ready: {scan_id}")
                    return None
                else:
                    log_debug(f"URLScan result fetch failed: {response.status}")
                    return None

        except asyncio.TimeoutError:
            log_debug(f"URLScan result fetch timeout for scan: {scan_id}")
            return None
        except Exception as e:
            log_debug(f"URLScan result fetch error: {str(e)}")
            return None

    @staticmethod
    async def check_url(session: aiohttp.ClientSession, url: str) -> Optional[EnrichmentResult]:
        """Submit URL to URLScan and retrieve results."""
        if not config.URLSCAN_API_KEY:
            return None

        try:
            # Submit for scanning
            scan_id = await URLScanEnricher.submit_url(session, url)
            if not scan_id:
                return None

            # Get results
            result = await URLScanEnricher.get_scan_result(session, scan_id)
            if not result:
                return EnrichmentResult(
                    ioc=url,
                    source="urlscan",
                    score=None,
                    verdict="unknown",
                    details={"message": "Scan submitted but results not yet available"},
                )

            # Extract verdict from URLScan
            page_stats = result.get("stats", {})
            verdicts = result.get("verdicts", {})
            url_verdict = verdicts.get("urlscan", {}).get("verdict", "clean")

            # Convert URLScan verdict to our format
            if "malicious" in url_verdict.lower():
                verdict = "malicious"
                score = 90
            elif "suspicious" in url_verdict.lower():
                verdict = "suspicious"
                score = 60
            else:
                verdict = "clean"
                score = 0

            return EnrichmentResult(
                ioc=url,
                source="urlscan",
                score=score,
                verdict=verdict,
                details={
                    "urlscan_verdict": url_verdict,
                    "malicious_count": page_stats.get("malicious", 0),
                    "suspicious_count": page_stats.get("suspicious", 0),
                    "scan_id": scan_id,
                },
                raw=result,
            )

        except Exception as e:
            log_debug(f"URLScan check error: {str(e)}")
            return None

    @staticmethod
    async def enrich(iocs: IOCs) -> List[EnrichmentResult]:
        """Enrich IOCs using URLScan.io."""
        results = []

        if not config.URLSCAN_API_KEY:
            log_info("URLScan API key not configured, skipping")
            return results

        async with aiohttp.ClientSession() as session:
            tasks = []

            # Check URLs
            for url in iocs.urls[:5]:  # Limit to 5 to avoid rate limiting
                tasks.append(URLScanEnricher.check_url(session, url))

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for response in responses:
                if isinstance(response, EnrichmentResult):
                    results.append(response)
                elif isinstance(response, Exception):
                    log_debug(f"URLScan enrichment error: {str(response)}")

        return results
