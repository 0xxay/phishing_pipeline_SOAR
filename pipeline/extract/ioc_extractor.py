"""Extract IOCs (URLs, IPs, domains, hashes) from email."""
import re
from typing import List, Set
from models import IOCs
from utils import log_ioc, log_debug


class IOCExtractor:
    """Extracts Indicators of Compromise from email text."""

    # Regex patterns
    URL_PATTERN = re.compile(
        r"https?://[^\s<>\"{}|\\^\[\]`]+"
    )

    # IPv4 pattern
    IPV4_PATTERN = re.compile(
        r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    )

    # Domain pattern (basic - matches domain.tld)
    DOMAIN_PATTERN = re.compile(
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}"
    )

    # Hash patterns
    MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
    SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
    SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

    # Private IP ranges to exclude
    PRIVATE_IP_RANGES = [
        re.compile(r"^10\."),
        re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
        re.compile(r"^192\.168\."),
        re.compile(r"^127\."),
        re.compile(r"^169\.254\."),
    ]

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP is in private range."""
        for pattern in IOCExtractor.PRIVATE_IP_RANGES:
            if pattern.match(ip):
                return True
        return False

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract URLs from text."""
        urls = IOCExtractor.URL_PATTERN.findall(text)
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        return unique_urls

    @staticmethod
    def extract_ips(text: str) -> List[str]:
        """Extract IPv4 addresses, excluding private ranges."""
        ips = IOCExtractor.IPV4_PATTERN.findall(text)
        # Filter out private IPs
        public_ips = [ip for ip in ips if not IOCExtractor.is_private_ip(ip)]
        # Remove duplicates
        return list(set(public_ips))

    @staticmethod
    def extract_domains(text: str) -> List[str]:
        """Extract domains from text and URLs."""
        domains = set()

        # Extract from text
        text_domains = IOCExtractor.DOMAIN_PATTERN.findall(text)
        domains.update(text_domains)

        # Extract from URLs
        urls = IOCExtractor.extract_urls(text)
        for url in urls:
            # Parse domain from URL
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.netloc.split(":")[0]  # Remove port if present
                if domain:
                    domains.add(domain)
            except Exception:
                pass

        # Filter out common TLDs and localhost
        filtered_domains = [
            d for d in domains
            if d and d != "localhost" and not d.startswith(".")
        ]
        return list(set(filtered_domains))

    @staticmethod
    def extract_hashes(text: str) -> List[str]:
        """Extract MD5, SHA1, and SHA256 hashes."""
        hashes = set()

        md5s = IOCExtractor.MD5_PATTERN.findall(text)
        sha1s = IOCExtractor.SHA1_PATTERN.findall(text)
        sha256s = IOCExtractor.SHA256_PATTERN.findall(text)

        hashes.update(md5s)
        hashes.update(sha1s)
        hashes.update(sha256s)

        return list(hashes)

    @staticmethod
    def extract_all(text: str) -> IOCs:
        """Extract all IOCs from text."""
        urls = IOCExtractor.extract_urls(text)
        ips = IOCExtractor.extract_ips(text)
        domains = IOCExtractor.extract_domains(text)
        hashes = IOCExtractor.extract_hashes(text)

        log_debug(f"Extracted {len(urls)} URLs, {len(ips)} IPs, {len(domains)} domains, {len(hashes)} hashes")

        for url in urls:
            log_ioc("URL", url)
        for ip in ips:
            log_ioc("IP", ip)
        for domain in domains:
            log_ioc("DOMAIN", domain)
        for hash_val in hashes:
            log_ioc("HASH", hash_val[:8] + "...")

        return IOCs(
            urls=urls,
            ips=ips,
            domains=domains,
            hashes=hashes,
        )
