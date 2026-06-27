"""
Test pipeline with mock emails without real Gmail/TheHive connections.
Useful for testing the extract/enrich/decide/respond flow.
"""
import asyncio
import sys
from datetime import datetime

import config
from models import Email, VerdictType
from pipeline.extract.ioc_extractor import IOCExtractor
from pipeline.extract.attachment_handler import AttachmentHandler
from pipeline.extract.header_parser import HeaderParser
from pipeline.enrich.virustotal import VirusTotalEnricher
from pipeline.enrich.abuseipdb import AbuseIPDBEnricher
from pipeline.enrich.urlscan import URLScanEnricher
from pipeline.decide.score_aggregator import ScoreAggregator
from pipeline.close.thehive_client import TheHiveClient
from models import PhishingCase
from utils import log_section, log_info, log_success, log_error, log_debug, logger


# Sample phishing emails for testing
SAMPLE_EMAILS = [
    {
        "id": "test_email_1",
        "subject": "URGENT: Verify Your Account - Click Here Immediately",
        "sender": "noreply@paypa1.suspicious.com",
        "reply_to": None,
        "body": """
Dear Customer,

Your account has been compromised. Please verify your identity immediately by clicking the link below:

Click here: https://paypa1.suspicious.com/verify?token=abc123
Or visit: http://192.168.1.100:8080/phish

If you don't verify within 24 hours, your account will be suspended.

Regards,
PayPal Security Team

MD5: 5d41402abc4b2a76b9719d911017c592
SHA256: 2c26b46911185131006ba5991596cdb8f1e89d97c27ce88a9e4fa9d95f6b8f6
""",
        "headers": {
            "From": "noreply@paypa1.suspicious.com",
            "Reply-To": None,
            "Subject": "URGENT: Verify Your Account - Click Here Immediately",
            "Return-Path": "<bounce@malicious.ru>",
        },
        "attachments": [],
    },
    {
        "id": "test_email_2",
        "subject": "Re: Project Update",
        "sender": "boss@company.com",
        "reply_to": "boss@company.com",
        "body": """
Thanks for your update. Everything looks good.
Let me know if you need anything else.
""",
        "headers": {
            "From": "boss@company.com",
            "Reply-To": "boss@company.com",
            "Subject": "Re: Project Update",
        },
        "attachments": [],
    },
]


def create_test_email(email_dict: dict) -> Email:
    """Create an Email object from test data."""
    return Email(
        id=email_dict["id"],
        subject=email_dict["subject"],
        sender=email_dict["sender"],
        reply_to=email_dict.get("reply_to"),
        body=email_dict["body"],
        headers=email_dict["headers"],
        attachments=email_dict["attachments"],
        received_at=datetime.utcnow(),
    )


async def test_extract_stage(email: Email):
    """Test IOC extraction."""
    log_section("TEST: IOC Extraction Stage")

    iocs = IOCExtractor.extract_all(email.body)
    log_success(f"Extracted: {iocs}")

    # Parse headers
    log_info("Analyzing headers...")
    header_analysis = HeaderParser.analyze_headers(email)
    log_info(f"Headers: {header_analysis}")

    return iocs


async def test_enrich_stage(iocs):
    """Test enrichment stage."""
    log_section("TEST: Enrichment Stage")

    if not config.VIRUSTOTAL_API_KEY:
        log_error("VirusTotal API key not configured - skipping VT tests")
    else:
        log_info("Testing VirusTotal enrichment...")
        vt_results = await VirusTotalEnricher.enrich(iocs)
        log_success(f"VirusTotal results: {len(vt_results)}")

    if not config.ABUSEIPDB_API_KEY:
        log_error("AbuseIPDB API key not configured - skipping AbuseIPDB tests")
    else:
        log_info("Testing AbuseIPDB enrichment...")
        abuse_results = await AbuseIPDBEnricher.enrich(iocs)
        log_success(f"AbuseIPDB results: {len(abuse_results)}")

    if not config.URLSCAN_API_KEY:
        log_error("URLScan API key not configured - skipping URLScan tests")
    else:
        log_info("Testing URLScan enrichment...")
        urlscan_results = await URLScanEnricher.enrich(iocs)
        log_success(f"URLScan results: {len(urlscan_results)}")

    # Parallel test
    log_info("Running all enrichments in parallel...")
    results = await asyncio.gather(
        VirusTotalEnricher.enrich(iocs),
        AbuseIPDBEnricher.enrich(iocs),
        URLScanEnricher.enrich(iocs),
        return_exceptions=True,
    )

    all_enrichments = []
    for result in results:
        if isinstance(result, list):
            all_enrichments.extend(result)

    log_success(f"Total enrichment results: {len(all_enrichments)}")
    return all_enrichments


async def test_decide_stage(email: Email, iocs, enrichments):
    """Test verdict decision."""
    log_section("TEST: Decision Stage")

    if not config.OPENAI_API_KEY:
        log_error("OpenAI API key not configured - using heuristic scoring")

    verdict = await ScoreAggregator.aggregate_score(email, iocs, enrichments)
    log_success(f"Verdict: {verdict}")

    return verdict


async def test_email(email_dict: dict):
    """Test pipeline on a single email."""
    email = create_test_email(email_dict)
    log_section(f"TESTING EMAIL: {email.subject}")

    # Stage 1: Extract
    iocs = await test_extract_stage(email)

    # Stage 2: Enrich (optional - requires API keys)
    enrichments = []
    if config.VIRUSTOTAL_API_KEY or config.ABUSEIPDB_API_KEY or config.URLSCAN_API_KEY:
        enrichments = await test_enrich_stage(iocs)
    else:
        log_error("No enrichment API keys configured - skipping enrichment tests")

    # Stage 3: Decide
    verdict = await test_decide_stage(email, iocs, enrichments)

    # Create case object
    case = PhishingCase(
        email=email,
        iocs=iocs,
        enrichments=enrichments,
        verdict=verdict,
    )

    log_section("TEST RESULT")
    log_info(f"Email: {email.subject}")
    log_info(f"Verdict: {verdict.value.value}")
    log_info(f"Confidence: {verdict.confidence:.1f}%")
    log_info(f"Reasoning: {verdict.reasoning}")

    return case


async def run_all_tests():
    """Run tests on all sample emails."""
    log_section("PHISHING PIPELINE TEST SUITE")
    log_info("Testing extract/enrich/decide stages with sample emails")

    for i, email_dict in enumerate(SAMPLE_EMAILS):
        try:
            await test_email(email_dict)
        except Exception as e:
            log_error(f"Test failed for email {i}: {str(e)}")
            logger.exception(e)

        print("\n")


def main():
    """Main test entry point."""
    try:
        asyncio.run(run_all_tests())
        log_success("All tests completed")
    except KeyboardInterrupt:
        log_info("Tests interrupted by user")
        sys.exit(0)
    except Exception as e:
        log_error(f"Test suite failed: {str(e)}")
        logger.exception(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
