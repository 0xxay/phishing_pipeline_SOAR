"""
Main orchestrator for the SOAR-Lite Phishing Response Pipeline.
Runs a polling loop to fetch and process phishing emails.
"""
import asyncio
import signal
import sys
from typing import List
from datetime import datetime

import config
from models import Email, PhishingCase
from pipeline.ingest.gmail_poller import GmailPoller
from pipeline.extract.ioc_extractor import IOCExtractor
from pipeline.extract.attachment_handler import AttachmentHandler
from pipeline.enrich.virustotal import VirusTotalEnricher
from pipeline.enrich.abuseipdb import AbuseIPDBEnricher
from pipeline.enrich.urlscan import URLScanEnricher
from pipeline.decide.score_aggregator import ScoreAggregator
from pipeline.respond.auto_block import AutoBlocker
from pipeline.respond.analyst_alert import AnalystAlert
from pipeline.respond.false_positive import FalsePositiveLogger
from pipeline.close.thehive_client import TheHiveClient
from pipeline.close.slack_notifier import SlackNotifier
from utils import log_section, log_info, log_success, log_error, log_warning, logger


class PhishingPipeline:
    """Main pipeline orchestrator."""

    def __init__(self):
        self.running = False
        self.gmail_poller = None
        self.thehive_client = TheHiveClient()

    async def process_email(self, email: Email) -> PhishingCase:
        """
        Process a single email through the full pipeline.
        Returns a PhishingCase with verdict and actions taken.
        """
        log_section(f"Processing Email: {email.subject}")
        log_info(f"Email ID: {email.id}")
        log_info(f"From: {email.sender}")

        # Stage 1: Extract IOCs
        log_section("Stage 1: IOC Extraction")
        iocs = IOCExtractor.extract_all(email.body)

        # Extract attachment hashes
        attachment_hashes = AttachmentHandler.get_attachment_hashes_list(email)
        iocs.hashes.extend(attachment_hashes)

        # Stage 2: Parallel Enrichment
        log_section("Stage 2: Threat Intelligence Enrichment")
        log_info("Querying VirusTotal, AbuseIPDB, URLScan in parallel...")

        enrichments = []
        try:
            # Run enrichment in parallel
            vt_results, abuse_results, urlscan_results = await asyncio.gather(
                VirusTotalEnricher.enrich(iocs),
                AbuseIPDBEnricher.enrich(iocs),
                URLScanEnricher.enrich(iocs),
                return_exceptions=True,
            )

            # Handle results
            if isinstance(vt_results, list):
                enrichments.extend(vt_results)
                log_info(f"VirusTotal: {len(vt_results)} results")
            elif isinstance(vt_results, Exception):
                log_warning(f"VirusTotal error: {str(vt_results)}")

            if isinstance(abuse_results, list):
                enrichments.extend(abuse_results)
                log_info(f"AbuseIPDB: {len(abuse_results)} results")
            elif isinstance(abuse_results, Exception):
                log_warning(f"AbuseIPDB error: {str(abuse_results)}")

            if isinstance(urlscan_results, list):
                enrichments.extend(urlscan_results)
                log_info(f"URLScan: {len(urlscan_results)} results")
            elif isinstance(urlscan_results, Exception):
                log_warning(f"URLScan error: {str(urlscan_results)}")

        except Exception as e:
            log_error(f"Enrichment error: {str(e)}")
            enrichments = []

        # Stage 3: Decision
        log_section("Stage 3: Verdict Decision")
        verdict = await ScoreAggregator.aggregate_score(email, iocs, enrichments)
        log_success(f"Verdict: {verdict.value.value} (Confidence: {verdict.confidence:.1f}%)")
        log_info(f"Reasoning: {verdict.reasoning}")

        # Create case
        case = PhishingCase(
            email=email,
            iocs=iocs,
            enrichments=enrichments,
            verdict=verdict,
        )

        # Stage 4: Response Actions
        log_section("Stage 4: Response Actions")
        if verdict.value.value == "MALICIOUS":
            log_info("MALICIOUS verdict - executing auto-block")
            await AutoBlocker.execute(case)

        elif verdict.value.value == "SUSPICIOUS":
            log_info("SUSPICIOUS verdict - alerting analyst")
            await AnalystAlert.execute(case)

        else:  # CLEAN
            log_info("CLEAN verdict - logging false positive")
            await FalsePositiveLogger.execute(case)

        # Stage 5: Close/Documentation
        if verdict.value.value != "CLEAN":
            log_section("Stage 5: Case Documentation")
            log_info("Creating TheHive case...")
            case.thehive_case_id = await self.thehive_client.create_case(case)

            if not config.SKIP_SLACK:
                log_info("Sending Slack notification...")
                await SlackNotifier.execute(case)

        return case

    async def poll_emails(self):
        """Poll Gmail for phishing emails and process them."""
        if config.SKIP_GMAIL:
            log_warning("Gmail polling disabled (SKIP_GMAIL=true)")
            return

        try:
            emails = self.gmail_poller.poll()
            if emails:
                log_success(f"Found {len(emails)} unread phishing emails")

                for email in emails:
                    try:
                        await self.process_email(email)
                    except Exception as e:
                        log_error(f"Error processing email {email.id}: {str(e)}")
                        logger.exception(e)

            else:
                log_info("No unread phishing emails found")

        except Exception as e:
            log_error(f"Error polling Gmail: {str(e)}")
            logger.exception(e)

    async def run(self):
        """Run the polling loop."""
        self.running = True
        log_section("PHISHING RESPONSE PIPELINE STARTED")
        log_info(f"Poll interval: {config.POLL_INTERVAL} seconds")

        # Initialize Gmail poller
        if not config.SKIP_GMAIL:
            try:
                self.gmail_poller = GmailPoller()
                log_success("Gmail authentication successful")
            except Exception as e:
                log_error(f"Gmail authentication failed: {str(e)}")
                log_warning("Continuing without Gmail polling...")
                config.SKIP_GMAIL = True

        # Polling loop
        while self.running:
            try:
                await self.poll_emails()
            except KeyboardInterrupt:
                log_warning("Received interrupt signal")
                break
            except Exception as e:
                log_error(f"Unhandled error in polling loop: {str(e)}")
                logger.exception(e)

            # Wait before next poll
            await asyncio.sleep(config.POLL_INTERVAL)

    def stop(self):
        """Stop the pipeline."""
        self.running = False
        log_warning("Pipeline stopping...")


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    pipeline.stop()


async def main():
    """Main entry point."""
    global pipeline

    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Create and run pipeline
    pipeline = PhishingPipeline()
    await pipeline.run()

    log_section("PHISHING RESPONSE PIPELINE STOPPED")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log_info("Pipeline shutdown by user")
    except Exception as e:
        log_error(f"Fatal error: {str(e)}")
        logger.exception(e)
        sys.exit(1)
