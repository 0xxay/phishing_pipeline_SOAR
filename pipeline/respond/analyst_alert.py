"""Alert analyst for SUSPICIOUS emails via Slack."""
import aiohttp
from models import PhishingCase
from utils import log_info, log_error, log_debug
import config


class AnalystAlert:
    """Sends analyst alerts via Slack for suspicious emails."""

    @staticmethod
    async def send_slack_alert(case: PhishingCase):
        """Send Slack notification for suspicious email."""
        if not config.SLACK_WEBHOOK_URL:
            log_debug("Slack webhook not configured, skipping alert")
            return

        message = {
            "attachments": [
                {
                    "color": "#FFA500",  # Orange for suspicious
                    "title": f"Suspicious Email Detected",
                    "fields": [
                        {"title": "Subject", "value": case.email.subject, "short": False},
                        {"title": "From", "value": case.email.sender, "short": True},
                        {"title": "Verdict", "value": case.verdict.value.value, "short": True},
                        {
                            "title": "Confidence",
                            "value": f"{case.verdict.confidence:.1f}%",
                            "short": True,
                        },
                        {"title": "Reasoning", "value": case.verdict.reasoning, "short": False},
                        {"title": "URLs Found", "value": str(len(case.iocs.urls)), "short": True},
                        {"title": "IPs Found", "value": str(len(case.iocs.ips)), "short": True},
                        {"title": "Domains Found", "value": str(len(case.iocs.domains)), "short": True},
                        {"title": "Hashes Found", "value": str(len(case.iocs.hashes)), "short": True},
                    ],
                    "footer": f"Email ID: {case.email.id}",
                }
            ]
        }

        # Add TheHive case ID if available
        if case.thehive_case_id:
            message["attachments"][0]["fields"].append(
                {
                    "title": "TheHive Case",
                    "value": f"<{config.THEHIVE_URL}/cases/{case.thehive_case_id}|{case.thehive_case_id}>",
                    "short": False,
                }
            )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    config.SLACK_WEBHOOK_URL,
                    json=message,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    if response.status == 200:
                        log_info("Analyst alert sent to Slack")
                    else:
                        log_error(f"Failed to send Slack alert: {response.status}")

        except asyncio.TimeoutError:
            log_error("Slack alert timeout")
        except Exception as e:
            log_error(f"Error sending Slack alert: {str(e)}")

    @staticmethod
    async def execute(case: PhishingCase):
        """Execute analyst alert."""
        if config.DRY_RUN:
            log_info("[DRY RUN] Would send analyst alert")
            return

        await AnalystAlert.send_slack_alert(case)


import asyncio
