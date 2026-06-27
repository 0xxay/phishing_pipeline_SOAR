"""Send final Slack notification with case summary."""
import aiohttp
from models import PhishingCase, VerdictType
from utils import log_info, log_error, log_debug
import config


class SlackNotifier:
    """Sends final Slack notification with case summary."""

    @staticmethod
    async def send_summary(case: PhishingCase):
        """Send case summary to Slack."""
        if not config.SLACK_WEBHOOK_URL:
            log_debug("Slack webhook not configured")
            return

        # Choose color based on verdict
        color_map = {
            VerdictType.MALICIOUS: "#FF0000",  # Red
            VerdictType.SUSPICIOUS: "#FFA500",  # Orange
            VerdictType.CLEAN: "#00AA00",  # Green
        }

        color = color_map.get(case.verdict.value, "#808080")

        message = {
            "attachments": [
                {
                    "color": color,
                    "title": f"Phishing Case Closed: {case.verdict.value.value}",
                    "fields": [
                        {"title": "Email Subject", "value": case.email.subject, "short": False},
                        {"title": "From", "value": case.email.sender, "short": True},
                        {"title": "Verdict", "value": case.verdict.value.value, "short": True},
                        {
                            "title": "Confidence",
                            "value": f"{case.verdict.confidence:.1f}%",
                            "short": True,
                        },
                        {"title": "MITRE ATT&CK", "value": case.verdict.mitre_tactic or "T1566", "short": True},
                        {"title": "Reasoning", "value": case.verdict.reasoning, "short": False},
                        {
                            "title": "IOCs Found",
                            "value": (
                                f"URLs: {len(case.iocs.urls)}, "
                                f"IPs: {len(case.iocs.ips)}, "
                                f"Domains: {len(case.iocs.domains)}, "
                                f"Hashes: {len(case.iocs.hashes)}"
                            ),
                            "short": False,
                        },
                    ],
                    "footer": f"Pipeline | {case.created_at.isoformat()}",
                }
            ]
        }

        # Add case details
        if case.blocked:
            message["attachments"][0]["fields"].append(
                {"title": "Status", "value": "IOCs Blocked", "short": True}
            )

        if case.thehive_case_id:
            message["attachments"][0]["fields"].append(
                {
                    "title": "TheHive Case",
                    "value": case.thehive_case_id,
                    "short": True,
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
                        log_info("Case summary sent to Slack")
                    else:
                        log_error(f"Failed to send Slack summary: {response.status}")

        except asyncio.TimeoutError:
            log_error("Slack summary timeout")
        except Exception as e:
            log_error(f"Error sending Slack summary: {str(e)}")

    @staticmethod
    async def execute(case: PhishingCase):
        """Execute case summary notification."""
        if config.DRY_RUN:
            log_info("[DRY RUN] Would send case summary to Slack")
            return

        await SlackNotifier.send_summary(case)


import asyncio
