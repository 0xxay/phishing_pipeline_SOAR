"""Log false positives (CLEAN emails)."""
import json
from pathlib import Path
from datetime import datetime
from models import PhishingCase
from utils import log_info, log_debug


class FalsePositiveLogger:
    """Handles logging of false positive (clean) emails."""

    FALSE_POSITIVE_LOG = Path("false_positive_log.jsonl")

    @staticmethod
    def log_false_positive(case: PhishingCase):
        """Log a false positive email."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "email_id": case.email.id,
            "email_subject": case.email.subject,
            "email_sender": case.email.sender,
            "verdict": case.verdict.value.value,
            "confidence": case.verdict.confidence,
            "reasoning": case.verdict.reasoning,
        }

        try:
            FalsePositiveLogger.FALSE_POSITIVE_LOG.parent.mkdir(
                parents=True, exist_ok=True
            )
            with open(FalsePositiveLogger.FALSE_POSITIVE_LOG, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
            log_info(f"Logged false positive: {case.email.subject}")
        except Exception as e:
            log_debug(f"Error logging false positive: {str(e)}")

    @staticmethod
    async def execute(case: PhishingCase):
        """Execute false positive logging."""
        FalsePositiveLogger.log_false_positive(case)
