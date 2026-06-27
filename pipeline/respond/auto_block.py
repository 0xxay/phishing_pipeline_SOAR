"""Auto-block malicious IOCs and escalate."""
import json
from pathlib import Path
from datetime import datetime
from models import PhishingCase
from utils import log_info, log_success, log_error, log_debug
import config


class AutoBlocker:
    """Handles auto-blocking of malicious IOCs."""

    BLOCK_LIST_PATH = Path(config.BLOCK_LIST_FILE)

    @staticmethod
    def _load_block_list() -> dict:
        """Load the block list from JSON file."""
        if AutoBlocker.BLOCK_LIST_PATH.exists():
            try:
                with open(AutoBlocker.BLOCK_LIST_PATH, "r") as f:
                    return json.load(f)
            except Exception as e:
                log_debug(f"Error loading block list: {str(e)}")
                return {"urls": [], "ips": [], "domains": [], "hashes": []}
        return {"urls": [], "ips": [], "domains": [], "hashes": []}

    @staticmethod
    def _save_block_list(block_list: dict):
        """Save the block list to JSON file."""
        try:
            AutoBlocker.BLOCK_LIST_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(AutoBlocker.BLOCK_LIST_PATH, "w") as f:
                json.dump(block_list, f, indent=2)
        except Exception as e:
            log_error(f"Error saving block list: {str(e)}")

    @staticmethod
    def block_iocs(case: PhishingCase):
        """Add malicious IOCs to block list."""
        block_list = AutoBlocker._load_block_list()

        added_count = 0

        # Add URLs
        for url in case.iocs.urls:
            if url not in block_list["urls"]:
                block_list["urls"].append(url)
                added_count += 1
                log_info(f"Blocked URL: {url}")

        # Add IPs
        for ip in case.iocs.ips:
            if ip not in block_list["ips"]:
                block_list["ips"].append(ip)
                added_count += 1
                log_info(f"Blocked IP: {ip}")

        # Add Domains
        for domain in case.iocs.domains:
            if domain not in block_list["domains"]:
                block_list["domains"].append(domain)
                added_count += 1
                log_info(f"Blocked Domain: {domain}")

        # Add Hashes
        for hash_val in case.iocs.hashes:
            if hash_val not in block_list["hashes"]:
                block_list["hashes"].append(hash_val)
                added_count += 1
                log_info(f"Blocked Hash: {hash_val[:16]}...")

        if added_count > 0:
            AutoBlocker._save_block_list(block_list)
            log_success(f"Added {added_count} IOCs to block list")
            case.blocked = True

    @staticmethod
    def log_escalation(case: PhishingCase):
        """Log escalation event for MALICIOUS verdict."""
        escalation_log = {
            "timestamp": datetime.utcnow().isoformat(),
            "email_id": case.email.id,
            "email_subject": case.email.subject,
            "email_sender": case.email.sender,
            "verdict": case.verdict.value.value,
            "confidence": case.verdict.confidence,
            "iocs_count": len(case.iocs.all_iocs()),
            "urls": case.iocs.urls,
            "ips": case.iocs.ips,
            "domains": case.iocs.domains,
            "hashes": case.iocs.hashes,
            "thehive_case_id": case.thehive_case_id,
        }

        # Append to escalation log
        escalation_log_path = Path("escalation_log.jsonl")

        try:
            with open(escalation_log_path, "a") as f:
                f.write(json.dumps(escalation_log) + "\n")
            log_success("Escalation logged")
        except Exception as e:
            log_error(f"Error logging escalation: {str(e)}")

    @staticmethod
    async def execute(case: PhishingCase):
        """Execute auto-block actions."""
        if config.DRY_RUN:
            log_info("[DRY RUN] Would execute auto-block")
            return

        AutoBlocker.block_iocs(case)
        AutoBlocker.log_escalation(case)
