"""Apply Gmail labels to flagged emails via IMAP.
Replaces auto-blocking — labels the email in-place so the user can review it.
"""
import imaplib
import config
from utils import log_info, log_error, log_debug
from models import PhishingCase, VerdictType

IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993


def _connect() -> imaplib.IMAP4_SSL:
    mail = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    mail.login(config.GMAIL_USER, config.GMAIL_APP_PASSWORD)
    return mail


def _ensure_label_exists(mail: imaplib.IMAP4_SSL, label: str):
    """Create label/folder if it doesn't exist yet."""
    try:
        mail.create(label)
        log_debug(f"Created Gmail label: {label}")
    except Exception:
        pass  # Already exists


def apply_label(message_id: str, label: str) -> bool:
    """
    Find an email by its Message-ID and copy it to the label folder,
    which applies the label in Gmail.
    Returns True on success.
    """
    if not config.GMAIL_USER or not config.GMAIL_APP_PASSWORD:
        log_error("IMAP credentials not configured — cannot apply Gmail label")
        return False

    if not message_id or not label:
        return False

    try:
        mail = _connect()
        mail.select("INBOX")
        _ensure_label_exists(mail, label)

        # Search by exact Message-ID header
        clean_id = message_id.strip().strip("<>")
        _, data = mail.search(None, f'HEADER Message-ID "{clean_id}"')
        ids = data[0].split()

        # Fallback: also try with angle brackets
        if not ids:
            _, data = mail.search(None, f'HEADER Message-ID "<{clean_id}>"')
            ids = data[0].split()

        if not ids:
            log_error(f"Could not find email in INBOX by Message-ID to label it")
            mail.logout()
            return False

        num = ids[-1]
        result = mail.copy(num, label)
        mail.logout()

        if result[0] == "OK":
            log_info(f"Applied Gmail label '{label}' to email")
            return True
        else:
            log_error(f"IMAP COPY failed: {result}")
            return False

    except imaplib.IMAP4.error as e:
        log_error(f"IMAP error while labeling: {e}")
        return False
    except Exception as e:
        log_error(f"Failed to apply Gmail label: {e}")
        return False


async def execute(case: PhishingCase) -> bool:
    """Label email in Gmail based on verdict. Called from the pipeline."""
    import asyncio

    label = config.GMAIL_LABEL or "phishing"

    if case.verdict.value == VerdictType.MALICIOUS:
        target_label = label
    elif case.verdict.value == VerdictType.SUSPICIOUS:
        # Sub-label so user can distinguish severity
        target_label = f"{label}/suspicious"
    else:
        return False  # Don't label clean emails

    success = await asyncio.to_thread(apply_label, case.email.id, target_label)
    if success:
        case.blocked = True  # reusing field to mean "actioned"
    return success
