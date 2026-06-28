"""Gmail IMAP poller — no OAuth, uses App Password."""
import imaplib
import email
import json
import os
from email.header import decode_header
from typing import List, Set
from datetime import datetime

import config
from models import Email
from utils import log_info, log_error, log_section


IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993


class GmailPoller:
    """Polls Gmail inbox via IMAP — read every email, no labels required."""

    def __init__(self):
        self._processed_ids: Set[str] = self._load_processed_ids()

    def _load_processed_ids(self) -> Set[str]:
        path = config.GMAIL_PROCESSED_IDS_FILE
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return set(json.load(f))
            except Exception:
                return set()
        return set()

    def _save_processed_ids(self):
        try:
            with open(config.GMAIL_PROCESSED_IDS_FILE, "w") as f:
                json.dump(list(self._processed_ids), f)
        except Exception as e:
            log_error(f"Failed to save processed IDs: {e}")

    def _mark_processed(self, message_id: str):
        self._processed_ids.add(message_id)
        self._save_processed_ids()

    def _decode_str(self, value: str) -> str:
        if not value:
            return ""
        parts = decode_header(value)
        result = []
        for part, charset in parts:
            if isinstance(part, bytes):
                result.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                result.append(str(part))
        return "".join(result)

    def _extract_body(self, msg) -> str:
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                disp = str(part.get("Content-Disposition", ""))
                if ct == "text/plain" and "attachment" not in disp:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        body = payload.decode(charset, errors="replace")
                        break
                    except Exception:
                        pass
            if not body:
                for part in msg.walk():
                    if part.get_content_type() == "text/html":
                        try:
                            payload = part.get_payload(decode=True)
                            charset = part.get_content_charset() or "utf-8"
                            body = payload.decode(charset, errors="replace")
                            break
                        except Exception:
                            pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or "utf-8"
                body = payload.decode(charset, errors="replace")
            except Exception:
                body = str(msg.get_payload())
        return body

    def poll(self) -> List[Email]:
        """Connect via IMAP, fetch all inbox emails not yet seen."""
        if not config.GMAIL_USER or not config.GMAIL_APP_PASSWORD:
            log_error("GMAIL_USER or GMAIL_APP_PASSWORD not configured in .env")
            return []

        emails = []
        try:
            mail = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
            mail.login(config.GMAIL_USER, config.GMAIL_APP_PASSWORD)
            mail.select("INBOX")

            _, data = mail.search(None, "ALL")
            all_ids = data[0].split()

            # Take the most recent N emails
            recent_ids = all_ids[-config.GMAIL_MAX_RESULTS:]
            log_info(f"Checking {len(recent_ids)} most recent inbox emails...")

            skipped = 0
            for num in reversed(recent_ids):
                try:
                    _, msg_data = mail.fetch(num, "(RFC822)")
                    raw = msg_data[0][1]
                    msg = email.message_from_bytes(raw)

                    msg_id = (msg.get("Message-ID") or f"imap-{num.decode()}").strip()

                    if msg_id in self._processed_ids:
                        skipped += 1
                        continue

                    subject = self._decode_str(msg.get("Subject", "(no subject)"))
                    sender = self._decode_str(msg.get("From", ""))
                    reply_to = self._decode_str(msg.get("Reply-To", "")) or None
                    body = self._extract_body(msg)
                    headers = {k: self._decode_str(v) for k, v in msg.items()}

                    emails.append(Email(
                        id=msg_id,
                        subject=subject,
                        sender=sender,
                        reply_to=reply_to,
                        body=body,
                        headers=headers,
                        attachments=[],
                        received_at=datetime.utcnow(),
                    ))
                    self._mark_processed(msg_id)

                except Exception as e:
                    log_error(f"Failed to parse email {num}: {e}")

            mail.logout()

            if skipped:
                log_info(f"Skipped {skipped} already-processed emails")
            log_info(f"Found {len(emails)} new emails to classify")

        except imaplib.IMAP4.error as e:
            log_error(f"IMAP login failed: {e}")
        except Exception as e:
            log_error(f"IMAP poll error: {e}")

        return emails


def setup_gmail_oauth():
    """No-op — IMAP mode does not need OAuth."""
    log_info("IMAP mode is active — no OAuth setup required")
