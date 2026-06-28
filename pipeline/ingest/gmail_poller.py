"""Gmail poller — scans all inbox emails and classifies every one."""
import pickle
import os
import json
from typing import List, Set
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64
import config
from models import Email
from utils import logger, log_info, log_error, log_section


SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]


class GmailPoller:
    """Polls Gmail inbox and classifies every email — read, unread, labelled or not."""

    def __init__(self):
        self.service = None
        self._processed_ids: Set[str] = self._load_processed_ids()
        self._authenticate()

    def _authenticate(self):
        """Authenticate with Gmail API."""
        creds = None

        # Load existing token if available
        if os.path.exists(config.GMAIL_TOKEN_PATH):
            with open(config.GMAIL_TOKEN_PATH, "rb") as token_file:
                creds = pickle.load(token_file)

        # If no valid credentials, perform OAuth flow
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists(config.GMAIL_CREDENTIALS_PATH):
                    raise FileNotFoundError(
                        f"Gmail credentials not found at {config.GMAIL_CREDENTIALS_PATH}"
                    )

                # Support both "web" and "installed" OAuth client types.
                # InstalledAppFlow has run_local_server(); web creds are
                # normalized to installed format since we run locally.
                with open(config.GMAIL_CREDENTIALS_PATH) as f:
                    client_info = json.load(f)

                if "web" in client_info:
                    import tempfile
                    installed_info = {"installed": {
                        **client_info["web"],
                        "redirect_uris": ["http://localhost", "urn:ietf:wg:oauth:2.0:oob"],
                    }}
                    with tempfile.NamedTemporaryFile(
                        mode="w", suffix=".json", delete=False
                    ) as tmp:
                        json.dump(installed_info, tmp)
                        tmp_path = tmp.name
                    try:
                        flow = InstalledAppFlow.from_client_secrets_file(tmp_path, SCOPES)
                        creds = flow.run_local_server(port=0)
                    finally:
                        os.unlink(tmp_path)
                else:
                    flow = InstalledAppFlow.from_client_secrets_file(
                        config.GMAIL_CREDENTIALS_PATH, SCOPES
                    )
                    creds = flow.run_local_server(port=0)

            # Save credentials for next run
            with open(config.GMAIL_TOKEN_PATH, "wb") as token_file:
                pickle.dump(creds, token_file)

        self.service = build("gmail", "v1", credentials=creds)
        log_info("Gmail authentication successful")

    def _load_processed_ids(self) -> Set[str]:
        """Load already-processed message IDs from disk."""
        path = config.GMAIL_PROCESSED_IDS_FILE
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return set(json.load(f))
            except Exception:
                return set()
        return set()

    def _save_processed_ids(self):
        """Persist processed IDs to disk."""
        try:
            with open(config.GMAIL_PROCESSED_IDS_FILE, "w") as f:
                json.dump(list(self._processed_ids), f)
        except Exception as e:
            log_error(f"Failed to save processed IDs: {e}")

    def _mark_processed(self, message_id: str):
        self._processed_ids.add(message_id)
        self._save_processed_ids()

    def _decode_payload(self, message_id: str) -> tuple[str, List[dict]]:
        """Decode email payload and extract body and attachments."""
        message = (
            self.service.users()
            .messages()
            .get(userId="me", id=message_id, format="full")
            .execute()
        )

        headers = message["payload"].get("headers", [])
        parts = message["payload"].get("parts", [])

        # Get email body
        body = ""
        attachments = []

        if "data" in message["payload"]["body"]:
            # Single part message
            data = message["payload"]["body"]["data"]
            body = base64.urlsafe_b64decode(data).decode("utf-8")
        else:
            # Multipart message
            for part in parts:
                mime_type = part["mimeType"]

                if mime_type == "text/plain":
                    if "data" in part["body"]:
                        data = part["body"]["data"]
                        body = base64.urlsafe_b64decode(data).decode("utf-8")
                elif mime_type == "text/html":
                    if "data" in part["body"]:
                        data = part["body"]["data"]
                        body = base64.urlsafe_b64decode(data).decode("utf-8")
                elif "attachment" in part["filename"]:
                    # Handle attachment
                    filename = part["filename"]
                    attachment_id = part["body"].get("attachmentId")

                    if attachment_id:
                        attachment_data = (
                            self.service.users()
                            .messages()
                            .attachments()
                            .get(
                                userId="me",
                                messageId=message_id,
                                id=attachment_id,
                            )
                            .execute()
                        )
                        file_data = base64.urlsafe_b64decode(
                            attachment_data["data"]
                        )
                        attachments.append(
                            {
                                "filename": filename,
                                "data": file_data,
                                "size": len(file_data),
                            }
                        )

        return body, attachments

    def _extract_headers(self, message_id: str) -> dict:
        """Extract key headers from email."""
        message = (
            self.service.users()
            .messages()
            .get(userId="me", id=message_id, format="full")
            .execute()
        )

        headers = message["payload"].get("headers", [])
        header_dict = {}

        for header in headers:
            name = header["name"]
            value = header["value"]
            header_dict[name] = value

        return header_dict

    def poll(self) -> List[Email]:
        """Scan all inbox emails — read and unread — classify each one that hasn't been seen before."""
        try:
            # Scan entire inbox, no label or read/unread filter
            query = "in:inbox"
            results = (
                self.service.users()
                .messages()
                .list(userId="me", q=query, maxResults=config.GMAIL_MAX_RESULTS)
                .execute()
            )

            messages = results.get("messages", [])
            new_emails = []
            skipped = 0

            for message in messages:
                message_id = message["id"]

                # Skip emails already processed
                if message_id in self._processed_ids:
                    skipped += 1
                    continue

                try:
                    headers = self._extract_headers(message_id)
                    body, attachments = self._decode_payload(message_id)

                    email = Email(
                        id=message_id,
                        subject=headers.get("Subject", ""),
                        sender=headers.get("From", ""),
                        reply_to=headers.get("Reply-To"),
                        body=body,
                        headers=headers,
                        attachments=attachments,
                    )
                    new_emails.append(email)
                    self._mark_processed(message_id)

                except Exception as e:
                    log_error(f"Failed to fetch email {message_id}: {e}")
                    self._mark_processed(message_id)  # skip broken emails too

            if skipped:
                log_info(f"Skipped {skipped} already-processed emails")
            log_info(f"Found {len(new_emails)} new emails to classify")
            return new_emails

        except Exception as e:
            log_error(f"Failed to poll Gmail: {str(e)}")
            return []


def setup_gmail_oauth():
    """One-time setup for Gmail OAuth. Run this once to generate credentials."""
    log_section("Gmail OAuth Setup")
    log_info(
        f"This will open a browser to authenticate with Gmail.\n"
        f"Credentials will be saved to {config.GMAIL_CREDENTIALS_PATH}"
    )

    if not os.path.exists(config.GMAIL_CREDENTIALS_PATH):
        print(f"ERROR: credentials file not found at {config.GMAIL_CREDENTIALS_PATH}")
        return

    with open(config.GMAIL_CREDENTIALS_PATH) as f:
        client_info = json.load(f)

    if "web" in client_info:
        import tempfile
        installed_info = {"installed": {
            **client_info["web"],
            "redirect_uris": ["http://localhost", "urn:ietf:wg:oauth:2.0:oob"],
        }}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(installed_info, tmp)
            tmp_path = tmp.name
        try:
            flow = InstalledAppFlow.from_client_secrets_file(tmp_path, SCOPES)
            creds = flow.run_local_server(port=0)
        finally:
            os.unlink(tmp_path)
    else:
        flow = InstalledAppFlow.from_client_secrets_file(
            config.GMAIL_CREDENTIALS_PATH, SCOPES
        )
        creds = flow.run_local_server(port=0)

    with open(config.GMAIL_TOKEN_PATH, "wb") as token_file:
        pickle.dump(creds, token_file)

    log_info("OAuth setup complete! Token saved to token.pickle")
