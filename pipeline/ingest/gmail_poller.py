"""Gmail poller to fetch emails with phishing label."""
import pickle
import os
import json
from typing import List, Optional
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow, Flow
from googleapiclient.discovery import build
import base64
import config
from models import Email
from utils import logger, log_info, log_error, log_section


SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
REDIRECT_URI = "http://localhost:8080/"


class GmailPoller:
    """Polls Gmail for emails with the phishing label."""

    def __init__(self):
        self.service = None
        self.label_id = None
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

                # Support both "web" and "installed" OAuth client types
                with open(config.GMAIL_CREDENTIALS_PATH) as f:
                    client_info = json.load(f)

                if "web" in client_info:
                    flow = Flow.from_client_secrets_file(
                        config.GMAIL_CREDENTIALS_PATH,
                        scopes=SCOPES,
                        redirect_uri=REDIRECT_URI,
                    )
                    creds = flow.run_local_server(port=8080, open_browser=True)
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

    def _get_label_id(self, label_name: str) -> str:
        """Get the ID of a label by name."""
        if self.label_id:
            return self.label_id

        results = self.service.users().labels().list(userId="me").execute()
        labels = results.get("labels", [])

        for label in labels:
            if label["name"].lower() == label_name.lower():
                self.label_id = label["id"]
                return self.label_id

        raise ValueError(f"Label '{label_name}' not found in Gmail")

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
        """Poll for unread emails with phishing label."""
        try:
            label_id = self._get_label_id(config.GMAIL_LABEL)

            # Query for unread messages with the phishing label
            query = f"label:{config.GMAIL_LABEL} is:unread"
            results = (
                self.service.users()
                .messages()
                .list(userId="me", q=query, maxResults=config.GMAIL_MAX_RESULTS)
                .execute()
            )

            messages = results.get("messages", [])
            emails = []

            for message in messages:
                message_id = message["id"]
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
                emails.append(email)

                # Mark as read
                self.service.users().messages().modify(
                    userId="me",
                    id=message_id,
                    body={"removeLabelIds": ["UNREAD"]},
                ).execute()

            return emails

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
        flow = Flow.from_client_secrets_file(
            config.GMAIL_CREDENTIALS_PATH,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI,
        )
        creds = flow.run_local_server(port=8080, open_browser=True)
    else:
        flow = InstalledAppFlow.from_client_secrets_file(
            config.GMAIL_CREDENTIALS_PATH, SCOPES
        )
        creds = flow.run_local_server(port=0)

    with open(config.GMAIL_TOKEN_PATH, "wb") as token_file:
        pickle.dump(creds, token_file)

    log_info("OAuth setup complete! Token saved to token.pickle")
