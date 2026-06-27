"""Parse and extract key email headers."""
from typing import Dict, Optional
from models import Email
from utils import log_ioc, log_debug


class HeaderParser:
    """Parses email headers for security analysis."""

    @staticmethod
    def extract_sender(headers: Dict[str, str]) -> str:
        """Extract sender email address."""
        return headers.get("From", "unknown")

    @staticmethod
    def extract_reply_to(headers: Dict[str, str]) -> Optional[str]:
        """Extract reply-to email address."""
        return headers.get("Reply-To")

    @staticmethod
    def extract_x_headers(headers: Dict[str, str]) -> Dict[str, str]:
        """Extract all X-* headers (often used for authentication/security)."""
        x_headers = {}
        for key, value in headers.items():
            if key.startswith("X-"):
                x_headers[key] = value
        return x_headers

    @staticmethod
    def check_authentication_headers(headers: Dict[str, str]) -> Dict[str, bool]:
        """Check for presence of authentication headers (SPF, DKIM, DMARC)."""
        auth_headers = {
            "dkim": "DKIM-Signature" in headers or "X-DKIM-Signature" in headers,
            "spf": "X-SPF" in headers or "Received-SPF" in headers,
            "dmarc": "X-DMARC" in headers or "X-DMARC-Result" in headers,
            "arc": "ARC-Seal" in headers or "X-ARC" in headers,
        }
        return auth_headers

    @staticmethod
    def extract_received_chain(headers: Dict[str, str]) -> list:
        """Extract the Received header chain to trace email path."""
        received = headers.get("Received", "")
        if isinstance(received, str):
            return [received]
        return received if isinstance(received, list) else []

    @staticmethod
    def analyze_headers(email: Email) -> Dict[str, any]:
        """Analyze all headers for security red flags."""
        headers = email.headers
        analysis = {
            "sender": HeaderParser.extract_sender(headers),
            "reply_to": HeaderParser.extract_reply_to(headers),
            "subject": headers.get("Subject", ""),
            "auth_headers": HeaderParser.check_authentication_headers(headers),
            "x_headers": HeaderParser.extract_x_headers(headers),
            "content_type": headers.get("Content-Type", ""),
            "return_path": headers.get("Return-Path", ""),
        }

        # Log suspicious patterns
        sender = analysis["sender"]
        reply_to = analysis["reply_to"]

        if sender and reply_to and sender != reply_to:
            log_debug(
                f"Sender mismatch: From={sender} vs Reply-To={reply_to}"
            )

        if "noreply" in sender.lower() and reply_to:
            log_debug(
                f"Suspicious: noreply sender but has Reply-To: {reply_to}"
            )

        return analysis
