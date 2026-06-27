"""Handle email attachments and compute file hashes."""
import hashlib
from typing import List, Dict, Any
from models import Email
from utils import log_ioc, log_debug


class AttachmentHandler:
    """Processes email attachments and extracts hashes."""

    @staticmethod
    def compute_md5(data: bytes) -> str:
        """Compute MD5 hash of bytes."""
        return hashlib.md5(data).hexdigest()

    @staticmethod
    def compute_sha256(data: bytes) -> str:
        """Compute SHA256 hash of bytes."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def extract_attachment_hashes(email: Email) -> Dict[str, Dict[str, str]]:
        """Extract hashes from all email attachments."""
        hashes = {}

        for attachment in email.attachments:
            try:
                filename = attachment.get("filename", "unknown")
                data = attachment.get("data", b"")

                if data:
                    md5 = AttachmentHandler.compute_md5(data)
                    sha256 = AttachmentHandler.compute_sha256(data)

                    hashes[filename] = {
                        "md5": md5,
                        "sha256": sha256,
                        "size": len(data),
                    }

                    log_ioc("ATTACHMENT_MD5", md5, filename)
                    log_ioc("ATTACHMENT_SHA256", sha256, filename)

            except Exception as e:
                log_debug(f"Error processing attachment: {str(e)}")

        return hashes

    @staticmethod
    def get_attachment_hashes_list(email: Email) -> List[str]:
        """Get all attachment hashes as a flat list."""
        hashes_list = []
        hashes_dict = AttachmentHandler.extract_attachment_hashes(email)

        for hash_data in hashes_dict.values():
            hashes_list.append(hash_data["md5"])
            hashes_list.append(hash_data["sha256"])

        return hashes_list
