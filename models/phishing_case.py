"""Data models for the phishing response pipeline."""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class VerdictType(Enum):
    """Verdict classification for phishing emails."""
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"


class MitreAttackTactic(Enum):
    """MITRE ATT&CK tactics related to phishing."""
    INITIAL_ACCESS = "T1566"
    INITIAL_ACCESS_SPEARPHISHING_ATTACHMENT = "T1566.001"
    INITIAL_ACCESS_SPEARPHISHING_LINK = "T1566.002"
    CREDENTIAL_ACCESS = "T1110"
    EXECUTION = "T1204"


@dataclass
class Email:
    """Represents an email message."""
    id: str
    subject: str
    sender: str
    reply_to: Optional[str]
    body: str
    headers: Dict[str, str]
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    received_at: Optional[datetime] = None

    def __repr__(self) -> str:
        return f"Email(id={self.id}, subject={self.subject}, sender={self.sender})"


@dataclass
class IOCs:
    """Indicators of Compromise extracted from email."""
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)

    def all_iocs(self) -> List[str]:
        """Return all IOCs as a single list."""
        return self.urls + self.ips + self.domains + self.hashes

    def __repr__(self) -> str:
        return f"IOCs(urls={len(self.urls)}, ips={len(self.ips)}, domains={len(self.domains)}, hashes={len(self.hashes)})"


@dataclass
class EnrichmentResult:
    """Result from a single enrichment API call."""
    ioc: str
    source: str  # "virustotal", "abuseipdb", "urlscan"
    score: Optional[float]  # 0-100 or vendor-specific
    verdict: Optional[str]  # e.g., "malicious", "suspicious", "clean"
    details: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def __repr__(self) -> str:
        return f"EnrichmentResult(ioc={self.ioc[:20]}..., source={self.source}, score={self.score})"


@dataclass
class Verdict:
    """Security verdict for a phishing email."""
    value: VerdictType
    confidence: float  # 0-100
    reasoning: str
    mitre_tactic: Optional[str] = None

    def __repr__(self) -> str:
        return f"Verdict(value={self.value.value}, confidence={self.confidence:.1f}%)"


@dataclass
class PhishingCase:
    """Complete case data for a phishing email."""
    email: Email
    iocs: IOCs
    enrichments: List[EnrichmentResult]
    verdict: Verdict
    thehive_case_id: Optional[str] = None
    slack_sent: bool = False
    blocked: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)

    def __repr__(self) -> str:
        return f"PhishingCase(email_id={self.email.id}, verdict={self.verdict.value.value}, thehive={self.thehive_case_id})"
