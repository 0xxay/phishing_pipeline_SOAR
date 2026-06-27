"""Models package for phishing pipeline."""
from .phishing_case import (
    Email,
    IOCs,
    EnrichmentResult,
    Verdict,
    VerdictType,
    MitreAttackTactic,
    PhishingCase,
)

__all__ = [
    "Email",
    "IOCs",
    "EnrichmentResult",
    "Verdict",
    "VerdictType",
    "MitreAttackTactic",
    "PhishingCase",
]
