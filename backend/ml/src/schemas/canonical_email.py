"""Canonical Email Schema Definition for MailForensix ML Pipeline.

Implements the single canonical, provenance-aware, leakage-safe email schema
specified in implementation.md Section 8 and Section 41.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
import hashlib
import json


@dataclass
class CanonicalEmail:
    """Standardized internal representation of an email across all datasets."""

    # 1. Primary Identity and Provenance
    email_id: str                              # Deterministic SHA256 identifier
    source_dataset: str                        # e.g., "enron", "trec07", "nazario"
    source_record_id: str                      # Identifier in source (filename, row idx, message-id)
    source_path: str                           # Path to original file relative to raw directory

    # 2. Content Hashes
    raw_message_sha256: str                    # SHA256 of immutable raw message bytes/text
    normalized_full_sha256: str                # SHA256 of canonical headers + canonical body
    normalized_body_sha256: str                # SHA256 of normalized subject + "\n" + normalized body

    # 3. Message Content
    headers: Dict[str, Any] = field(default_factory=dict)
    subject: str = ""
    body_plain: str = ""
    body_html: str = ""

    # 4. Sender / Recipient Metadata
    sender: str = ""
    sender_domain: str = ""
    reply_to: Optional[str] = None
    mail_from: Optional[str] = None
    recipients: List[str] = field(default_factory=list)

    # 5. Envelope & Temporal Identifiers
    date: Optional[str] = None                 # Raw Date header value
    message_id: Optional[str] = None           # Message-ID header value
    email_timestamp: Optional[str] = None      # ISO 8601 UTC timestamp parsed from Date header

    # 6. Artifacts & Links
    urls: List[str] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)  # [{filename, content_type, size, sha256}]

    # 7. Labeling & Taxonomy
    source_label: Optional[str] = None         # Label as recorded in source dataset
    canonical_label: Optional[str] = None      # Mapped 5-class label (LEGITIMATE, SUSPICIOUS, PHISHING, BEC_FRAUD, IMPERSONATION)
    label_confidence: Optional[float] = None   # 0.0 - 1.0 confidence
    label_source: str = "direct_dataset_mapping" # "direct_dataset_mapping", "manual_review", "reviewed_candidate", "derived_mapping"

    # 8. Synthetic & Fraud Provenance Tracking
    is_synthetic: bool = False                 # True if LLM-generated or synthetic header recombination
    synthetic_source: Optional[str] = None     # e.g., "BEC-2", "EPVME"
    construction_type: str = "authentic"       # "authentic", "llm_generated", "header_recombination"
    fraud_subtype: Optional[str] = None        # e.g., "419_advance_fee", "synthetic_bec", "ceo_fraud"

    # 9. Licensing & Compliance
    license: Optional[str] = None
    license_verified: bool = False

    # 10. Historical Reliability & Usability
    historical_reliability: str = "unknown"    # "high", "medium", "low", "unknown"
    nlp_usable: bool = True
    forensic_usable: bool = True
    exclusion_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to Python dictionary suitable for JSON or Parquet export."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CanonicalEmail":
        """Create CanonicalEmail instance from dictionary."""
        headers = data.get("headers") or {}
        if isinstance(headers, str):
            try:
                headers = json.loads(headers)
            except Exception:
                headers = {}

        attachments = data.get("attachments") or []
        if isinstance(attachments, str):
            try:
                attachments = json.loads(attachments)
            except Exception:
                attachments = []

        recipients = data.get("recipients") or []
        if isinstance(recipients, str):
            try:
                recipients = json.loads(recipients)
            except Exception:
                recipients = [recipients]

        urls = data.get("urls") or []
        if isinstance(urls, str):
            try:
                urls = json.loads(urls)
            except Exception:
                urls = []

        return cls(
            email_id=str(data.get("email_id", "")),
            source_dataset=str(data.get("source_dataset", "")),
            source_record_id=str(data.get("source_record_id", "")),
            source_path=str(data.get("source_path", "")),
            raw_message_sha256=str(data.get("raw_message_sha256", "")),
            normalized_full_sha256=str(data.get("normalized_full_sha256", "")),
            normalized_body_sha256=str(data.get("normalized_body_sha256", "")),
            headers=headers,
            subject=str(data.get("subject", "") or ""),
            body_plain=str(data.get("body_plain", "") or ""),
            body_html=str(data.get("body_html", "") or ""),
            sender=str(data.get("sender", "") or ""),
            sender_domain=str(data.get("sender_domain", "") or ""),
            reply_to=data.get("reply_to"),
            mail_from=data.get("mail_from"),
            recipients=recipients,
            date=data.get("date"),
            message_id=data.get("message_id"),
            email_timestamp=data.get("email_timestamp"),
            urls=urls,
            attachments=attachments,
            source_label=data.get("source_label"),
            canonical_label=data.get("canonical_label"),
            label_confidence=float(data["label_confidence"]) if data.get("label_confidence") is not None else None,
            label_source=str(data.get("label_source", "direct_dataset_mapping")),
            is_synthetic=bool(data.get("is_synthetic", False)),
            synthetic_source=data.get("synthetic_source"),
            construction_type=str(data.get("construction_type", "authentic")),
            fraud_subtype=data.get("fraud_subtype"),
            license=data.get("license"),
            license_verified=bool(data.get("license_verified", False)),
            historical_reliability=str(data.get("historical_reliability", "unknown")),
            nlp_usable=bool(data.get("nlp_usable", True)),
            forensic_usable=bool(data.get("forensic_usable", True)),
            exclusion_reason=data.get("exclusion_reason"),
        )


def compute_deterministic_email_id(
    source_dataset: str,
    source_record_id: str,
    raw_message_sha256: str,
    normalized_full_sha256: str,
) -> str:
    """Compute a deterministic, machine-independent, run-invariant email ID."""
    if raw_message_sha256:
        return f"email_{raw_message_sha256[:32]}"
    ident = f"{source_dataset}:{source_record_id}:{normalized_full_sha256}"
    return f"email_{hashlib.sha256(ident.encode('utf-8')).hexdigest()[:32]}"
