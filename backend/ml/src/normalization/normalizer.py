"""Deterministic Email Normalizer for MailForensix ML Pipeline.

Implements normalization invariants from implementation.md Section 9 and Section 10:
- Deterministic MIME decoding and character set detection
- Unicode NFKC normalization
- Newline and whitespace normalization
- HTML body parsing and script/style sanitization
- Attachment detection and SHA256 hashing
- URL extraction, unquoting, and IDNA normalization
- Deterministic content hashing (raw, full, body)
"""

import email
from email import policy
from email.utils import parsedate_to_datetime, parseaddr
import hashlib
import re
import unicodedata
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
from bs4 import BeautifulSoup
import chardet

from ml.src.schemas.canonical_email import CanonicalEmail, compute_deterministic_email_id


class EmailNormalizer:
    """Normalizes raw email bytes or structured email fields into CanonicalEmail."""

    URL_REGEX = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)

    @staticmethod
    def normalize_unicode(text: Optional[str]) -> str:
        """Apply Unicode NFKC normalization."""
        if not text:
            return ""
        return unicodedata.normalize("NFKC", str(text))

    @staticmethod
    def normalize_newlines(text: Optional[str]) -> str:
        """Standardize all line endings to Unix style LF ('\\n')."""
        if not text:
            return ""
        return text.replace("\r\n", "\n").replace("\r", "\n")

    @classmethod
    def clean_text(cls, text: Optional[str]) -> str:
        """Normalize unicode, newlines, and trailing whitespace per line."""
        if not text:
            return ""
        t = cls.normalize_unicode(text)
        t = cls.normalize_newlines(t)
        # Strip trailing whitespace on each line
        lines = [line.rstrip() for line in t.split("\n")]
        # Collapse 3+ consecutive newlines to 2
        cleaned = "\n".join(lines)
        cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
        return cleaned.strip()

    @classmethod
    def extract_urls(cls, text: str, html: str) -> List[str]:
        """Extract, decode, IDNA-normalize, and deduplicate all URLs in text and HTML."""
        found_urls: List[str] = []

        # 1. Plain text regex extraction
        if text:
            found_urls.extend(cls.URL_REGEX.findall(text))

        # 2. HTML tag attribute extraction
        if html:
            try:
                # Fast regex scan for URLs in HTML attributes
                for match in re.finditer(r'(?:href|src|action)=["\']?(https?://[^"\'\s>]+)', html[:200000], re.IGNORECASE):
                    found_urls.append(match.group(1))
            except Exception:
                pass

        # 3. Clean, unquote, and IDNA-normalize
        clean_urls: List[str] = []
        seen = set()
        for raw_u in found_urls:
            raw_clean = raw_u.strip()
            if not raw_clean:
                continue
            try:
                unquoted = urllib.parse.unquote(raw_clean)
                parsed = urllib.parse.urlparse(unquoted)
                if parsed.netloc:
                    netloc_idna = parsed.netloc.encode("idna").decode("utf-8")
                    norm_url = urllib.parse.urlunparse(parsed._replace(netloc=netloc_idna))
                else:
                    norm_url = unquoted
            except Exception:
                norm_url = raw_clean

            if norm_url not in seen:
                seen.add(norm_url)
                clean_urls.append(norm_url)

        return clean_urls

    @classmethod
    def extract_html_plain(cls, html: str) -> str:
        """Extract clean human-readable text from HTML body."""
        if not html:
            return ""
        try:
            soup = BeautifulSoup(html[:200000], "html.parser")
            for tag in soup(["script", "style", "head", "meta", "noscript"]):
                tag.extract()
            for br in soup.find_all("br"):
                br.replace_with("\n")
            text = soup.get_text(separator=" ")
            return cls.clean_text(text)
        except Exception:
            return ""

    @staticmethod
    def parse_timestamp(date_str: Optional[str]) -> Optional[str]:
        """Parse raw RFC 822 Date header into standard ISO 8601 UTC timestamp."""
        if not date_str:
            return None
        try:
            dt = parsedate_to_datetime(date_str)
            return dt.isoformat()
        except Exception:
            return None

    @classmethod
    def parse_raw_eml_bytes(
        cls,
        raw_bytes: bytes,
        source_dataset: str,
        source_record_id: str,
        source_path: str = "",
        source_label: Optional[str] = None,
        is_synthetic: bool = False,
        synthetic_source: Optional[str] = None,
        construction_type: str = "authentic",
        license_str: Optional[str] = None,
        license_verified: bool = False,
        historical_reliability: str = "unknown",
    ) -> CanonicalEmail:
        """Parse raw RFC 822 / EML bytes into CanonicalEmail."""
        # Strip UTF-8 BOM if present
        if raw_bytes.startswith(b'\xef\xbb\xbf'):
            raw_bytes = raw_bytes[3:]

        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        msg = email.message_from_bytes(raw_bytes, policy=policy.default)

        # Extract headers
        headers_dict: Dict[str, Any] = {}
        for k, v in msg.items():
            if k in headers_dict:
                if isinstance(headers_dict[k], list):
                    headers_dict[k].append(str(v))
                else:
                    headers_dict[k] = [headers_dict[k], str(v)]
            else:
                headers_dict[k] = str(v)

        sender = str(msg.get("From", "") or "")
        _, sender_email = parseaddr(sender)
        sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""

        recipients: List[str] = []
        for hdr in ["To", "Cc", "Bcc"]:
            vals = msg.get_all(hdr, [])
            for v in vals:
                recipients.extend([r.strip() for r in str(v).split(",") if r.strip()])

        subject = str(msg.get("Subject", "") or "")
        body_plain = ""
        body_html = ""
        attachments: List[Dict[str, Any]] = []

        # Walk parts
        for part in msg.walk():
            content_type = part.get_content_type()
            if part.get_content_maintype() == "multipart":
                continue

            filename = part.get_filename()
            if not filename:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                charset = part.get_content_charset()
                try:
                    if charset:
                        decoded = payload.decode(charset, errors="replace")
                    else:
                        try:
                            decoded = payload.decode("utf-8")
                        except UnicodeDecodeError:
                            decoded = payload.decode("windows-1252", errors="replace")
                    if content_type == "text/plain":
                        body_plain += decoded + "\n"
                    elif content_type == "text/html":
                        body_html += decoded + "\n"
                except Exception:
                    pass
            else:
                payload = part.get_payload(decode=True)
                if payload:
                    attachments.append({
                        "filename": filename,
                        "content_type": content_type,
                        "size": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    })

        # If body_plain is empty but body_html exists, derive body_plain from HTML
        norm_plain = cls.clean_text(body_plain)
        if not norm_plain and body_html:
            norm_plain = cls.extract_html_plain(body_html)

        norm_subject = cls.clean_text(subject)
        urls = cls.extract_urls(norm_plain, body_html)

        # Hashes
        body_identity = f"{norm_subject}\n{norm_plain}"
        norm_body_sha256 = hashlib.sha256(body_identity.encode("utf-8")).hexdigest()

        canonical_headers_str = f"from:{sender.lower()}|to:{','.join(sorted(recipients)).lower()}|subject:{norm_subject.lower()}"
        full_identity = f"{canonical_headers_str}\n\n{norm_plain}"
        norm_full_sha256 = hashlib.sha256(full_identity.encode("utf-8")).hexdigest()

        email_id = compute_deterministic_email_id(
            source_dataset=source_dataset,
            source_record_id=source_record_id,
            raw_message_sha256=raw_sha256,
            normalized_full_sha256=norm_full_sha256,
        )

        date_hdr = msg.get("Date")
        date_str = str(date_hdr) if date_hdr else None
        timestamp_iso = cls.parse_timestamp(date_str)

        return CanonicalEmail(
            email_id=email_id,
            source_dataset=source_dataset,
            source_record_id=source_record_id,
            source_path=source_path,
            raw_message_sha256=raw_sha256,
            normalized_full_sha256=norm_full_sha256,
            normalized_body_sha256=norm_body_sha256,
            headers=headers_dict,
            subject=norm_subject,
            body_plain=norm_plain,
            body_html=body_html,
            sender=sender,
            sender_domain=sender_domain,
            reply_to=str(msg.get("Reply-To")) if msg.get("Reply-To") else None,
            mail_from=str(msg.get("Return-Path")) if msg.get("Return-Path") else None,
            recipients=recipients,
            date=date_str,
            message_id=str(msg.get("Message-ID")) if msg.get("Message-ID") else None,
            email_timestamp=timestamp_iso,
            urls=urls,
            attachments=attachments,
            source_label=source_label,
            canonical_label=None,
            label_confidence=None,
            is_synthetic=is_synthetic,
            synthetic_source=synthetic_source,
            construction_type=construction_type,
            license=license_str,
            license_verified=license_verified,
            historical_reliability=historical_reliability,
        )

    @classmethod
    def parse_structured_fields(
        cls,
        subject: str,
        body: str,
        sender: str = "",
        recipients: Optional[List[str]] = None,
        headers: Optional[Dict[str, Any]] = None,
        source_dataset: str = "custom",
        source_record_id: str = "0",
        source_path: str = "",
        source_label: Optional[str] = None,
        is_synthetic: bool = False,
        synthetic_source: Optional[str] = None,
        construction_type: str = "authentic",
        fraud_subtype: Optional[str] = None,
        license_str: Optional[str] = None,
        license_verified: bool = False,
        urls: Optional[List[str]] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
        historical_reliability: str = "unknown",
    ) -> CanonicalEmail:
        """Normalize tabular/text-only email records into CanonicalEmail."""
        norm_subject = cls.clean_text(subject)
        norm_plain = cls.clean_text(body)

        _, sender_email = parseaddr(sender)
        sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""

        recs = recipients or []
        extracted_urls = urls if urls is not None else cls.extract_urls(norm_plain, "")

        # Compute content hashes
        body_identity = f"{norm_subject}\n{norm_plain}"
        norm_body_sha256 = hashlib.sha256(body_identity.encode("utf-8")).hexdigest()

        canonical_headers_str = f"from:{sender.lower()}|to:{','.join(sorted(recs)).lower()}|subject:{norm_subject.lower()}"
        full_identity = f"{canonical_headers_str}\n\n{norm_plain}"
        norm_full_sha256 = hashlib.sha256(full_identity.encode("utf-8")).hexdigest()

        raw_sha256 = hashlib.sha256(f"{norm_subject}\n\n{norm_plain}\n\n{sender}".encode("utf-8")).hexdigest()

        email_id = compute_deterministic_email_id(
            source_dataset=source_dataset,
            source_record_id=source_record_id,
            raw_message_sha256=raw_sha256,
            normalized_full_sha256=norm_full_sha256,
        )

        return CanonicalEmail(
            email_id=email_id,
            source_dataset=source_dataset,
            source_record_id=source_record_id,
            source_path=source_path,
            raw_message_sha256=raw_sha256,
            normalized_full_sha256=norm_full_sha256,
            normalized_body_sha256=norm_body_sha256,
            headers=headers or {},
            subject=norm_subject,
            body_plain=norm_plain,
            body_html="",
            sender=sender,
            sender_domain=sender_domain,
            reply_to=None,
            mail_from=None,
            recipients=recs,
            date=None,
            message_id=None,
            email_timestamp=None,
            urls=extracted_urls,
            attachments=attachments or [],
            source_label=source_label,
            canonical_label=None,
            label_confidence=None,
            is_synthetic=is_synthetic,
            synthetic_source=synthetic_source,
            construction_type=construction_type,
            fraud_subtype=fraud_subtype,
            license=license_str,
            license_verified=license_verified,
            historical_reliability=historical_reliability,
        )
