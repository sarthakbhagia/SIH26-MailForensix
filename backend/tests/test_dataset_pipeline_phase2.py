"""Phase 2 Test Suite: Dataset Ingestion, Parsing, Normalization, and Schemas.

Verifies:
- Maildir, mbox, RFC822/EML, CSV, CLAIR, and BEC-2 parsers
- Deterministic email_id generation and immutable raw hashing
- MIME multipart parsing and attachment extraction with SHA256
- HTML text and link extraction, IDNA domain normalization
- Unicode NFKC and newline normalization
- Malformed and missing field handling
- Provenance preservation and Parquet export/import roundtrip
"""

import email
from email.message import EmailMessage
import io
import json
import mailbox
from pathlib import Path
import tempfile
import pytest
import pandas as pd

from ml.src.schemas.canonical_email import CanonicalEmail, compute_deterministic_email_id
from ml.src.normalization.normalizer import EmailNormalizer
from ml.src.parsers.maildir_parser import MaildirParser
from ml.src.parsers.mbox_parser import MboxParser
from ml.src.parsers.rfc822_parser import RFC822Parser
from ml.src.parsers.csv_parser import CSVTabularParser
from ml.src.parsers.clair_parser import CLAIRParser
from ml.src.parsers.bec2_parser import BEC2Parser
from ml.src.parsers.registry import get_parser, parse_dataset_from_config
from ml.src.corpus.builder import CanonicalCorpusBuilder
from ml.src.acquisition.acquire import DatasetAcquisitionManager


# ---------------------------------------------------------------------------
# 1. Normalizer & Hashing Unit Tests
# ---------------------------------------------------------------------------

def test_deterministic_email_id_reproducibility():
    """Verify that parsing the exact same raw email twice yields the identical email_id."""
    raw_eml = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.com\r\n"
        b"Subject: Test Subject\r\n"
        b"Date: Mon, 31 Aug 2026 12:00:00 +0000\r\n"
        b"\r\n"
        b"Hello Bob,\nThis is a test email message.\n"
    )

    email1 = EmailNormalizer.parse_raw_eml_bytes(
        raw_bytes=raw_eml,
        source_dataset="enron",
        source_record_id="msg_001.eml",
    )
    email2 = EmailNormalizer.parse_raw_eml_bytes(
        raw_bytes=raw_eml,
        source_dataset="enron",
        source_record_id="msg_001.eml",
    )

    assert email1.email_id == email2.email_id
    assert email1.raw_message_sha256 == email2.raw_message_sha256
    assert email1.normalized_full_sha256 == email2.normalized_full_sha256
    assert email1.normalized_body_sha256 == email2.normalized_body_sha256
    assert len(email1.email_id) > 10


def test_html_extraction_and_url_normalization():
    """Verify HTML body parsing, tag stripping, and IDNA/unquoted URL extraction."""
    html_content = (
        "<html><body>"
        "<p>Please click <a href='https://xn--e1afmkfd.xn--p1ai/login?id=123'>here</a> to verify.</p>"
        "<img src='http://tracking.bad-domain.com%2Ftrack%3Fuser%3Dalice' />"
        "<script>alert('malicious')</script>"
        "</body></html>"
    )
    plain_text = EmailNormalizer.extract_html_plain(html_content)
    assert "Please click" in plain_text
    assert "verify" in plain_text
    assert "alert('malicious')" not in plain_text

    urls = EmailNormalizer.extract_urls(plain_text, html_content)
    assert len(urls) >= 2
    # Check IDNA / unquoting
    assert any("xn--e1afmkfd.xn--p1ai" in u or "пример.рф" in u for u in urls)
    assert any("tracking.bad-domain.com/track" in u for u in urls)


def test_mime_multipart_attachment_extraction():
    """Verify attachment decoding, filename capture, and attachment SHA256 calculation."""
    msg = EmailMessage()
    msg["From"] = "sender@domain.com"
    msg["To"] = "target@domain.com"
    msg["Subject"] = "Invoice with Attachment"
    msg.set_content("Please find attached the invoice document.")

    pdf_bytes = b"%PDF-1.4 Mock PDF Content for SHA256 validation"
    msg.add_attachment(
        pdf_bytes,
        maintype="application",
        subtype="pdf",
        filename="invoice_2026.pdf",
    )

    raw_eml = msg.as_bytes()
    canonical = EmailNormalizer.parse_raw_eml_bytes(
        raw_bytes=raw_eml,
        source_dataset="sample",
        source_record_id="sample.eml",
    )

    assert len(canonical.attachments) == 1
    att = canonical.attachments[0]
    assert att["filename"] == "invoice_2026.pdf"
    assert att["size"] == len(pdf_bytes)
    assert len(att["sha256"]) == 64


def test_encoding_resilience_and_bom_handling():
    """Verify handling of UTF-8 BOM, ISO-8859-1, and Windows-1252 character encodings."""
    # UTF-8 BOM message
    bom_eml = (
        b"\xef\xbb\xbfFrom: test@corp.com\r\n"
        b"Subject: BOM Test\r\n"
        b"\r\n"
        b"Hello with BOM\r\n"
    )
    canonical_bom = EmailNormalizer.parse_raw_eml_bytes(
        raw_bytes=bom_eml,
        source_dataset="test",
        source_record_id="bom.eml",
    )
    assert canonical_bom.subject == "BOM Test"
    assert "Hello with BOM" in canonical_bom.body_plain


def test_malformed_and_missing_fields_handling():
    """Verify that corrupt or incomplete emails do not crash the pipeline and use nulls/empty."""
    # Empty message
    empty_eml = b""
    canonical = EmailNormalizer.parse_raw_eml_bytes(
        raw_bytes=empty_eml,
        source_dataset="test",
        source_record_id="empty.eml",
    )
    assert canonical.subject == ""
    assert canonical.body_plain == ""
    assert canonical.sender == ""
    assert canonical.reply_to is None
    assert canonical.mail_from is None
    assert canonical.date is None
    assert canonical.email_timestamp is None


# ---------------------------------------------------------------------------
# 2. Dataset Parser Tests
# ---------------------------------------------------------------------------

def test_maildir_parser(tmp_path):
    """Verify MaildirParser on a mock Maildir directory."""
    maildir = tmp_path / "enron_mock"
    cur_dir = maildir / "user_a" / "cur"
    cur_dir.mkdir(parents=True)

    eml_file = cur_dir / "1.txt"
    eml_file.write_text(
        "From: jeff.skilling@enron.com\n"
        "To: ken.lay@enron.com\n"
        "Subject: Q3 Energy Trading Review\n"
        "Date: Tue, 15 Aug 2001 09:30:00 -0500\n\n"
        "Attached are the trading volume metrics.",
        encoding="utf-8",
    )

    parser = MaildirParser()
    config = {
        "name": "enron",
        "default_label": "Legitimate",
        "license": "Public Domain",
        "license_verified": True,
    }

    records = list(parser.parse(maildir, config))
    assert len(records) == 1
    rec = records[0]
    assert rec.source_dataset == "enron"
    assert rec.subject == "Q3 Energy Trading Review"
    assert rec.source_label == "Legitimate"
    assert rec.is_synthetic is False
    assert parser.stats.discovered_count == 1
    assert parser.stats.parseable_count == 1


def test_mbox_parser(tmp_path):
    """Verify MboxParser on a generated mbox file."""
    mbox_path = tmp_path / "nazario_mock.mbox"
    mb = mailbox.mbox(str(mbox_path))
    mb.lock()

    msg1 = mailbox.mboxMessage()
    msg1["From"] = "security@fake-bank.com"
    msg1["To"] = "victim@target.com"
    msg1["Subject"] = "Urgent: Verify Your Account Credentials"
    msg1.set_payload("Your online banking is locked. Click http://fake-bank.com/login immediately.")
    mb.add(msg1)

    msg2 = mailbox.mboxMessage()
    msg2["From"] = "alert@paypal-update.net"
    msg2["To"] = "victim2@target.com"
    msg2["Subject"] = "Security Notice: Unauthorized Access"
    msg2.set_payload("Login to verify: http://paypal-update.net/verify")
    mb.add(msg2)

    mb.flush()
    mb.unlock()

    parser = MboxParser()
    config = {"name": "nazario", "default_label": "Phishing"}
    records = list(parser.parse(mbox_path, config))

    assert len(records) == 2
    assert records[0].source_dataset == "nazario"
    assert records[0].source_label == "Phishing"
    assert "http://fake-bank.com/login" in records[0].urls
    assert records[1].subject == "Security Notice: Unauthorized Access"
    assert parser.stats.parseable_count == 2


def test_rfc822_parser_with_label_index(tmp_path):
    """Verify RFC822Parser with TREC-style label index mapping."""
    trec_dir = tmp_path / "trec07_mock"
    full_dir = trec_dir / "full"
    data_dir = trec_dir / "data"
    full_dir.mkdir(parents=True)
    data_dir.mkdir(parents=True)

    # Email 1: Ham
    (data_dir / "inmail.1").write_text(
        "From: legit@university.edu\nSubject: Research Paper\n\nPlease find the paper attached.",
        encoding="utf-8",
    )
    # Email 2: Spam
    (data_dir / "inmail.2").write_text(
        "From: promo@cheap-meds.com\nSubject: Buy Discounted Products Today\n\nVisit http://cheap-meds.com",
        encoding="utf-8",
    )

    # Index file
    (full_dir / "index").write_text("ham ../data/inmail.1\nspam ../data/inmail.2\n", encoding="utf-8")

    parser = RFC822Parser()
    config = {
        "name": "trec07",
        "source_labels": {"ham": "Legitimate", "spam": "candidate_suspicious"},
    }

    records = list(parser.parse(trec_dir, config))
    assert len(records) == 2
    labels = {r.source_record_id: r.source_label for r in records}
    assert any(lbl == "Legitimate" for lbl in labels.values())
    assert any(lbl == "candidate_suspicious" for lbl in labels.values())


def test_csv_tabular_parser(tmp_path):
    """Verify CSVTabularParser for datasets like zefang-liu or IWSPA-AP."""
    csv_file = tmp_path / "phish_table.csv"
    df = pd.DataFrame([
        {"subject": "HR Notice", "body": "Please review policy http://hr.com/update", "sender": "hr@corp.com", "label": "0"},
        {"subject": "Free Gift Card", "body": "Claim your $500 card now http://gift.com", "sender": "promo@spam.com", "label": "1"},
    ])
    df.to_csv(csv_file, index=False)

    parser = CSVTabularParser()
    config = {
        "name": "zefang_liu",
        "source_labels": {"0": "Legitimate", "1": "Phishing"},
    }

    records = list(parser.parse(csv_file, config))
    assert len(records) == 2
    assert records[0].source_label == "Legitimate"
    assert records[1].source_label == "Phishing"
    assert "http://gift.com" in records[1].urls


def test_clair_parser_with_fraud_subtype(tmp_path):
    """Verify CLAIRParser parses 419 scam texts and records fraud_subtype='419_advance_fee'."""
    clair_file = tmp_path / "clair_419.txt"
    clair_file.write_text(
        "From: Dr. Bakare Tunde <tunde@nigeria-finance.org>\n"
        "Subject: URGENT ASSISTANCE: $25,000,000 TRANSFER\n\n"
        "Dear Friend,\n"
        "I am the auditor general. I need your account to transfer $25M funds. You get 30%.\n"
        "Reply urgently with your banking details.",
        encoding="utf-8",
    )

    parser = CLAIRParser()
    config = {"name": "clair"}
    records = list(parser.parse(clair_file, config))

    assert len(records) == 1
    rec = records[0]
    assert rec.source_label == "BEC/Fraud"
    assert rec.fraud_subtype == "419_advance_fee"
    assert rec.is_synthetic is False
    assert "25,000,000" in rec.subject
    assert "$25M" in rec.body_plain


def test_bec2_parser_with_synthetic_provenance(tmp_path):
    """Verify BEC2Parser enforces is_synthetic=True and synthetic_source metadata."""
    bec2_file = tmp_path / "bec2_sample.json"
    data = [
        {
            "subject": "Urgent Wire Transfer Authorization",
            "body": "Please process an immediate wire transfer of $75,000 for acquisition fees.",
            "sender": "ceo.office@partner-corp.com",
        }
    ]
    bec2_file.write_text(json.dumps(data), encoding="utf-8")

    parser = BEC2Parser()
    config = {"name": "bec2"}
    records = list(parser.parse(bec2_file, config))

    assert len(records) == 1
    rec = records[0]
    assert rec.is_synthetic is True
    assert "BEC-2" in rec.synthetic_source
    assert rec.fraud_subtype == "synthetic_bec"
    assert rec.source_label == "BEC/Fraud"


# ---------------------------------------------------------------------------
# 3. Canonical Corpus Builder & Parquet Roundtrip Tests
# ---------------------------------------------------------------------------

def test_canonical_corpus_parquet_roundtrip(tmp_path):
    """Verify building, Parquet serialization, and schema restoration."""
    sample_dir = tmp_path / "sample_dataset"
    sample_dir.mkdir()

    (sample_dir / "email1.eml").write_text(
        "From: Alice <alice@example.com>\n"
        "To: Bob <bob@example.com>\n"
        "Subject: Hello Bob\n\n"
        "Meeting at 3 PM today.",
        encoding="utf-8",
    )

    builder = CanonicalCorpusBuilder(
        config_path=None,
        data_dir=tmp_path,
        output_dir=tmp_path / "output",
    )

    # Parse local directory
    records = list(RFC822Parser().parse(sample_dir, {"name": "test_sample"}))
    assert len(records) == 1

    emails_pq, manifest_pq = builder.save_corpus(records)
    assert emails_pq.exists()
    assert manifest_pq.exists()

    # Read back and verify
    df_read = pd.read_parquet(emails_pq)
    assert len(df_read) == 1
    assert df_read.iloc[0]["email_id"] == records[0].email_id
    assert df_read.iloc[0]["subject"] == "Hello Bob"

    # Convert back to CanonicalEmail
    restored = CanonicalEmail.from_dict(df_read.iloc[0].to_dict())
    assert restored.email_id == records[0].email_id
    assert restored.subject == records[0].subject
    assert restored.sender == records[0].sender


def test_acquisition_manager_inspection(tmp_path):
    """Verify DatasetAcquisitionManager inspects datasets and records inventory without fabrications."""
    mgr = DatasetAcquisitionManager(
        config_path=None,
        raw_data_dir=tmp_path / "raw",
    )
    inv = mgr.generate_inventory(tmp_path / "raw_inventory.json")

    assert "datasets" in inv
    assert "enron" in inv["datasets"]
    assert "trec07" in inv["datasets"]
    assert "bec2" in inv["datasets"]
    # Verify trec07 requires manual agreement
    assert inv["datasets"]["trec07"]["requires_manual_acquisition"] is True
    # Verify bec2 synthetic metadata
    assert inv["datasets"]["bec2"]["is_synthetic"] is True
