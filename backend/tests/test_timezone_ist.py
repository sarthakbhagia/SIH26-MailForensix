import pytest
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from uuid import uuid4

from app.core.utils.timezone import (
    IST,
    UTC,
    now_utc,
    now_ist,
    to_utc,
    to_ist,
    format_ist,
    to_iso_utc,
    to_iso_ist,
)
from app.core.reporting.report_generator import ReportGenerator
from app.models.email_case import Email, EmailStatus
from app.models.analysis_result import AnalysisResult
from app.models.alert import Alert, AlertSeverity


def test_timezone_constants():
    """Verify canonical IST timezone is Asia/Kolkata with UTC+05:30 offset."""
    assert IST.key == "Asia/Kolkata"
    assert UTC == timezone.utc


def test_current_timestamp_ist():
    """Verify now_ist() returns timezone-aware Asia/Kolkata datetime with +05:30 offset."""
    u = now_utc()
    i = now_ist()

    assert u.tzinfo == UTC
    assert i.tzinfo.key == "Asia/Kolkata"

    # Time difference between u and i as absolute time must be less than 1 second
    diff = abs((u - i).total_seconds())
    assert diff < 1.0

    # Formatted IST string must contain 'IST'
    ist_str = format_ist(i)
    assert "IST" in ist_str


def test_database_created_timestamp_conversion():
    """Verify timezone-naive UTC datetime stored in database converts to exact IST."""
    # Stored in DB as naive UTC 14:48:44
    naive_db_dt = datetime(2026, 8, 27, 14, 48, 44)

    ist_dt = to_ist(naive_db_dt)
    assert ist_dt.year == 2026
    assert ist_dt.month == 8
    assert ist_dt.day == 27
    assert ist_dt.hour == 20
    assert ist_dt.minute == 18
    assert ist_dt.second == 44
    assert ist_dt.tzinfo.key == "Asia/Kolkata"

    formatted = format_ist(naive_db_dt)
    assert formatted == "2026-08-27 20:18:44 IST"


def test_no_double_timezone_conversion():
    """Verify timezone-aware IST datetimes are preserved without double offset."""
    # Already IST aware
    aware_ist = datetime(2026, 8, 27, 20, 18, 44, tzinfo=IST)

    converted = to_ist(aware_ist)
    assert converted.hour == 20
    assert converted.minute == 18
    assert converted.second == 44

    formatted = format_ist(aware_ist)
    assert formatted == "2026-08-27 20:18:44 IST"

    # From ISO string with +05:30
    iso_ist = "2026-08-27T20:18:44+05:30"
    converted_iso = to_ist(iso_ist)
    assert converted_iso.hour == 20
    assert converted_iso.minute == 18
    assert format_ist(iso_ist) == "2026-08-27 20:18:44 IST"


def test_rfc2822_email_date_header_parsing():
    """Verify standard email RFC 2822 date headers convert accurately to IST."""
    # Email sent at 14:48:44 UTC
    email_date_utc = "Thu, 27 Aug 2026 14:48:44 +0000"
    ist_str = format_ist(email_date_utc)
    assert ist_str == "2026-08-27 20:18:44 IST"

    # Email sent from US Eastern (UTC-04:00) at 10:48:44
    email_date_edt = "Thu, 27 Aug 2026 10:48:44 -0400"
    ist_str_edt = format_ist(email_date_edt)
    assert ist_str_edt == "2026-08-27 20:18:44 IST"


@pytest.mark.asyncio
async def test_report_generation_timestamps_ist():
    """Verify generated forensic reports display consistent IST timestamps across metadata and custody."""
    class MockDb:
        def __init__(self, email, analysis):
            self.email = email
            self.analysis = analysis
            self.audit_logs = []
        def add(self, o): self.audit_logs.append(o)
        async def commit(self): pass
        async def refresh(self, o): pass
        async def execute(self, stmt):
            class Res:
                def __init__(self, item): self.item = item
                def scalar_one_or_none(self): return self.item
            s = str(stmt).lower()
            if "from emails" in s: return Res(self.email)
            if "from analysis_results" in s: return Res(self.analysis)
            return Res(None)

    eid = uuid4()
    # Ingested at naive UTC 14:48:44
    ingested_time = datetime(2026, 8, 27, 14, 48, 44)
    email = Email(
        id=eid,
        sender="attacker@phish.in",
        subject="Urgent Security Alert",
        status=EmailStatus.analyzed,
        ingested_at=ingested_time,
        headers={"Date": "Thu, 27 Aug 2026 14:48:44 +0000"},
        raw_hash_sha256="b" * 64,
        raw_hash_sha1="b" * 40,
        raw_hash_md5="b" * 32,
    )
    analysis = AnalysisResult(
        id=uuid4(),
        email_id=eid,
        composite_risk_score=85.0,
        nlp_label="Phishing",
        nlp_confidence=95.0,
        analyzed_at=datetime(2026, 8, 27, 14, 49, 0),
        auth_status={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        risk_breakdown={"overall_score": 85.0, "severity": "high", "factors": []},
        iocs=[],
        relay_path=[],
        geo_data=[],
    )
    db = MockDb(email, analysis)
    generator = ReportGenerator()

    # 1. JSON Report
    report_json = await generator.generate_json(email_id=eid, db=db)
    assert "IST" in report_json["generated_at"]
    assert report_json["email_metadata"]["date"] == "2026-08-27 20:18:44 IST"
    assert report_json["chain_of_custody"]["ingested_at"] == "2026-08-27 20:18:44 IST"
    assert report_json["chain_of_custody"]["analyzed_at"] == "2026-08-27 20:19:00 IST"

    # 2. HTML Report Preview
    html = generator._render_html(report_json)
    assert "2026-08-27 20:18:44 IST" in html
    assert "2026-08-27 20:19:00 IST" in html
    assert "UTC" not in html.split("Generated:")[1].split("</div>")[0]

    # 3. PDF Fallback
    pdf = generator._generate_pdf_fallback(report_json)
    assert isinstance(pdf, bytes)
    assert len(pdf) > 1000
    assert pdf.startswith(b"%PDF-")


def test_alert_timestamp_ist():
    """Verify alert timestamps format in IST."""
    naive_created = datetime(2026, 8, 27, 14, 48, 44)
    alert = Alert(
        id=uuid4(),
        severity=AlertSeverity.high,
        message="Critical Phish Alert",
        risk_score=90.0,
        created_at=naive_created,
    )
    formatted = format_ist(alert.created_at)
    assert formatted == "2026-08-27 20:18:44 IST"


def test_iso_utc_and_ist_helpers():
    """Verify to_iso_utc and to_iso_ist produce standards-compliant strings."""
    naive_dt = datetime(2026, 8, 27, 14, 48, 44)

    iso_utc = to_iso_utc(naive_dt)
    assert iso_utc == "2026-08-27T14:48:44Z"

    iso_ist = to_iso_ist(naive_dt)
    assert "+05:30" in iso_ist
    assert "2026-08-27T20:18:44+05:30" in iso_ist
