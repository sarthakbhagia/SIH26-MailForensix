import io
import pytest
from datetime import datetime, timezone
from uuid import UUID, uuid4
from fastapi.testclient import TestClient

from app.core.reporting.report_generator import ReportGenerator
from app.database import get_db
from app.main import app
from app.models.analysis_result import AnalysisResult
from app.models.email_case import Email, EmailStatus
from app.models.audit_log import AuditLog
from app.services.audit_service import AuditService


class FakeScalarResult:
    def __init__(self, item):
        self._item = item

    def scalar_one_or_none(self):
        return self._item

    def scalar(self):
        return self._item

    def scalars(self):
        class ScalarIter:
            def __init__(self, item):
                self._items = [item] if item is not None else []
            def all(self):
                return self._items
        return ScalarIter(self._item)


class MockReportDbSession:
    """Mock DB Session for ReportGenerator testing."""

    def __init__(self):
        self.emails: dict[UUID, Email] = {}
        self.analyses: dict[UUID, AnalysisResult] = {}
        self.audit_logs: list[AuditLog] = []

    def add(self, obj):
        if isinstance(obj, AuditLog):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.audit_logs.append(obj)
        elif isinstance(obj, Email):
            self.emails[obj.id] = obj
        elif isinstance(obj, AnalysisResult):
            self.analyses[obj.email_id] = obj

    async def commit(self):
        pass

    async def refresh(self, obj):
        pass

    async def execute(self, stmt):
        stmt_str = str(stmt).lower()

        # AuditLog latest query
        if "from audit_logs" in stmt_str:
            last = self.audit_logs[-1] if self.audit_logs else None
            return FakeScalarResult(last)

        # Lookup Email
        if "from emails" in stmt_str and "emails.id =" in stmt_str:
            target_id = None
            for criterion in getattr(stmt, "_where_criteria", []):
                if hasattr(criterion, "right") and hasattr(criterion.right, "value"):
                    target_id = criterion.right.value
                elif hasattr(criterion, "value"):
                    target_id = criterion.value
            if target_id is not None:
                return FakeScalarResult(self.emails.get(target_id))
            for eid, email in self.emails.items():
                if str(eid) in stmt_str:
                    return FakeScalarResult(email)
            return FakeScalarResult(None)

        # Lookup AnalysisResult
        if "from analysis_results" in stmt_str and "analysis_results.email_id =" in stmt_str:
            target_id = None
            for criterion in getattr(stmt, "_where_criteria", []):
                if hasattr(criterion, "right") and hasattr(criterion.right, "value"):
                    target_id = criterion.right.value
                elif hasattr(criterion, "value"):
                    target_id = criterion.value
            if target_id is not None:
                return FakeScalarResult(self.analyses.get(target_id))
            for eid, analysis in self.analyses.items():
                if str(eid) in stmt_str:
                    return FakeScalarResult(analysis)
            return FakeScalarResult(None)

        return FakeScalarResult(None)


@pytest.fixture
def mock_report_db():
    db = MockReportDbSession()
    eid = uuid4()
    email = Email(
        id=eid,
        sender="attacker@spoofed-bank.com",
        recipients=["victim@corp.com"],
        subject="URGENT: Verify Account Access",
        raw_hash_sha256="e" * 64,
        raw_hash_sha1="e" * 40,
        raw_hash_md5="e" * 32,
        headers={"Message-ID": "<20260826@spoofed-bank.com>"},
        status=EmailStatus.analyzed,
        ingested_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    analysis = AnalysisResult(
        id=uuid4(),
        email_id=eid,
        composite_risk_score=94.5,
        nlp_label="Phishing",
        nlp_confidence=98.0,
        nlp_details={"explanation": "Credential harvesting lure detected."},
        auth_status={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        risk_breakdown={
            "overall_score": 94.5,
            "severity": "critical",
            "recommended_action": "Block & Quarantine immediately",
            "factors": [
                {"name": "NLP Threat Classification", "raw_score": 98.0, "weight": 0.35, "weighted_score": 34.3, "severity": "critical", "details": "High confidence credential phish."},
                {"name": "Authentication Verification", "raw_score": 90.0, "weight": 0.25, "weighted_score": 22.5, "severity": "critical", "details": "SPF/DKIM/DMARC failed."},
            ],
        },
        iocs=[
            {"type": "URL", "value": "http://phish-login.com", "risk_score": 95, "reason": "Phishing lure"},
            {"type": "IP", "value": "198.51.100.42", "risk_score": 85, "reason": "Known malicious relay"},
        ],
        relay_path=[{"ip": "198.51.100.42", "country": "RU"}],
        geo_data=[{"ip": "198.51.100.42", "city": "Moscow", "country": "Russia"}],
    )
    db.add(email)
    db.add(analysis)
    return db, eid


@pytest.mark.asyncio
async def test_generate_json_report(mock_report_db):
    """Verify generate_json returns complete structured forensic telemetry with all required sections and logs audit action."""
    db, eid = mock_report_db
    generator = ReportGenerator()

    report = await generator.generate_json(email_id=eid, db=db)

    # 1. Top-level metadata
    assert report["version"] == "1.0"
    assert report["report_id"] is not None
    assert "platform" in report
    assert "generated_at" in report

    # 2. Email metadata & hashes
    meta = report["email_metadata"]
    assert meta["id"] == str(eid)
    assert meta["sender"] == "attacker@spoofed-bank.com"
    assert meta["subject"] == "URGENT: Verify Account Access"
    assert meta["recipients"] == ["victim@corp.com"]
    assert meta["message_id"] == "<20260826@spoofed-bank.com>"
    assert meta["hashes"]["sha256"] == "e" * 64
    assert meta["hashes"]["sha1"] == "e" * 40
    assert meta["hashes"]["md5"] == "e" * 32

    # 3. Threat assessment & risk factors
    assessment = report["threat_assessment"]
    assert assessment["overall_risk_score"] == 94.5
    assert assessment["severity"] == "critical"
    assert "recommended_action" in assessment
    assert len(assessment["risk_factors"]) >= 2
    assert assessment["risk_factors"][0]["name"] == "NLP Threat Classification"

    # 4. NLP classification
    nlp = report["nlp_classification"]
    assert nlp["label"] == "Phishing"
    assert nlp["confidence"] == 98.0
    assert "details" in nlp

    # 5. Authentication
    auth = report["authentication"]
    assert auth["spf"] == "fail"
    assert auth["dkim"] == "fail"
    assert auth["dmarc"] == "fail"

    # 6. Infrastructure & Network (relay path & geo data)
    infra = report["infrastructure_and_network"]
    assert len(infra["relay_path"]) >= 1
    assert infra["relay_path"][0]["ip"] == "198.51.100.42"
    assert len(infra["geo_data"]) >= 1
    assert infra["geo_data"][0]["city"] == "Moscow"

    # 7. Indicators of Compromise (IOCs)
    iocs = report["indicators_of_compromise"]
    assert len(iocs) == 2
    assert any(i["type"] == "URL" and i["value"] == "http://phish-login.com" for i in iocs)
    assert any(i["type"] == "IP" and i["value"] == "198.51.100.42" for i in iocs)

    # 8. Attribution assessment
    att = report["attribution"]
    assert "category" in att
    assert "confidence" in att

    # 9. Chain of custody
    custody = report["chain_of_custody"]
    assert "ingested_at" in custody
    assert "analyzed_at" in custody
    assert custody["hash_verification"] == "MATCH - Cryptographically Verified"

    # Verify audit action logged
    assert len(db.audit_logs) >= 1
    assert db.audit_logs[-1].action == "forensic_report_generated"
    assert db.audit_logs[-1].action_data["format"] == "json"


@pytest.mark.asyncio
async def test_generate_pdf_report(mock_report_db):
    """Verify generate_pdf returns valid publication-ready PDF binary bytes and logs audit action."""
    db, eid = mock_report_db
    generator = ReportGenerator()

    pdf_bytes = await generator.generate_pdf(email_id=eid, db=db)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-")

    # Verify audit action logged
    assert len(db.audit_logs) >= 1
    assert db.audit_logs[-1].action == "forensic_report_generated"
    assert db.audit_logs[-1].action_data["format"] == "pdf"
    assert db.audit_logs[-1].action_data["size_bytes"] == len(pdf_bytes)


@pytest.mark.asyncio
async def test_render_html_template(mock_report_db):
    """Verify HTML template renders all sections cleanly without double percentage formatting."""
    db, eid = mock_report_db
    generator = ReportGenerator()

    report_data = await generator.generate_json(email_id=eid, db=db)
    html = generator._render_html(report_data)

    assert "<html" in html
    assert "attacker@spoofed-bank.com" in html
    assert "94.5" in html
    assert "http://phish-login.com" in html
    assert "CONFIDENTIAL" in html
    # Verify confidence formatting is 98.0% and NOT 9800.0%
    assert "98.0%" in html or "98%" in html
    assert "9800" not in html


@pytest.mark.parametrize(
    "conf_input,expected_str,forbidden_str",
    [
        (0.0, "0.0%", "000.0%"),
        (25.0, "25.0%", "2500.0%"),
        (45.0, "45.0%", "4500.0%"),
        (75.0, "75.0%", "7500.0%"),
        (100.0, "100.0%", "10000.0%"),
        # Fractional inputs normalized to canonical scale
        (0.25, "25.0%", "2500.0%"),
        (0.45, "45.0%", "4500.0%"),
        (0.75, "75.0%", "7500.0%"),
        (1.0, "100.0%", "10000.0%"),
    ],
)
@pytest.mark.asyncio
async def test_confidence_percentage_values(conf_input, expected_str, forbidden_str):
    """Verify 0%, 25%, 45%, 75%, and 100% confidence values render cleanly in HTML and PDF reports."""
    db = MockReportDbSession()
    eid = uuid4()
    email = Email(
        id=eid,
        sender="tester@security-audit.com",
        recipients=["analyst@corp.com"],
        subject="Threat Analysis Validation",
        raw_hash_sha256="a" * 64,
        raw_hash_sha1="a" * 40,
        raw_hash_md5="a" * 32,
        headers={"Message-ID": "<audit@test.com>"},
        status=EmailStatus.analyzed,
        ingested_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    analysis = AnalysisResult(
        id=uuid4(),
        email_id=eid,
        composite_risk_score=float(conf_input if conf_input > 1.0 else conf_input * 100.0),
        nlp_label="Phishing",
        nlp_confidence=float(conf_input),
        attribution_confidence=float(conf_input),
        nlp_details={"explanation": f"Test confidence {expected_str}"},
        auth_status={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        risk_breakdown={
            "overall_score": float(conf_input if conf_input > 1.0 else conf_input * 100.0),
            "severity": "medium",
            "recommended_action": "Review",
            "factors": [
                {"name": "NLP Threat Classification", "raw_score": 50.0, "weight": 0.35, "weighted_score": 17.5, "severity": "medium", "details": "Test factor"},
            ],
        },
        iocs=[],
        relay_path=[],
        geo_data=[],
    )
    db.add(email)
    db.add(analysis)

    generator = ReportGenerator()

    # 1. Test JSON data assembly
    report_json = await generator.generate_json(email_id=eid, db=db)
    expected_numeric = float(conf_input if conf_input > 1.0 or conf_input == 0.0 else conf_input * 100.0)
    assert report_json["nlp_classification"]["confidence"] == expected_numeric
    assert report_json["attribution"]["confidence"] == expected_numeric

    # 2. Test HTML rendering
    html = generator._render_html(report_json)
    assert expected_str in html
    assert forbidden_str not in html

    # 3. Test PDF fallback generation
    pdf_bytes = generator._generate_pdf_fallback(report_json)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF-")



@pytest.mark.asyncio
async def test_missing_email_error():
    """Verify generate_json/pdf raises ValueError when email does not exist."""
    empty_db = MockReportDbSession()
    generator = ReportGenerator()

    with pytest.raises(ValueError, match="not found"):
        await generator.generate_json(email_id=uuid4(), db=empty_db)

    with pytest.raises(ValueError, match="not found"):
        await generator.generate_pdf(email_id=uuid4(), db=empty_db)


@pytest.mark.asyncio
async def test_missing_analysis_error():
    """Verify generate_json/pdf raises ValueError when analysis result is missing."""
    db = MockReportDbSession()
    eid = uuid4()
    email = Email(id=eid, sender="user@domain.com", status=EmailStatus.pending)
    db.add(email)

    generator = ReportGenerator()

    with pytest.raises(ValueError, match="Analysis result"):
        await generator.generate_json(email_id=eid, db=db)

    with pytest.raises(ValueError, match="Analysis result"):
        await generator.generate_pdf(email_id=eid, db=db)


def test_api_report_endpoints(mock_report_db):
    """Verify GET /api/reports/{id}/json and /pdf return 200 responses."""
    db, eid = mock_report_db

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    # 1. JSON report
    res_json = client.get(f"/api/reports/{eid}/json")
    assert res_json.status_code == 200
    data = res_json.json()
    assert data["version"] == "1.0"
    assert data["email_metadata"]["sender"] == "attacker@spoofed-bank.com"

    # 1b. Nested /emails/{eid}/json
    res_json2 = client.get(f"/api/reports/emails/{eid}/json")
    assert res_json2.status_code == 200

    # 2. PDF report
    res_pdf = client.get(f"/api/reports/{eid}/pdf")
    assert res_pdf.status_code == 200
    assert res_pdf.headers["content-type"] == "application/pdf"
    assert len(res_pdf.content) > 500
    assert res_pdf.content.startswith(b"%PDF-")

    # 2b. Nested /emails/{eid}/pdf
    res_pdf2 = client.get(f"/api/reports/emails/{eid}/pdf")
    assert res_pdf2.status_code == 200
    assert res_pdf2.headers["content-type"] == "application/pdf"

    # 3. Preview report
    res_prev = client.get(f"/api/reports/emails/{eid}/preview")
    assert res_prev.status_code == 200
    assert "text/html" in res_prev.headers["content-type"]
    assert "<html" in res_prev.text
    assert "attacker@spoofed-bank.com" in res_prev.text

    # 4. Missing email 404
    missing_id = uuid4()
    res_missing = client.get(f"/api/reports/emails/{missing_id}/json")
    assert res_missing.status_code == 404

    res_missing_prev = client.get(f"/api/reports/emails/{missing_id}/preview")
    assert res_missing_prev.status_code == 404

    app.dependency_overrides.clear()

