import pytest
from datetime import datetime, timezone
from uuid import UUID, uuid4
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db
from app.models.email_case import Email, EmailStatus
from app.models.analysis_result import AnalysisResult


class FakeScalarResult:
    def __init__(self, items):
        self._items = items if isinstance(items, list) else ([items] if items is not None else [])

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None

    def scalar(self):
        return self._items[0] if self._items else None

    def scalars(self):
        class ScalarIter:
            def __init__(self, items):
                self._items = items
            def all(self):
                return list(self._items)
        return ScalarIter(self._items)


class MockLifecycleDbSession:
    def __init__(self):
        self.emails: list[Email] = []
        self.analysis_results: list[AnalysisResult] = []

    def add(self, obj):
        if isinstance(obj, Email):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.emails.append(obj)
        elif isinstance(obj, AnalysisResult):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.analysis_results.append(obj)

    async def commit(self):
        pass

    async def flush(self):
        pass

    async def refresh(self, obj):
        pass

    async def delete(self, obj):
        if obj in self.emails:
            self.emails.remove(obj)
        if obj in self.analysis_results:
            self.analysis_results.remove(obj)

    async def execute(self, stmt):
        stmt_str = str(stmt).lower()

        # 1. Lookup Email by ID
        if "from emails" in stmt_str and "emails.id =" in stmt_str:
            for em in self.emails:
                return FakeScalarResult(em)
            return FakeScalarResult(None)

        # 2. Lookup AnalysisResult by email_id
        if "from analysis_results" in stmt_str and "analysis_results.email_id =" in stmt_str:
            for ar in self.analysis_results:
                return FakeScalarResult(ar)
            return FakeScalarResult(None)

        return FakeScalarResult(None)


@pytest.fixture
def mock_session():
    return MockLifecycleDbSession()


@pytest.fixture
def client(mock_session):
    async def override_get_db():
        yield mock_session

    app.dependency_overrides[get_db] = override_get_db
    test_client = TestClient(app)
    yield test_client
    app.dependency_overrides.clear()


def test_get_analysis_email_not_found(client):
    """Querying analysis for non-existent email returns 404."""
    non_existent_id = uuid4()
    resp = client.get(f"/api/analysis/{non_existent_id}")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_get_analysis_pending_state(client, mock_session):
    """Querying analysis when email is still pending returns 200 with status=pending."""
    email_id = uuid4()
    email = Email(
        id=email_id,
        sender="sender@example.com",
        subject="Pending Analysis Test",
        status=EmailStatus.pending,
        ingested_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    mock_session.emails.append(email)

    resp = client.get(f"/api/analysis/{email_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["email_id"] == str(email_id)
    assert data["status"] == "pending"
    assert data["nlp_result"] is None
    assert data["auth_result"] is None
    assert data["relay_path"] == []
    assert data["geo_data"] == []
    assert data["iocs"] == []


def test_get_analysis_processing_state(client, mock_session):
    """Querying analysis when email is processing returns 200 with status=processing."""
    email_id = uuid4()
    email = Email(
        id=email_id,
        sender="sender@example.com",
        subject="Processing Analysis Test",
        status=EmailStatus.processing,
        ingested_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    mock_session.emails.append(email)

    resp = client.get(f"/api/analysis/{email_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["email_id"] == str(email_id)
    assert data["status"] == "processing"


def test_get_analysis_error_state(client, mock_session):
    """Querying analysis when pipeline failed returns 200 with status=error and error_message."""
    email_id = uuid4()
    email = Email(
        id=email_id,
        sender="sender@example.com",
        subject="Failed Analysis Test",
        status=EmailStatus.error,
        ingested_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    mock_session.emails.append(email)

    resp = client.get(f"/api/analysis/{email_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["email_id"] == str(email_id)
    assert data["status"] == "error"
    assert data["error_message"] is not None


def test_get_analysis_completed_state(client, mock_session):
    """Querying analysis when analysis is complete returns 200 with full data."""
    email_id = uuid4()
    email = Email(
        id=email_id,
        sender="attacker@phish.com",
        subject="Urgent Account Verification",
        status=EmailStatus.analyzed,
        ingested_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    analysis = AnalysisResult(
        id=uuid4(),
        email_id=email_id,
        nlp_label="Phishing",
        nlp_confidence=88.5,
        nlp_details={"urgency_score": 75.0},
        auth_status={"spf_status": "fail", "dkim_status": "none", "dmarc_status": "fail"},
        relay_path=[{"hop_number": 1, "ip": "1.2.3.4", "hostname": "mail.phish.com"}],
        geo_data=[{"ip": "1.2.3.4", "country": "Russia", "latitude": 55.75, "longitude": 37.61}],
        iocs=[{"type": "URL", "value": "http://phish.com/login", "risk_score": 90}],
        composite_risk_score=85.0,
        risk_breakdown={"nlp": 88.5, "auth": 90.0},
        attribution_category="Spoofed Domain",
        attribution_confidence=75.0,
        analyzed_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    mock_session.emails.append(email)
    mock_session.analysis_results.append(analysis)

    resp = client.get(f"/api/analysis/{email_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["email_id"] == str(email_id)
    assert data["status"] == "analyzed"
    assert data["nlp_result"]["label"] == "Phishing"
    assert data["nlp_result"]["confidence"] == 88.5
    assert data["auth_result"]["spf_status"] == "fail"
    assert data["composite_risk_score"] == 85.0
    assert len(data["relay_path"]) == 1
    assert len(data["geo_data"]) == 1
    assert len(data["iocs"]) == 1


def test_retry_analysis_endpoint(client, mock_session):
    """POST /api/analysis/{email_id}/retry queues email for re-processing."""
    email_id = uuid4()
    email = Email(
        id=email_id,
        sender="sender@example.com",
        subject="Retry Test",
        status=EmailStatus.error,
        ingested_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    mock_session.emails.append(email)

    resp = client.post(f"/api/analysis/{email_id}/retry")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "pending"
    assert data["email_id"] == str(email_id)
    assert email.status == EmailStatus.pending


def test_child_endpoints_when_pending(client, mock_session):
    """Child endpoints (/iocs, /relay-path, /geo) return empty lists instead of 404 when analysis is pending."""
    email_id = uuid4()
    email = Email(
        id=email_id,
        sender="sender@example.com",
        subject="Pending Child Endpoints Test",
        status=EmailStatus.pending,
        ingested_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    mock_session.emails.append(email)

    iocs_resp = client.get(f"/api/analysis/{email_id}/iocs")
    assert iocs_resp.status_code == 200
    assert iocs_resp.json() == []

    relay_resp = client.get(f"/api/analysis/{email_id}/relay-path")
    assert relay_resp.status_code == 200
    assert relay_resp.json() == []

    geo_resp = client.get(f"/api/analysis/{email_id}/geo")
    assert geo_resp.status_code == 200
    assert geo_resp.json() == []
