import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from fastapi.testclient import TestClient

from app.database import get_db
from app.main import app
from app.models.alert import Alert, AlertSeverity
from app.models.analysis_result import AnalysisResult
from app.models.email_case import Case, CaseSeverity, CaseStatus, Email, EmailStatus


class FakeScalarResult:
    def __init__(self, item):
        self._item = item

    def scalar(self):
        return self._item

    def scalar_one_or_none(self):
        return self._item

    def first(self):
        if isinstance(self._item, (list, tuple)):
            return self._item
        return (self._item,)

    def all(self):
        if self._item is None:
            return []
        if isinstance(self._item, list):
            return self._item
        return [self._item]


class MockDashboardDbSession:
    def __init__(self):
        self.emails: list[Email] = []
        self.analyses: list[AnalysisResult] = []
        self.cases: list[Case] = []
        self.alerts: list[Alert] = []

    async def execute(self, stmt):
        stmt_str = str(stmt).lower()

        # 1. Total emails: func.count(Email.id)
        if "count(emails.id)" in stmt_str:
            return FakeScalarResult(len(self.emails))

        # 2. Active cases: func.count(Case.id) with Case.status in (open, investigating)
        if "count(cases.id)" in stmt_str:
            active_count = sum(
                1 for c in self.cases if c.status in (CaseStatus.open, CaseStatus.investigating, "open", "investigating")
            )
            return FakeScalarResult(active_count)

        # 3. Threats detected: count(AnalysisResult.id) where composite_risk_score > 50
        if "count(analysis_results.id)" in stmt_str and "where analysis_results.composite_risk_score >" in stmt_str:
            threats_count = sum(
                1 for a in self.analyses if a.composite_risk_score is not None and a.composite_risk_score > 50.0
            )
            return FakeScalarResult(threats_count)

        # 4. Avg composite score
        if "avg(analysis_results.composite_risk_score)" in stmt_str:
            scores = [a.composite_risk_score for a in self.analyses if a.composite_risk_score is not None]
            avg_score = sum(scores) / len(scores) if scores else 0.0
            return FakeScalarResult(avg_score)

        # 5. Unacknowledged alerts: count(Alert.id) where acknowledged = False
        if "count(alerts.id)" in stmt_str:
            unack_count = sum(1 for al in self.alerts if not al.acknowledged)
            return FakeScalarResult(unack_count)

        # 6. Threat distribution by NLP label: group by nlp_label
        if "group by analysis_results.nlp_label" in stmt_str:
            dist = {}
            for a in self.analyses:
                label = a.nlp_label or "Unclassified"
                dist[label] = dist.get(label, 0) + 1
            rows = [(label, count) for label, count in dist.items()]
            return FakeScalarResult(rows)

        # 7. Risk distribution (case statements for low, med, high, crit)
        if "case" in stmt_str and "when" in stmt_str:
            low = sum(1 for a in self.analyses if a.composite_risk_score is not None and a.composite_risk_score <= 25.0)
            med = sum(1 for a in self.analyses if a.composite_risk_score is not None and 25.0 < a.composite_risk_score <= 50.0)
            high = sum(1 for a in self.analyses if a.composite_risk_score is not None and 50.0 < a.composite_risk_score <= 75.0)
            crit = sum(1 for a in self.analyses if a.composite_risk_score is not None and a.composite_risk_score > 75.0)
            return FakeScalarResult((low, med, high, crit))

        # 8. Ingestion timeline query
        if "emails.ingested_at >=" in stmt_str or "outerjoin" in stmt_str:
            analysis_by_eid = {a.email_id: a.composite_risk_score for a in self.analyses}
            timeline_rows = []
            for e in self.emails:
                score = analysis_by_eid.get(e.id)
                timeline_rows.append((e.ingested_at, score))
            return FakeScalarResult(timeline_rows)

        return FakeScalarResult([])


@pytest.fixture
def seeded_dashboard_db():
    db = MockDashboardDbSession()
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

    # Seed 5 emails with analysis results
    configs = [
        ("Phishing", 90.0, 0),
        ("Phishing", 90.0, 1),
        ("Suspicious", 65.0, 2),
        ("BEC", 40.0, 3),
        ("Legitimate", 15.0, 4),
    ]

    for label, score, days_ago in configs:
        eid = uuid4()
        ingested = now_utc - timedelta(days=days_ago)
        email = Email(
            id=eid,
            sender=f"test{days_ago}@domain.com",
            subject=f"Subject {days_ago}",
            status=EmailStatus.analyzed,
            ingested_at=ingested,
        )
        analysis = AnalysisResult(
            id=uuid4(),
            email_id=eid,
            nlp_label=label,
            composite_risk_score=score,
        )
        db.emails.append(email)
        db.analyses.append(analysis)

    # Seed 3 Cases (1 open, 1 investigating, 1 closed)
    db.cases.append(Case(id=uuid4(), title="Case Open", status=CaseStatus.open, severity=CaseSeverity.high))
    db.cases.append(Case(id=uuid4(), title="Case Investigating", status=CaseStatus.investigating, severity=CaseSeverity.critical))
    db.cases.append(Case(id=uuid4(), title="Case Closed", status=CaseStatus.closed, severity=CaseSeverity.low))

    # Seed 4 Alerts (3 unacknowledged, 1 acknowledged)
    db.alerts.append(Alert(id=uuid4(), email_id=uuid4(), risk_score=95.0, severity=AlertSeverity.critical, message="A1", acknowledged=False))
    db.alerts.append(Alert(id=uuid4(), email_id=uuid4(), risk_score=80.0, severity=AlertSeverity.high, message="A2", acknowledged=False))
    db.alerts.append(Alert(id=uuid4(), email_id=uuid4(), risk_score=92.0, severity=AlertSeverity.critical, message="A3", acknowledged=False))
    db.alerts.append(Alert(id=uuid4(), email_id=uuid4(), risk_score=85.0, severity=AlertSeverity.high, message="A4", acknowledged=True))

    return db


def test_dashboard_stats_endpoint(seeded_dashboard_db):
    """Test /api/dashboard/stats returns real aggregated database metrics."""
    db = seeded_dashboard_db

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200
    data = response.json()

    # 1. Total emails
    assert data["total_emails"] == 5

    # 2. Active cases (open + investigating)
    assert data["active_cases"] == 2

    # 3. Threats detected (>50 risk score: 90, 90, 65)
    assert data["threats_detected"] == 3

    # 4. Average risk score ((90 + 90 + 65 + 40 + 15) / 5 = 60.0)
    assert data["avg_risk_score"] == 60.0

    # 5. Unacknowledged alerts
    assert data["unacknowledged_alerts"] == 3

    # 6. Threat distribution by label (strictly normalized canonical categories)
    assert data["threat_distribution"] == {
        "PHISHING": 2,
        "SUSPICIOUS": 1,
        "BEC_FRAUD": 1,
        "LEGITIMATE": 1,
    }

    # 7. Risk distribution (low: 1, medium: 1, high: 1, critical: 2)
    assert data["risk_distribution"] == {
        "low": 1,
        "medium": 1,
        "high": 1,
        "critical": 2,
    }

    # 8. Ingestion timeline: 7 days contiguous array
    assert len(data["ingestion_timeline"]) == 7
    total_timeline_ingested = sum(item["ingested"] for item in data["ingestion_timeline"])
    assert total_timeline_ingested == 5

    total_timeline_threats = sum(item["threats"] for item in data["ingestion_timeline"])
    assert total_timeline_threats == 3

    app.dependency_overrides.clear()
