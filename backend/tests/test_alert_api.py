import pytest
from datetime import datetime, timezone
from uuid import UUID, uuid4
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db
from app.models.alert import Alert, AlertSeverity


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


class MockApiDbSession:
    def __init__(self):
        self.alerts: list[Alert] = []

    def add(self, obj):
        if isinstance(obj, Alert):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.alerts.append(obj)

    async def commit(self):
        pass

    async def refresh(self, obj):
        pass

    async def execute(self, stmt):
        stmt_str = str(stmt).lower()

        # 1. Stats queries
        if "count(alerts.id)" in stmt_str and "acknowledged = false" in stmt_str:
            unack = sum(1 for a in self.alerts if not a.acknowledged)
            return FakeScalarResult(unack)
        if "count(alerts.id)" in stmt_str and ("critical" in stmt_str or "severity = :severity_1" in stmt_str):
            crit = sum(1 for a in self.alerts if str(a.severity).lower() in ("critical", "alertseverity.critical"))
            return FakeScalarResult(crit)
        if "count(alerts.id)" in stmt_str:
            return FakeScalarResult(len(self.alerts))

        # 2. Lookup single Alert by ID
        if "from alerts" in stmt_str and "alerts.id =" in stmt_str:
            for a in self.alerts:
                if str(a.id) in stmt_str:
                    return FakeScalarResult([a])
            if self.alerts:
                return FakeScalarResult([self.alerts[0]])
            return FakeScalarResult([])

        # 3. List alerts
        if "from alerts" in stmt_str:
            filtered = list(self.alerts)
            limit_val = getattr(stmt, "_limit", None)
            offset_val = getattr(stmt, "_offset", None) or 0

            sorted_items = sorted(filtered, key=lambda x: (x.created_at, str(x.id)), reverse=True)
            if offset_val:
                sorted_items = sorted_items[offset_val:]
            if limit_val is not None:
                sorted_items = sorted_items[:limit_val]

            return FakeScalarResult(sorted_items)

        return FakeScalarResult(None)


@pytest.fixture
def mock_db():
    return MockApiDbSession()


def test_get_alert_stats(mock_db):
    """Verify GET /api/alerts/stats returns total, unacknowledged, and critical counts."""
    a1 = Alert(id=uuid4(), severity=AlertSeverity.critical, message="Phish 1", risk_score=92.0, acknowledged=False, created_at=datetime.now(timezone.utc).replace(tzinfo=None))
    a2 = Alert(id=uuid4(), severity=AlertSeverity.high, message="Phish 2", risk_score=80.0, acknowledged=True, created_at=datetime.now(timezone.utc).replace(tzinfo=None))
    mock_db.alerts.extend([a1, a2])

    async def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    res = client.get("/api/alerts/stats")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 2
    assert data["unacknowledged"] == 1
    assert data["critical"] == 1

    app.dependency_overrides.clear()


def test_list_alerts_endpoint(mock_db):
    """Verify GET /api/alerts returns paginated alert items and total count."""
    for i in range(5):
        mock_db.alerts.append(
            Alert(
                id=uuid4(),
                severity=AlertSeverity.high if i % 2 == 0 else AlertSeverity.critical,
                message=f"Threat alert {i}",
                risk_score=75.0 + i * 5,
                acknowledged=False,
                created_at=datetime.now(timezone.utc).replace(tzinfo=None),
            )
        )

    async def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    res = client.get("/api/alerts/?page=1&page_size=3")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 5
    assert len(data["items"]) == 3
    assert data["items"][0]["message"] is not None

    app.dependency_overrides.clear()


def test_acknowledge_alert_endpoint(mock_db):
    """Verify PUT /api/alerts/{id}/acknowledge marks acknowledged=True."""
    target_id = uuid4()
    alert = Alert(
        id=target_id,
        severity=AlertSeverity.high,
        message="Suspicious email",
        risk_score=80.0,
        acknowledged=False,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    mock_db.alerts.append(alert)

    async def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    res = client.put(f"/api/alerts/{target_id}/acknowledge")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "acknowledged"
    assert data["acknowledged"] is True
    assert alert.acknowledged is True

    app.dependency_overrides.clear()


def test_acknowledge_nonexistent_alert():
    """Verify PUT /api/alerts/{id}/acknowledge returns 404 for missing alert."""
    empty_db = MockApiDbSession()

    async def override_get_db():
        yield empty_db

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    missing_id = uuid4()
    res = client.put(f"/api/alerts/{missing_id}/acknowledge")
    assert res.status_code == 404
    assert "Alert not found" in res.json()["detail"]

    app.dependency_overrides.clear()
