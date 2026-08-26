import json
import pytest
from datetime import datetime, timezone
from uuid import UUID, uuid4

from app.core.reporting.alert_engine import AlertEngine, AlertConfig, AlertTrigger
from app.models.alert import Alert, AlertSeverity


class MockAlertDbSession:
    """In-memory DB session for AlertEngine testing."""

    def __init__(self):
        self.alerts: list[Alert] = []

    def add(self, obj):
        if not getattr(obj, "id", None):
            obj.id = uuid4()
        self.alerts.append(obj)

    async def commit(self):
        pass

    async def refresh(self, obj):
        pass


class MockRedis:
    """In-memory mock Redis for Pub/Sub and rate limit testing."""

    def __init__(self):
        self.published: list[tuple[str, str]] = []
        self.counts: dict[str, int] = {}
        self.closed = False

    async def ping(self):
        return True

    async def get(self, key):
        return self.counts.get(key, 0)

    async def publish(self, channel, message):
        self.published.append((channel, message))

    def pipeline(self):
        class MockPipe:
            def __init__(self, parent):
                self.parent = parent

            def incr(self, key):
                self.parent.counts[key] = int(self.parent.counts.get(key, 0)) + 1

            def expire(self, key, ttl):
                pass

            async def execute(self):
                return [1, True]

        return MockPipe(self)

    async def close(self):
        self.closed = True


@pytest.fixture
def mock_redis():
    return MockRedis()


@pytest.fixture
def sample_risk_breakdown():
    return {
        "severity": "critical",
        "recommended_action": "Block & Investigate — high-confidence threat detection",
        "factors": [
            {"name": "NLP Threat Classification", "raw_score": 95.0, "severity": "critical"},
            {"name": "Authentication Verification", "raw_score": 90.0, "severity": "critical"},
            {"name": "IP Reputation", "raw_score": 85.0, "severity": "high"},
            {"name": "Link Risk", "raw_score": 60.0, "severity": "medium"},
            {"name": "Attachment Risk", "raw_score": 30.0, "severity": "low"},
        ],
    }


@pytest.fixture
def sample_iocs():
    return [
        {"type": "URL", "value": "http://evil1.com", "risk_score": 95},
        {"type": "IP", "value": "198.51.100.1", "risk_score": 85},
        {"type": "Domain", "value": "micros0ft.com", "risk_score": 90},
        {"type": "Hash", "value": "a" * 64, "risk_score": 75},
        {"type": "URL", "value": "http://evil2.com", "risk_score": 70},
        {"type": "IP", "value": "198.51.100.2", "risk_score": 40},
        {"type": "URL", "value": "http://low.com", "risk_score": 10},
    ]


@pytest.mark.asyncio
async def test_high_threshold_alert(sample_risk_breakdown, sample_iocs, mock_redis):
    """Verify risk scores 75-89.99 trigger a HIGH severity alert."""
    db = MockAlertDbSession()
    engine = AlertEngine()
    engine._redis = mock_redis

    eid = uuid4()
    alert = await engine.evaluate(
        email_id=eid,
        risk_score=82.0,
        risk_breakdown=sample_risk_breakdown,
        iocs=sample_iocs,
        nlp_label="Phishing",
        db=db,
    )

    assert alert is not None
    assert alert.severity in (AlertSeverity.high, "high")
    assert alert.risk_score == 82.0
    assert alert.acknowledged is False
    assert "🟠" in alert.contributing_factors["title"]
    assert len(db.alerts) == 1
    assert len(mock_redis.published) == 1
    assert mock_redis.published[0][0] == "alerts:realtime"


@pytest.mark.asyncio
async def test_critical_threshold_alert(sample_risk_breakdown, sample_iocs, mock_redis):
    """Verify risk scores >= 90 trigger a CRITICAL severity alert."""
    db = MockAlertDbSession()
    engine = AlertEngine()
    engine._redis = mock_redis

    eid = uuid4()
    alert = await engine.evaluate(
        email_id=eid,
        risk_score=94.5,
        risk_breakdown=sample_risk_breakdown,
        iocs=sample_iocs,
        nlp_label="BEC/Fraud",
        db=db,
    )

    assert alert is not None
    assert alert.severity in (AlertSeverity.critical, "critical")
    assert alert.risk_score == 94.5
    assert "🔴" in alert.contributing_factors["title"]
    assert "Business Email Compromise" in alert.contributing_factors["title"]


@pytest.mark.asyncio
async def test_below_threshold_no_alert(sample_risk_breakdown, sample_iocs, mock_redis):
    """Verify risk scores < 75 do NOT generate an alert."""
    db = MockAlertDbSession()
    engine = AlertEngine()
    engine._redis = mock_redis

    alert = await engine.evaluate(
        email_id=uuid4(),
        risk_score=74.9,
        risk_breakdown=sample_risk_breakdown,
        iocs=sample_iocs,
        nlp_label="Suspicious",
        db=db,
    )

    assert alert is None
    assert len(db.alerts) == 0
    assert len(mock_redis.published) == 0


@pytest.mark.asyncio
async def test_disabled_engine_no_alert(sample_risk_breakdown, sample_iocs, mock_redis):
    """Verify disabled AlertEngine suppresses all alerts regardless of risk score."""
    db = MockAlertDbSession()
    config = AlertConfig(enabled=False)
    engine = AlertEngine(config=config)
    engine._redis = mock_redis

    alert = await engine.evaluate(
        email_id=uuid4(),
        risk_score=99.0,
        risk_breakdown=sample_risk_breakdown,
        iocs=sample_iocs,
        nlp_label="Phishing",
        db=db,
    )

    assert alert is None
    assert len(db.alerts) == 0


@pytest.mark.asyncio
async def test_rate_limiting_suppression(sample_risk_breakdown, sample_iocs, mock_redis):
    """Verify alert rate limit of 100/hour suppresses subsequent alerts."""
    db = MockAlertDbSession()
    config = AlertConfig(max_alerts_per_hour=3)
    engine = AlertEngine(config=config)
    engine._redis = mock_redis

    # Trigger 3 allowed alerts
    for i in range(3):
        a = await engine.evaluate(
            email_id=uuid4(),
            risk_score=95.0,
            risk_breakdown=sample_risk_breakdown,
            iocs=sample_iocs,
            nlp_label="Phishing",
            db=db,
        )
        assert a is not None

    assert len(db.alerts) == 3

    # 4th alert exceeds rate limit
    suppressed = await engine.evaluate(
        email_id=uuid4(),
        risk_score=95.0,
        risk_breakdown=sample_risk_breakdown,
        iocs=sample_iocs,
        nlp_label="Phishing",
        db=db,
    )
    assert suppressed is None
    assert len(db.alerts) == 3


def test_title_generation():
    """Verify title generation for various threat classifications and severities."""
    engine = AlertEngine()

    assert "🔴 Phishing Email Detected" in engine._build_title("Phishing", "critical", 95)
    assert "🟠 Phishing Email Detected" in engine._build_title("Phishing", "high", 80)
    assert "🔴 Business Email Compromise Attempt" in engine._build_title("BEC/Fraud", "critical", 92)
    assert "🟠 Impersonation Attack Detected" in engine._build_title("Impersonation", "high", 78)
    assert "🟠 Suspicious Email Flagged" in engine._build_title("Suspicious", "high", 76)
    assert "🔴 Threat Detected" in engine._build_title("CustomMalware", "critical", 99)


def test_message_generation(sample_risk_breakdown):
    """Verify detailed message format with top 3 factors and recommended action."""
    engine = AlertEngine()
    msg = engine._build_message("Phishing", sample_risk_breakdown)

    assert "Classification: Phishing" in msg
    assert "NLP Threat Classification: 95/100 (critical)" in msg
    assert "Authentication Verification: 90/100 (critical)" in msg
    assert "IP Reputation: 85/100 (high)" in msg
    # 4th and 5th factors should not be in the top 3
    assert "Attachment Risk" not in msg
    assert "Action: Block & Investigate" in msg


@pytest.mark.asyncio
async def test_top_5_ioc_selection(sample_risk_breakdown, sample_iocs, mock_redis):
    """Verify only top 5 IOCs sorted by risk score are selected into alert payload."""
    db = MockAlertDbSession()
    engine = AlertEngine()
    engine._redis = mock_redis

    alert = await engine.evaluate(
        email_id=uuid4(),
        risk_score=95.0,
        risk_breakdown=sample_risk_breakdown,
        iocs=sample_iocs,
        nlp_label="Phishing",
        db=db,
    )

    iocs_in_alert = alert.contributing_factors["ioc_summary"]
    assert len(iocs_in_alert) == 5
    assert iocs_in_alert[0]["risk_score"] == 95  # http://evil1.com
    assert iocs_in_alert[1]["risk_score"] == 90  # micros0ft.com
    assert iocs_in_alert[2]["risk_score"] == 85  # 198.51.100.1
    assert iocs_in_alert[3]["risk_score"] == 75  # Hash
    assert iocs_in_alert[4]["risk_score"] == 70  # http://evil2.com


@pytest.mark.asyncio
async def test_redis_publish_payload_format(sample_risk_breakdown, sample_iocs, mock_redis):
    """Verify published JSON payload contains all required alert fields."""
    db = MockAlertDbSession()
    engine = AlertEngine()
    engine._redis = mock_redis

    eid = uuid4()
    await engine.evaluate(
        email_id=eid,
        risk_score=95.0,
        risk_breakdown=sample_risk_breakdown,
        iocs=sample_iocs,
        nlp_label="Phishing",
        db=db,
    )

    assert len(mock_redis.published) == 1
    channel, message_str = mock_redis.published[0]
    assert channel == "alerts:realtime"

    payload = json.loads(message_str)
    assert payload["email_id"] == str(eid)
    assert payload["severity"] == "critical"
    assert payload["risk_score"] == 95.0
    assert payload["acknowledged"] is False
    assert "title" in payload["contributing_factors"]
    assert "factors" in payload["contributing_factors"]
    assert "ioc_summary" in payload["contributing_factors"]
