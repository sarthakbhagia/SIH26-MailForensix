import io
import json
import pytest
from datetime import datetime, timezone, timedelta
from uuid import UUID, uuid4
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db
from app.core.pipeline import AnalysisPipeline
from app.core.reporting.alert_engine import AlertEngine, AlertConfig
from app.core.reporting.report_generator import ReportGenerator
from app.services.case_service import CaseService
from app.services.audit_service import AuditService, GENESIS_HASH
from app.models.email_case import Email, EmailStatus, Case, CaseEmail, CaseNote, CaseStatus, CaseSeverity
from app.models.analysis_result import AnalysisResult
from app.models.alert import Alert, AlertSeverity
from app.models.audit_log import AuditLog
from app.schemas.case import CaseCreate, CaseUpdate, CaseNoteCreate
from app.core.analysis.header_forensics import HeaderForensicsResult, SPFResult, DKIMResult, DMARCResult, RelayHop
from app.core.analysis.geo_intel import GeoIntelResult, IPGeoResult, DomainIntelResult
from app.core.analysis.nlp_classifier import NLPClassificationResult
from app.core.analysis.link_analyzer import LinkAnalysisResult
from app.core.analysis.attachment_analyzer import AttachmentAnalysisReport


class FakeScalarResult:
    def __init__(self, item):
        self._item = item

    def scalar_one_or_none(self):
        if isinstance(self._item, list):
            return self._item[0] if self._item else None
        return self._item

    def scalar(self):
        if isinstance(self._item, list):
            return self._item[0] if self._item else None
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

    def scalars(self):
        class ScalarIter:
            def __init__(self, items):
                if items is None:
                    self._items = []
                elif isinstance(items, list):
                    self._items = items
                else:
                    self._items = [items]

            def all(self):
                return list(self._items)

            def first(self):
                return self._items[0] if self._items else None

        return ScalarIter(self._item)


class MockE2EDbSession:
    """Unified in-memory database session supporting all Phase 1-4 models and queries."""

    def __init__(self):
        self.emails: dict[UUID, Email] = {}
        self.analyses: dict[UUID, AnalysisResult] = {}
        self.cases: dict[UUID, Case] = {}
        self.case_emails: list[CaseEmail] = []
        self.case_notes: list[CaseNote] = []
        self.alerts: list[Alert] = []
        self.audit_logs: list[AuditLog] = []

    def add(self, obj):
        if isinstance(obj, Email):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.emails[obj.id] = obj
        elif isinstance(obj, AnalysisResult):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.analyses[obj.email_id] = obj
        elif isinstance(obj, Case):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.cases[obj.id] = obj
        elif isinstance(obj, CaseEmail):
            if not any(ce.case_id == obj.case_id and ce.email_id == obj.email_id for ce in self.case_emails):
                self.case_emails.append(obj)
        elif isinstance(obj, CaseNote):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.case_notes.append(obj)
        elif isinstance(obj, Alert):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.alerts.append(obj)
        elif isinstance(obj, AuditLog):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.audit_logs.append(obj)

    async def commit(self):
        pass

    async def refresh(self, obj):
        if not getattr(obj, "id", None):
            obj.id = uuid4()

    async def delete(self, obj):
        if isinstance(obj, Case) and obj.id in self.cases:
            del self.cases[obj.id]
        elif isinstance(obj, CaseEmail) and obj in self.case_emails:
            self.case_emails.remove(obj)
        elif isinstance(obj, CaseNote) and obj in self.case_notes:
            self.case_notes.remove(obj)

    async def execute(self, stmt):
        stmt_str = str(stmt).lower()

        # 0. Dashboard timeline query (Email outerjoin AnalysisResult)
        if "outerjoin" in stmt_str or "emails.ingested_at >=" in stmt_str:
            rows = []
            for e in self.emails.values():
                score = self.analyses[e.id].composite_risk_score if e.id in self.analyses else None
                rows.append((e.ingested_at, score))
            return FakeScalarResult(rows)

        # 1. AuditLog queries
        if "from audit_logs" in stmt_str:
            if "order by audit_logs.timestamp asc" in stmt_str or "order by audit_logs.timestamp," in stmt_str:
                sorted_logs = sorted(self.audit_logs, key=lambda x: (x.timestamp, str(x.id)))
                return FakeScalarResult(sorted_logs)
            # Latest log (descending)
            if self.audit_logs:
                sorted_logs = sorted(self.audit_logs, key=lambda x: (x.timestamp, str(x.id)), reverse=True)
                return FakeScalarResult(sorted_logs[0])
            return FakeScalarResult(None)

        # 2. Email queries
        if "from emails" in stmt_str:
            if "join case_emails" in stmt_str:
                target_id = self._extract_id(stmt)
                linked_eids = [ce.email_id for ce in self.case_emails if ce.case_id == target_id]
                linked = [self.emails[eid] for eid in linked_eids if eid in self.emails]
                return FakeScalarResult(linked)
            if "emails.id =" in stmt_str or "where emails.id" in stmt_str:
                target_id = self._extract_id(stmt)
                if target_id and target_id in self.emails:
                    return FakeScalarResult(self.emails[target_id])
                for eid, email in self.emails.items():
                    if str(eid) in stmt_str:
                        return FakeScalarResult(email)
                return FakeScalarResult(None)
            if "count(emails.id)" in stmt_str:
                return FakeScalarResult(len(self.emails))
            return FakeScalarResult(list(self.emails.values()))

        # 3. AnalysisResult queries
        if "from analysis_results" in stmt_str:
            if "count(analysis_results.id)" in stmt_str and "where analysis_results.composite_risk_score >" in stmt_str:
                threats_count = sum(1 for a in self.analyses.values() if a.composite_risk_score is not None and a.composite_risk_score > 50.0)
                return FakeScalarResult(threats_count)
            if "avg(analysis_results.composite_risk_score)" in stmt_str:
                scores = [a.composite_risk_score for a in self.analyses.values() if a.composite_risk_score is not None]
                return FakeScalarResult(sum(scores) / len(scores) if scores else 0.0)
            if "group by analysis_results.nlp_label" in stmt_str:
                dist = {}
                for a in self.analyses.values():
                    lbl = a.nlp_label or "Unclassified"
                    dist[lbl] = dist.get(lbl, 0) + 1
                return FakeScalarResult(list(dist.items()))
            if "case" in stmt_str and "when" in stmt_str:
                low = sum(1 for a in self.analyses.values() if a.composite_risk_score is not None and a.composite_risk_score <= 25.0)
                med = sum(1 for a in self.analyses.values() if a.composite_risk_score is not None and 25.0 < a.composite_risk_score <= 50.0)
                high = sum(1 for a in self.analyses.values() if a.composite_risk_score is not None and 50.0 < a.composite_risk_score <= 75.0)
                crit = sum(1 for a in self.analyses.values() if a.composite_risk_score is not None and a.composite_risk_score > 75.0)
                return FakeScalarResult((low, med, high, crit))
            if "analysis_results.email_id =" in stmt_str or "where analysis_results.email_id" in stmt_str:
                target_id = self._extract_id(stmt)
                if target_id and target_id in self.analyses:
                    return FakeScalarResult(self.analyses[target_id])
                for eid, analysis in self.analyses.items():
                    if str(eid) in stmt_str:
                        return FakeScalarResult(analysis)
                return FakeScalarResult(None)
            return FakeScalarResult(list(self.analyses.values()))

        # 4. Case queries
        if "from cases" in stmt_str:
            if "count(cases.id)" in stmt_str:
                active_count = sum(1 for c in self.cases.values() if str(c.status).lower() in ("open", "investigating", "casestatus.open", "casestatus.investigating"))
                return FakeScalarResult(active_count)
            if "cases.id =" in stmt_str or "where cases.id" in stmt_str:
                target_id = self._extract_id(stmt)
                return FakeScalarResult(self.cases.get(target_id))
            return FakeScalarResult(list(self.cases.values()))

        # 5. CaseEmail queries
        if "from case_emails" in stmt_str:
            ids = self._extract_ids(stmt)
            if len(ids) >= 2:
                cid, eid = ids[0], ids[1]
                matched = next((ce for ce in self.case_emails if (ce.case_id == cid and ce.email_id == eid) or (ce.case_id == eid and ce.email_id == cid)), None)
                return FakeScalarResult(matched)
            elif len(ids) == 1:
                target_id = ids[0]
                matched = next((ce for ce in self.case_emails if ce.case_id == target_id or ce.email_id == target_id), None)
                return FakeScalarResult(matched)
            return FakeScalarResult(None)

        # 6. CaseNote queries
        if "from case_notes" in stmt_str:
            target_id = self._extract_id(stmt)
            notes = [n for n in self.case_notes if n.case_id == target_id]
            sorted_notes = sorted(notes, key=lambda x: x.created_at)
            return FakeScalarResult(sorted_notes)

        # 7. Alert queries
        if "from alerts" in stmt_str:
            if "count(alerts.id)" in stmt_str and "acknowledged = false" in stmt_str:
                unack = sum(1 for al in self.alerts if not al.acknowledged)
                return FakeScalarResult(unack)
            if "count(alerts.id)" in stmt_str and "critical" in stmt_str:
                crit = sum(1 for al in self.alerts if str(al.severity).lower() in ("critical", "alertseverity.critical"))
                return FakeScalarResult(crit)
            if "count(alerts.id)" in stmt_str:
                return FakeScalarResult(len(self.alerts))
            if "alerts.id =" in stmt_str:
                target_id = self._extract_id(stmt)
                matched = next((al for al in self.alerts if al.id == target_id or str(al.id) in stmt_str), None)
                return FakeScalarResult(matched)
            return FakeScalarResult(list(self.alerts))

        # 8. Dashboard timeline query
        if "emails.ingested_at >=" in stmt_str or "outerjoin" in stmt_str:
            rows = []
            for e in self.emails.values():
                score = self.analyses[e.id].composite_risk_score if e.id in self.analyses else None
                rows.append((e.ingested_at, score))
            return FakeScalarResult(rows)

        return FakeScalarResult([])

    def _extract_ids(self, stmt):
        ids = []
        for criterion in getattr(stmt, "_where_criteria", []):
            if hasattr(criterion, "right") and hasattr(criterion.right, "value"):
                val = criterion.right.value
                if isinstance(val, (UUID, str)):
                    try:
                        ids.append(UUID(str(val)))
                    except ValueError:
                        ids.append(val)
            elif hasattr(criterion, "value"):
                val = criterion.value
                if isinstance(val, (UUID, str)):
                    try:
                        ids.append(UUID(str(val)))
                    except ValueError:
                        ids.append(val)
        return ids

    def _extract_id(self, stmt):
        ids = self._extract_ids(stmt)
        return ids[0] if ids else None


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

    async def aclose(self):
        self.closed = True


# ==============================================================================
# SECTION 1: ALERTS TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_e2e_alerts_workflow():
    """Verify high-risk alert trigger, low-risk suppression, acknowledgement, and rate limiting."""
    db = MockE2EDbSession()
    engine = AlertEngine()

    sample_breakdown = {
        "severity": "critical",
        "recommended_action": "Quarantine & Block",
        "factors": [
            {"name": "NLP Threat Classification", "raw_score": 95.0, "severity": "critical"},
            {"name": "Authentication Verification", "raw_score": 90.0, "severity": "critical"},
        ],
    }

    # 1. High-risk email triggers alert
    phish_id = uuid4()
    alert = await engine.evaluate(
        email_id=phish_id,
        risk_score=92.0,
        risk_breakdown=sample_breakdown,
        iocs=[{"type": "URL", "value": "http://bad.com", "risk_score": 90}],
        nlp_label="Phishing",
        db=db,
    )
    assert alert is not None
    assert alert.severity in (AlertSeverity.critical, "critical")
    assert alert.risk_score == 92.0
    assert alert.acknowledged is False
    assert len(db.alerts) == 1

    # 2. Low-risk email does not trigger alert
    legit_id = uuid4()
    no_alert = await engine.evaluate(
        email_id=legit_id,
        risk_score=20.0,
        risk_breakdown={"severity": "low", "recommended_action": "None", "factors": []},
        iocs=[],
        nlp_label="Legitimate",
        db=db,
    )
    assert no_alert is None
    assert len(db.alerts) == 1

    # 3. Acknowledgement works via API
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    ack_res = client.put(f"/api/alerts/{alert.id}/acknowledge")
    assert ack_res.status_code == 200
    assert ack_res.json()["acknowledged"] is True
    assert alert.acknowledged is True

    # 4. Rate limiting works
    mock_redis = MockRedis()
    rate_limited_engine = AlertEngine(config=AlertConfig(max_alerts_per_hour=2))
    rate_limited_engine._redis = mock_redis
    for _ in range(2):
        a = await rate_limited_engine.evaluate(
            email_id=uuid4(),
            risk_score=85.0,
            risk_breakdown=sample_breakdown,
            iocs=[],
            nlp_label="Phishing",
            db=db,
        )
        assert a is not None

    suppressed = await rate_limited_engine.evaluate(
        email_id=uuid4(),
        risk_score=85.0,
        risk_breakdown=sample_breakdown,
        iocs=[],
        nlp_label="Phishing",
        db=db,
    )
    assert suppressed is None

    app.dependency_overrides.clear()


# ==============================================================================
# SECTION 2: REPORTS TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_e2e_reports_workflow():
    """Verify forensic PDF generation, structured JSON generation, and 404 on nonexistent email."""
    db = MockE2EDbSession()
    generator = ReportGenerator()
    eid = uuid4()

    email = Email(
        id=eid,
        sender="attacker@spoofed.com",
        recipients=["victim@target.com"],
        subject="Action Required: Password Expiry",
        raw_hash_sha256="a" * 64,
        raw_hash_sha1="a" * 40,
        raw_hash_md5="a" * 32,
        headers={"Message-ID": "<msg123@spoofed.com>"},
        status=EmailStatus.analyzed,
        ingested_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    analysis = AnalysisResult(
        id=uuid4(),
        email_id=eid,
        composite_risk_score=88.0,
        nlp_label="Phishing",
        nlp_confidence=96.0,
        auth_status={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        risk_breakdown={"overall_score": 88.0, "severity": "high", "recommended_action": "Quarantine", "factors": []},
        iocs=[{"type": "URL", "value": "http://spoofed.com/login", "risk_score": 90}],
        relay_path=[{"ip": "198.51.100.1"}],
        geo_data=[{"ip": "198.51.100.1", "country": "RU"}],
    )
    db.add(email)
    db.add(analysis)

    # 1. JSON report generation
    json_report = await generator.generate_json(email_id=eid, db=db)
    assert json_report["report_id"] is not None
    assert json_report["threat_assessment"]["overall_risk_score"] == 88.0
    assert json_report["nlp_classification"]["label"] == "Phishing"
    assert json_report["email_metadata"]["hashes"]["sha256"] == "a" * 64

    # 2. PDF report generation
    pdf_bytes = await generator.generate_pdf(email_id=eid, db=db)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF-")

    # 3. Nonexistent email returns 404 via API
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    missing_id = uuid4()
    res_404 = client.get(f"/api/reports/emails/{missing_id}/json")
    assert res_404.status_code == 404

    app.dependency_overrides.clear()


# ==============================================================================
# SECTION 3: CASES TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_e2e_cases_workflow():
    """Verify Case CRUD, evidence linking/unlinking, notes, and chronological timeline."""
    db = MockE2EDbSession()
    service = CaseService()
    eid = uuid4()
    email = Email(id=eid, sender="bad@lure.com", subject="Wire Request", status=EmailStatus.analyzed)
    db.add(email)

    # 1. Create Case
    case = await service.create_case(
        db,
        CaseCreate(title="Operation Spear", description="C-level phishing lure", severity=CaseSeverity.critical),
        user_id="lead_analyst",
    )
    assert case.id is not None
    assert case.title == "Operation Spear"
    assert case.status == CaseStatus.open

    # 2. Read Case
    fetched = await service.get_case(db, case.id)
    assert fetched.id == case.id

    # 3. Update Case
    updated = await service.update_case(
        db,
        case.id,
        CaseUpdate(status=CaseStatus.investigating, assigned_to="senior_soc"),
        user_id="lead_analyst",
    )
    assert updated.status == CaseStatus.investigating
    assert updated.assigned_to == "senior_soc"

    # 4. Link Email
    link = await service.add_email_to_case(db, case.id, eid, user_id="senior_soc")
    assert link.email_id == eid
    linked_emails = await service.get_case_emails(db, case.id)
    assert len(linked_emails) == 1

    # 5. Add Note
    note = await service.add_note(
        db,
        case.id,
        CaseNoteCreate(content="Verified bulletproof hosting ASN", author="senior_soc"),
        user_id="senior_soc",
    )
    assert note.content == "Verified bulletproof hosting ASN"
    notes = await service.get_case_notes(db, case.id)
    assert len(notes) == 1

    # 6. Timeline Aggregation
    timeline = await service.get_case_timeline(db, case.id)
    assert len(timeline) >= 3
    types = [item["type"] for item in timeline]
    assert "case_created" in types
    assert "email_linked" in types
    assert "note_added" in types

    # 7. Unlink Email
    await service.remove_email_from_case(db, case.id, eid, user_id="senior_soc")
    assert len(await service.get_case_emails(db, case.id)) == 0

    # 8. Delete Case
    await service.delete_case(db, case.id, user_id="lead_analyst")
    assert case.id not in db.cases


# ==============================================================================
# SECTION 4: AUDIT TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_e2e_audit_workflow():
    """Verify unbroken cryptographic SHA-256 hash chaining and tamper detection."""
    db = MockE2EDbSession()
    service = AuditService()

    # Create sequence of entries
    e1 = await service.log_action(action="ingest", action_data={"batch": 1}, user_id="sys", db=db)
    e2 = await service.log_action(action="analyze", action_data={"risk": 90}, user_id="sys", db=db)
    e3 = await service.log_action(action="alert", action_data={"severity": "crit"}, user_id="sys", db=db)

    assert e1.previous_hash == GENESIS_HASH
    assert e2.previous_hash == e1.entry_hash
    assert e3.previous_hash == e2.entry_hash

    # Valid chain verification
    v1 = await service.verify_chain(db)
    assert v1["valid"] is True
    assert v1["entries_checked"] == 3

    # Tamper detection
    e2.action_data = {"risk": 0}  # Attacker alters payload
    v2 = await service.verify_chain(db)
    assert v2["valid"] is False
    assert v2["broken_at_index"] == 1


# ==============================================================================
# SECTION 5: COMPLETE 12-STEP END-TO-END ANALYST WORKFLOW
# ==============================================================================

@pytest.mark.asyncio
async def test_complete_analyst_e2e_workflow():
    """
    Execute complete end-to-end analyst workflow:
    1. Upload 3 phishing emails + 1 legitimate email.
    2. Verify all are analyzed.
    3. Verify risk scores exist.
    4. Verify 3 phishing emails create alerts.
    5. Verify legitimate email creates no alert.
    6. Create investigation case.
    7. Link the 3 phishing emails.
    8. Add analyst note.
    9. Verify timeline.
    10. Generate forensic PDF.
    11. Verify audit trail contains the expected actions.
    12. Verify dashboard statistics reflect the workflow.
    """
    db = MockE2EDbSession()
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

    # --------------------------------------------------------------------------
    # Step 1: Upload 3 phishing emails + 1 legitimate email
    # --------------------------------------------------------------------------
    p1_id = uuid4()
    p2_id = uuid4()
    p3_id = uuid4()
    legit_id = uuid4()

    phish1 = Email(
        id=p1_id,
        sender="spoof@bank-verify.com",
        recipients=["cfo@target.com"],
        subject="URGENT: Verify Wire Transfer Access",
        body_text="Please verify your wire transfer credentials immediately.",
        headers={"from": "spoof@bank-verify.com", "to": "cfo@target.com", "received_hops": []},
        raw_eml=b"From: spoof@bank-verify.com\nSubject: Wire\n\nBody",
        status=EmailStatus.pending,
        raw_hash_sha256="1" * 64,
        raw_hash_sha1="1" * 40,
        raw_hash_md5="1" * 32,
        ingested_at=now_utc - timedelta(days=2),
    )
    phish2 = Email(
        id=p2_id,
        sender="attacker@fake-msft.com",
        recipients=["it@target.com"],
        subject="Security Notice: Password Reset Required",
        body_text="Your password has expired. Click here to reset.",
        headers={"from": "attacker@fake-msft.com", "to": "it@target.com", "received_hops": []},
        raw_eml=b"From: attacker@fake-msft.com\nSubject: Reset\n\nBody",
        status=EmailStatus.pending,
        raw_hash_sha256="2" * 64,
        raw_hash_sha1="2" * 40,
        raw_hash_md5="2" * 32,
        ingested_at=now_utc - timedelta(days=1),
    )
    phish3 = Email(
        id=p3_id,
        sender="payroll@hacked-partner.com",
        recipients=["hr@target.com"],
        subject="Updated Direct Deposit Instructions",
        body_text="Here are the new bank account details for payroll.",
        headers={"from": "payroll@hacked-partner.com", "to": "hr@target.com", "received_hops": []},
        raw_eml=b"From: payroll@hacked-partner.com\nSubject: Payroll\n\nBody",
        status=EmailStatus.pending,
        raw_hash_sha256="3" * 64,
        raw_hash_sha1="3" * 40,
        raw_hash_md5="3" * 32,
        ingested_at=now_utc,
    )
    legit = Email(
        id=legit_id,
        sender="newsletter@verified-tech.com",
        recipients=["team@target.com"],
        subject="Weekly Engineering Digest #42",
        body_text="Here is our weekly team engineering newsletter and updates.",
        headers={"from": "newsletter@verified-tech.com", "to": "team@target.com", "received_hops": []},
        raw_eml=b"From: newsletter@verified-tech.com\nSubject: Newsletter\n\nBody",
        status=EmailStatus.pending,
        raw_hash_sha256="4" * 64,
        raw_hash_sha1="4" * 40,
        raw_hash_md5="4" * 32,
        ingested_at=now_utc,
    )

    db.add(phish1)
    db.add(phish2)
    db.add(phish3)
    db.add(legit)

    # --------------------------------------------------------------------------
    # Step 2 & 3: Run pipeline analysis and verify risk scores
    # --------------------------------------------------------------------------
    pipeline = AnalysisPipeline()

    # Mock high threat forensics for phishing emails
    mock_phish_hdr = HeaderForensicsResult(
        spf=SPFResult(status="fail", domain="bank-verify.com", ip="198.51.100.10", record="", details="SPF Fail"),
        dkim=DKIMResult(status="fail", domain="bank-verify.com", selector="s1", details="DKIM Fail"),
        dmarc=DMARCResult(status="fail", policy="reject", domain="bank-verify.com", alignment_spf=False, alignment_dkim=False, record=""),
        relay_path=[RelayHop(hop_number=1, from_host="bad.node", by_host="relay.node", ip="198.51.100.10", timestamp="2026-08-26T00:00:00Z", protocol="ESMTP", delay_seconds=0.1, is_private=False)],
        anomalies=[],
        auth_confidence_score=0.0,
    )
    mock_phish_geo = GeoIntelResult(
        originating_ip="198.51.100.10",
        geo_locations=[IPGeoResult(ip="198.51.100.10", country="RU", country_code="RU", region="MOW", city="Moscow", latitude=55.7, longitude=37.6, isp="Bulletproof ISP", asn="9999", org="Bad Org", is_private=False, infrastructure_type="tor_exit_node", confidence="high")],
        domain_intel=DomainIntelResult(domain="bank-verify.com", registrar="Anon", registration_date="2026-08-20", expiration_date="2027-08-20", registrant_country="RU", name_servers=[], mx_records=[], a_records=[], domain_age_days=6, is_newly_registered=True),
        infrastructure_flags=["tor_exit_node"],
        location_confidence="high",
        ip_reputation_score=10.0,
    )
    mock_phish_nlp = NLPClassificationResult(
        label="Phishing",
        confidence=98.0,
        probabilities={"Phishing": 98.0, "Legitimate": 1.0, "Suspicious": 1.0},
        urgency_score=90.0,
        bec_indicators=["wire_transfer"],
        impersonation_signals=["lookalike_domain"],
        contributing_factors=["high_urgency", "credential_lure"],
    )
    mock_phish_link = LinkAnalysisResult(urls_analyzed=1, url_results=[], overall_link_risk=90.0, phishing_urls_found=1, suspicious_urls_found=0)
    mock_phish_att = AttachmentAnalysisReport(total_attachments=0, results=[], overall_attachment_risk=0.0)

    # Mock clean forensics for legitimate email
    mock_legit_hdr = HeaderForensicsResult(
        spf=SPFResult(status="pass", domain="verified-tech.com", ip="192.0.2.1", record="", details="SPF Pass"),
        dkim=DKIMResult(status="pass", domain="verified-tech.com", selector="default", details="DKIM Pass"),
        dmarc=DMARCResult(status="pass", policy="reject", domain="verified-tech.com", alignment_spf=True, alignment_dkim=True, record=""),
        relay_path=[RelayHop(hop_number=1, from_host="mail.verified-tech.com", by_host="relay.host", ip="192.0.2.1", timestamp="2026-08-26T00:00:00Z", protocol="ESMTP", delay_seconds=0.1, is_private=False)],
        anomalies=[],
        auth_confidence_score=100.0,
    )
    mock_legit_geo = GeoIntelResult(
        originating_ip="192.0.2.1",
        geo_locations=[IPGeoResult(ip="192.0.2.1", country="US", country_code="US", region="CA", city="San Francisco", latitude=37.7, longitude=-122.4, isp="Cloudflare", asn="13335", org="Cloudflare", is_private=False, infrastructure_type="clean", confidence="high")],
        domain_intel=DomainIntelResult(domain="verified-tech.com", registrar="MarkMonitor", registration_date="2012-01-01", expiration_date="2032-01-01", registrant_country="US", name_servers=[], mx_records=[], a_records=[], domain_age_days=5000, is_newly_registered=False),
        infrastructure_flags=[],
        location_confidence="high",
        ip_reputation_score=95.0,
    )
    mock_legit_nlp = NLPClassificationResult(label="Legitimate", confidence=99.0, probabilities={"Legitimate": 99.0, "Phishing": 0.0}, urgency_score=0.0, bec_indicators=[], impersonation_signals=[], contributing_factors=[])
    mock_legit_link = LinkAnalysisResult(urls_analyzed=0, url_results=[], overall_link_risk=0.0, phishing_urls_found=0, suspicious_urls_found=0)
    mock_legit_att = AttachmentAnalysisReport(total_attachments=0, results=[], overall_attachment_risk=0.0)

    # Analyze Phishing Email 1
    with patch("app.core.pipeline.HeaderForensics.analyze", new_callable=AsyncMock, return_value=mock_phish_hdr), \
         patch("app.core.pipeline.GeoIntelligence.analyze", new_callable=AsyncMock, return_value=mock_phish_geo), \
         patch("app.core.pipeline.NLPClassifier.classify", return_value=mock_phish_nlp), \
         patch("app.core.pipeline.LinkAnalyzer.analyze", new_callable=AsyncMock, return_value=mock_phish_link), \
         patch("app.core.pipeline.AttachmentAnalyzer.analyze", return_value=mock_phish_att), \
         patch("app.workers.tasks.enrich_threat_intel_task.apply_async"):
        res1 = await pipeline.run(str(p1_id), db)

    # Analyze Phishing Email 2
    with patch("app.core.pipeline.HeaderForensics.analyze", new_callable=AsyncMock, return_value=mock_phish_hdr), \
         patch("app.core.pipeline.GeoIntelligence.analyze", new_callable=AsyncMock, return_value=mock_phish_geo), \
         patch("app.core.pipeline.NLPClassifier.classify", return_value=mock_phish_nlp), \
         patch("app.core.pipeline.LinkAnalyzer.analyze", new_callable=AsyncMock, return_value=mock_phish_link), \
         patch("app.core.pipeline.AttachmentAnalyzer.analyze", return_value=mock_phish_att), \
         patch("app.workers.tasks.enrich_threat_intel_task.apply_async"):
        res2 = await pipeline.run(str(p2_id), db)

    # Analyze Phishing Email 3
    with patch("app.core.pipeline.HeaderForensics.analyze", new_callable=AsyncMock, return_value=mock_phish_hdr), \
         patch("app.core.pipeline.GeoIntelligence.analyze", new_callable=AsyncMock, return_value=mock_phish_geo), \
         patch("app.core.pipeline.NLPClassifier.classify", return_value=mock_phish_nlp), \
         patch("app.core.pipeline.LinkAnalyzer.analyze", new_callable=AsyncMock, return_value=mock_phish_link), \
         patch("app.core.pipeline.AttachmentAnalyzer.analyze", return_value=mock_phish_att), \
         patch("app.workers.tasks.enrich_threat_intel_task.apply_async"):
        res3 = await pipeline.run(str(p3_id), db)

    # Analyze Legitimate Email
    with patch("app.core.pipeline.HeaderForensics.analyze", new_callable=AsyncMock, return_value=mock_legit_hdr), \
         patch("app.core.pipeline.GeoIntelligence.analyze", new_callable=AsyncMock, return_value=mock_legit_geo), \
         patch("app.core.pipeline.NLPClassifier.classify", return_value=mock_legit_nlp), \
         patch("app.core.pipeline.LinkAnalyzer.analyze", new_callable=AsyncMock, return_value=mock_legit_link), \
         patch("app.core.pipeline.AttachmentAnalyzer.analyze", return_value=mock_legit_att), \
         patch("app.workers.tasks.enrich_threat_intel_task.apply_async"):
        res_legit = await pipeline.run(str(legit_id), db)

    assert res1.composite_risk_score >= 75.0
    assert res2.composite_risk_score >= 75.0
    assert res3.composite_risk_score >= 75.0
    assert res_legit.composite_risk_score < 50.0

    # --------------------------------------------------------------------------
    # Step 4 & 5: Verify 3 phishing emails create alerts, legitimate creates none
    # --------------------------------------------------------------------------
    assert len(db.alerts) == 3
    alerted_eids = {al.email_id for al in db.alerts}
    assert p1_id in alerted_eids
    assert p2_id in alerted_eids
    assert p3_id in alerted_eids
    assert legit_id not in alerted_eids

    # --------------------------------------------------------------------------
    # Step 6: Create investigation case
    # --------------------------------------------------------------------------
    case_service = CaseService()
    case = await case_service.create_case(
        db,
        CaseCreate(
            title="Campaign Investigation: Multi-Vector Executive Phishing",
            description="Coordinated phishing lure campaign targeting finance and IT departments",
            severity=CaseSeverity.critical,
        ),
        user_id="lead_analyst",
    )
    assert case.id is not None
    assert case.status == CaseStatus.open

    # --------------------------------------------------------------------------
    # Step 7: Link the 3 phishing emails to the case
    # --------------------------------------------------------------------------
    await case_service.add_email_to_case(db, case.id, p1_id, user_id="lead_analyst")
    await case_service.add_email_to_case(db, case.id, p2_id, user_id="lead_analyst")
    await case_service.add_email_to_case(db, case.id, p3_id, user_id="lead_analyst")

    linked_emails = await case_service.get_case_emails(db, case.id)
    assert len(linked_emails) == 3

    # --------------------------------------------------------------------------
    # Step 8: Add analyst note
    # --------------------------------------------------------------------------
    note = await case_service.add_note(
        db,
        case.id,
        CaseNoteCreate(
            content="Correlated shared infrastructure: Bulletproof Russian ASN 9999 and Tor Exit Node 198.51.100.10.",
            author="lead_analyst",
        ),
        user_id="lead_analyst",
    )
    assert note.content.startswith("Correlated shared infrastructure")

    # --------------------------------------------------------------------------
    # Step 9: Verify timeline aggregation
    # --------------------------------------------------------------------------
    timeline = await case_service.get_case_timeline(db, case.id)
    assert len(timeline) >= 5  # case_created + 3 email_linked + 1 note_added
    event_types = [item["type"] for item in timeline]
    assert "case_created" in event_types
    assert event_types.count("email_linked") == 3
    assert "note_added" in event_types

    # --------------------------------------------------------------------------
    # Step 10: Generate forensic PDF for linked evidence
    # --------------------------------------------------------------------------
    report_gen = ReportGenerator()
    pdf_bytes = await report_gen.generate_pdf(email_id=p1_id, db=db, user_id="lead_analyst")
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-")

    # --------------------------------------------------------------------------
    # Step 11: Verify audit trail contains expected actions & unbroken chain
    # --------------------------------------------------------------------------
    audit_service = AuditService()
    chain_verif = await audit_service.verify_chain(db)
    assert chain_verif["valid"] is True
    assert chain_verif["entries_checked"] >= 8

    actions = [log.action for log in db.audit_logs]
    assert "email_analysis_completed" in actions
    assert "case_created" in actions
    assert "case_email_linked" in actions
    assert "case_note_added" in actions
    assert "forensic_report_generated" in actions

    # --------------------------------------------------------------------------
    # Step 12: Verify dashboard statistics reflect workflow via API
    # --------------------------------------------------------------------------
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    stats_res = client.get("/api/dashboard/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()

    assert stats["total_emails"] == 4
    assert stats["threats_detected"] == 3
    assert stats["active_cases"] == 1
    assert stats["unacknowledged_alerts"] == 3
    assert (stats["threat_distribution"].get("PHISHING") or stats["threat_distribution"].get("Phishing")) == 3
    assert (stats["threat_distribution"].get("LEGITIMATE") or stats["threat_distribution"].get("Legitimate")) == 1
    assert stats["risk_distribution"]["critical"] >= 3
    assert stats["risk_distribution"]["low"] >= 1
    assert len(stats["ingestion_timeline"]) == 7

    app.dependency_overrides.clear()
