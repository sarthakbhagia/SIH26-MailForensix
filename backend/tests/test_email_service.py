import pytest
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from app.models.analysis_result import AnalysisResult
from app.models.email_case import Email, EmailStatus
from app.services.email_service import EmailService

SAMPLE_DIR = Path(__file__).resolve().parent.parent.parent / "sample_emails"


class FakeScalarResult:
    def __init__(self, item):
        self._item = item

    def scalar_one_or_none(self):
        return self._item

    def scalar(self):
        return self._item

    def scalars(self):
        class ScalarIter:
            def __init__(self, items):
                self._items = items if isinstance(items, list) else ([items] if items is not None else [])
            def all(self):
                return list(self._items)
        return ScalarIter(self._item)


class MockEmailDbSession:
    """In-memory DB session supporting Email & AnalysisResult operations for unit testing."""

    def __init__(self):
        self.emails: list[Email] = []
        self.analyses: list[AnalysisResult] = []

    def add(self, obj):
        if isinstance(obj, Email):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.emails.append(obj)
        elif isinstance(obj, AnalysisResult):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.analyses.append(obj)

    async def commit(self):
        pass

    async def refresh(self, obj):
        pass

    async def delete(self, obj):
        if isinstance(obj, Email) and obj in self.emails:
            self.emails.remove(obj)
        elif isinstance(obj, AnalysisResult) and obj in self.analyses:
            self.analyses.remove(obj)

    async def execute(self, stmt):
        stmt_str = str(stmt)

        # 1. Total emails count
        if "count(emails.id)" in stmt_str and "emails.status =" not in stmt_str and "emails.sender" not in stmt_str:
            return FakeScalarResult(len(self.emails))

        # 2. Analyzed emails count
        if "count(emails.id)" in stmt_str and "emails.status =" in stmt_str:
            analyzed_count = sum(1 for e in self.emails if e.status in (EmailStatus.analyzed, "analyzed"))
            return FakeScalarResult(analyzed_count)

        # 3. Average risk score
        if "avg(analysis_results.composite_risk_score)" in stmt_str:
            scores = [a.composite_risk_score for a in self.analyses if getattr(a, "composite_risk_score", None) is not None]
            avg = (sum(scores) / len(scores)) if scores else None
            return FakeScalarResult(avg)

        # 4. Get single Email by ID
        if "FROM emails" in stmt_str and "emails.id =" in stmt_str:
            # We match by searching through emails
            for email in self.emails:
                if str(email.id) in stmt_str or any(isinstance(val, UUID) and val == email.id for val in getattr(stmt, "_where_criteria", [])):
                    return FakeScalarResult(email)
            # Fallback: check last parameter or return first match if criteria matches
            # Let's inspect where criteria expressions
            for email in self.emails:
                return FakeScalarResult(email)
            return FakeScalarResult(None)

        # 5. Get AnalysisResult by email_id
        if "FROM analysis_results" in stmt_str and "analysis_results.email_id =" in stmt_str:
            if self.analyses:
                return FakeScalarResult(self.analyses[0])
            return FakeScalarResult(None)

        # 6. List query with pagination / filters
        if "FROM emails" in stmt_str:
            filtered = list(self.emails)
            # Apply limit and offset
            limit_val = getattr(stmt, "_limit", None)
            offset_val = getattr(stmt, "_offset", None) or 0

            # Sort descending by ingested_at
            sorted_entries = sorted(filtered, key=lambda x: (x.ingested_at, str(x.id)), reverse=True)

            if offset_val:
                sorted_entries = sorted_entries[offset_val:]
            if limit_val is not None:
                sorted_entries = sorted_entries[:limit_val]

            return FakeScalarResult(sorted_entries)

        return FakeScalarResult(None)


@pytest.mark.asyncio
async def test_ingest_email_success():
    """Verify ingest_email correctly hashes and saves a raw email."""
    sample_file = SAMPLE_DIR / "sample_phishing.eml"
    with open(sample_file, "rb") as f:
        raw_bytes = f.read()

    db = MockEmailDbSession()
    service = EmailService()

    email = await service.ingest_email(db, raw_bytes)

    assert email.id is not None
    assert email.raw_hash_sha256 is not None
    assert len(email.raw_hash_sha256) == 64
    assert email.status == EmailStatus.pending
    assert email.sender is not None
    assert len(db.emails) == 1


@pytest.mark.asyncio
async def test_get_email_and_missing_handling():
    """Verify get_email retrieves existing email and handles missing/invalid IDs safely."""
    db = MockEmailDbSession()
    service = EmailService()

    email_id = uuid4()
    mock_email = Email(
        id=email_id,
        sender="test@corp.com",
        subject="Meeting Update",
        status=EmailStatus.pending,
        ingested_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.emails.append(mock_email)

    # 1. Successful lookup
    retrieved = await service.get_email(email_id=email_id, db=db)
    assert retrieved is not None
    assert retrieved.id == email_id

    # 2. Reverse parameter order get_email(db, email_id)
    retrieved_rev = await service.get_email(db, email_id)
    assert retrieved_rev is not None

    # 3. Missing / None ID
    assert await service.get_email(email_id="invalid-uuid", db=db) is None
    assert await service.get_email(email_id=None, db=db) is None


@pytest.mark.asyncio
async def test_list_emails_pagination_and_legacy_signature():
    """Verify list_emails supports both offset/limit and legacy page/page_size pagination."""
    db = MockEmailDbSession()
    service = EmailService()

    for i in range(5):
        db.emails.append(Email(
            id=uuid4(),
            sender=f"user_{i}@domain.com",
            subject=f"Subject {i}",
            status=EmailStatus.analyzed if i % 2 == 0 else EmailStatus.pending,
            ingested_at=datetime.now(timezone.utc).replace(tzinfo=None),
        ))

    # 1. Modern signature list_emails(status=None, limit=2, offset=0, db=db)
    items, total = await service.list_emails(status=None, limit=2, offset=0, db=db)
    assert len(items) == 2
    assert total == 5

    # 2. Offset pagination
    items_page2, _ = await service.list_emails(status=None, limit=2, offset=2, db=db)
    assert len(items_page2) == 2

    # 3. Legacy signature list_emails(db, page=1, page_size=3, filters={})
    legacy_items, legacy_total = await service.list_emails(db, 1, 3, {})
    assert len(legacy_items) == 3
    assert legacy_total == 5


@pytest.mark.asyncio
async def test_get_email_with_analysis():
    """Verify get_email_with_analysis returns both email and associated analysis result."""
    db = MockEmailDbSession()
    service = EmailService()

    eid = uuid4()
    email = Email(
        id=eid,
        sender="phish@evil.com",
        subject="Suspicious link",
        status=EmailStatus.analyzed,
        ingested_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    analysis = AnalysisResult(
        id=uuid4(),
        email_id=eid,
        nlp_label="Phishing",
        composite_risk_score=88.5,
    )
    db.emails.append(email)
    db.analyses.append(analysis)

    res = await service.get_email_with_analysis(email_id=eid, db=db)
    assert res["email"] is not None
    assert res["email"].id == eid
    assert res["analysis"] is not None
    assert res["analysis"].composite_risk_score == 88.5

    # Missing email
    missing = await service.get_email_with_analysis(email_id=None, db=db)
    assert missing["email"] is None
    assert missing["analysis"] is None


@pytest.mark.asyncio
async def test_delete_email():
    """Verify delete_email removes the email and associated analysis record."""
    db = MockEmailDbSession()
    service = EmailService()

    eid = uuid4()
    email = Email(id=eid, status=EmailStatus.analyzed, ingested_at=datetime.now(timezone.utc).replace(tzinfo=None))
    analysis = AnalysisResult(id=uuid4(), email_id=eid, composite_risk_score=90.0)
    db.emails.append(email)
    db.analyses.append(analysis)

    assert len(db.emails) == 1
    assert len(db.analyses) == 1

    deleted = await service.delete_email(email_id=eid, db=db)
    assert deleted is True
    assert len(db.emails) == 0
    assert len(db.analyses) == 0

    # Deleting nonexistent email returns False
    assert await service.delete_email(email_id=eid, db=db) is False


@pytest.mark.asyncio
async def test_get_email_stats():
    """Verify get_email_stats computes total, analyzed, and average risk score."""
    db = MockEmailDbSession()
    service = EmailService()

    # Empty stats
    empty_stats = await service.get_email_stats(db=db)
    assert empty_stats["total_emails"] == 0
    assert empty_stats["analyzed"] == 0
    assert empty_stats["avg_risk_score"] == 0.0

    # Populate emails
    e1 = Email(id=uuid4(), status=EmailStatus.analyzed, ingested_at=datetime.now(timezone.utc).replace(tzinfo=None))
    e2 = Email(id=uuid4(), status=EmailStatus.analyzed, ingested_at=datetime.now(timezone.utc).replace(tzinfo=None))
    e3 = Email(id=uuid4(), status=EmailStatus.pending, ingested_at=datetime.now(timezone.utc).replace(tzinfo=None))
    db.emails.extend([e1, e2, e3])

    # Populate analyses with risk scores
    a1 = AnalysisResult(id=uuid4(), email_id=e1.id, composite_risk_score=80.0)
    a2 = AnalysisResult(id=uuid4(), email_id=e2.id, composite_risk_score=90.0)
    db.analyses.extend([a1, a2])

    stats = await service.get_email_stats(db=db)
    assert stats["total_emails"] == 3
    assert stats["analyzed"] == 2
    assert stats["avg_risk_score"] == 85.0
