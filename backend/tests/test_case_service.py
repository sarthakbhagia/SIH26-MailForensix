import pytest
from datetime import datetime, timezone
from uuid import UUID, uuid4
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.database import get_db
from app.main import app
from app.models.audit_log import AuditLog
from app.models.email_case import Case, CaseEmail, CaseNote, CaseSeverity, CaseStatus, Email, EmailStatus
from app.schemas.case import CaseCreate, CaseNoteCreate, CaseUpdate
from app.services.case_service import CaseService


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
                if items is None:
                    self._items = []
                elif isinstance(items, list):
                    self._items = items
                else:
                    self._items = [items]
            def all(self):
                return self._items
        return ScalarIter(self._item)


class MockCaseDbSession:
    """Mock DB session for CaseService tests."""

    def __init__(self):
        self.cases: dict[UUID, Case] = {}
        self.emails: dict[UUID, Email] = {}
        self.case_emails: list[CaseEmail] = []
        self.case_notes: list[CaseNote] = []
        self.audit_logs: list[AuditLog] = []

    def add(self, obj):
        if isinstance(obj, Case):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.cases[obj.id] = obj
        elif isinstance(obj, Email):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.emails[obj.id] = obj
        elif isinstance(obj, CaseEmail):
            self.case_emails.append(obj)
        elif isinstance(obj, CaseNote):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.case_notes.append(obj)
        elif isinstance(obj, AuditLog):
            if not getattr(obj, "id", None):
                obj.id = uuid4()
            self.audit_logs.append(obj)

    async def commit(self):
        pass

    async def refresh(self, obj):
        pass

    async def delete(self, obj):
        if isinstance(obj, Case) and obj.id in self.cases:
            del self.cases[obj.id]
        elif isinstance(obj, CaseEmail) and obj in self.case_emails:
            self.case_emails.remove(obj)
        elif isinstance(obj, CaseNote) and obj in self.case_notes:
            self.case_notes.remove(obj)

    async def execute(self, stmt):
        stmt_str = str(stmt).lower()

        # AuditLog latest query for previous_hash
        if "from audit_logs" in stmt_str:
            if "audit_logs.case_id =" in stmt_str:
                target_id = self._extract_id(stmt)
                matching = [a for a in self.audit_logs if a.case_id == target_id]
                return FakeScalarResult(matching)
            last = self.audit_logs[-1] if self.audit_logs else None
            return FakeScalarResult(last)

        # Lookup Case
        if "from cases" in stmt_str:
            if "cases.id =" in stmt_str:
                target_id = self._extract_id(stmt)
                return FakeScalarResult(self.cases.get(target_id))
            return FakeScalarResult(list(self.cases.values()))

        # Lookup Email
        if "from emails" in stmt_str:
            if "join case_emails" in stmt_str:
                target_id = self._extract_id(stmt)
                linked_eids = [ce.email_id for ce in self.case_emails if ce.case_id == target_id]
                linked = [self.emails[eid] for eid in linked_eids if eid in self.emails]
                return FakeScalarResult(linked)
            if "emails.id =" in stmt_str:
                target_id = self._extract_id(stmt)
                return FakeScalarResult(self.emails.get(target_id))
            return FakeScalarResult(list(self.emails.values()))

        # Lookup CaseEmail
        if "from case_emails" in stmt_str:
            target_id = self._extract_id(stmt)
            for ce in self.case_emails:
                if ce.case_id == target_id or ce.email_id == target_id:
                    return FakeScalarResult(ce)
            return FakeScalarResult(None)

        # Lookup CaseNote
        if "from case_notes" in stmt_str:
            target_id = self._extract_id(stmt)
            notes = [n for n in self.case_notes if n.case_id == target_id]
            return FakeScalarResult(notes)

        return FakeScalarResult(None)

    def _extract_id(self, stmt):
        for criterion in getattr(stmt, "_where_criteria", []):
            if hasattr(criterion, "right") and hasattr(criterion.right, "value"):
                return criterion.right.value
            elif hasattr(criterion, "value"):
                return criterion.value
        return None


@pytest.fixture
def mock_case_db():
    db = MockCaseDbSession()
    eid = uuid4()
    email = Email(
        id=eid,
        sender="spoofed@financial-lure.com",
        subject="Wire Transfer Instructions",
        status=EmailStatus.analyzed,
        raw_hash_sha256="f" * 64,
        ingested_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.add(email)
    return db, eid


@pytest.mark.asyncio
async def test_case_crud_lifecycle(mock_case_db):
    """Test full Case lifecycle: create, get, list, update, and delete."""
    db, eid = mock_case_db
    service = CaseService()

    # 1. Create Case
    case_in = CaseCreate(
        title="BEC Attack on Finance Dept",
        description="Investigation into spoofed wire instructions",
        severity=CaseSeverity.high,
    )
    case = await service.create_case(db, case_in, user_id="lead_analyst")

    assert case.id is not None
    assert case.title == "BEC Attack on Finance Dept"
    assert case.status == CaseStatus.open
    assert case.severity == CaseSeverity.high
    assert case.assigned_to == "lead_analyst"

    # Verify audit event
    assert len(db.audit_logs) >= 1
    assert db.audit_logs[-1].action == "case_created"

    # 2. Get Case
    fetched = await service.get_case(db, case.id)
    assert fetched.id == case.id

    # 3. List Cases
    cases = await service.list_cases(db)
    assert len(cases) == 1

    # 4. Update Case
    update_in = CaseUpdate(
        status=CaseStatus.investigating,
        severity=CaseSeverity.critical,
        assigned_to="senior_soc",
    )
    updated = await service.update_case(db, case.id, update_in, user_id="lead_analyst")
    assert updated.status == CaseStatus.investigating
    assert updated.severity == CaseSeverity.critical
    assert updated.assigned_to == "senior_soc"

    # Verify update audit event
    assert db.audit_logs[-1].action == "case_updated"
    assert db.audit_logs[-1].action_data["previous_status"] == "CaseStatus.open"

    # 5. Delete Case
    await service.delete_case(db, case.id, user_id="lead_analyst")
    assert case.id not in db.cases
    assert db.audit_logs[-1].action == "case_deleted"


@pytest.mark.asyncio
async def test_case_email_linking(mock_case_db):
    """Test linking and unlinking email evidence records with duplicate prevention."""
    db, eid = mock_case_db
    service = CaseService()

    case = await service.create_case(
        db,
        {"title": "Phishing Incident", "description": "Lure investigation"},
        user_id="analyst",
    )

    # 1. Link email
    link = await service.add_email_to_case(db, case.id, eid, user_id="analyst")
    assert link.case_id == case.id
    assert link.email_id == eid
    assert db.audit_logs[-1].action == "case_email_linked"

    # 2. Duplicate link returns existing link safely
    dup_link = await service.add_email_to_case(db, case.id, eid, user_id="analyst")
    assert dup_link.email_id == eid
    assert len(db.case_emails) == 1

    # 3. Get linked emails
    linked_emails = await service.get_case_emails(db, case.id)
    assert len(linked_emails) == 1
    assert linked_emails[0].id == eid

    # 4. Unlink email
    await service.remove_email_from_case(db, case.id, eid, user_id="analyst")
    assert len(db.case_emails) == 0
    assert db.audit_logs[-1].action == "case_email_unlinked"


@pytest.mark.asyncio
async def test_case_notes_chronology(mock_case_db):
    """Test adding analyst investigation notes and retrieving them in chronological order."""
    db, eid = mock_case_db
    service = CaseService()

    case = await service.create_case(
        db,
        {"title": "Note Test Case", "description": "Testing notes"},
        user_id="analyst1",
    )

    # Add notes
    note1 = await service.add_note(
        db,
        case.id,
        CaseNoteCreate(content="Identified bulletproof relay IP", author="analyst1"),
        user_id="analyst1",
    )
    note2 = await service.add_note(
        db,
        case.id,
        CaseNoteCreate(content="Submitted domain takedown request", author="analyst2"),
        user_id="analyst2",
    )

    assert note1.id is not None
    assert note2.id is not None
    assert db.audit_logs[-1].action == "case_note_added"

    # Retrieve notes
    notes = await service.get_case_notes(db, case.id)
    assert len(notes) == 2
    assert notes[0].content == "Identified bulletproof relay IP"
    assert notes[1].content == "Submitted domain takedown request"


@pytest.mark.asyncio
async def test_case_timeline_aggregation(mock_case_db):
    """Test get_case_timeline combining creation, linked evidence, notes, and audit events."""
    db, eid = mock_case_db
    service = CaseService()

    case = await service.create_case(
        db,
        {"title": "Timeline Test Case", "description": "Comprehensive timeline"},
        user_id="analyst",
    )
    await service.add_email_to_case(db, case.id, eid, user_id="analyst")
    await service.add_note(
        db,
        case.id,
        CaseNoteCreate(content="Analyzed header authentication.", author="analyst"),
        user_id="analyst",
    )

    timeline = await service.get_case_timeline(db, case.id)
    assert len(timeline) >= 3

    event_types = [item["type"] for item in timeline]
    assert "case_created" in event_types
    assert "email_linked" in event_types
    assert "note_added" in event_types


@pytest.mark.asyncio
async def test_case_invalid_ids(mock_case_db):
    """Test 404 error handling on invalid / nonexistent IDs."""
    db, eid = mock_case_db
    service = CaseService()
    missing_id = uuid4()

    with pytest.raises(HTTPException) as exc1:
        await service.get_case(db, missing_id)
    assert exc1.value.status_code == 404

    with pytest.raises(HTTPException) as exc2:
        await service.add_email_to_case(db, missing_id, eid)
    assert exc2.value.status_code == 404

    case = await service.create_case(
        db, {"title": "Valid Case", "description": "desc"}
    )
    with pytest.raises(HTTPException) as exc3:
        await service.add_email_to_case(db, case.id, missing_id)
    assert exc3.value.status_code == 404


def test_case_api_integration(mock_case_db):
    """Test cases REST API endpoints."""
    db, eid = mock_case_db

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    # 1. Create Case
    res = client.post(
        "/api/cases/",
        json={
            "title": "API Test Case",
            "description": "Created via test client",
            "severity": "high",
        },
    )
    assert res.status_code in (200, 201)
    case_data = res.json()
    case_id = case_data["id"]
    assert case_data["title"] == "API Test Case"

    # 2. List Cases
    res_list = client.get("/api/cases/")
    assert res_list.status_code == 200
    assert len(res_list.json()) >= 1

    # 3. Add Note
    res_note = client.post(
        f"/api/cases/{case_id}/notes",
        json={"content": "Investigating email IOCs", "author": "analyst"},
    )
    assert res_note.status_code in (200, 201)
    assert res_note.json()["content"] == "Investigating email IOCs"

    # 4. Link Email
    res_link = client.post(f"/api/cases/{case_id}/emails/{eid}")
    assert res_link.status_code == 200

    # 5. Get Timeline
    res_timeline = client.get(f"/api/cases/{case_id}/timeline")
    assert res_timeline.status_code == 200
    assert len(res_timeline.json()) >= 1

    app.dependency_overrides.clear()
