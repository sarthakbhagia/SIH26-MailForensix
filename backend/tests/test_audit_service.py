import hashlib
import json
import pytest
from datetime import datetime, timezone
from uuid import UUID, uuid4

from app.models.audit_log import AuditLog
from app.services.audit_service import AuditService, GENESIS_HASH


class FakeScalarResult:
    def __init__(self, items):
        self._items = items

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None

    def scalars(self):
        class ScalarIter:
            def __init__(self, items):
                self._items = items
            def all(self):
                return list(self._items)
        return ScalarIter(self._items)


class MockAuditDbSession:
    """In-memory database session supporting AuditLog operations for testing."""

    def __init__(self):
        self.entries: list[AuditLog] = []

    def add(self, obj: AuditLog):
        if not getattr(obj, "id", None):
            obj.id = uuid4()
        self.entries.append(obj)

    async def commit(self):
        pass

    async def refresh(self, obj: AuditLog):
        pass

    async def execute(self, stmt):
        stmt_str = str(stmt)
        filtered = list(self.entries)

        limit_val = getattr(stmt, "_limit", None)
        offset_val = getattr(stmt, "_offset", None) or 0

        # Handle DESC ordering
        if "DESC" in stmt_str:
            sorted_entries = sorted(filtered, key=lambda x: (x.timestamp, str(x.id)), reverse=True)
        else:
            # ASC ordering
            sorted_entries = sorted(filtered, key=lambda x: (x.timestamp, str(x.id)))

        if offset_val:
            sorted_entries = sorted_entries[offset_val:]
        if limit_val is not None:
            sorted_entries = sorted_entries[:limit_val]

        return FakeScalarResult(sorted_entries)


def test_genesis_hash_constant():
    """Verify GENESIS_HASH is 64 zeros (SHA-256 length)."""
    assert GENESIS_HASH == "0" * 64
    assert len(GENESIS_HASH) == 64
    service = AuditService()
    assert service.GENESIS_HASH == "0" * 64


def test_compute_entry_hash_determinism_and_key_sorting():
    """Verify _compute_entry_hash produces consistent SHA-256 regardless of JSON key order."""
    service = AuditService()
    ts = "2026-08-26T12:00:00.000000"
    case_id = str(uuid4())
    user_id = "analyst_01"

    # Keys in different orders
    data_1 = {"zebra": 1, "alpha": "test", "nested": {"z": 9, "a": 1}}
    data_2 = {"alpha": "test", "zebra": 1, "nested": {"a": 1, "z": 9}}

    hash_1 = service._compute_entry_hash(GENESIS_HASH, ts, case_id, user_id, data_1)
    hash_2 = service._compute_entry_hash(GENESIS_HASH, ts, case_id, user_id, data_2)

    assert hash_1 == hash_2
    assert len(hash_1) == 64

    # Direct manual SHA-256 verification
    expected_payload = f"{GENESIS_HASH}|{ts}|{case_id}|{user_id}|{json.dumps(data_1, sort_keys=True)}"
    expected_hash = hashlib.sha256(expected_payload.encode("utf-8")).hexdigest()
    assert hash_1 == expected_hash


def test_compute_entry_hash_handles_none_values():
    """Verify _compute_entry_hash handles None/empty fields gracefully."""
    service = AuditService()
    ts = "2026-08-26T12:00:00"
    h = service._compute_entry_hash("prev_hash", ts, None, None, None)
    expected_payload = "prev_hash|2026-08-26T12:00:00|||{}"
    assert h == hashlib.sha256(expected_payload.encode("utf-8")).hexdigest()


@pytest.mark.asyncio
async def test_genesis_hash_on_first_entry():
    """Verify first entry created in empty database uses GENESIS_HASH."""
    db = MockAuditDbSession()
    service = AuditService()

    entry = await service.log_action(
        action="email_ingested",
        action_data={"email_id": "123", "sender": "bad@attacker.com"},
        user_id="system",
        db=db,
    )

    assert entry.previous_hash == GENESIS_HASH
    assert entry.entry_hash is not None
    assert len(entry.entry_hash) == 64
    assert entry.action == "email_ingested"
    assert len(db.entries) == 1


@pytest.mark.asyncio
async def test_valid_hash_chain():
    """Verify multiple sequential log entries form a valid chain."""
    db = MockAuditDbSession()
    service = AuditService()

    entry1 = await service.log_action(
        action="email_ingested",
        action_data={"subject": "Invoice #123"},
        user_id="system",
        db=db,
    )
    entry2 = await service.log_action(
        action="analysis_completed",
        action_data={"risk_score": 92.5, "label": "Phishing"},
        user_id="system",
        db=db,
    )
    entry3 = await service.log_action(
        action="case_created",
        action_data={"title": "Finance Phishing Campaign"},
        user_id="analyst_alice",
        db=db,
    )

    assert entry1.previous_hash == GENESIS_HASH
    assert entry2.previous_hash == entry1.entry_hash
    assert entry3.previous_hash == entry2.entry_hash

    # Verify entire chain
    verification = await service.verify_chain(db)
    assert verification["valid"] is True
    assert verification["entries_checked"] == 3
    assert verification["broken_at_index"] is None
    assert "verified" in verification["message"].lower()


@pytest.mark.asyncio
async def test_tampered_entry_payload_detection():
    """Verify modifying action_data in an entry is detected."""
    db = MockAuditDbSession()
    service = AuditService()

    await service.log_action(action="act_1", action_data={"amount": 100}, db=db)
    entry2 = await service.log_action(action="act_2", action_data={"amount": 200}, db=db)
    await service.log_action(action="act_3", action_data={"amount": 300}, db=db)

    # Attacker tampers with entry2 action_data
    entry2.action_data = {"amount": 999999}

    verification = await service.verify_chain(db)
    assert verification["valid"] is False
    assert verification["broken_at_index"] == 1
    assert "tampered" in verification["message"].lower()


@pytest.mark.asyncio
async def test_broken_previous_hash_link_detection():
    """Verify breaking the previous_hash link is detected."""
    db = MockAuditDbSession()
    service = AuditService()

    await service.log_action(action="act_1", action_data={"step": 1}, db=db)
    entry2 = await service.log_action(action="act_2", action_data={"step": 2}, db=db)
    await service.log_action(action="act_3", action_data={"step": 3}, db=db)

    # Attacker tampers with entry2's previous_hash pointer
    entry2.previous_hash = "f" * 64

    verification = await service.verify_chain(db)
    assert verification["valid"] is False
    assert verification["broken_at_index"] == 1
    assert "previous hash mismatch" in verification["message"].lower()


@pytest.mark.asyncio
async def test_empty_audit_trail_verification():
    """Verify empty audit trail returns valid=True with 0 entries checked."""
    db = MockAuditDbSession()
    service = AuditService()

    verification = await service.verify_chain(db)
    assert verification["valid"] is True
    assert verification["entries_checked"] == 0
    assert verification["broken_at_index"] is None


@pytest.mark.asyncio
async def test_get_audit_trail_and_ordering():
    """Verify get_audit_trail returns entries newest first with limits."""
    db = MockAuditDbSession()
    service = AuditService()

    for i in range(5):
        await service.log_action(action=f"event_{i}", action_data={"i": i}, user_id="admin", db=db)

    trail = await service.get_audit_trail(db=db, limit=3)
    assert len(trail) == 3
    # Newest first
    assert trail[0].action == "event_4"
    assert trail[1].action == "event_3"
    assert trail[2].action == "event_2"


@pytest.mark.asyncio
async def test_create_entry_backward_compatibility():
    """Verify create_entry alias works for legacy callers."""
    db = MockAuditDbSession()
    service = AuditService()
    cid = uuid4()

    entry = await service.create_entry(
        db=db,
        case_id=cid,
        email_id=None,
        user_id="analyst_bob",
        action="case_status_changed",
        action_data={"old": "open", "new": "investigating"},
    )

    assert entry.case_id == cid
    assert entry.user_id == "analyst_bob"
    assert entry.action == "case_status_changed"
    assert entry.previous_hash == GENESIS_HASH
