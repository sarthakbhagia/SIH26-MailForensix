import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


def _normalize_uuid(val: Optional[Union[str, UUID]]) -> Optional[UUID]:
    if val is None or val == "":
        return None
    if isinstance(val, UUID):
        return val
    try:
        return UUID(str(val))
    except (ValueError, TypeError, AttributeError):
        return None


def _is_db_session(obj: Any) -> bool:
    return obj is not None and hasattr(obj, "execute")


class AuditService:
    """Tamper-evident audit trail service using SHA-256 hash chaining."""

    GENESIS_HASH = GENESIS_HASH

    def _compute_entry_hash(
        self,
        previous_hash: str,
        timestamp: str,
        case_id: Any,
        user_id: Any,
        action_data: Optional[Dict[str, Any]],
    ) -> str:
        """
        Compute deterministic SHA-256 entry hash.

        EntryHash = SHA256(PreviousHash | Timestamp | CaseID | UserID | ActionData)
        """
        cid_str = str(case_id) if case_id else ""
        uid_str = str(user_id) if user_id else ""
        serialized_action_data = json.dumps(action_data or {}, sort_keys=True)
        payload = f"{previous_hash}|{timestamp}|{cid_str}|{uid_str}|{serialized_action_data}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    async def log_action(
        self,
        case_id: Optional[Union[str, UUID]] = None,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        action_data: Optional[Dict[str, Any]] = None,
        db: Optional[AsyncSession] = None,
        *,
        email_id: Optional[Union[str, UUID]] = None,
        **kwargs: Any,
    ) -> AuditLog:
        """
        Create a new hash-chained audit log entry.
        Supports flexible positional and keyword argument orders.
        """
        resolved_db = db or kwargs.get("db") or (case_id if _is_db_session(case_id) else (user_id if _is_db_session(user_id) else None))
        if resolved_db is None:
            raise ValueError("An active AsyncSession 'db' must be provided to log_action.")

        resolved_case_id = kwargs.get("case_id", case_id if not _is_db_session(case_id) else None)
        resolved_user_id = kwargs.get("user_id", user_id if not _is_db_session(user_id) else None)
        resolved_action = kwargs.get("action", action or "unknown_action")
        resolved_action_data = kwargs.get("action_data", action_data or {})
        resolved_email_id = kwargs.get("email_id", email_id)

        # 1. Fetch the latest entry hash (or use genesis hash if table is empty)
        stmt = select(AuditLog).order_by(desc(AuditLog.timestamp), desc(AuditLog.id)).limit(1)
        result = await resolved_db.execute(stmt)
        last_entry = result.scalar_one_or_none()
        previous_hash = getattr(last_entry, "entry_hash", None) or GENESIS_HASH

        # 2. Capture deterministic timestamp
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        timestamp_str = now.isoformat()

        # 3. Compute entry hash
        entry_hash = self._compute_entry_hash(
            previous_hash=previous_hash,
            timestamp=timestamp_str,
            case_id=resolved_case_id,
            user_id=resolved_user_id,
            action_data=resolved_action_data,
        )

        # 4. Persist entry
        log_entry = AuditLog(
            previous_hash=previous_hash,
            entry_hash=entry_hash,
            case_id=_normalize_uuid(resolved_case_id),
            email_id=_normalize_uuid(resolved_email_id),
            user_id=resolved_user_id,
            action=resolved_action,
            action_data=resolved_action_data,
            timestamp=now,
        )

        resolved_db.add(log_entry)
        await resolved_db.commit()
        await resolved_db.refresh(log_entry)

        logger.debug(
            f"Audit log entry created: action={resolved_action}, hash={entry_hash[:12]}..., prev={previous_hash[:12]}..."
        )
        return log_entry

    async def create_entry(
        self,
        db: AsyncSession,
        case_id: Optional[Union[str, UUID]] = None,
        email_id: Optional[Union[str, UUID]] = None,
        user_id: Optional[str] = None,
        action: str = "action",
        action_data: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """Backward-compatible alias for log_action."""
        return await self.log_action(
            case_id=case_id,
            user_id=user_id,
            action=action,
            action_data=action_data,
            db=db,
            email_id=email_id,
        )

    async def verify_chain(
        self,
        case_id_or_db: Union[AsyncSession, str, UUID, None] = None,
        db_or_case_id: Union[AsyncSession, str, UUID, None] = None,
        *,
        case_id: Optional[Union[str, UUID]] = None,
        db: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """
        Verify the mathematical integrity of the audit hash chain.
        Detects broken previous_hash links or altered payloads.

        Returns:
            {
                "valid": bool,
                "entries_checked": int,
                "broken_at_index": Optional[int],
                "message": str
            }
        """
        resolved_db: Optional[AsyncSession] = None
        resolved_case_id: Optional[Union[str, UUID]] = None

        if _is_db_session(case_id_or_db):
            resolved_db = case_id_or_db
            resolved_case_id = db_or_case_id if not _is_db_session(db_or_case_id) else case_id
        elif _is_db_session(db_or_case_id):
            resolved_db = db_or_case_id
            resolved_case_id = case_id_or_db or case_id
        else:
            resolved_db = db
            resolved_case_id = case_id or case_id_or_db

        if resolved_db is None:
            raise ValueError("An active AsyncSession 'db' must be provided to verify_chain.")

        query = select(AuditLog).order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
        parsed_case_uuid = _normalize_uuid(resolved_case_id)
        if parsed_case_uuid:
            query = query.where(AuditLog.case_id == parsed_case_uuid)

        result = await resolved_db.execute(query)
        entries: List[AuditLog] = list(result.scalars().all())

        if not entries:
            return {
                "valid": True,
                "entries_checked": 0,
                "broken_at_index": None,
                "message": "No entries to verify",
            }

        expected_prev = GENESIS_HASH
        valid = True
        broken_at: Optional[int] = None
        error_msg: Optional[str] = None

        for i, entry in enumerate(entries):
            # 1. Check backward linkage to expected previous hash
            if entry.previous_hash != expected_prev:
                valid = False
                broken_at = i
                error_msg = f"Previous hash mismatch at entry {i}: expected '{expected_prev}', got '{entry.previous_hash}'"
                break

            # 2. Recompute and verify entry hash
            timestamp_str = entry.timestamp.isoformat() if hasattr(entry.timestamp, "isoformat") else str(entry.timestamp)
            computed = self._compute_entry_hash(
                previous_hash=entry.previous_hash,
                timestamp=timestamp_str,
                case_id=entry.case_id,
                user_id=entry.user_id,
                action_data=entry.action_data,
            )

            if computed != entry.entry_hash:
                valid = False
                broken_at = i
                error_msg = f"Entry hash tampered at entry {i}: computed '{computed}', stored '{entry.entry_hash}'"
                break

            expected_prev = entry.entry_hash

        return {
            "valid": valid,
            "entries_checked": len(entries) if valid else (broken_at if broken_at is not None else 0),
            "broken_at_index": broken_at,
            "message": "Chain integrity verified" if valid else (error_msg or f"Chain broken at entry {broken_at}"),
        }

    async def get_audit_trail(
        self,
        db: AsyncSession,
        case_id: Optional[Union[str, UUID]] = None,
        email_id: Optional[Union[str, UUID]] = None,
        action: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        """
        Retrieve audit trail entries with optional filtering and pagination.
        Ordered newest first (descending timestamp).
        """
        query = select(AuditLog).order_by(desc(AuditLog.timestamp), desc(AuditLog.id))

        parsed_case_uuid = _normalize_uuid(case_id)
        if parsed_case_uuid:
            query = query.where(AuditLog.case_id == parsed_case_uuid)

        parsed_email_uuid = _normalize_uuid(email_id)
        if parsed_email_uuid:
            query = query.where(AuditLog.email_id == parsed_email_uuid)

        if action:
            query = query.where(AuditLog.action == action)

        query = query.offset(max(0, offset)).limit(max(1, min(limit, 500)))
        result = await db.execute(query)
        return list(result.scalars().all())
