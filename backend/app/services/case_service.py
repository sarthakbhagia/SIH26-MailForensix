import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.email_case import Case, CaseEmail, CaseNote, CaseSeverity, CaseStatus, Email
from app.schemas.case import CaseCreate, CaseNoteCreate, CaseUpdate
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)


def _normalize_uuid(val: Optional[Union[str, UUID]]) -> Optional[UUID]:
    if val is None or val == "":
        return None
    if isinstance(val, UUID):
        return val
    try:
        return UUID(str(val))
    except (ValueError, TypeError, AttributeError):
        return None


class CaseService:
    """Service managing investigation cases, linked email evidence, analyst notes, and audit timelines."""

    def __init__(self, audit_service: Optional[AuditService] = None):
        self.audit_service = audit_service or AuditService()

    async def create_case(
        self,
        db: AsyncSession,
        case_data: Union[CaseCreate, Dict[str, Any]],
        user_id: str = "analyst",
    ) -> Case:
        """Create a new case, log audit event, and return the persisted case."""
        if isinstance(case_data, dict):
            title = case_data.get("title", "Untitled Case")
            description = case_data.get("description", "")
            raw_sev = case_data.get("severity", CaseSeverity.medium)
            assigned_to = case_data.get("assigned_to")
            raw_status = case_data.get("status", CaseStatus.open)
        else:
            title = case_data.title
            description = case_data.description
            raw_sev = case_data.severity
            assigned_to = getattr(case_data, "assigned_to", None)
            raw_status = getattr(case_data, "status", CaseStatus.open)

        # Handle severity enum
        if isinstance(raw_sev, str):
            severity = CaseSeverity(raw_sev.lower())
        else:
            severity = raw_sev or CaseSeverity.medium

        # Handle status enum
        if isinstance(raw_status, str):
            status = CaseStatus(raw_status.lower())
        else:
            status = raw_status or CaseStatus.open

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        case = Case(
            id=uuid4(),
            title=title,
            description=description,
            severity=severity,
            status=status,
            assigned_to=assigned_to or user_id,
            created_at=now_utc,
            updated_at=now_utc,
        )
        db.add(case)
        await db.commit()
        await db.refresh(case)

        # Log audit trail
        await self.audit_service.log_action(
            case_id=case.id,
            email_id=None,
            user_id=user_id,
            action="case_created",
            action_data={
                "case_id": str(case.id),
                "title": case.title,
                "severity": str(case.severity),
                "status": str(case.status),
                "assigned_to": case.assigned_to,
            },
            db=db,
        )

        return case

    async def get_case(self, db: AsyncSession, case_id: Union[str, UUID]) -> Case:
        """Retrieve a case by ID or raise 404 if not found."""
        cid = _normalize_uuid(case_id)
        if not cid:
            raise HTTPException(status_code=404, detail="Case not found")

        result = await db.execute(select(Case).filter(Case.id == cid))
        case = result.scalar_one_or_none()
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        return case

    async def list_cases(
        self,
        db: AsyncSession,
        status: Optional[Union[str, CaseStatus]] = None,
        severity: Optional[Union[str, CaseSeverity]] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Case]:
        """List cases with optional status/severity filtering and pagination."""
        stmt = select(Case).order_by(Case.created_at.desc())

        if status:
            s_val = status if isinstance(status, CaseStatus) else CaseStatus(str(status).lower())
            stmt = stmt.filter(Case.status == s_val)
        if severity:
            sev_val = severity if isinstance(severity, CaseSeverity) else CaseSeverity(str(severity).lower())
            stmt = stmt.filter(Case.severity == sev_val)

        stmt = stmt.offset(offset).limit(limit)
        result = await db.execute(stmt)
        return list(result.scalars().all())

    async def update_case(
        self,
        db: AsyncSession,
        case_id: Union[str, UUID],
        case_update: Union[CaseUpdate, Dict[str, Any]],
        user_id: str = "analyst",
    ) -> Case:
        """Update case fields, update timestamps, and log status transitions in the audit trail."""
        case = await self.get_case(db, case_id)
        update_dict = (
            case_update.model_dump(exclude_unset=True)
            if hasattr(case_update, "model_dump")
            else dict(case_update)
        )

        prev_status = case.status
        prev_severity = case.severity

        for key, value in update_dict.items():
            if value is not None:
                if key == "status" and isinstance(value, str):
                    value = CaseStatus(value.lower())
                elif key == "severity" and isinstance(value, str):
                    value = CaseSeverity(value.lower())
                setattr(case, key, value)

        case.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        await db.commit()
        await db.refresh(case)

        # Audit status/field updates
        action_data = {"case_id": str(case.id), "updated_fields": list(update_dict.keys())}
        if "status" in update_dict and update_dict["status"] != prev_status:
            action_data["previous_status"] = str(prev_status)
            action_data["new_status"] = str(case.status)
        if "severity" in update_dict and update_dict["severity"] != prev_severity:
            action_data["previous_severity"] = str(prev_severity)
            action_data["new_severity"] = str(case.severity)

        await self.audit_service.log_action(
            case_id=case.id,
            email_id=None,
            user_id=user_id,
            action="case_updated",
            action_data=action_data,
            db=db,
        )

        return case

    async def delete_case(
        self,
        db: AsyncSession,
        case_id: Union[str, UUID],
        user_id: str = "analyst",
    ):
        """Delete case and cascade-delete notes and email associations."""
        case = await self.get_case(db, case_id)
        cid = case.id

        # Remove email associations
        email_links = await db.execute(select(CaseEmail).filter(CaseEmail.case_id == cid))
        for link in email_links.scalars().all():
            await db.delete(link)

        # Remove notes
        notes = await db.execute(select(CaseNote).filter(CaseNote.case_id == cid))
        for note in notes.scalars().all():
            await db.delete(note)

        await db.delete(case)
        await db.commit()

        # Audit action
        await self.audit_service.log_action(
            case_id=cid,
            email_id=None,
            user_id=user_id,
            action="case_deleted",
            action_data={"case_id": str(cid), "title": case.title},
            db=db,
        )

    async def add_email_to_case(
        self,
        db: AsyncSession,
        case_id: Union[str, UUID],
        email_id: Union[str, UUID],
        user_id: str = "analyst",
    ) -> CaseEmail:
        """Link an email evidence record to a case with existence and duplicate checks."""
        case = await self.get_case(db, case_id)
        eid = _normalize_uuid(email_id)
        if not eid:
            raise HTTPException(status_code=404, detail="Email not found")

        email_res = await db.execute(select(Email).filter(Email.id == eid))
        email = email_res.scalar_one_or_none()
        if not email:
            raise HTTPException(status_code=404, detail="Email not found")

        # Check existing link
        existing = await db.execute(
            select(CaseEmail).filter_by(case_id=case.id, email_id=eid)
        )
        link = existing.scalar_one_or_none()
        if link:
            return link  # Already linked; prevent duplicate insertion

        new_link = CaseEmail(case_id=case.id, email_id=eid)
        db.add(new_link)
        await db.commit()

        # Audit trail
        await self.audit_service.log_action(
            case_id=case.id,
            email_id=eid,
            user_id=user_id,
            action="case_email_linked",
            action_data={"case_id": str(case.id), "email_id": str(eid), "subject": email.subject},
            db=db,
        )

        return new_link

    async def link_email(self, db: AsyncSession, case_id: UUID, email_id: UUID) -> CaseEmail:
        """Alias for add_email_to_case for backward compatibility."""
        return await self.add_email_to_case(db, case_id, email_id)

    async def remove_email_from_case(
        self,
        db: AsyncSession,
        case_id: Union[str, UUID],
        email_id: Union[str, UUID],
        user_id: str = "analyst",
    ):
        """Unlink an email from a case and log to audit trail."""
        case = await self.get_case(db, case_id)
        eid = _normalize_uuid(email_id)
        if not eid:
            raise HTTPException(status_code=404, detail="Email not found")

        result = await db.execute(
            select(CaseEmail).filter_by(case_id=case.id, email_id=eid)
        )
        link = result.scalar_one_or_none()
        if link:
            await db.delete(link)
            await db.commit()

            await self.audit_service.log_action(
                case_id=case.id,
                email_id=eid,
                user_id=user_id,
                action="case_email_unlinked",
                action_data={"case_id": str(case.id), "email_id": str(eid)},
                db=db,
            )

    async def unlink_email(self, db: AsyncSession, case_id: UUID, email_id: UUID):
        """Alias for remove_email_from_case for backward compatibility."""
        await self.remove_email_from_case(db, case_id, email_id)

    async def add_note(
        self,
        db: AsyncSession,
        case_id: Union[str, UUID],
        note: Union[CaseNoteCreate, Dict[str, Any]],
        user_id: str = "analyst",
    ) -> CaseNote:
        """Add an analyst investigation note to a case and log to audit trail."""
        case = await self.get_case(db, case_id)

        if isinstance(note, dict):
            content = note.get("content", "")
            author = note.get("author") or user_id
        else:
            content = note.content
            author = note.author or user_id

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        case_note = CaseNote(
            id=uuid4(),
            case_id=case.id,
            author=author,
            content=content,
            created_at=now_utc,
        )
        db.add(case_note)
        await db.commit()
        await db.refresh(case_note)

        # Audit trail
        await self.audit_service.log_action(
            case_id=case.id,
            email_id=None,
            user_id=author,
            action="case_note_added",
            action_data={"case_id": str(case.id), "note_id": str(case_note.id)},
            db=db,
        )

        return case_note

    async def get_case_notes(
        self,
        db: AsyncSession,
        case_id: Union[str, UUID],
    ) -> List[CaseNote]:
        """Retrieve all notes for a case in chronological order."""
        case = await self.get_case(db, case_id)
        result = await db.execute(
            select(CaseNote)
            .filter(CaseNote.case_id == case.id)
            .order_by(CaseNote.created_at.asc())
        )
        return list(result.scalars().all())

    async def list_notes(self, db: AsyncSession, case_id: UUID) -> List[CaseNote]:
        """Alias for get_case_notes for backward compatibility."""
        return await self.get_case_notes(db, case_id)

    async def get_case_emails(
        self,
        db: AsyncSession,
        case_id: Union[str, UUID],
    ) -> List[Email]:
        """Retrieve all Email evidence records linked to a case."""
        case = await self.get_case(db, case_id)
        stmt = (
            select(Email)
            .join(CaseEmail, CaseEmail.email_id == Email.id)
            .filter(CaseEmail.case_id == case.id)
            .order_by(Email.ingested_at.desc())
        )
        result = await db.execute(stmt)
        return list(result.scalars().all())

    async def get_case_timeline(
        self,
        db: AsyncSession,
        case_id: Union[str, UUID],
    ) -> List[Dict[str, Any]]:
        """Combine case creation, linked emails, notes, status changes, and audit logs into a unified timeline."""
        case = await self.get_case(db, case_id)
        cid = case.id
        events: List[Dict[str, Any]] = []

        # 1. Case creation event
        if case.created_at:
            events.append({
                "type": "case_created",
                "timestamp": case.created_at.isoformat(),
                "actor": case.assigned_to or "System",
                "title": f"Case Created: {case.title}",
                "severity": str(case.severity),
                "details": {"description": case.description, "status": str(case.status)},
            })

        # 2. Linked emails
        emails = await self.get_case_emails(db, cid)
        for email in emails:
            ts = email.ingested_at.isoformat() if email.ingested_at else case.created_at.isoformat()
            events.append({
                "type": "email_linked",
                "timestamp": ts,
                "actor": "System",
                "title": f"Evidence Linked: {email.subject or 'No Subject'}",
                "email_id": str(email.id),
                "details": {
                    "sender": email.sender,
                    "status": str(email.status),
                    "sha256": email.raw_hash_sha256,
                },
            })

        # 3. Analyst Notes
        notes = await self.get_case_notes(db, cid)
        for note in notes:
            ts = note.created_at.isoformat() if note.created_at else case.created_at.isoformat()
            events.append({
                "type": "note_added",
                "timestamp": ts,
                "actor": note.author or "Analyst",
                "title": f"Note Added by {note.author}",
                "note_id": str(note.id),
                "details": {"content": note.content},
            })

        # 4. Audit Log events
        audit_res = await db.execute(
            select(AuditLog)
            .filter(AuditLog.case_id == cid)
            .order_by(AuditLog.timestamp.asc())
        )
        audit_logs = list(audit_res.scalars().all())
        for audit in audit_logs:
            # Avoid duplicate note/link logs if already represented
            if audit.action not in ("case_created", "case_note_added"):
                ts = audit.timestamp.isoformat() if audit.timestamp else case.created_at.isoformat()
                events.append({
                    "type": "audit_event",
                    "action": audit.action,
                    "timestamp": ts,
                    "actor": audit.user_id or "System",
                    "title": audit.action.replace("_", " ").title(),
                    "details": audit.action_data or {},
                })

        # Sort timeline chronologically (earliest to latest)
        events.sort(key=lambda x: x.get("timestamp") or "")
        return events

