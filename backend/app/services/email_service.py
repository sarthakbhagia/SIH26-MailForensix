import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ingestion.hasher import EvidenceHasher
from app.core.ingestion.parser import EmailParser
from app.core.ingestion.preprocessor import EmailPreprocessor
from app.models.analysis_result import AnalysisResult
from app.models.email_case import Email, EmailStatus

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


def _is_db_session(obj: Any) -> bool:
    return obj is not None and hasattr(obj, "execute")


class EmailService:
    """Service handling email ingestion, querying, analysis retrieval, and stats."""

    def __init__(self):
        self.hasher = EvidenceHasher()
        self.parser = EmailParser()
        self.preprocessor = EmailPreprocessor()

    async def ingest_email(self, db: AsyncSession, raw_bytes: bytes) -> Email:
        """Parse, hash, and ingest a raw .eml file into the database."""
        hashes = self.hasher.hash(raw_bytes)
        parsed = self.parser.parse(raw_bytes)
        processed = self.preprocessor.preprocess(parsed)

        email = Email(
            raw_hash_sha256=hashes.sha256,
            raw_hash_sha1=hashes.sha1,
            raw_hash_md5=hashes.md5,
            sender=processed.sender,
            recipients=processed.recipients,
            subject=processed.subject,
            body_text=processed.body_text,
            body_html=processed.body_html,
            headers=processed.headers,
            attachments=[{k: v for k, v in a.items() if k != "content"} for a in processed.attachments],
            urls=processed.urls,
            raw_eml=raw_bytes,
            status=EmailStatus.pending,
            ingested_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        db.add(email)
        await db.commit()
        await db.refresh(email)
        return email

    async def get_email(
        self,
        email_id_or_db: Optional[Union[AsyncSession, str, UUID]] = None,
        db_or_email_id: Optional[Union[AsyncSession, str, UUID]] = None,
        *,
        email_id: Optional[Union[str, UUID]] = None,
        db: Optional[AsyncSession] = None,
        **kwargs: Any,
    ) -> Optional[Email]:
        """
        Get an email by its UUID. Returns Email or None.
        Supports get_email(email_id, db), get_email(db, email_id), and get_email(email_id=..., db=...).
        """
        if _is_db_session(email_id_or_db):
            resolved_db = email_id_or_db
            resolved_id = db_or_email_id or email_id or kwargs.get("email_id")
        elif _is_db_session(db_or_email_id):
            resolved_db = db_or_email_id
            resolved_id = email_id_or_db or email_id or kwargs.get("email_id")
        else:
            resolved_db = db or kwargs.get("db")
            resolved_id = email_id or kwargs.get("email_id") or email_id_or_db

        if resolved_db is None:
            raise ValueError("An active AsyncSession 'db' must be provided.")

        parsed_uuid = _normalize_uuid(resolved_id)
        if parsed_uuid is None:
            return None

        result = await resolved_db.execute(select(Email).where(Email.id == parsed_uuid))
        return result.scalar_one_or_none()

    async def list_emails(
        self,
        arg1: Any = None,
        arg2: Any = None,
        arg3: Any = None,
        arg4: Any = None,
        *,
        status: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        filters: Optional[Dict[str, Any]] = None,
        sender: Optional[str] = None,
        db: Optional[AsyncSession] = None,
        **kwargs: Any,
    ) -> Tuple[List[Email], int]:
        """
        List paginated emails with optional status and sender filtering.
        Supports both modern list_emails(status, limit, offset, db) and
        legacy list_emails(db, page, page_size, filters).
        """
        resolved_db = None
        status_val = status
        sender_val = sender
        calc_limit = limit or 20
        calc_offset = offset or 0

        if _is_db_session(arg1):
            resolved_db = arg1
            if isinstance(arg2, int) and isinstance(arg3, int):
                # Legacy signature: list_emails(db, page, page_size, filters)
                page_val = arg2
                page_size_val = arg3
                filters_dict = arg4 if isinstance(arg4, dict) else (filters or {})
                calc_offset = max(0, (page_val - 1) * page_size_val)
                calc_limit = max(1, page_size_val)
                status_val = filters_dict.get("status") or status
                sender_val = filters_dict.get("sender") or sender
            else:
                status_val = arg2 if isinstance(arg2, str) else status
                calc_limit = arg3 if isinstance(arg3, int) else (limit or 20)
                calc_offset = arg4 if isinstance(arg4, int) else (offset or 0)
        elif _is_db_session(arg4):
            # Signature: list_emails(status, limit, offset, db)
            resolved_db = arg4
            status_val = arg1
            calc_limit = arg2 if isinstance(arg2, int) else 20
            calc_offset = arg3 if isinstance(arg3, int) else 0
        else:
            resolved_db = db or kwargs.get("db")
            if isinstance(arg1, str):
                status_val = arg1
            if isinstance(arg2, int):
                calc_limit = arg2
            if isinstance(arg3, int):
                calc_offset = arg3

        if resolved_db is None:
            raise ValueError("An active AsyncSession 'db' must be provided.")

        if page is not None and page_size is not None:
            calc_limit = max(1, page_size)
            calc_offset = max(0, (page - 1) * page_size)

        query = select(Email)
        count_query = select(func.count(Email.id))

        if status_val:
            query = query.where(Email.status == status_val)
            count_query = count_query.where(Email.status == status_val)

        if sender_val:
            query = query.where(Email.sender.ilike(f"%{sender_val}%"))
            count_query = count_query.where(Email.sender.ilike(f"%{sender_val}%"))

        total_res = await resolved_db.execute(count_query)
        total = total_res.scalar() or 0

        query = query.order_by(desc(Email.ingested_at), desc(Email.id)).offset(calc_offset).limit(calc_limit)
        result = await resolved_db.execute(query)
        emails = list(result.scalars().all())

        return emails, total

    async def get_email_with_analysis(
        self,
        email_id_or_db: Optional[Union[AsyncSession, str, UUID]] = None,
        db_or_email_id: Optional[Union[AsyncSession, str, UUID]] = None,
        *,
        email_id: Optional[Union[str, UUID]] = None,
        db: Optional[AsyncSession] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Get an email along with its full analysis result record."""
        if _is_db_session(email_id_or_db):
            resolved_db = email_id_or_db
            resolved_id = db_or_email_id or email_id or kwargs.get("email_id")
        elif _is_db_session(db_or_email_id):
            resolved_db = db_or_email_id
            resolved_id = email_id_or_db or email_id or kwargs.get("email_id")
        else:
            resolved_db = db or kwargs.get("db")
            resolved_id = email_id or kwargs.get("email_id") or email_id_or_db

        if resolved_db is None:
            raise ValueError("An active AsyncSession 'db' must be provided.")

        parsed_uuid = _normalize_uuid(resolved_id)
        if parsed_uuid is None:
            return {"email": None, "analysis": None}

        email_res = await resolved_db.execute(select(Email).where(Email.id == parsed_uuid))
        email = email_res.scalar_one_or_none()

        analysis_res = await resolved_db.execute(
            select(AnalysisResult).where(AnalysisResult.email_id == parsed_uuid)
        )
        analysis = analysis_res.scalar_one_or_none()

        return {"email": email, "analysis": analysis}

    async def delete_email(
        self,
        email_id_or_db: Optional[Union[AsyncSession, str, UUID]] = None,
        db_or_email_id: Optional[Union[AsyncSession, str, UUID]] = None,
        *,
        email_id: Optional[Union[str, UUID]] = None,
        db: Optional[AsyncSession] = None,
        **kwargs: Any,
    ) -> bool:
        """Delete an email and any associated analysis record from the database."""
        if _is_db_session(email_id_or_db):
            resolved_db = email_id_or_db
            resolved_id = db_or_email_id or email_id or kwargs.get("email_id")
        elif _is_db_session(db_or_email_id):
            resolved_db = db_or_email_id
            resolved_id = email_id_or_db or email_id or kwargs.get("email_id")
        else:
            resolved_db = db or kwargs.get("db")
            resolved_id = email_id or kwargs.get("email_id") or email_id_or_db

        if resolved_db is None:
            raise ValueError("An active AsyncSession 'db' must be provided.")

        parsed_uuid = _normalize_uuid(resolved_id)
        if parsed_uuid is None:
            return False

        email = await self.get_email(db=resolved_db, email_id=parsed_uuid)
        if email:
            # Delete dependent analysis if present
            analysis_res = await resolved_db.execute(
                select(AnalysisResult).where(AnalysisResult.email_id == parsed_uuid)
            )
            analysis = analysis_res.scalar_one_or_none()
            if analysis:
                await resolved_db.delete(analysis)

            await resolved_db.delete(email)
            await resolved_db.commit()
            return True
        return False

    async def get_email_stats(self, db: AsyncSession) -> Dict[str, Any]:
        """Calculate aggregate statistics: total emails, analyzed emails, avg risk score."""
        total_query = select(func.count(Email.id))
        total = (await db.execute(total_query)).scalar() or 0

        analyzed_query = select(func.count(Email.id)).where(
            or_(Email.status == EmailStatus.analyzed, Email.status == "analyzed")
        )
        analyzed = (await db.execute(analyzed_query)).scalar() or 0

        avg_query = select(func.avg(AnalysisResult.composite_risk_score))
        avg_risk = (await db.execute(avg_query)).scalar()

        avg_score_val = round(float(avg_risk), 1) if avg_risk is not None else 0.0

        return {
            "total_emails": total,
            "analyzed": analyzed,
            "avg_risk_score": avg_score_val,
        }

