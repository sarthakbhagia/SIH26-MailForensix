from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.case import (
    CaseCreate,
    CaseNoteCreate,
    CaseNoteResponse,
    CaseResponse,
    CaseUpdate,
)
from app.services.case_service import CaseService

router = APIRouter()
case_service = CaseService()


@router.post("", response_model=CaseResponse, status_code=201)
@router.post("/", response_model=CaseResponse, status_code=201)
async def create_case(case: CaseCreate, db: AsyncSession = Depends(get_db)):
    result = await case_service.create_case(db, case)
    result.email_ids = []
    result.notes = []
    return result


@router.get("", response_model=List[CaseResponse])
@router.get("/", response_model=List[CaseResponse])
async def list_cases(
    status: Optional[str] = Query(None, description="Filter by case status: open, investigating, closed"),
    severity: Optional[str] = Query(None, description="Filter by severity: low, medium, high, critical"),
    limit: int = Query(50, ge=1, le=200, description="Max cases to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: AsyncSession = Depends(get_db),
):
    cases = await case_service.list_cases(
        db, status=status, severity=severity, limit=limit, offset=offset
    )
    for c in cases:
        emails = await case_service.get_case_emails(db, c.id)
        c.email_ids = [e.id for e in emails]
        c.notes = await case_service.get_case_notes(db, c.id)
    return cases


@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(case_id: UUID, db: AsyncSession = Depends(get_db)):
    case = await case_service.get_case(db, case_id)
    emails = await case_service.get_case_emails(db, case.id)
    case.email_ids = [e.id for e in emails]
    case.notes = await case_service.get_case_notes(db, case_id)
    return case


@router.put("/{case_id}", response_model=CaseResponse)
async def update_case(case_id: UUID, case: CaseUpdate, db: AsyncSession = Depends(get_db)):
    c = await case_service.update_case(db, case_id, case)
    emails = await case_service.get_case_emails(db, c.id)
    c.email_ids = [e.id for e in emails]
    c.notes = await case_service.get_case_notes(db, case_id)
    return c


@router.delete("/{case_id}")
async def delete_case(case_id: UUID, db: AsyncSession = Depends(get_db)):
    await case_service.delete_case(db, case_id)
    return {"status": "deleted", "case_id": str(case_id)}


@router.post("/{case_id}/emails/{email_id}")
async def link_email(case_id: UUID, email_id: UUID, db: AsyncSession = Depends(get_db)):
    await case_service.add_email_to_case(db, case_id, email_id)
    return {"status": "linked", "case_id": str(case_id), "email_id": str(email_id)}


@router.delete("/{case_id}/emails/{email_id}")
async def unlink_email(case_id: UUID, email_id: UUID, db: AsyncSession = Depends(get_db)):
    await case_service.remove_email_from_case(db, case_id, email_id)
    return {"status": "unlinked", "case_id": str(case_id), "email_id": str(email_id)}


@router.post("/{case_id}/notes", response_model=CaseNoteResponse, status_code=201)
async def add_note(case_id: UUID, note: CaseNoteCreate, db: AsyncSession = Depends(get_db)):
    return await case_service.add_note(db, case_id, note)


@router.get("/{case_id}/notes", response_model=List[CaseNoteResponse])
async def list_notes(case_id: UUID, db: AsyncSession = Depends(get_db)):
    return await case_service.get_case_notes(db, case_id)


@router.get("/{case_id}/emails")
async def list_case_emails(case_id: UUID, db: AsyncSession = Depends(get_db)):
    emails = await case_service.get_case_emails(db, case_id)
    return [
        {
            "id": str(e.id),
            "sender": e.sender,
            "subject": e.subject,
            "status": str(e.status),
            "ingested_at": e.ingested_at.isoformat() if e.ingested_at else None,
            "raw_hash_sha256": e.raw_hash_sha256,
        }
        for e in emails
    ]


@router.get("/{case_id}/timeline")
async def get_case_timeline(case_id: UUID, db: AsyncSession = Depends(get_db)):
    return await case_service.get_case_timeline(db, case_id)


