import logging
from fastapi import APIRouter, UploadFile, File, Depends, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import UUID
from app.database import get_db, AsyncSessionLocal
from app.core.pipeline import AnalysisPipeline
from app.schemas.email import EmailUploadResponse, EmailListResponse, EmailDetail
from app.services.email_service import EmailService
from app.workers.tasks import analyze_email_task

logger = logging.getLogger(__name__)
router = APIRouter()
email_service = EmailService()

async def run_pipeline_async(email_id: str):
    try:
        async with AsyncSessionLocal() as session:
            pipeline = AnalysisPipeline()
            await pipeline.run(email_id, session)
    except Exception as e:
        logger.error(f"Error analyzing email {email_id}: {e}", exc_info=True)

@router.post("/upload", response_model=EmailUploadResponse)
async def upload_email(
    file: UploadFile = File(...), 
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: AsyncSession = Depends(get_db)
):
    raw_bytes = await file.read()
    email = await email_service.ingest_email(db, raw_bytes)
    
    try:
        analyze_email_task.delay(str(email.id))
    except Exception:
        pass
    background_tasks.add_task(run_pipeline_async, str(email.id))
    
    return EmailUploadResponse(
        email_id=email.id,
        status=email.status,
        hashes={"sha256": email.raw_hash_sha256, "md5": email.raw_hash_md5, "sha1": email.raw_hash_sha1},
        ingested_at=email.ingested_at
    )

@router.post("/batch", response_model=List[EmailUploadResponse])
@router.post("/upload-batch", response_model=List[EmailUploadResponse])
async def upload_batch(
    files: List[UploadFile] = File(...), 
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: AsyncSession = Depends(get_db)
):
    responses = []
    for file in files:
        raw_bytes = await file.read()
        email = await email_service.ingest_email(db, raw_bytes)
        try:
            analyze_email_task.delay(str(email.id))
        except Exception:
            pass
        background_tasks.add_task(run_pipeline_async, str(email.id))
        responses.append(
            EmailUploadResponse(
                email_id=email.id,
                status=email.status,
                hashes={"sha256": email.raw_hash_sha256},
                ingested_at=email.ingested_at
            )
        )
    return responses


@router.get("", response_model=EmailListResponse)
@router.get("/", response_model=EmailListResponse)
async def list_emails(
    page: int = 1, 
    page_size: int = 20, 
    status: str = Query(None), 
    sender: str = Query(None), 
    db: AsyncSession = Depends(get_db)
):
    filters = {"status": status, "sender": sender}
    items, total = await email_service.list_emails(db, page, page_size, filters)
    return EmailListResponse(items=items, total=total, page=page, page_size=page_size)

@router.get("/{email_id}", response_model=EmailDetail)
async def get_email(email_id: UUID, db: AsyncSession = Depends(get_db)):
    return await email_service.get_email(db, email_id)
