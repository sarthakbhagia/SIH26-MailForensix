from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import UUID
from app.models.email_case import EmailStatus

class EmailUploadResponse(BaseModel):
    case_id: Optional[UUID] = None
    email_id: UUID
    status: EmailStatus
    hashes: Dict[str, str]
    ingested_at: datetime
    model_config = ConfigDict(from_attributes=True)

class EmailSummary(BaseModel):
    id: UUID
    sender: Optional[str]
    subject: Optional[str]
    ingested_at: datetime
    status: EmailStatus
    risk_score: Optional[float] = None
    model_config = ConfigDict(from_attributes=True)

class EmailDetail(BaseModel):
    id: UUID
    sender: Optional[str]
    recipients: Optional[Any]
    subject: Optional[str]
    body_text: Optional[str]
    body_html: Optional[str]
    headers: Optional[Dict[str, Any]]
    attachments: Optional[Any]
    urls: Optional[Any]
    ingested_at: datetime
    status: EmailStatus
    model_config = ConfigDict(from_attributes=True)

class EmailListResponse(BaseModel):
    items: List[EmailSummary]
    total: int
    page: int
    page_size: int
