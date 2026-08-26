from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from datetime import datetime
from uuid import UUID
from app.models.email_case import CaseStatus, CaseSeverity

class CaseCreate(BaseModel):
    title: str
    description: str
    severity: CaseSeverity

class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[CaseStatus] = None
    severity: Optional[CaseSeverity] = None
    assigned_to: Optional[str] = None

class CaseNoteCreate(BaseModel):
    content: str
    author: str

class CaseNoteResponse(BaseModel):
    id: UUID
    author: str
    content: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class CaseResponse(BaseModel):
    id: UUID
    title: str
    description: str
    status: CaseStatus
    severity: CaseSeverity
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str]
    email_ids: List[UUID]
    notes: List[CaseNoteResponse]
    model_config = ConfigDict(from_attributes=True)
