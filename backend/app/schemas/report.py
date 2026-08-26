from pydantic import BaseModel
from datetime import datetime
from uuid import UUID

class ReportRequest(BaseModel):
    email_id: UUID
    format: str # pdf/json

class ReportMetadata(BaseModel):
    report_id: UUID
    email_id: UUID
    generated_at: datetime
    format: str
    download_url: str
