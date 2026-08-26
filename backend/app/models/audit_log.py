from sqlalchemy import Column, String, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid
from datetime import datetime
from app.database import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    previous_hash = Column(String)
    entry_hash = Column(String)
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id"), nullable=True)
    email_id = Column(UUID(as_uuid=True), ForeignKey("emails.id"), nullable=True)
    user_id = Column(String, nullable=True)
    action = Column(String)
    action_data = Column(JSONB)
    timestamp = Column(DateTime, default=datetime.utcnow)
