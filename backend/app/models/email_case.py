import enum
from sqlalchemy import Column, String, Float, ForeignKey, DateTime, Enum, LargeBinary
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime
from app.database import Base

class EmailStatus(str, enum.Enum):
    pending = "pending"
    processing = "processing"
    analyzed = "analyzed"
    error = "error"

class CaseStatus(str, enum.Enum):
    open = "open"
    investigating = "investigating"
    closed = "closed"

class CaseSeverity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class Email(Base):
    __tablename__ = "emails"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    raw_hash_sha256 = Column(String)
    raw_hash_sha1 = Column(String)
    raw_hash_md5 = Column(String)
    sender = Column(String)
    recipients = Column(JSONB)
    subject = Column(String)
    body_text = Column(String)
    body_html = Column(String)
    headers = Column(JSONB)
    attachments = Column(JSONB)
    urls = Column(JSONB)
    raw_eml = Column(LargeBinary)
    ingested_at = Column(DateTime, default=datetime.utcnow)
    status = Column(Enum(EmailStatus))

class Case(Base):
    __tablename__ = "cases"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String)
    description = Column(String)
    status = Column(Enum(CaseStatus))
    severity = Column(Enum(CaseSeverity))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    assigned_to = Column(String)

class CaseEmail(Base):
    __tablename__ = "case_emails"
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id"), primary_key=True)
    email_id = Column(UUID(as_uuid=True), ForeignKey("emails.id"), primary_key=True)

class CaseNote(Base):
    __tablename__ = "case_notes"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id"))
    author = Column(String)
    content = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
