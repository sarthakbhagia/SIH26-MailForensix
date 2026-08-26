import enum
from sqlalchemy import Column, String, Float, ForeignKey, DateTime, Enum, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid
from datetime import datetime
from app.database import Base

class AlertSeverity(enum.Enum):
    info = "info"
    warning = "warning"
    high = "high"
    critical = "critical"

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_id = Column(UUID(as_uuid=True), ForeignKey("emails.id"))
    severity = Column(Enum(AlertSeverity))
    message = Column(String)
    risk_score = Column(Float)
    contributing_factors = Column(JSONB)
    acknowledged = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
