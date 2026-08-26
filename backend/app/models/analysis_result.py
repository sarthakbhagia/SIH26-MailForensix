from sqlalchemy import Column, String, Float, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid
from datetime import datetime
from app.database import Base

class AnalysisResult(Base):
    __tablename__ = "analysis_results"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_id = Column(UUID(as_uuid=True), ForeignKey("emails.id"), unique=True)
    nlp_label = Column(String)
    nlp_confidence = Column(Float)
    nlp_details = Column(JSONB)
    auth_status = Column(JSONB)
    relay_path = Column(JSONB)
    geo_data = Column(JSONB)
    ip_reputation = Column(JSONB)
    domain_intel = Column(JSONB)
    iocs = Column(JSONB)
    composite_risk_score = Column(Float)
    risk_breakdown = Column(JSONB)
    attribution_category = Column(String)
    attribution_confidence = Column(Float)
    graph_data = Column(JSONB)
    analyzed_at = Column(DateTime, default=datetime.utcnow)
