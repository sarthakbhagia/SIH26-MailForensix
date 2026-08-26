from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import UUID
from app.models.alert import AlertSeverity


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email_id: Optional[UUID] = None
    severity: AlertSeverity
    message: str
    risk_score: float
    contributing_factors: Optional[Dict[str, Any]] = None
    acknowledged: bool
    created_at: datetime


class AlertListResponse(BaseModel):
    items: List[AlertResponse]
    total: int


class AlertStatsResponse(BaseModel):
    total: int
    unacknowledged: int
    critical: int


class AlertAcknowledgeResponse(BaseModel):
    status: str
    alert_id: UUID
    acknowledged: bool

