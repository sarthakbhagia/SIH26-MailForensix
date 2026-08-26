from pydantic import BaseModel
from typing import List, Optional, Dict, Any, Union
from uuid import UUID

class NLPResult(BaseModel):
    label: str
    confidence: float
    details: Dict[str, Any] = {}

class AuthResult(BaseModel):
    spf_status: str = "none"
    dkim_status: str = "none"
    dmarc_status: str = "none"
    details: Dict[str, Any] = {}

class GeoLocation(BaseModel):
    ip: Optional[str] = ""
    country: Optional[str] = "Unknown"
    country_code: Optional[str] = "?"
    region: Optional[str] = "Unknown"
    city: Optional[str] = "Unknown"
    latitude: Optional[float] = 0.0
    longitude: Optional[float] = 0.0
    isp: Optional[str] = "Unknown"
    asn: Optional[str] = "?"
    org: Optional[str] = "Unknown"
    confidence: Optional[Union[str, float]] = "low"
    infrastructure_type: Optional[str] = "residential"

class RelayHop(BaseModel):
    hop_number: Optional[int] = 1
    ip: Optional[str] = ""
    hostname: Optional[str] = ""
    from_host: Optional[str] = ""
    by_host: Optional[str] = ""
    timestamp: Optional[str] = ""
    protocol: Optional[str] = ""
    delay_seconds: Optional[float] = 0.0
    geo: Optional[GeoLocation] = None

class IOCItem(BaseModel):
    type: Optional[str] = "unknown" # ip/url/domain/hash
    value: Optional[str] = ""
    risk_score: Optional[float] = 0.0
    reason: Optional[str] = ""
    source: Optional[str] = "pipeline"

class AnalysisResponse(BaseModel):
    email_id: UUID
    nlp_result: Optional[NLPResult]
    auth_result: Optional[AuthResult]
    relay_path: Optional[List[RelayHop]]
    geo_data: Optional[List[GeoLocation]]
    iocs: Optional[List[IOCItem]]
    composite_risk_score: Optional[float] = None
    risk_breakdown: Optional[Dict[str, Any]] = None
    attribution_category: Optional[str] = None
    attribution_confidence: Optional[float] = None
