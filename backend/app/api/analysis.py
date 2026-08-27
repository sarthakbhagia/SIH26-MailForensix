from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from uuid import UUID
from app.database import get_db
from app.models.analysis_result import AnalysisResult
from app.schemas.analysis import AnalysisResponse, IOCItem, RelayHop, GeoLocation, NLPResult, AuthResult
from typing import List

router = APIRouter()

async def get_analysis_result(email_id: UUID, db: AsyncSession) -> AnalysisResult:
    result = await db.execute(select(AnalysisResult).filter(AnalysisResult.email_id == email_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis

@router.get("/{email_id}", response_model=AnalysisResponse)
async def get_analysis(email_id: UUID, db: AsyncSession = Depends(get_db)):
    analysis = await get_analysis_result(email_id, db)
    return AnalysisResponse(
        email_id=analysis.email_id,
        nlp_result=NLPResult(
            label=analysis.nlp_label or "Unknown",
            confidence=analysis.nlp_confidence or 0.0,
            details=analysis.nlp_details or {}
        ) if analysis.nlp_label else None,
        auth_result=AuthResult(
            spf_status=(analysis.auth_status or {}).get("spf_status") or (analysis.auth_status or {}).get("spf", "none"),
            spf_domain=(analysis.auth_status or {}).get("spf_domain", ""),
            spf_ip=(analysis.auth_status or {}).get("spf_ip", ""),
            spf_record=(analysis.auth_status or {}).get("spf_record", ""),
            spf_details=(analysis.auth_status or {}).get("spf_details", ""),
            dkim_status=(analysis.auth_status or {}).get("dkim_status") or (analysis.auth_status or {}).get("dkim", "none"),
            dkim_domain=(analysis.auth_status or {}).get("dkim_domain", ""),
            dkim_selector=(analysis.auth_status or {}).get("dkim_selector", ""),
            dkim_details=(analysis.auth_status or {}).get("dkim_details", ""),
            dmarc_status=(analysis.auth_status or {}).get("dmarc_status") or (analysis.auth_status or {}).get("dmarc", "none"),
            dmarc_policy=(analysis.auth_status or {}).get("dmarc_policy") or (analysis.auth_status or {}).get("policy", "none"),
            dmarc_domain=(analysis.auth_status or {}).get("dmarc_domain", ""),
            dmarc_record=(analysis.auth_status or {}).get("dmarc_record", ""),
            dmarc_details=(analysis.auth_status or {}).get("dmarc_details", ""),
            alignment_spf=(analysis.auth_status or {}).get("alignment_spf", False),
            alignment_dkim=(analysis.auth_status or {}).get("alignment_dkim", False),
            auth_confidence_score=(analysis.auth_status or {}).get("auth_confidence_score", 100.0),
            details=analysis.auth_status or {},
        ) if analysis.auth_status else None,
        relay_path=analysis.relay_path or [],
        geo_data=analysis.geo_data or [],
        iocs=analysis.iocs or [],
        composite_risk_score=analysis.composite_risk_score or 0.0,
        risk_breakdown=analysis.risk_breakdown or {},
        attribution_category=analysis.attribution_category or "Unknown",
        attribution_confidence=analysis.attribution_confidence or 0.0
    )

@router.get("/{email_id}/iocs", response_model=List[IOCItem])
async def get_iocs(email_id: UUID, db: AsyncSession = Depends(get_db)):
    analysis = await get_analysis_result(email_id, db)
    return analysis.iocs or []

@router.get("/{email_id}/relay-path", response_model=List[RelayHop])
async def get_relay_path(email_id: UUID, db: AsyncSession = Depends(get_db)):
    analysis = await get_analysis_result(email_id, db)
    return analysis.relay_path or []

@router.get("/{email_id}/geo", response_model=List[GeoLocation])
async def get_geo_data(email_id: UUID, db: AsyncSession = Depends(get_db)):
    analysis = await get_analysis_result(email_id, db)
    return analysis.geo_data or []