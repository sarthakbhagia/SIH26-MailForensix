import logging
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db, AsyncSessionLocal
from app.models.analysis_result import AnalysisResult
from app.models.email_case import Email, EmailStatus
from app.schemas.analysis import AnalysisResponse, IOCItem, RelayHop, GeoLocation, NLPResult, AuthResult
from app.core.pipeline import AnalysisPipeline

logger = logging.getLogger(__name__)
router = APIRouter()

async def run_pipeline_async(email_id: str):
    """Background task to run full forensic pipeline on an email."""
    try:
        async with AsyncSessionLocal() as session:
            pipeline = AnalysisPipeline()
            await pipeline.run(email_id, session)
    except Exception as e:
        logger.error(f"Error analyzing email {email_id}: {e}", exc_info=True)

async def get_email_record(email_id: UUID, db: AsyncSession) -> Email:
    result = await db.execute(select(Email).filter(Email.id == email_id))
    email = result.scalar_one_or_none()
    if not email:
        raise HTTPException(status_code=404, detail="Email evidence artifact not found")
    return email

async def get_analysis_result_optional(email_id: UUID, db: AsyncSession) -> Optional[AnalysisResult]:
    result = await db.execute(select(AnalysisResult).filter(AnalysisResult.email_id == email_id))
    return result.scalar_one_or_none()

@router.get("/{email_id}", response_model=AnalysisResponse)
async def get_analysis(email_id: UUID, db: AsyncSession = Depends(get_db)):
    email = await get_email_record(email_id, db)
    analysis = await get_analysis_result_optional(email_id, db)

    # 1. If analysis record exists, return analyzed status with full payload
    if analysis:
        nlp_details = analysis.nlp_details if isinstance(analysis.nlp_details, dict) else {}
        graph_data = analysis.graph_data if isinstance(analysis.graph_data, dict) else {}
        attr_evidence = graph_data.get("attribution_evidence_score")

        return AnalysisResponse(
            email_id=analysis.email_id,
            status="analyzed",
            nlp_result=NLPResult(
                label=analysis.nlp_label or "Unknown",
                confidence=analysis.nlp_confidence,
                confidence_calibrated=bool(nlp_details.get("confidence_calibrated", False)),
                confidence_method=nlp_details.get("confidence_method", "rule_heuristic" if analysis.nlp_label else None),
                evidence_score=nlp_details.get("evidence_score", analysis.nlp_confidence),
                details=nlp_details,
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
                auth_confidence_score=(analysis.auth_status or {}).get("auth_confidence_score", None),
                details=analysis.auth_status or {},
            ) if analysis.auth_status else None,
            relay_path=analysis.relay_path or [],
            geo_data=analysis.geo_data or [],
            iocs=analysis.iocs or [],
            composite_risk_score=analysis.composite_risk_score,
            risk_breakdown=analysis.risk_breakdown or {},
            attribution_category=analysis.attribution_category or "Undetermined",
            attribution_confidence=analysis.attribution_confidence,
            attribution_confidence_calibrated=False,
            attribution_evidence_score=attr_evidence,
        )

    # 2. If analysis record does not yet exist, inspect email lifecycle status
    raw_status = email.status.value if hasattr(email.status, "value") else str(email.status or "pending")

    if raw_status in ("pending", "processing"):
        return AnalysisResponse(
            email_id=email.id,
            status=raw_status,
            nlp_result=None,
            auth_result=None,
            relay_path=[],
            geo_data=[],
            iocs=[],
            composite_risk_score=None,
            risk_breakdown=None,
            attribution_category="Undetermined",
            attribution_confidence=None,
        )
    elif raw_status == "error":
        return AnalysisResponse(
            email_id=email.id,
            status="error",
            error_message="Analysis pipeline failed during processing",
            nlp_result=None,
            auth_result=None,
            relay_path=[],
            geo_data=[],
            iocs=[],
            composite_risk_score=None,
            risk_breakdown=None,
            attribution_category=None,
            attribution_confidence=None,
        )
    else:
        # Fallback for unexpected status: treat as pending
        return AnalysisResponse(
            email_id=email.id,
            status="pending",
            nlp_result=None,
            auth_result=None,
            relay_path=[],
            geo_data=[],
            iocs=[],
            composite_risk_score=None,
            risk_breakdown=None,
            attribution_category=None,
            attribution_confidence=None,
        )

@router.post("/{email_id}/retry")
@router.post("/{email_id}/reanalyze")
async def retry_analysis(
    email_id: UUID, 
    background_tasks: BackgroundTasks, 
    db: AsyncSession = Depends(get_db)
):
    email = await get_email_record(email_id, db)
    email.status = EmailStatus.pending
    await db.commit()

    background_tasks.add_task(run_pipeline_async, str(email.id))
    return {
        "status": "pending",
        "email_id": str(email.id),
        "message": "Analysis queued for re-processing",
    }

@router.get("/{email_id}/iocs", response_model=List[IOCItem])
async def get_iocs(email_id: UUID, db: AsyncSession = Depends(get_db)):
    await get_email_record(email_id, db)
    analysis = await get_analysis_result_optional(email_id, db)
    if not analysis or not analysis.iocs:
        return []
    return analysis.iocs

@router.get("/{email_id}/relay-path", response_model=List[RelayHop])
async def get_relay_path(email_id: UUID, db: AsyncSession = Depends(get_db)):
    await get_email_record(email_id, db)
    analysis = await get_analysis_result_optional(email_id, db)
    if not analysis or not analysis.relay_path:
        return []
    return analysis.relay_path

@router.get("/{email_id}/geo", response_model=List[GeoLocation])
async def get_geo_data(email_id: UUID, db: AsyncSession = Depends(get_db)):
    await get_email_record(email_id, db)
    analysis = await get_analysis_result_optional(email_id, db)
    if not analysis or not analysis.geo_data:
        return []
    return analysis.geo_data