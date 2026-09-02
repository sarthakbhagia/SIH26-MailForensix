import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.alert import Alert
from app.models.analysis_result import AnalysisResult
from app.models.email_case import Case, CaseStatus, Email
from app.core.utils.timezone import now_ist, to_ist, to_utc

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Return aggregated SOC dashboard metrics, threat distributions, risk breakdowns, and 7-day ingestion timeline in IST."""
    try:
        # 1. Total emails count
        total_emails_res = await db.execute(select(func.count(Email.id)))
        total_emails = total_emails_res.scalar() or 0

        # 2. Active cases (open + investigating)
        active_cases_res = await db.execute(
            select(func.count(Case.id)).where(
                Case.status.in_([CaseStatus.open, CaseStatus.investigating])
            )
        )
        active_cases = active_cases_res.scalar() or 0

        # 3. Threats detected (composite_risk_score > 50)
        threats_res = await db.execute(
            select(func.count(AnalysisResult.id)).where(
                AnalysisResult.composite_risk_score > 50.0
            )
        )
        threats_detected = threats_res.scalar() or 0

        # 4. Average composite risk score
        avg_score_res = await db.execute(
            select(func.avg(AnalysisResult.composite_risk_score))
        )
        avg_raw = avg_score_res.scalar()
        avg_risk_score = round(float(avg_raw), 1) if avg_raw is not None else 0.0

        # 5. Unacknowledged alerts count
        unack_res = await db.execute(
            select(func.count(Alert.id)).where(Alert.acknowledged.is_(False))
        )
        unacknowledged_alerts = unack_res.scalar() or 0

        # 6. Threat distribution by NLP classification label (strictly normalized & deduplicated)
        dist_res = await db.execute(
            select(AnalysisResult.nlp_label, func.count(AnalysisResult.id))
            .group_by(AnalysisResult.nlp_label)
        )
        threat_distribution: Dict[str, int] = {}
        for row in dist_res.all():
            raw_label = str(row[0] or "").strip()
            if not raw_label:
                normalized_label = "UNCLASSIFIED"
            else:
                cleaned = raw_label.upper().replace("/", "_").replace("-", "_").replace(" ", "_")
                if cleaned in ("LEGITIMATE", "CLEAN", "BENIGN", "SAFE"):
                    normalized_label = "LEGITIMATE"
                elif cleaned in ("SUSPICIOUS", "ANOMALOUS"):
                    normalized_label = "SUSPICIOUS"
                elif cleaned in ("PHISHING", "PHISH"):
                    normalized_label = "PHISHING"
                elif cleaned in ("BEC_FRAUD", "BEC", "FRAUD"):
                    normalized_label = "BEC_FRAUD"
                elif cleaned in ("IMPERSONATION", "SPOOF", "SPOOFING"):
                    normalized_label = "IMPERSONATION"
                else:
                    normalized_label = cleaned

            count = int(row[1] or 0)
            threat_distribution[normalized_label] = threat_distribution.get(normalized_label, 0) + count

        # 7. Risk distribution (low <=25, medium <=50, high <=75, critical >75)
        risk_dist_res = await db.execute(
            select(
                func.count(case((AnalysisResult.composite_risk_score <= 25.0, 1))),
                func.count(
                    case(
                        (
                            (AnalysisResult.composite_risk_score > 25.0)
                            & (AnalysisResult.composite_risk_score <= 50.0),
                            1,
                        )
                    )
                ),
                func.count(
                    case(
                        (
                            (AnalysisResult.composite_risk_score > 50.0)
                            & (AnalysisResult.composite_risk_score <= 75.0),
                            1,
                        )
                    )
                ),
                func.count(case((AnalysisResult.composite_risk_score > 75.0, 1))),
            )
        )
        risk_row = risk_dist_res.first()
        risk_distribution = {
            "low": int(risk_row[0] if risk_row else 0),
            "medium": int(risk_row[1] if risk_row else 0),
            "high": int(risk_row[2] if risk_row else 0),
            "critical": int(risk_row[3] if risk_row else 0),
        }

        # 8. Ingestion timeline (last 7 days in IST, daily buckets)
        now_ist_dt = now_ist()
        start_ist_date = (now_ist_dt - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
        start_utc_dt = to_utc(start_ist_date).replace(tzinfo=None)

        # Initialize contiguous 7-day timeline map with IST dates
        timeline_map: Dict[str, Dict[str, Any]] = {}
        for i in range(7):
            d = (start_ist_date + timedelta(days=i)).strftime("%Y-%m-%d")
            timeline_map[d] = {"date": d, "ingested": 0, "threats": 0}

        # Fetch emails from start date with composite risk score
        timeline_stmt = (
            select(Email.ingested_at, AnalysisResult.composite_risk_score)
            .outerjoin(AnalysisResult, AnalysisResult.email_id == Email.id)
            .where(Email.ingested_at >= start_utc_dt)
        )
        timeline_res = await db.execute(timeline_stmt)
        for ingested_at, score in timeline_res.all():
            if ingested_at:
                d_str = to_ist(ingested_at).strftime("%Y-%m-%d")
                if d_str in timeline_map:
                    timeline_map[d_str]["ingested"] += 1
                    if score is not None and score > 50.0:
                        timeline_map[d_str]["threats"] += 1

        ingestion_timeline: List[Dict[str, Any]] = list(timeline_map.values())
        ingestion_timeline.sort(key=lambda x: x["date"])

        return {
            "total_emails": total_emails,
            "threats_detected": threats_detected,
            "active_cases": active_cases,
            "avg_risk_score": avg_risk_score,
            "unacknowledged_alerts": unacknowledged_alerts,
            "threat_distribution": threat_distribution,
            "risk_distribution": risk_distribution,
            "ingestion_timeline": ingestion_timeline,
        }
    except Exception as e:
        logger.error(f"Failed to aggregate dashboard stats: {e}", exc_info=True)
        raise

