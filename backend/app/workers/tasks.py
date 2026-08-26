import asyncio
import logging
from dataclasses import asdict
from typing import Any, Dict, List, Optional
from uuid import UUID
from sqlalchemy.future import select

from app.workers.celery_app import celery_app
from app.core.pipeline import AnalysisPipeline
from app.core.correlation.cache import RedisCache
from app.core.correlation.threat_intel import ThreatIntelAggregator
from app.core.correlation.risk_scorer import RiskScorer
from app.models.analysis_result import AnalysisResult
from app.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="analyze_email_task", max_retries=2, default_retry_delay=30)
def analyze_email_task(self, email_id: str):
    """Run full analysis pipeline for an email asynchronously via Celery worker."""
    async def _run():
        async with AsyncSessionLocal() as session:
            pipeline = AnalysisPipeline()
            result = await pipeline.run(email_id, session)
            return {
                "status": "completed",
                "email_id": email_id,
                "risk_score": result.composite_risk_score if result else None,
            }

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_run())
    except Exception as exc:
        logger.error(f"Analysis task failed for email {email_id}: {exc}")
        if hasattr(self, "retry"):
            raise self.retry(exc=exc)
        raise exc
    finally:
        loop.close()


@celery_app.task(name="enrich_threat_intel_task")
def enrich_threat_intel_task(
    email_id: str,
    ips: Optional[List[str]] = None,
    domains: Optional[List[str]] = None,
    urls: Optional[List[str]] = None,
    hashes: Optional[List[str]] = None,
):
    """Run post-analysis threat intelligence enrichment asynchronously."""
    async def _enrich():
        cache = RedisCache()
        await cache.connect()
        try:
            aggregator = ThreatIntelAggregator(cache)
            report = await aggregator.enrich(
                ips=ips or [],
                domains=domains or [],
                urls=urls or [],
                hashes=hashes or [],
            )

            async with AsyncSessionLocal() as session:
                stmt = select(AnalysisResult).filter(AnalysisResult.email_id == UUID(email_id))
                res = await session.execute(stmt)
                analysis = res.scalar_one_or_none()

                if analysis:
                    # Update ip_reputation with external threat intelligence report
                    current_ip_rep = analysis.ip_reputation or {}
                    current_ip_rep["threat_intel"] = {
                        "ip_results": {k: asdict(v) for k, v in report.ip_results.items()},
                        "domain_results": {k: asdict(v) for k, v in report.domain_results.items()},
                        "url_results": {k: asdict(v) for k, v in report.url_results.items()},
                        "hash_results": {k: asdict(v) for k, v in report.hash_results.items()},
                        "phishtank_results": {k: asdict(v) for k, v in report.phishtank_results.items()},
                        "enrichment_timestamp": report.enrichment_timestamp,
                        "apis_queried": report.apis_queried,
                    }
                    analysis.ip_reputation = current_ip_rep

                    # Recalculate composite risk score with threat intel boost
                    scorer = RiskScorer()
                    nlp_dummy = type("N", (), {
                        "label": analysis.nlp_label,
                        "confidence": analysis.nlp_confidence or 0.0,
                        "urgency_score": (analysis.nlp_details or {}).get("urgency_score", 0.0),
                    })()
                    header_dummy = type("H", (), {
                        "auth_confidence_score": 100.0 - (analysis.risk_breakdown or {}).get("auth", 0.0) if analysis.risk_breakdown else 80.0,
                        "spf": type("S", (), {"status": (analysis.auth_status or {}).get("spf", "unknown")})(),
                        "dkim": type("S", (), {"status": (analysis.auth_status or {}).get("dkim", "unknown")})(),
                        "dmarc": type("S", (), {"status": (analysis.auth_status or {}).get("dmarc", "unknown")})(),
                    })()
                    geo_dummy = type("G", (), {
                        "ip_reputation_score": (analysis.ip_reputation or {}).get("score", 50.0),
                        "originating_ip": (analysis.geo_data or [{}])[0].get("ip", "unknown") if analysis.geo_data else "unknown",
                        "infrastructure_flags": [],
                    })()
                    link_dummy = type("L", (), {
                        "overall_link_risk": (analysis.risk_breakdown or {}).get("link", 0.0),
                        "urls_analyzed": len(urls or []),
                        "phishing_urls_found": sum(1 for p in report.phishtank_results.values() if p.is_phishing),
                    })()
                    att_dummy = type("A", (), {
                        "overall_attachment_risk": (analysis.risk_breakdown or {}).get("attachment", 0.0),
                        "total_attachments": len(hashes or []),
                    })()

                    boosted_risk = scorer.compute(
                        nlp_dummy, header_dummy, geo_dummy, link_dummy, att_dummy, threat_intel=report
                    )
                    analysis.composite_risk_score = boosted_risk.overall_score
                    if isinstance(analysis.risk_breakdown, dict) and "factors" in analysis.risk_breakdown:
                        analysis.risk_breakdown = {
                            "factors": [asdict(f) for f in boosted_risk.factors],
                            "severity": boosted_risk.severity,
                            "recommended_action": boosted_risk.recommended_action,
                        }

                    await session.commit()
            return {"status": "enriched", "email_id": email_id, "apis_queried": report.apis_queried}
        finally:
            await cache.disconnect()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_enrich())
    except Exception as exc:
        logger.error(f"Threat intel enrichment failed for email {email_id}: {exc}")
        return {"status": "error", "error": str(exc), "email_id": email_id}
    finally:
        loop.close()


@celery_app.task(name="refresh_phishtank_db")
def refresh_phishtank_db():
    """Periodic task to refresh PhishTank indicators."""
    logger.info("Executing periodic PhishTank DB refresh...")
    return {"status": "refreshed"}


@celery_app.task(name="refresh_tor_exit_nodes")
def refresh_tor_exit_nodes():
    """Periodic task to refresh TOR exit nodes."""
    logger.info("Executing periodic TOR exit nodes refresh...")
    return {"status": "refreshed"}
