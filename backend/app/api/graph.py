import logging
from dataclasses import asdict
from typing import Any, Dict, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db
from app.models.analysis_result import AnalysisResult
from app.models.email_case import Email
from app.core.correlation.graph_engine import GraphEngine
from app.core.correlation.campaign_cluster import CampaignClusterer

logger = logging.getLogger(__name__)

router = APIRouter(tags=["graph"])


async def _fetch_emails_and_analysis(db: AsyncSession) -> tuple[List[dict], List[dict]]:
    """Helper to fetch emails and their analysis records from database safely."""
    email_res = await db.execute(select(Email))
    emails_db = email_res.scalars().all()

    analysis_res = await db.execute(select(AnalysisResult))
    analyses_db = analysis_res.scalars().all()

    emails_data = []
    for em in emails_db:
        emails_data.append({
            "id": str(em.id),
            "subject": em.subject or "No Subject",
            "sender": em.sender or "unknown",
            "body_text": em.body_text or "",
            "ingested_at": em.ingested_at.isoformat() if em.ingested_at else None,
            "status": str(em.status.value) if hasattr(em.status, "value") else str(em.status or "pending"),
        })

    analyses_data = []
    for a in analyses_db:
        analyses_data.append({
            "id": str(a.id),
            "email_id": str(a.email_id),
            "nlp_label": a.nlp_label or "Unknown",
            "nlp_confidence": a.nlp_confidence or 0.0,
            "relay_path": a.relay_path or [],
            "geo_data": a.geo_data or [],
            "domain_intel": a.domain_intel or {},
            "composite_risk_score": a.composite_risk_score or 0.0,
            "attribution_category": a.attribution_category,
            "analyzed_at": a.analyzed_at.isoformat() if a.analyzed_at else None,
        })

    return emails_data, analyses_data


@router.get("/")
async def get_full_graph(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Get the full attribution graph across all analyzed emails, including detected campaign clusters."""
    emails, analyses = await _fetch_emails_and_analysis(db)
    
    engine = GraphEngine()
    graph_obj = engine.build_graph(emails, analyses)

    clusterer = CampaignClusterer()
    campaigns = clusterer.cluster(engine.graph, emails, analyses)

    json_graph = engine.to_json()
    stats = {
        **graph_obj.graph_stats,
        "email_count": len(emails),
        "campaign_count": len(campaigns),
    }

    return {
        "nodes": json_graph["nodes"],
        "links": json_graph["links"],
        "stats": stats,
        "campaigns": [asdict(c) for c in campaigns],
        "shared_infrastructure": engine.find_shared_infrastructure(),
    }


@router.get("/email/{email_id}")
async def get_email_graph(email_id: str, db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Get the attribution subgraph for a specific email and its 2-hop connected entities."""
    emails, analyses = await _fetch_emails_and_analysis(db)

    engine = GraphEngine()
    engine.build_graph(emails, analyses)

    clusterer = CampaignClusterer()
    clusterer.cluster(engine.graph, emails, analyses)

    subgraph = engine.get_subgraph_for_email(email_id, hops=2)
    if not subgraph["nodes"]:
        raise HTTPException(status_code=404, detail=f"Email {email_id} not found in attribution graph")

    return subgraph


@router.get("/campaigns")
async def get_campaigns(db: AsyncSession = Depends(get_db)) -> List[Dict[str, Any]]:
    """Get all detected campaign clusters with their member emails and shared infrastructure."""
    emails, analyses = await _fetch_emails_and_analysis(db)

    engine = GraphEngine()
    engine.build_graph(emails, analyses)

    clusterer = CampaignClusterer()
    campaigns = clusterer.cluster(engine.graph, emails, analyses)

    return [asdict(c) for c in campaigns]


@router.get("/campaigns/{campaign_id}")
async def get_campaign_detail(campaign_id: str, db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Get detailed information for a specific campaign cluster."""
    emails, analyses = await _fetch_emails_and_analysis(db)

    engine = GraphEngine()
    engine.build_graph(emails, analyses)

    clusterer = CampaignClusterer()
    campaigns = clusterer.cluster(engine.graph, emails, analyses)

    matched = next((c for c in campaigns if c.campaign_id == campaign_id), None)
    if not matched:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")

    # Build subgraph for campaign
    camp_node_id = f"campaign:{campaign_id}"
    camp_subgraph = engine.get_subgraph_for_email(camp_node_id, hops=2)

    return {
        "campaign": asdict(matched),
        "subgraph": camp_subgraph,
    }


@router.get("/node/{node_id:path}/connections")
async def get_node_connections(node_id: str, db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Get all connections and relationships for a specific graph node (IP, domain, ASN, etc.)."""
    emails, analyses = await _fetch_emails_and_analysis(db)

    engine = GraphEngine()
    engine.build_graph(emails, analyses)

    clusterer = CampaignClusterer()
    clusterer.cluster(engine.graph, emails, analyses)

    connections = engine.get_node_connections(node_id)
    if not connections and not engine.graph.has_node(node_id):
        raise HTTPException(status_code=404, detail=f"Node {node_id} not found in graph")

    return {
        "node_id": node_id,
        "connections": [asdict(c) for c in connections],
        "degree": len(connections),
    }
