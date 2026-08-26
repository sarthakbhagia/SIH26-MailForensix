import os
from pathlib import Path
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from uuid import uuid4
from datetime import datetime, timezone

from app.core.pipeline import AnalysisPipeline
from app.core.correlation.graph_engine import GraphEngine
from app.core.correlation.campaign_cluster import CampaignClusterer
from app.core.correlation.risk_scorer import RiskScorer
from app.models.email_case import Email, EmailStatus
from app.models.analysis_result import AnalysisResult
from app.core.analysis.header_forensics import HeaderForensicsResult, SPFResult, DKIMResult, DMARCResult, RelayHop
from app.core.analysis.geo_intel import GeoIntelResult, IPGeoResult, DomainIntelResult
from app.core.analysis.link_analyzer import LinkAnalysisResult
from app.core.analysis.attachment_analyzer import AttachmentAnalysisReport

# Path to email-threat-intel/sample_emails
SAMPLE_DIR = Path(__file__).resolve().parent.parent.parent / "sample_emails"


def test_sample_emails_exist():
    """Verify curated test .eml sample fixtures are present."""
    assert (SAMPLE_DIR / "sample_phishing.eml").exists()
    assert (SAMPLE_DIR / "sample_bec_fraud.eml").exists()
    assert (SAMPLE_DIR / "sample_legit_newsletter.eml").exists()


@pytest.mark.asyncio
async def test_e2e_phishing_email_pipeline():
    """Test 1: Known phishing email produces Phishing/Suspicious label and risk score >= 50."""
    phish_path = SAMPLE_DIR / "sample_phishing.eml"
    with open(phish_path, "rb") as f:
        eml_bytes = f.read()

    test_id = uuid4()
    mock_email = Email(
        id=test_id,
        sender="security-alert@micros0ft-support.com",
        recipients=["user@victim.com"],
        subject="URGENT: Security Alert - Verify Your Account Immediately",
        body_text="Your account has been suspended due to suspicious activity. Click here immediately to confirm your identity within 24 hours: http://micros0ft-verify.com/login",
        headers={
            "from": "Microsoft Security <security-alert@micros0ft-support.com>",
            "to": "user@victim.com",
            "received_hops": [{"ip": "198.51.100.15", "is_private": False, "hop_number": 1}],
        },
        urls=["http://micros0ft-verify.com/login"],
        raw_eml=eml_bytes,
        status=EmailStatus.pending,
        ingested_at=datetime.now(timezone.utc),
    )

    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_execute_result = MagicMock()
    mock_execute_result.scalar_one_or_none.return_value = mock_email
    mock_db.execute.return_value = mock_execute_result

    mock_header = HeaderForensicsResult(
        spf=SPFResult(status="fail", domain="micros0ft-support.com", ip="198.51.100.15", record="", details="fail"),
        dkim=DKIMResult(status="none", domain="micros0ft-support.com", selector="none", details="none"),
        dmarc=DMARCResult(status="fail", policy="reject", domain="micros0ft-support.com", alignment_spf=False, alignment_dkim=False, record=""),
        relay_path=[RelayHop(hop_number=1, from_host="bad.node", by_host="relay.node", ip="198.51.100.15", timestamp="2026-08-26T00:00:00Z", protocol="ESMTP", delay_seconds=1.0, is_private=False)],
        anomalies=[],
        auth_confidence_score=15.0,
    )
    mock_geo = GeoIntelResult(
        originating_ip="198.51.100.15",
        geo_locations=[IPGeoResult(ip="198.51.100.15", country="RU", country_code="RU", region="MOW", city="Moscow", latitude=55.7, longitude=37.6, isp="Bulletproof Host", asn="6666", org="Malicious Net", is_private=False, infrastructure_type="known_vpn", confidence="high")],
        domain_intel=DomainIntelResult(domain="micros0ft-support.com", registrar="NameCheap", registration_date="2026-08-10", expiration_date="2027-08-10", registrant_country="RU", name_servers=[], mx_records=[], a_records=[], domain_age_days=16, is_newly_registered=True),
        infrastructure_flags=["known_vpn"],
        location_confidence="high",
        ip_reputation_score=15.0,
    )

    with patch("app.core.pipeline.HeaderForensics.analyze", new_callable=AsyncMock) as mock_hdr, \
         patch("app.core.pipeline.GeoIntelligence.analyze", new_callable=AsyncMock) as mock_geo_fn, \
         patch("app.workers.tasks.enrich_threat_intel_task.apply_async"):

        mock_hdr.return_value = mock_header
        mock_geo_fn.return_value = mock_geo

        pipeline = AnalysisPipeline()
        analysis = await pipeline.run(str(test_id), mock_db)

        assert analysis is not None
        assert analysis.nlp_label in ("Phishing", "Suspicious", "Impersonation")
        assert analysis.composite_risk_score >= 50.0
        assert analysis.risk_breakdown["severity"] in ("high", "critical")
        assert analysis.graph_data is not None
        assert any(n["id"] == f"email:{test_id}" for n in analysis.graph_data["nodes"])


@pytest.mark.asyncio
async def test_e2e_legitimate_email_pipeline():
    """Test 2: Legitimate email produces Legitimate label and low risk score."""
    legit_path = SAMPLE_DIR / "sample_legit_newsletter.eml"
    with open(legit_path, "rb") as f:
        eml_bytes = f.read()

    test_id = uuid4()
    mock_email = Email(
        id=test_id,
        sender="newsletter@tech-digest.com",
        recipients=["user@company.com"],
        subject="Weekly Technology Digest #142",
        body_text="Welcome to this week's edition of the Technology Digest. Here are the top software architecture stories.",
        headers={
            "from": "Tech Digest <newsletter@tech-digest.com>",
            "to": "user@company.com",
            "received_hops": [{"ip": "142.250.190.46", "is_private": False, "hop_number": 1}],
        },
        urls=[],
        raw_eml=eml_bytes,
        status=EmailStatus.pending,
        ingested_at=datetime.now(timezone.utc),
    )

    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_execute_result = MagicMock()
    mock_execute_result.scalar_one_or_none.return_value = mock_email
    mock_db.execute.return_value = mock_execute_result

    mock_header = HeaderForensicsResult(
        spf=SPFResult(status="pass", domain="tech-digest.com", ip="142.250.190.46", record="v=spf1 ...", details="pass"),
        dkim=DKIMResult(status="pass", domain="tech-digest.com", selector="s1", details="pass"),
        dmarc=DMARCResult(status="pass", policy="none", domain="tech-digest.com", alignment_spf=True, alignment_dkim=True, record=""),
        relay_path=[RelayHop(hop_number=1, from_host="mail.google.com", by_host="relay.google.com", ip="142.250.190.46", timestamp="2026-08-26T00:00:00Z", protocol="ESMTPS", delay_seconds=0.2, is_private=False)],
        anomalies=[],
        auth_confidence_score=95.0,
    )
    mock_geo = GeoIntelResult(
        originating_ip="142.250.190.46",
        geo_locations=[IPGeoResult(ip="142.250.190.46", country="US", country_code="US", region="CA", city="Mountain View", latitude=37.4, longitude=-122.0, isp="Google LLC", asn="15169", org="Google", is_private=False, infrastructure_type="datacenter", confidence="high")],
        domain_intel=DomainIntelResult(domain="tech-digest.com", registrar="MarkMonitor", registration_date="2015-01-01", expiration_date="2028-01-01", registrant_country="US", name_servers=[], mx_records=[], a_records=[], domain_age_days=3500, is_newly_registered=False),
        infrastructure_flags=[],
        location_confidence="high",
        ip_reputation_score=95.0,
    )

    with patch("app.core.pipeline.HeaderForensics.analyze", new_callable=AsyncMock) as mock_hdr, \
         patch("app.core.pipeline.GeoIntelligence.analyze", new_callable=AsyncMock) as mock_geo_fn, \
         patch("app.workers.tasks.enrich_threat_intel_task.apply_async"):

        mock_hdr.return_value = mock_header
        mock_geo_fn.return_value = mock_geo

        pipeline = AnalysisPipeline()
        analysis = await pipeline.run(str(test_id), mock_db)

        assert analysis is not None
        assert analysis.nlp_label == "Legitimate"
        assert analysis.composite_risk_score <= 35.0
        assert analysis.risk_breakdown["severity"] in ("low", "medium")


def test_bulk_campaign_clustering_attribution():
    """Test 3: Bulk campaign clustering across coordinated threat emails."""
    engine = GraphEngine()
    clusterer = CampaignClusterer()

    emails = [
        {"id": f"camp-{i}", "subject": f"Urgent: Invoice #{100+i} Payment Required", "sender": "billing@malicious-camp.org", "body_text": f"Please process urgent transfer for Invoice #{100+i} to Account 98765.", "ingested_at": "2026-08-26T01:00:00Z"}
        for i in range(5)
    ]
    analyses = [
        {"email_id": f"camp-{i}", "nlp_label": "BEC/Fraud", "composite_risk_score": 85.0, "relay_path": [{"ip": "198.51.100.88", "is_private": False}], "geo_data": [{"ip": "198.51.100.88", "asn": "54321", "org": "BadHost"}], "domain_intel": {"registrar": "EvilReg"}}
        for i in range(5)
    ]

    graph_obj = engine.build_graph(emails, analyses)
    campaigns = clusterer.cluster(engine.graph, emails, analyses)

    assert len(campaigns) >= 1
    camp = campaigns[0]
    assert len(camp.email_ids) >= 2
    assert "198.51.100.88" in camp.shared_indicators["ips"]
    assert "malicious-camp.org" in camp.shared_indicators["domains"]
    assert camp.confidence >= 70.0

    # Ensure campaign node is in serialized graph
    json_graph = engine.to_json()
    assert any(n["type"] == "campaign" for n in json_graph["nodes"])
    assert any(l["relationship"] == "in_campaign" for l in json_graph["links"])
