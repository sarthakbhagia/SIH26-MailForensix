import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from uuid import uuid4
from datetime import datetime, timezone

from app.core.pipeline import AnalysisPipeline
from app.models.email_case import Email, EmailStatus
from app.models.analysis_result import AnalysisResult
from app.core.analysis.header_forensics import HeaderForensicsResult, SPFResult, DKIMResult, DMARCResult, RelayHop
from app.core.analysis.geo_intel import GeoIntelResult, IPGeoResult, DomainIntelResult
from app.core.analysis.link_analyzer import LinkAnalysisResult
from app.core.analysis.attachment_analyzer import AttachmentAnalysisReport


@pytest.mark.asyncio
async def test_pipeline_run_integration():
    test_id = uuid4()
    mock_email = Email(
        id=test_id,
        sender="attacker@spoofed-domain.com",
        recipients=["victim@company.com"],
        subject="Urgent: Wire Transfer Required",
        body_text="Please wire $20,000 to Account #12345 immediately.",
        body_html="<p>Please wire $20,000 to Account #12345 immediately.</p>",
        headers={
            "from": "CEO <attacker@spoofed-domain.com>",
            "to": "victim@company.com",
            "received_hops": [
                {"ip": "198.51.100.22", "is_private": False, "hop_number": 1}
            ],
        },
        raw_eml=b"From: attacker@spoofed-domain.com\nSubject: Urgent: Wire Transfer Required\n\nBody",
        status=EmailStatus.pending,
        ingested_at=datetime.now(timezone.utc),
    )

    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_execute_result = MagicMock()
    mock_execute_result.scalar_one_or_none.return_value = mock_email
    mock_db.execute.return_value = mock_execute_result

    # Mock forensic results
    mock_header = HeaderForensicsResult(
        spf=SPFResult(status="fail", domain="spoofed-domain.com", ip="198.51.100.22", record="", details="fail"),
        dkim=DKIMResult(status="none", domain="spoofed-domain.com", selector="none", details="none"),
        dmarc=DMARCResult(status="none", policy="none", domain="spoofed-domain.com", alignment_spf=False, alignment_dkim=False, record=""),
        relay_path=[
            RelayHop(hop_number=1, from_host="bad.host", by_host="relay.host", ip="198.51.100.22", timestamp="2026-08-26T00:00:00Z", protocol="ESMTP", delay_seconds=0.5, is_private=False)
        ],
        anomalies=[],
        auth_confidence_score=20.0,
    )

    mock_geo = GeoIntelResult(
        originating_ip="198.51.100.22",
        geo_locations=[
            IPGeoResult(ip="198.51.100.22", country="US", country_code="US", region="CA", city="San Jose", latitude=37.3, longitude=-121.8, isp="Bad ISP", asn="12345", org="Host Org", is_private=False, infrastructure_type="known_vpn", confidence="high")
        ],
        domain_intel=DomainIntelResult(domain="spoofed-domain.com", registrar="Namecheap", registration_date="2026-08-01", expiration_date="2027-08-01", registrant_country="US", name_servers=[], mx_records=[], a_records=[], domain_age_days=25, is_newly_registered=True),
        infrastructure_flags=["known_vpn"],
        location_confidence="high",
        ip_reputation_score=30.0,
    )

    mock_link = LinkAnalysisResult(
        urls_analyzed=0,
        url_results=[],
        overall_link_risk=0.0,
        phishing_urls_found=0,
        suspicious_urls_found=0,
    )

    mock_att = AttachmentAnalysisReport(
        total_attachments=0,
        results=[],
        overall_attachment_risk=0.0,
    )

    with patch("app.core.pipeline.HeaderForensics.analyze", new_callable=AsyncMock) as mock_hdr_analyze, \
         patch("app.core.pipeline.GeoIntelligence.analyze", new_callable=AsyncMock) as mock_geo_analyze, \
         patch("app.core.pipeline.LinkAnalyzer.analyze", new_callable=AsyncMock) as mock_link_analyze, \
         patch("app.core.pipeline.AttachmentAnalyzer.analyze") as mock_att_analyze, \
         patch("app.workers.tasks.enrich_threat_intel_task.apply_async") as mock_celery_dispatch:

        mock_hdr_analyze.return_value = mock_header
        mock_geo_analyze.return_value = mock_geo
        mock_link_analyze.return_value = mock_link
        mock_att_analyze.return_value = mock_att

        pipeline = AnalysisPipeline()
        result = await pipeline.run(str(test_id), mock_db)

        assert result is not None
        assert isinstance(result, AnalysisResult)
        assert result.composite_risk_score >= 0.0
        assert result.nlp_label.upper() in ("BEC/FRAUD", "BEC_FRAUD", "IMPERSONATION", "SUSPICIOUS", "LEGITIMATE", "PHISHING")
        assert result.risk_breakdown is not None
        assert "factors" in result.risk_breakdown
        assert "severity" in result.risk_breakdown
        assert "recommended_action" in result.risk_breakdown
        assert result.graph_data is not None
        assert "nodes" in result.graph_data
        assert "links" in result.graph_data
        assert any(n["id"] == f"email:{test_id}" for n in result.graph_data["nodes"])
        assert mock_celery_dispatch.called
