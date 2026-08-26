import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from uuid import uuid4
from app.workers.tasks import (
    analyze_email_task,
    enrich_threat_intel_task,
    refresh_phishtank_db,
    refresh_tor_exit_nodes,
)


def test_periodic_tasks():
    res1 = refresh_phishtank_db()
    assert res1["status"] == "refreshed"

    res2 = refresh_tor_exit_nodes()
    assert res2["status"] == "refreshed"


def test_analyze_email_task():
    test_email_id = str(uuid4())
    mock_pipeline_result = MagicMock()
    mock_pipeline_result.composite_risk_score = 88.5

    mock_session = AsyncMock()
    mock_session_ctx = MagicMock()
    mock_session_ctx.__aenter__.return_value = mock_session
    mock_session_ctx.__aexit__.return_value = None

    with patch("app.workers.tasks.AsyncSessionLocal", return_value=mock_session_ctx), \
         patch("app.core.pipeline.AnalysisPipeline.run", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = mock_pipeline_result
        res = analyze_email_task(test_email_id)

        assert res["status"] == "completed"
        assert res["email_id"] == test_email_id
        assert res["risk_score"] == 88.5


def test_enrich_threat_intel_task():
    test_email_id = str(uuid4())

    mock_report = MagicMock()
    mock_report.ip_results = {}
    mock_report.domain_results = {}
    mock_report.url_results = {}
    mock_report.hash_results = {}
    mock_report.phishtank_results = {}
    mock_report.enrichment_timestamp = "2026-08-26T00:00:00Z"
    mock_report.apis_queried = ["AbuseIPDB", "VirusTotal"]

    mock_analysis = MagicMock()
    mock_analysis.nlp_label = "Phishing"
    mock_analysis.nlp_confidence = 85.0
    mock_analysis.nlp_details = {"urgency_score": 75.0}
    mock_analysis.auth_status = {"spf": "fail", "dkim": "none", "dmarc": "none"}
    mock_analysis.ip_reputation = {"score": 30.0}
    mock_analysis.geo_data = [{"ip": "198.51.100.1"}]
    mock_analysis.risk_breakdown = {"auth": 80.0, "link": 0.0, "attachment": 0.0, "factors": []}

    mock_db_res = MagicMock()
    mock_db_res.scalar_one_or_none.return_value = mock_analysis

    mock_session = AsyncMock()
    mock_session.execute.return_value = mock_db_res
    mock_session_ctx = MagicMock()
    mock_session_ctx.__aenter__.return_value = mock_session
    mock_session_ctx.__aexit__.return_value = None

    with patch("app.workers.tasks.AsyncSessionLocal", return_value=mock_session_ctx), \
         patch("app.core.correlation.threat_intel.ThreatIntelAggregator.enrich", new_callable=AsyncMock) as mock_enrich, \
         patch("app.core.correlation.cache.RedisCache.connect", new_callable=AsyncMock), \
         patch("app.core.correlation.cache.RedisCache.disconnect", new_callable=AsyncMock):

        mock_enrich.return_value = mock_report

        res = enrich_threat_intel_task(
            email_id=test_email_id,
            ips=["198.51.100.1"],
            domains=["threat.com"],
            urls=["http://threat.com/login"],
            hashes=["a" * 64],
        )

        assert res["status"] == "enriched"
        assert res["email_id"] == test_email_id
        assert "AbuseIPDB" in res["apis_queried"]
