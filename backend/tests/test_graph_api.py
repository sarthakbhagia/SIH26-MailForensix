import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from app.main import app
from app.api.graph import _fetch_emails_and_analysis


def test_get_full_graph_endpoint():
    mock_emails = [
        {"id": "e1", "subject": "Test 1", "sender": "user@test.com", "body_text": "Body 1", "ingested_at": "2026-08-26T00:00:00Z", "status": "analyzed"},
        {"id": "e2", "subject": "Test 2", "sender": "user@test.com", "body_text": "Body 2", "ingested_at": "2026-08-26T01:00:00Z", "status": "analyzed"},
    ]
    mock_analyses = [
        {"id": "a1", "email_id": "e1", "nlp_label": "Phishing", "composite_risk_score": 85.0, "relay_path": [{"ip": "1.2.3.4", "is_private": False}], "geo_data": [], "domain_intel": {}},
        {"id": "a2", "email_id": "e2", "nlp_label": "Phishing", "composite_risk_score": 80.0, "relay_path": [{"ip": "1.2.3.4", "is_private": False}], "geo_data": [], "domain_intel": {}},
    ]

    with patch("app.api.graph._fetch_emails_and_analysis", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = (mock_emails, mock_analyses)
        client = TestClient(app)

        response = client.get("/api/graph/")
        assert response.status_code == 200
        data = response.json()

        assert "nodes" in data
        assert "links" in data
        assert "stats" in data
        assert "campaigns" in data
        assert "shared_infrastructure" in data
        assert len(data["nodes"]) >= 2
        assert data["stats"]["email_count"] == 2


def test_get_campaigns_and_subgraph_endpoints():
    mock_emails = [
        {"id": "e1", "subject": "Wire 1", "sender": "a@fraud.com", "body_text": "Wire transfer $1000", "ingested_at": "2026-08-26T00:00:00Z", "status": "analyzed"},
        {"id": "e2", "subject": "Wire 2", "sender": "b@fraud.com", "body_text": "Wire transfer $2000", "ingested_at": "2026-08-26T01:00:00Z", "status": "analyzed"},
    ]
    mock_analyses = [
        {"id": "a1", "email_id": "e1", "nlp_label": "BEC/Fraud", "composite_risk_score": 90.0, "relay_path": [{"ip": "100.1.1.1", "is_private": False}], "geo_data": [], "domain_intel": {}},
        {"id": "a2", "email_id": "e2", "nlp_label": "BEC/Fraud", "composite_risk_score": 90.0, "relay_path": [{"ip": "100.1.1.1", "is_private": False}], "geo_data": [], "domain_intel": {}},
    ]

    with patch("app.api.graph._fetch_emails_and_analysis", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = (mock_emails, mock_analyses)
        client = TestClient(app)

        # 1. Get campaigns list
        camp_res = client.get("/api/graph/campaigns")
        assert camp_res.status_code == 200
        campaigns = camp_res.json()
        assert len(campaigns) >= 1
        camp_id = campaigns[0]["campaign_id"]

        # 2. Get campaign detail
        detail_res = client.get(f"/api/graph/campaigns/{camp_id}")
        assert detail_res.status_code == 200
        detail = detail_res.json()
        assert detail["campaign"]["campaign_id"] == camp_id
        assert "subgraph" in detail

        # 3. Get email subgraph
        sub_res = client.get("/api/graph/email/e1")
        assert sub_res.status_code == 200
        sub_data = sub_res.json()
        assert "nodes" in sub_data

        # 4. Get node connections
        conn_res = client.get("/api/graph/node/domain:fraud.com/connections")
        assert conn_res.status_code == 200
        conn_data = conn_res.json()
        assert conn_data["degree"] >= 1


def test_graph_api_404_handling():
    """Verify clean 404 responses for non-existent entities."""
    with patch("app.api.graph._fetch_emails_and_analysis", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = ([], [])
        client = TestClient(app)

        # 1. Non-existent email
        res1 = client.get("/api/graph/email/non-existent-id")
        assert res1.status_code == 404

        # 2. Non-existent campaign
        res2 = client.get("/api/graph/campaigns/non-existent-campaign")
        assert res2.status_code == 404

        # 3. Non-existent node
        res3 = client.get("/api/graph/node/ip:999.999.999.999/connections")
        assert res3.status_code == 404
