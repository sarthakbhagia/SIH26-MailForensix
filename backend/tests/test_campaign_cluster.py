import pytest
from app.core.correlation.graph_engine import GraphEngine
from app.core.correlation.campaign_cluster import CampaignClusterer, CampaignCluster


def test_campaign_cluster_detection():
    engine = GraphEngine()
    clusterer = CampaignClusterer()

    emails = [
        {
            "id": "e1",
            "subject": "Urgent: Wire Payment Required",
            "sender": "ceo@imposter-corp.com",
            "body_text": "Please process an urgent wire transfer of $45,000 to Account #12345 today.",
            "ingested_at": "2026-08-25T10:00:00Z",
        },
        {
            "id": "e2",
            "subject": "Urgent: Wire Payment Transfer Required",
            "sender": "cfo@imposter-corp.com",
            "body_text": "Please process an urgent wire transfer of $60,000 to Account #12345 immediately.",
            "ingested_at": "2026-08-25T11:00:00Z",
        },
        {
            "id": "e3",
            "subject": "Unrelated Newsletter",
            "sender": "news@safe-domain.com",
            "body_text": "Here is your weekly summary of tech news and upcoming events.",
            "ingested_at": "2026-08-20T08:00:00Z",
        },
    ]

    analyses = [
        {
            "email_id": "e1",
            "nlp_label": "BEC/Fraud",
            "composite_risk_score": 90.0,
            "relay_path": [{"ip": "198.51.100.99", "is_private": False}],
            "geo_data": [{"ip": "198.51.100.99", "asn": "1234", "org": "Bad ISP"}],
        },
        {
            "email_id": "e2",
            "nlp_label": "BEC/Fraud",
            "composite_risk_score": 88.0,
            "relay_path": [{"ip": "198.51.100.99", "is_private": False}],
            "geo_data": [{"ip": "198.51.100.99", "asn": "1234", "org": "Bad ISP"}],
        },
        {
            "email_id": "e3",
            "nlp_label": "Legitimate",
            "composite_risk_score": 10.0,
            "relay_path": [{"ip": "8.8.8.8", "is_private": False}],
            "geo_data": [{"ip": "8.8.8.8", "asn": "15169", "org": "Google"}],
        },
    ]

    engine.build_graph(emails, analyses)
    campaigns = clusterer.cluster(engine.graph, emails, analyses)

    # There should be 1 campaign cluster grouping e1 and e2
    assert len(campaigns) >= 1
    bec_campaign = next(c for c in campaigns if "e1" in c.email_ids and "e2" in c.email_ids)

    assert "e1" in bec_campaign.email_ids
    assert "e2" in bec_campaign.email_ids
    assert "e3" not in bec_campaign.email_ids

    assert "198.51.100.99" in bec_campaign.shared_indicators["ips"]
    assert "imposter-corp.com" in bec_campaign.shared_indicators["domains"]
    assert bec_campaign.content_similarity >= 0.50
    assert bec_campaign.confidence >= 50.0
    assert "BEC" in bec_campaign.attribution

    # Verify campaign node added to graph
    camp_node_id = f"campaign:{bec_campaign.campaign_id}"
    assert engine.graph.has_node(camp_node_id)
    assert engine.graph.has_edge("email:e1", camp_node_id)
    assert engine.graph.has_edge("email:e2", camp_node_id)


def test_campaign_determinism_and_stable_uuids():
    """Verify identical clustering input generates deterministic campaign IDs and properties."""
    emails = [
        {"id": "camp-a", "subject": "Urgent Action Required", "sender": "threat@spoofed.org", "body_text": "Click here to login immediately"},
        {"id": "camp-b", "subject": "Urgent Action Required Now", "sender": "threat@spoofed.org", "body_text": "Click here to login now"},
    ]
    analyses = [
        {"email_id": "camp-a", "composite_risk_score": 75.0, "relay_path": [{"ip": "203.0.113.88", "is_private": False}]},
        {"email_id": "camp-b", "composite_risk_score": 80.0, "relay_path": [{"ip": "203.0.113.88", "is_private": False}]},
    ]

    engine1 = GraphEngine()
    engine1.build_graph(emails, analyses)
    c1 = CampaignClusterer().cluster(engine1.graph, emails, analyses)

    engine2 = GraphEngine()
    engine2.build_graph(list(reversed(emails)), list(reversed(analyses)))
    c2 = CampaignClusterer().cluster(engine2.graph, list(reversed(emails)), list(reversed(analyses)))

    assert len(c1) == len(c2) == 1
    assert c1[0].campaign_id == c2[0].campaign_id
    assert c1[0].email_ids == c2[0].email_ids
    assert c1[0].confidence == c2[0].confidence
    assert c1[0].attribution == c2[0].attribution


def test_isolated_emails_not_clustered():
    engine = GraphEngine()
    clusterer = CampaignClusterer()

    emails = [
        {"id": "iso-1", "subject": "Newsletter 1", "sender": "a@news1.com", "body_text": "News body 1"},
        {"id": "iso-2", "subject": "Receipt 2", "sender": "b@store2.com", "body_text": "Store receipt 2"},
    ]
    analyses = [
        {"email_id": "iso-1", "relay_path": [{"ip": "1.1.1.1", "is_private": False}]},
        {"email_id": "iso-2", "relay_path": [{"ip": "2.2.2.2", "is_private": False}]},
    ]

    engine.build_graph(emails, analyses)
    campaigns = clusterer.cluster(engine.graph, emails, analyses)
    assert len(campaigns) == 0
