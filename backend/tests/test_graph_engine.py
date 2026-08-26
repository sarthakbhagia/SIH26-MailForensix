import pytest
from app.core.correlation.graph_engine import GraphEngine, GraphNode, GraphEdge, AttributionGraph


def test_add_single_email():
    engine = GraphEngine()
    email_data = {
        "id": "e1-uuid",
        "subject": "Phishing Alert",
        "sender": "attacker@evil-domain.com",
    }
    analysis_data = {
        "composite_risk_score": 85.0,
        "domain_intel": {
            "registrar": "NameCheap Inc",
            "domain_age_days": 12,
            "is_newly_registered": True,
        },
        "relay_path": [
            {"ip": "198.51.100.10", "is_private": False, "hop_number": 1},
            {"ip": "10.0.0.1", "is_private": True, "hop_number": 2},
        ],
        "geo_data": [
            {
                "ip": "198.51.100.10",
                "country": "Germany",
                "city": "Frankfurt",
                "isp": "Bad Hosting Ltd",
                "asn": "12345",
                "org": "Bad Org",
                "infrastructure_type": "known_vpn",
            }
        ],
        "analyzed_at": "2026-08-26T00:00:00Z",
    }

    engine.add_email(email_data, analysis_data)
    graph = engine.graph

    # Verify node creation
    assert graph.has_node("email:e1-uuid")
    assert graph.nodes["email:e1-uuid"]["type"] == "email"
    assert graph.nodes["email:e1-uuid"]["risk_score"] == 85.0

    assert graph.has_node("domain:evil-domain.com")
    assert graph.nodes["domain:evil-domain.com"]["type"] == "domain"

    assert graph.has_node("registrar:NameCheap Inc")
    assert graph.nodes["registrar:NameCheap Inc"]["type"] == "registrar"

    assert graph.has_node("ip:198.51.100.10")
    assert graph.nodes["ip:198.51.100.10"]["type"] == "ip"
    assert not graph.has_node("ip:10.0.0.1")  # Private IP should be ignored

    assert graph.has_node("asn:12345")
    assert graph.nodes["asn:12345"]["type"] == "asn"

    # Verify edges
    assert graph.has_edge("email:e1-uuid", "domain:evil-domain.com")
    assert graph.get_edge_data("email:e1-uuid", "domain:evil-domain.com")["relationship"] == "sent_from"

    assert graph.has_edge("email:e1-uuid", "ip:198.51.100.10")
    assert graph.get_edge_data("email:e1-uuid", "ip:198.51.100.10")["relationship"] == "relayed_through"

    assert graph.has_edge("ip:198.51.100.10", "asn:12345")
    assert graph.get_edge_data("ip:198.51.100.10", "asn:12345")["relationship"] == "belongs_to_asn"


def test_entity_identifier_normalization():
    """Verify stable entity identifiers and normalization across various input formats."""
    engine = GraphEngine()

    email_data = {
        "id": "email:clean-id",  # Already has email: prefix
        "subject": "Important Account Update",
        "sender": "John Doe <john.doe@SubDomain.TargetCompany.Com>",
    }
    analysis_data = {
        "composite_risk_score": 60.0,
        "domain_intel": {"registrar": " GoDaddy.com, LLC "},
        "relay_path": [
            {"ip": " 198.51.100.50 ", "is_private": False},
            {"ip": "127.0.0.1", "is_private": False},  # Loopback should be filtered
            {"ip": "192.168.1.100", "is_private": True},  # Private should be filtered
        ],
        "geo_data": [
            {"ip": "198.51.100.50", "asn": "AS15169", "org": "Google LLC"}  # "AS" prefix
        ],
    }

    engine.add_email(email_data, analysis_data)
    graph = engine.graph

    # Verify stable IDs
    assert graph.has_node("email:clean-id")
    assert not graph.has_node("email:email:clean-id")
    assert graph.has_node("domain:subdomain.targetcompany.com")
    assert graph.has_node("registrar:GoDaddy.com, LLC")
    assert graph.has_node("ip:198.51.100.50")
    assert not graph.has_node("ip:127.0.0.1")
    assert not graph.has_node("ip:192.168.1.100")
    assert graph.has_node("asn:15169")
    assert not graph.has_node("asn:AS15169")


def test_missing_data_resilience():
    """Verify graph handles empty/null fields without crashing."""
    engine = GraphEngine()

    email_data = {
        "id": "e-sparse",
        "subject": None,
        "sender": None,
    }
    analysis_data = {
        "composite_risk_score": None,
        "domain_intel": None,
        "relay_path": None,
        "geo_data": None,
    }

    engine.add_email(email_data, analysis_data)
    assert engine.graph.has_node("email:e-sparse")
    assert engine.graph.nodes["email:e-sparse"]["subject"] == "No Subject"
    assert engine.graph.nodes["email:e-sparse"]["risk_score"] == 0.0


def test_deterministic_graph_construction():
    """Verify building graph from the same data yields identical nodes and edges."""
    emails = [
        {"id": f"e-{i}", "subject": f"Subj {i}", "sender": f"user{i}@dom{i%2}.com"}
        for i in range(10)
    ]
    analyses = [
        {"email_id": f"e-{i}", "composite_risk_score": float(i * 10), "relay_path": [{"ip": f"198.51.100.{10 + (i%3)}", "is_private": False}]}
        for i in range(10)
    ]

    engine1 = GraphEngine()
    g1 = engine1.build_graph(emails, analyses)

    engine2 = GraphEngine()
    # Reverse input order to test deterministic sorting
    g2 = engine2.build_graph(list(reversed(emails)), list(reversed(analyses)))

    assert g1.graph_stats["node_count"] == g2.graph_stats["node_count"]
    assert g1.graph_stats["edge_count"] == g2.graph_stats["edge_count"]
    assert [n.id for n in g1.nodes] == [n.id for n in g2.nodes]
    assert [(e.source, e.target) for e in g1.edges] == [(e.source, e.target) for e in g2.edges]


def test_shared_infrastructure_correlation():
    engine = GraphEngine()

    # Email 1
    engine.add_email(
        {"id": "email-1", "subject": "Invoice 1", "sender": "user1@threat-domain.com"},
        {
            "composite_risk_score": 80.0,
            "relay_path": [{"ip": "203.0.113.5", "is_private": False, "hop_number": 1}],
            "geo_data": [{"ip": "203.0.113.5", "asn": "9999", "org": "Host Org"}],
        },
    )

    # Email 2 (shares domain and IP with Email 1)
    engine.add_email(
        {"id": "email-2", "subject": "Invoice 2", "sender": "user2@threat-domain.com"},
        {
            "composite_risk_score": 75.0,
            "relay_path": [{"ip": "203.0.113.5", "is_private": False, "hop_number": 1}],
            "geo_data": [{"ip": "203.0.113.5", "asn": "9999", "org": "Host Org"}],
        },
    )

    # Run shared infrastructure detection
    engine._add_shared_infrastructure_edges()

    # Direct edge should exist between email-1 and email-2
    assert engine.graph.has_edge("email:email-1", "email:email-2")
    edge_data = engine.graph.get_edge_data("email:email-1", "email:email-2")
    assert edge_data["relationship"] in ("shares_infrastructure", "shares_ip", "shares_domain")

    # Check shared infrastructure finding
    shared_infra = engine.find_shared_infrastructure()
    assert len(shared_infra) >= 2
    types = [item["type"] for item in shared_infra]
    assert "domain" in types
    assert "ip" in types


def test_to_json_and_subgraph():
    engine = GraphEngine()
    engine.add_email(
        {"id": "e1", "subject": "Test", "sender": "test@domain.com"},
        {"composite_risk_score": 50.0, "relay_path": [{"ip": "1.1.1.1", "is_private": False}]},
    )

    json_data = engine.to_json()
    assert "nodes" in json_data
    assert "links" in json_data
    assert any(n["id"] == "email:e1" for n in json_data["nodes"])

    subgraph = engine.get_subgraph_for_email("e1", hops=1)
    assert len(subgraph["nodes"]) >= 2
    assert len(subgraph["links"]) >= 1
