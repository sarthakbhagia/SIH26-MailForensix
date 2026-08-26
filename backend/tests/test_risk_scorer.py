import pytest
from app.core.correlation.risk_scorer import RiskScorer, CompositeRiskScore
from app.core.correlation.threat_intel import (
    ThreatIntelReport,
    AbuseIPDBResult,
    VirusTotalResult,
    PhishTankResult,
)


class MockNLPResult:
    def __init__(self, label="Legitimate", confidence=95.0, urgency=0.0):
        self.label = label
        self.confidence = confidence
        self.urgency_score = urgency
        self.probabilities = {label: confidence}
        self.bec_indicators = []
        self.impersonation_signals = []
        self.contributing_factors = []


class MockHeaderResult:
    def __init__(self, auth_score=100.0, spf="pass", dkim="pass", dmarc="pass"):
        self.auth_confidence_score = auth_score
        self.spf = type("S", (), {"status": spf})()
        self.dkim = type("S", (), {"status": dkim})()
        self.dmarc = type("S", (), {"status": dmarc, "policy": "reject"})()
        self.relay_path = []
        self.anomalies = []


class MockGeoResult:
    def __init__(self, ip_rep=90.0, orig_ip="8.8.8.8"):
        self.ip_reputation_score = ip_rep
        self.originating_ip = orig_ip
        self.infrastructure_flags = []
        self.geo_locations = []
        self.domain_intel = None


class MockLinkResult:
    def __init__(self, overall_risk=0.0, analyzed=0, phish_count=0):
        self.overall_link_risk = overall_risk
        self.urls_analyzed = analyzed
        self.phishing_urls_found = phish_count


class MockAttachmentResult:
    def __init__(self, overall_risk=0.0, total=0):
        self.overall_attachment_risk = overall_risk
        self.total_attachments = total


def test_legitimate_email_scoring():
    scorer = RiskScorer()
    nlp = MockNLPResult(label="Legitimate", confidence=95.0)
    header = MockHeaderResult(auth_score=100.0)
    geo = MockGeoResult(ip_rep=95.0)
    link = MockLinkResult(overall_risk=0.0)
    att = MockAttachmentResult(overall_risk=0.0)

    score = scorer.compute(nlp, header, geo, link, att)
    assert score.overall_score < 25.0
    assert score.severity == "low"
    assert "No action needed" in score.recommended_action
    assert score.threat_intel_enhanced is False


def test_phishing_email_scoring():
    scorer = RiskScorer()
    nlp = MockNLPResult(label="Phishing", confidence=90.0, urgency=80.0)
    header = MockHeaderResult(auth_score=20.0, spf="fail", dkim="fail", dmarc="none")
    geo = MockGeoResult(ip_rep=20.0)
    link = MockLinkResult(overall_risk=85.0, analyzed=2, phish_count=2)
    att = MockAttachmentResult(overall_risk=90.0, total=1)

    score = scorer.compute(nlp, header, geo, link, att)
    assert score.overall_score >= 75.0
    assert score.severity == "critical"
    assert "Block & Investigate" in score.recommended_action


def test_threat_intel_boosting():
    scorer = RiskScorer()
    nlp = MockNLPResult(label="Legitimate", confidence=80.0)
    header = MockHeaderResult(auth_score=80.0)
    geo = MockGeoResult(ip_rep=70.0)
    link = MockLinkResult(overall_risk=10.0, analyzed=1, phish_count=0)
    att = MockAttachmentResult(overall_risk=0.0)

    # Base score without threat intel
    base_score = scorer.compute(nlp, header, geo, link, att)

    # Construct threat intel report with high-confidence malicious indicators
    ti_report = ThreatIntelReport(
        ip_results={
            "1.2.3.4": AbuseIPDBResult(
                ip="1.2.3.4",
                abuse_confidence_score=95,
                total_reports=50,
                last_reported="2026-08-25T00:00:00Z",
                categories=[18],
                category_names=["Brute-Force"],
                isp="Bad ISP",
                domain="bad.com",
                country_code="RU",
                is_whitelisted=False,
            )
        },
        domain_results={},
        url_results={
            "http://phish.com": VirusTotalResult(
                indicator="http://phish.com",
                indicator_type="url",
                malicious_count=25,
                suspicious_count=2,
                harmless_count=10,
                total_vendors=70,
                detection_ratio=0.35,
                community_score=-30,
                categories={},
                last_analysis_date="2026-08-25",
            )
        },
        hash_results={},
        phishtank_results={
            "http://phish.com": PhishTankResult(
                url="http://phish.com",
                is_phishing=True,
                phish_id=12345,
                verified=True,
                verified_at="2026-08-25T00:00:00Z",
            )
        },
        enrichment_timestamp="2026-08-26T00:00:00Z",
        apis_queried=["AbuseIPDB", "VirusTotal", "PhishTank"],
    )

    boosted_score = scorer.compute(nlp, header, geo, link, att, threat_intel=ti_report)
    assert boosted_score.overall_score > base_score.overall_score
    assert boosted_score.threat_intel_enhanced is True


def test_edge_cases_and_fallbacks():
    scorer = RiskScorer()
    # All None inputs
    score_none = scorer.compute(None, None, None, None, None)
    assert isinstance(score_none, CompositeRiskScore)
    assert len(score_none.factors) == 5

    # Dict inputs
    dict_nlp = {"label": "Suspicious", "confidence": 60.0, "urgency_score": 40.0}
    dict_header = {"auth_status": {"spf": "softfail", "dkim": "pass", "dmarc": "none"}, "auth_confidence_score": 60.0}
    dict_geo = {"originating_ip": "1.1.1.1", "ip_reputation_score": 60.0, "infrastructure_flags": ["known_vpn"]}
    dict_link = {"overall_link_risk": 30.0}
    dict_att = {"overall_attachment_risk": 20.0}

    score_dict = scorer.compute(dict_nlp, dict_header, dict_geo, dict_link, dict_att)
    assert isinstance(score_dict, CompositeRiskScore)
    assert score_dict.severity in ("low", "medium", "high", "critical")
