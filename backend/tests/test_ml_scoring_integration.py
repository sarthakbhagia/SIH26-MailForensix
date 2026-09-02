"""Comprehensive Unit & Integration Test Suite for ML Scoring & Downstream Integration (Fix 2).

Verifies:
1. Label normalization (normalize_threat_label) across canonical uppercase, legacy title-case, lowercase, and variant inputs.
2. Case 1: High-confidence PHISHING (98.7%) produces genuine high NLP risk (>= 75.0) and high/critical composite score.
3. Case 2: High-confidence LEGITIMATE (99.2%) produces low NLP risk (<= 15.0) and low composite score (<= 25.0).
4. Case 3: SUSPICIOUS produces calibrated moderate/elevated risk.
5. Case 4: BEC_FRAUD produces high NLP risk (>= 75.0) and critical composite score.
6. Case 5: Legacy/TitleCase labels ('Phishing', 'BEC/Fraud', 'Suspicious', 'Legitimate', 'Impersonation') normalize and score identically.
7. AlertEngine title generation uses canonical label normalization.
8. Pipeline attribution determination is case-resilient.
"""

from dataclasses import dataclass
from uuid import uuid4
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.core.correlation.risk_scorer import (
    RiskScorer,
    normalize_threat_label,
    CompositeRiskScore,
)
from app.core.reporting.alert_engine import AlertEngine
from app.core.pipeline import AnalysisPipeline
from app.models.email_case import Email, EmailStatus
from app.models.analysis_result import AnalysisResult


@dataclass
class MockNLPResult:
    label: str
    confidence: float
    confidence_calibrated: bool = True
    confidence_method: str = "ensemble_stacking"
    evidence_score: float = 0.0
    urgency_score: float = 0.0


@dataclass
class MockHeaderResult:
    auth_confidence_score: float = 100.0
    spf: Any = None
    dkim: Any = None
    dmarc: Any = None
    relay_path: list = None
    anomalies: list = None


@dataclass
class MockGeoResult:
    ip_reputation_score: float = 95.0
    geo_locations: list = None
    domain_intel: Any = None
    infrastructure_flags: list = None


def test_label_normalization_exhaustive():
    """Verify normalize_threat_label maps all known taxonomy variants to canonical uppercase."""
    # Phishing variants
    assert normalize_threat_label("PHISHING") == "PHISHING"
    assert normalize_threat_label("Phishing") == "PHISHING"
    assert normalize_threat_label("phishing") == "PHISHING"
    assert normalize_threat_label("phish") == "PHISHING"
    assert normalize_threat_label("CREDENTIAL_HARVESTING") == "PHISHING"

    # BEC / Fraud variants
    assert normalize_threat_label("BEC_FRAUD") == "BEC_FRAUD"
    assert normalize_threat_label("BEC/Fraud") == "BEC_FRAUD"
    assert normalize_threat_label("bec_fraud") == "BEC_FRAUD"
    assert normalize_threat_label("bec/fraud") == "BEC_FRAUD"
    assert normalize_threat_label("BEC") == "BEC_FRAUD"
    assert normalize_threat_label("Fraud") == "BEC_FRAUD"
    assert normalize_threat_label("WIRE_FRAUD") == "BEC_FRAUD"

    # Legitimate variants
    assert normalize_threat_label("LEGITIMATE") == "LEGITIMATE"
    assert normalize_threat_label("Legitimate") == "LEGITIMATE"
    assert normalize_threat_label("legitimate") == "LEGITIMATE"
    assert normalize_threat_label("CLEAN") == "LEGITIMATE"
    assert normalize_threat_label("Clean") == "LEGITIMATE"
    assert normalize_threat_label("Ham") == "LEGITIMATE"
    assert normalize_threat_label(None) == "LEGITIMATE"
    assert normalize_threat_label("") == "LEGITIMATE"

    # Suspicious variants
    assert normalize_threat_label("SUSPICIOUS") == "SUSPICIOUS"
    assert normalize_threat_label("Suspicious") == "SUSPICIOUS"
    assert normalize_threat_label("suspicious") == "SUSPICIOUS"
    assert normalize_threat_label("Warning") == "SUSPICIOUS"

    # Impersonation variants
    assert normalize_threat_label("IMPERSONATION") == "IMPERSONATION"
    assert normalize_threat_label("Impersonation") == "IMPERSONATION"
    assert normalize_threat_label("impersonation") == "IMPERSONATION"
    assert normalize_threat_label("Spoofed Domain") == "IMPERSONATION"


def test_case_1_phishing_high_confidence():
    """Case 1: ML label = PHISHING, confidence = 98.7%."""
    scorer = RiskScorer()
    nlp = MockNLPResult(label="PHISHING", confidence=98.7)
    
    nlp_risk, details = scorer._compute_nlp_risk(nlp)
    assert nlp_risk == 98.7
    assert "PHISHING" in details
    assert "98.7%" in details

    # Test composite calculation with neutral forensics
    header = MockHeaderResult(auth_confidence_score=50.0)  # 50 risk
    geo = MockGeoResult(ip_reputation_score=50.0)          # 50 risk
    composite = scorer.compute(nlp, header, geo)

    # 98.7*0.35 + 50*0.25 + 50*0.20 + 0*0.10 + 0*0.10 = 34.55 + 12.5 + 10 = 57.05 (High)
    assert composite.overall_score >= 55.0
    assert composite.severity in ("high", "critical")
    # Verify NLP risk was NOT forced to 30.0
    nlp_factor = next(f for f in composite.factors if f.name == "NLP Threat Classification")
    assert nlp_factor.raw_score == 98.7


def test_case_2_legitimate_high_confidence():
    """Case 2: ML label = LEGITIMATE, confidence = 99.2%."""
    scorer = RiskScorer()
    nlp = MockNLPResult(label="LEGITIMATE", confidence=99.2)

    nlp_risk, details = scorer._compute_nlp_risk(nlp)
    # 99.2 * 0.15 = 14.88
    assert nlp_risk == pytest.approx(14.88, rel=1e-2)
    assert "LEGITIMATE" in details

    # Clean forensics: 100 auth confidence -> 0 risk; 95 ip rep -> 5 risk
    header = MockHeaderResult(auth_confidence_score=100.0)
    geo = MockGeoResult(ip_reputation_score=95.0)
    composite = scorer.compute(nlp, header, geo)

    # 14.88*0.35 + 0*0.25 + 5*0.20 = 5.21 + 1.0 = 6.21 (Low)
    assert composite.overall_score <= 20.0
    assert composite.severity == "low"


def test_case_3_suspicious_moderate_confidence():
    """Case 3: ML label = SUSPICIOUS, confidence = 66.0%."""
    scorer = RiskScorer()
    nlp = MockNLPResult(label="SUSPICIOUS", confidence=66.0)

    nlp_risk, details = scorer._compute_nlp_risk(nlp)
    # max(50.0, 66.0 * 0.8) = max(50.0, 52.8) = 52.8
    assert nlp_risk == pytest.approx(52.8, rel=1e-2)
    assert "SUSPICIOUS" in details

    header = MockHeaderResult(auth_confidence_score=70.0)  # 30 risk
    geo = MockGeoResult(ip_reputation_score=60.0)          # 40 risk
    composite = scorer.compute(nlp, header, geo)

    # 52.8*0.35 + 30*0.25 + 40*0.20 = 18.48 + 7.5 + 8.0 = 33.98 (Medium)
    assert 26.0 <= composite.overall_score <= 50.0
    assert composite.severity == "medium"


def test_case_4_bec_fraud_high_confidence():
    """Case 4: ML label = BEC_FRAUD, confidence = 96.5%."""
    scorer = RiskScorer()
    nlp = MockNLPResult(label="BEC_FRAUD", confidence=96.5, urgency_score=80.0)

    nlp_risk, details = scorer._compute_nlp_risk(nlp)
    # min(100.0, max(75.0, 96.5)) = 96.5 + urgency boost 10.0 -> 100.0
    assert nlp_risk == 100.0
    assert "BEC_FRAUD" in details

    header = MockHeaderResult(auth_confidence_score=20.0)  # 80 risk
    geo = MockGeoResult(ip_reputation_score=30.0)          # 70 risk
    composite = scorer.compute(nlp, header, geo)

    # 100*0.35 + 80*0.25 + 70*0.20 = 35 + 20 + 14 = 69.0 (High/Critical)
    assert composite.overall_score >= 65.0
    assert composite.severity in ("high", "critical")


def test_case_5_legacy_title_case_compatibility():
    """Case 5: Legacy/TitleCase labels match identical scoring to canonical uppercase."""
    scorer = RiskScorer()
    
    # Compare "Phishing" vs "PHISHING"
    res_title = scorer._compute_nlp_risk(MockNLPResult(label="Phishing", confidence=90.0))
    res_upper = scorer._compute_nlp_risk(MockNLPResult(label="PHISHING", confidence=90.0))
    assert res_title[0] == res_upper[0] == 90.0
    assert "PHISHING" in res_title[1]

    # Compare "BEC/Fraud" vs "BEC_FRAUD"
    res_bec_slash = scorer._compute_nlp_risk(MockNLPResult(label="BEC/Fraud", confidence=85.0))
    res_bec_upper = scorer._compute_nlp_risk(MockNLPResult(label="BEC_FRAUD", confidence=85.0))
    assert res_bec_slash[0] == res_bec_upper[0] == 85.0

    # Compare "Legitimate" vs "LEGITIMATE"
    res_legit_title = scorer._compute_nlp_risk(MockNLPResult(label="Legitimate", confidence=95.0))
    res_legit_upper = scorer._compute_nlp_risk(MockNLPResult(label="LEGITIMATE", confidence=95.0))
    assert res_legit_title[0] == res_legit_upper[0] == pytest.approx(14.25, rel=1e-2)


def test_alert_engine_canonical_title_generation():
    """Verify AlertEngine formats alert titles properly for canonical labels."""
    engine = AlertEngine()
    
    title_phish = engine._build_title("PHISHING", "critical", 92.0)
    assert "🔴 Phishing Email Detected (Risk: 92)" in title_phish

    title_bec = engine._build_title("BEC_FRAUD", "critical", 95.0)
    assert "🔴 Business Email Compromise Attempt (Risk: 95)" in title_bec

    title_susp = engine._build_title("SUSPICIOUS", "high", 65.0)
    assert "🟠 Suspicious Email Flagged (Risk: 65)" in title_susp

    # Legacy title-case should produce exact same title
    title_phish_legacy = engine._build_title("Phishing", "critical", 92.0)
    assert title_phish_legacy == title_phish


def test_pipeline_attribution_case_resilience():
    """Verify pipeline _determine_attribution correctly handles canonical uppercase labels."""
    pipeline = AnalysisPipeline()
    
    mock_header = type('H', (), {
        'spf': type('S', (), {'status': 'pass'})(),
        'dkim': type('S', (), {'status': 'pass'})(),
        'anomalies': [],
    })()
    mock_geo = type('G', (), {'infrastructure_flags': [], 'ip_reputation_score': 80})()
    
    # 1. Legitimate email with SPF=pass & DKIM=pass should NOT be marked Compromised Account
    nlp_legit = type('N', (), {'label': 'LEGITIMATE', 'impersonation_signals': []})()
    attr_legit = pipeline._determine_attribution(mock_header, mock_geo, nlp_legit)
    assert attr_legit == "Unknown"

    # 2. Phishing email with SPF=pass & DKIM=pass SHOULD be marked Compromised Account
    nlp_phish = type('N', (), {'label': 'PHISHING', 'impersonation_signals': []})()
    attr_phish = pipeline._determine_attribution(mock_header, mock_geo, nlp_phish)
    assert attr_phish == "Compromised Account"
