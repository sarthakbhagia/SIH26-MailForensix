import pytest
import io
from uuid import uuid4
from datetime import datetime, timezone
from app.core.analysis.nlp_classifier import NLPClassifier, NLPClassificationResult
from app.core.reporting.report_generator import ReportGenerator, _normalize_percentage
from app.models.email_case import Email, EmailStatus
from app.models.analysis_result import AnalysisResult
from app.schemas.analysis import AnalysisResponse, NLPResult


@pytest.fixture
def nlp_classifier():
    return NLPClassifier()


@pytest.fixture
def report_generator():
    return ReportGenerator()


# Scenario A: No analysis -> confidence = unavailable/None
def test_scenario_a_no_analysis_confidence_unavailable():
    """Verify that when no analysis is present, confidence defaults to None / uncomputed rather than fake numbers."""
    nlp_res = NLPResult(label="Unknown", confidence=None)
    assert nlp_res.confidence is None
    assert nlp_res.confidence_calibrated is False
    assert nlp_res.confidence_method is None
    assert nlp_res.evidence_score is None

    resp = AnalysisResponse(
        email_id=uuid4(),
        status="pending",
        nlp_result=None,
        attribution_confidence=None,
    )
    assert resp.nlp_result is None
    assert resp.attribution_confidence is None
    assert resp.attribution_confidence_calibrated is False


# Scenario B: Clean email -> must NOT become fake 100% confidence
def test_scenario_b_clean_email_no_fake_100_percent(nlp_classifier):
    """Verify that a clean legitimate email without threat signals does NOT report 100% statistical confidence."""
    clean_subject = "Meeting Notes from Yesterday's Architecture Discussion"
    clean_body = "Hi team, attached are the discussion points regarding database index optimization. Let's sync tomorrow."
    sender = "teammate@internalcorp.com"
    headers = {"from": "Teammate <teammate@internalcorp.com>"}

    result = nlp_classifier.classify(clean_subject, clean_body, sender, headers)

    assert result.label == "Legitimate"
    # Rule heuristic engine must NOT claim 100.0% statistical confidence on 0 matched rules
    assert result.confidence is None or result.confidence != 100.0
    assert result.confidence_calibrated is False
    assert result.confidence_method == "rule_heuristic"
    assert result.evidence_score == 0.0 or result.evidence_score is not None


# Scenario C: Phishing email -> classification/risk still works
def test_scenario_c_phishing_email_classification_and_risk(nlp_classifier):
    """Verify that threat classification and evidence scoring function correctly on phishing text."""
    phish_subject = "Security Alert: Verify your account immediately"
    phish_body = "Account suspended due to unauthorized access. Click here immediately to verify your account within 24 hours."
    sender = "security-update@micros0ft-security.com"
    headers = {"from": "Microsoft Security <attacker@micros0ft-security.com>"}

    result = nlp_classifier.classify(phish_subject, phish_body, sender, headers)

    assert result.label in ("Phishing", "BEC/Fraud", "Suspicious", "Impersonation")
    assert result.urgency_score > 0
    assert len(result.contributing_factors) > 0
    # Rule score provides raw evidence score, but is appropriately flagged as uncalibrated
    assert result.confidence_calibrated is False
    assert result.confidence_method == "rule_heuristic"
    assert result.evidence_score is not None and result.evidence_score > 0


# Scenario D: Missing NLP confidence -> no hardcoded fallback (no 88, 75, 95)
def test_scenario_d_missing_nlp_confidence_no_hardcoded_fallback(report_generator):
    """Verify report generator outputs None/null instead of substituting 88.0, 75.0, 95.0."""
    email_id = uuid4()
    mock_email = Email(
        id=email_id,
        sender="sender@example.com",
        recipients=["user@company.com"],
        subject="Test Report Without NLP Confidence",
        status=EmailStatus.analyzed,
        raw_hash_sha256="abc123sha256",
    )
    mock_analysis = AnalysisResult(
        email_id=email_id,
        nlp_label="Phishing",
        nlp_confidence=None,  # Missing confidence
        nlp_details={"indicators": ["urgent_keywords"]},
        composite_risk_score=85.0,
        risk_breakdown={"factors": [], "recommended_action": "Quarantine"},
        attribution_category="Opportunistic Cybercrime",
        attribution_confidence=None,
    )

    report_json = report_generator._assemble_report_data(mock_email, mock_analysis)
    nlp_report = report_json["nlp_classification"]

    # Must NOT substitute 88.0, 75.0, 95.0, or 100.0!
    assert nlp_report["confidence"] is None
    assert nlp_report["confidence_formatted"] == "Not Computed"
    assert nlp_report["confidence_calibrated"] is False


# Scenario E: Missing attribution confidence -> no synthetic fallback (no 75.0)
def test_scenario_e_missing_attribution_confidence_no_synthetic_fallback(report_generator):
    """Verify report generator outputs None/null for attribution confidence instead of hardcoded 75.0."""
    email_id = uuid4()
    mock_email = Email(
        id=email_id,
        sender="spoofed@domain.com",
        recipients=["victim@domain.com"],
        subject="Attribution Test",
        status=EmailStatus.analyzed,
    )
    mock_analysis = AnalysisResult(
        email_id=email_id,
        nlp_label="Suspicious",
        nlp_confidence=50.0,
        nlp_details={"confidence_calibrated": False, "confidence_method": "rule_heuristic"},
        composite_risk_score=60.0,
        attribution_category="Spoofed Domain",
        attribution_confidence=None,  # Missing attribution confidence
        graph_data={"attribution_evidence_score": 75.0},
    )

    report_json = report_generator._assemble_report_data(mock_email, mock_analysis)
    attr_report = report_json["attribution"]

    # Must NOT substitute 75.0 for statistical confidence
    assert attr_report["confidence"] is None
    assert attr_report["confidence_formatted"] == "Not Computed"
    assert attr_report["confidence_calibrated"] is False
    assert attr_report["evidence_support_score"] == 75.0


# Scenario F: JSON report -> correct confidence metadata
def test_scenario_f_json_report_confidence_metadata(report_generator):
    """Verify JSON report includes confidence_calibrated, confidence_method, and evidence_score."""
    email_id = uuid4()
    mock_email = Email(
        id=email_id,
        sender="alert@bank.com",
        recipients=["client@bank.com"],
        subject="Account Security Alert",
        status=EmailStatus.analyzed,
    )
    mock_analysis = AnalysisResult(
        email_id=email_id,
        nlp_label="Phishing",
        nlp_confidence=82.5,
        nlp_details={
            "confidence_calibrated": False,
            "confidence_method": "rule_heuristic",
            "evidence_score": 82.5,
        },
        composite_risk_score=80.0,
        attribution_category="Direct Malicious Actor",
        attribution_confidence=None,
        graph_data={"attribution_evidence_score": 100.0},
    )

    report_json = report_generator._assemble_report_data(mock_email, mock_analysis)
    nlp_report = report_json["nlp_classification"]
    attr_report = report_json["attribution"]

    assert nlp_report["label"] == "Phishing"
    assert nlp_report["confidence"] == 82.5
    assert nlp_report["confidence_calibrated"] is False
    assert nlp_report["confidence_method"] == "rule_heuristic"
    assert nlp_report["evidence_score"] == 82.5

    assert attr_report["category"] == "Direct Malicious Actor"
    assert attr_report["confidence"] is None
    assert attr_report["confidence_calibrated"] is False
    assert attr_report["evidence_support_score"] == 100.0


# Scenario G: HTML/PDF report -> correct N/A and not-computed rendering
def test_scenario_g_html_and_pdf_report_rendering(report_generator):
    """Verify HTML template and PDF generation render truthfully when confidence is uncomputed or uncalibrated."""
    email_id = uuid4()
    mock_email = Email(
        id=email_id,
        sender="noreply@service.org",
        recipients=["user@company.com"],
        subject="Monthly Newsletter",
        status=EmailStatus.analyzed,
    )
    # 1. Uncomputed confidence test
    mock_analysis_uncomputed = AnalysisResult(
        email_id=email_id,
        nlp_label="Legitimate",
        nlp_confidence=None,
        nlp_details={},
        composite_risk_score=5.0,
        attribution_category="Undetermined",
        attribution_confidence=None,
    )

    report_data = report_generator._assemble_report_data(mock_email, mock_analysis_uncomputed)
    html_uncomputed = report_generator._render_html(report_data)
    assert "Confidence: Not Computed" in html_uncomputed or "Not Computed" in html_uncomputed
    # Must NOT have 88.0% or 95.0% or 0.0% fake confidence
    assert "95.0% Confidence" not in html_uncomputed
    assert "88.0% Confidence" not in html_uncomputed

    pdf_bytes = report_generator._generate_pdf_fallback(report_data)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500

    # 2. Heuristic evidence confidence test
    mock_analysis_heuristic = AnalysisResult(
        email_id=email_id,
        nlp_label="BEC/Fraud",
        nlp_confidence=85.0,
        nlp_details={
            "confidence_calibrated": False,
            "confidence_method": "rule_heuristic",
            "evidence_score": 85.0,
        },
        composite_risk_score=90.0,
        attribution_category="Opportunistic Cybercrime",
        attribution_confidence=None,
        graph_data={"attribution_evidence_score": 75.0},
    )

    report_data_heuristic = report_generator._assemble_report_data(mock_email, mock_analysis_heuristic)
    html_heuristic = report_generator._render_html(report_data_heuristic)
    assert "85.0%" in html_heuristic
    assert "Heuristic" in html_heuristic

    pdf_heuristic_bytes = report_generator._generate_pdf_fallback(report_data_heuristic)
    assert isinstance(pdf_heuristic_bytes, bytes)
    assert len(pdf_heuristic_bytes) > 500


# Scenario H: Frontend / Backend semantics alignment
def test_scenario_h_backend_semantics_alignment():
    """Verify percentage normalization preserves None and handles edge cases properly."""
    assert _normalize_percentage(None) is None
    assert _normalize_percentage("") is None
    assert _normalize_percentage(0.95) == 95.0
    assert _normalize_percentage(95.0) == 95.0
    assert _normalize_percentage(0) == 0.0
    assert _normalize_percentage("88.5") == 88.5
    assert _normalize_percentage("invalid") is None
