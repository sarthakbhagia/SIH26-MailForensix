"""Comprehensive Unit & Integration Test Suite for ML Runtime Activation.

Tests:
1. Test A: Application and NLPClassifier load all 3 models (DistilRoBERTa, LightGBM, Ensemble) on startup.
2. Test B: NLPClassifier.classify() executes DistilRoBERTa transformer inference.
3. Test C: FeatureExtractor extracts the exact 35 canonical features with proper types and bounds.
4. Test D: LightGBM predict_proba() is invoked with the 35 tabular features.
5. Test E: Stacking Ensemble receives NLP, real tabular, and heuristic probabilities.
6. Test F: ML result reports calibrated confidence (confidence_calibrated=True) and ensemble_stacking method.
7. Test G: Graceful heuristic fallback occurs when models are unconfigured/missing.
8. Test H: End-to-end AnalysisPipeline.run() executes the complete active ML flow.
"""

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
import numpy as np
import pandas as pd
import pytest

from app.config import settings
from app.core.analysis.nlp_classifier import NLPClassifier, NLPClassificationResult
from app.core.correlation.risk_scorer import RiskScorer
from app.core.pipeline import AnalysisPipeline
from app.models.analysis_result import AnalysisResult
from app.models.email_case import Email, EmailStatus
from ml.feature_engineering import FEATURE_COLUMNS, FeatureExtractor
from ml.train_ensemble import LABEL_NAMES


@pytest.fixture
def backend_dir():
    return Path(__file__).resolve().parent.parent


def test_test_a_application_loads_models_successfully(backend_dir):
    """Test A: Verify NLPClassifier discovers and loads DistilRoBERTa, LightGBM, and Ensemble."""
    clf = NLPClassifier(
        model_path=settings.NLP_MODEL_PATH,
        ensemble_path=settings.ENSEMBLE_MODEL_PATH,
        tabular_path=settings.TABULAR_MODEL_PATH,
    )
    assert clf.rule_based_only is False
    assert clf.transformer_model is not None
    assert clf.tokenizer is not None
    assert clf.tabular_classifier is not None
    assert clf.ensemble_classifier is not None


def test_test_b_transformer_inference_executes(backend_dir):
    """Test B: Verify NLPClassifier.classify() executes DistilRoBERTa transformer."""
    clf = NLPClassifier(
        model_path=settings.NLP_MODEL_PATH,
        ensemble_path=settings.ENSEMBLE_MODEL_PATH,
        tabular_path=settings.TABULAR_MODEL_PATH,
    )
    res = clf.classify(
        subject="CRITICAL: Password verification required",
        body_text="Your account will be terminated unless you verify credentials at http://evil.com",
        sender="security@alert-service.com",
        headers={"from": "security@alert-service.com"},
    )
    assert isinstance(res, NLPClassificationResult)
    assert res.label in LABEL_NAMES
    assert res.confidence_calibrated is True
    assert res.confidence_method == "ensemble_stacking"
    assert res.confidence is not None
    assert 0.0 <= res.confidence <= 100.0


def test_test_c_feature_extractor_35_features():
    """Test C: Verify FeatureExtractor produces exactly the 35 expected features."""
    extractor = FeatureExtractor()
    email_data = {
        "subject": "Wire Transfer Invoice",
        "body_text": "Please process payment of $45,000 immediately.",
        "sender": "ceo@company.com",
        "headers": {"received-spf": "Pass", "dkim-signature": "v=1; a=rsa-sha256;"},
        "urls": ["http://bank-payment-portal.com"],
        "attachments": [{"filename": "invoice.pdf", "size": 1024}],
    }
    analysis_context = {
        "auth_status": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "geo_data": [{"infrastructure_type": "residential", "ip": "1.2.3.4"}],
        "ip_reputation": {"score": 85.0},
    }
    fv = extractor.extract(email_data, analysis_context)
    fv_dict = asdict(fv)

    assert len(fv_dict) == 35
    for col in FEATURE_COLUMNS:
        assert col in fv_dict
        assert fv_dict[col] is not None


def test_test_d_tabular_lightgbm_is_called(backend_dir):
    """Test D: Verify LightGBM predict_proba is called with tabular features."""
    clf = NLPClassifier(
        model_path=settings.NLP_MODEL_PATH,
        ensemble_path=settings.ENSEMBLE_MODEL_PATH,
        tabular_path=settings.TABULAR_MODEL_PATH,
    )

    with patch.object(clf.tabular_classifier, "predict_proba", wraps=clf.tabular_classifier.predict_proba) as mock_predict_proba:
        res = clf.classify(
            subject="Invoice attached for payment",
            body_text="Please find attached invoice for payment to updated bank account.",
            sender="accounting@supplier.com",
            headers={"from": "accounting@supplier.com"},
        )
        assert mock_predict_proba.called
        assert mock_predict_proba.call_count >= 1
        args, kwargs = mock_predict_proba.call_args
        df_passed = args[0]
        assert isinstance(df_passed, pd.DataFrame)
        assert list(df_passed.columns) == FEATURE_COLUMNS


def test_test_e_ensemble_receives_all_probability_streams(backend_dir):
    """Test E: Verify EnsembleClassifier receives NLP, Tabular, and Heuristic probabilities."""
    clf = NLPClassifier(
        model_path=settings.NLP_MODEL_PATH,
        ensemble_path=settings.ENSEMBLE_MODEL_PATH,
        tabular_path=settings.TABULAR_MODEL_PATH,
    )

    with patch.object(clf.ensemble_classifier, "predict", wraps=clf.ensemble_classifier.predict) as mock_ens_predict:
        res = clf.classify(
            subject="Urgent action required",
            body_text="Click here to login and update account details.",
            sender="admin@notice.com",
            headers={"from": "admin@notice.com"},
        )
        assert mock_ens_predict.called
        kwargs = mock_ens_predict.call_args.kwargs
        assert "nlp_probs" in kwargs
        assert "tabular_probs" in kwargs
        assert "heuristic_probs" in kwargs
        assert len(kwargs["nlp_probs"]) == 5
        assert len(kwargs["tabular_probs"]) == 5
        assert len(kwargs["heuristic_probs"]) == 5
        assert kwargs.get("suspicious_threshold") == 0.225


def test_test_f_ml_metadata_provenance(backend_dir):
    """Test F: Verify ML result correctly reports calibrated confidence and stacking method."""
    clf = NLPClassifier(
        model_path=settings.NLP_MODEL_PATH,
        ensemble_path=settings.ENSEMBLE_MODEL_PATH,
        tabular_path=settings.TABULAR_MODEL_PATH,
    )
    res = clf.classify(
        subject="Quarterly financial review",
        body_text="Please review the attached financial statements for Q3.",
        sender="cfo@company.com",
        headers={"from": "cfo@company.com"},
    )
    assert res.confidence_calibrated is True
    assert res.confidence_method == "ensemble_stacking"
    assert res.evidence_score == res.confidence


def test_test_g_graceful_fallback_when_models_absent():
    """Test G: Verify rule-based heuristic fallback occurs when models are absent."""
    clf = NLPClassifier(model_path=None, ensemble_path=None, tabular_path=None)
    assert clf.rule_based_only is True

    res = clf.classify(
        subject="Meeting at 2pm",
        body_text="Hi, see you in conference room A.",
        sender="colleague@work.com",
        headers={"from": "colleague@work.com"},
    )
    assert res.confidence_calibrated is False
    assert res.confidence_method == "rule_heuristic"
    assert res.label in ("Legitimate", "Suspicious", "Phishing", "BEC/Fraud", "Impersonation")


@pytest.mark.asyncio
async def test_test_h_pipeline_run_with_active_ml(backend_dir):
    """Test H: Verify complete AnalysisPipeline.run() executes and persists ML results."""
    pipeline = AnalysisPipeline()
    assert pipeline.nlp_classifier.rule_based_only is False

    test_id = uuid4()
    mock_email = Email(
        id=test_id,
        sender="security@alert-service.com",
        recipients=["target@victim.org"],
        subject="CRITICAL: Your account will be closed within 24 hours",
        body_text="Please verify your identity immediately at http://secure-login.suspicious.ru",
        body_html="<p>Please verify your identity immediately</p>",
        headers={"from": "security@alert-service.com", "received_hops": []},
        urls=["http://secure-login.suspicious.ru"],
        attachments=[],
        raw_eml=b"From: security@alert-service.com\nSubject: CRITICAL\n\nBody",
        status=EmailStatus.pending,
        ingested_at=datetime.now(timezone.utc),
    )

    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_execute_result = MagicMock()
    mock_execute_result.scalar_one_or_none.return_value = mock_email
    mock_db.execute.return_value = mock_execute_result

    analysis = await pipeline.run(test_id, mock_db)
    assert analysis is not None
    assert analysis.nlp_label in LABEL_NAMES
    assert analysis.nlp_confidence is not None
    assert analysis.nlp_details["confidence_calibrated"] is True
    assert analysis.nlp_details["confidence_method"] == "ensemble_stacking"
    assert 0.0 <= analysis.composite_risk_score <= 100.0
