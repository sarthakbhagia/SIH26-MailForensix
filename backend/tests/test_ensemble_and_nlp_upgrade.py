import pytest
import numpy as np
from app.core.analysis.nlp_classifier import NLPClassifier, NLPClassificationResult
from ml.train_ensemble import EnsembleClassifier, EnsemblePrediction, OVERRIDE_RULES


def test_ensemble_meta_features_and_training(tmp_path):
    ensemble = EnsembleClassifier()

    n = 20
    nlp_probs = np.random.dirichlet(np.ones(5), size=n)
    tab_probs = np.random.dirichlet(np.ones(5), size=n)
    heu_probs = np.random.dirichlet(np.ones(5), size=n)
    labels = np.random.choice([0, 1, 2, 3, 4], size=n)

    # 1. Meta feature construction
    meta_f = ensemble.construct_meta_features(nlp_probs, tab_probs, heu_probs)
    assert meta_f.shape == (n, 15)

    # 2. Training and saving
    model_file = tmp_path / "test_ensemble.joblib"
    ensemble.train(nlp_probs, tab_probs, heu_probs, labels, output_path=str(model_file))
    assert model_file.exists()

    # 3. Loading
    loaded_ensemble = EnsembleClassifier(model_path=str(model_file))
    pred = loaded_ensemble.predict(
        nlp_probs=nlp_probs[0],
        tabular_probs=tab_probs[0],
        heuristic_probs=heu_probs[0],
        raw_features={},
    )
    assert isinstance(pred, EnsemblePrediction)
    assert pred.label in ("Legitimate", "Suspicious", "Phishing", "BEC/Fraud", "Impersonation")
    assert 0.0 <= pred.confidence <= 100.0


def test_ensemble_override_rules():
    ensemble = EnsembleClassifier()
    dummy_probs = np.array([0.9, 0.025, 0.025, 0.025, 0.025])  # Heavily predicting Legitimate

    # 1. DMARC failure + lookalike domain -> force Phishing (min 85%)
    pred1 = ensemble.predict(
        nlp_probs=dummy_probs,
        tabular_probs=dummy_probs,
        heuristic_probs=dummy_probs,
        raw_features={"dmarc_status_encoded": 1, "lookalike_domain_count": 1},
    )
    assert pred1.label == "Phishing"
    assert pred1.confidence >= 85.0
    assert any("DMARC" in factor for factor in pred1.contributing_factors)

    # 2. Executable + High URL Risk -> force Phishing (min 95%)
    pred2 = ensemble.predict(
        nlp_probs=dummy_probs,
        tabular_probs=dummy_probs,
        heuristic_probs=dummy_probs,
        raw_features={"has_executable_attachment": True, "max_url_risk_score": 75.0},
    )
    assert pred2.label == "Phishing"
    assert pred2.confidence >= 95.0


def test_nlp_classifier_rule_fallback():
    classifier = NLPClassifier()

    # 1. Legitimate email
    res_legit = classifier.classify(
        subject="Team Meeting Tomorrow",
        body_text="Hi team, see you at 10 AM in Conference Room B.",
        sender="bob@company.com",
        headers={"from": "Bob <bob@company.com>"},
    )
    assert isinstance(res_legit, NLPClassificationResult)
    assert res_legit.label == "Legitimate"

    # 2. BEC / Fraud email
    res_bec = classifier.classify(
        subject="Urgent: Wire Transfer Required",
        body_text="Please process a confidential wire transfer of $50,000 to Account #12345 today.",
        sender="ceo@company.com",
        headers={"from": "CEO <ceo@company.com>"},
    )
    assert res_bec.label == "BEC/Fraud"
    assert len(res_bec.bec_indicators) >= 1
    assert "wire transfer" in res_bec.bec_indicators

    # 3. Phishing email
    res_phish = classifier.classify(
        subject="Security Alert: Verify Your Account Immediately",
        body_text="Your account suspended. Click here immediately to update your payment within 24 hours.",
        sender="security@bad-domain.com",
        headers={"from": "Security Alert <security@bad-domain.com>"},
    )
    assert res_phish.label == "Phishing"
    assert res_phish.urgency_score > 0.0
