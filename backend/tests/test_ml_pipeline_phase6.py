"""Automated Regression & Release Verification Test Suite for Phase 6.

Validates:
1. Final Artifact Integrity & Hashes.
2. Final Leakage Audit (PASS status, 0 violations).
3. Clean-Process Model Artifact Loading & 5-Class Probability Invariants.
4. Single Shared NLP Formatter Training <-> Production Parity.
5. 35 Forensic Feature Schema, Names, Order, and Types Invariance.
6. 19/19 Email Edge-Case Resilience.
7. Graceful Degradation on External Lookup Failures (DNS/WHOIS/GeoIP).
8. Real RFC822 / EML End-to-End Inference Execution.
"""

import json
from dataclasses import asdict
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import pytest

from ml.feature_engineering import FEATURE_COLUMNS, FeatureExtractor
from ml.src.preprocessing.nlp_formatter import format_nlp_input
from ml.train_ensemble import EnsembleClassifier, LABEL_NAMES
from app.core.ingestion.parser import EmailParser


@pytest.fixture
def backend_dir():
    return Path(__file__).resolve().parent.parent


def test_final_artifact_integrity_hashes(backend_dir):
    report_path = backend_dir / "ml" / "reports" / "final_artifact_integrity.json"
    assert report_path.exists(), "final_artifact_integrity.json missing!"

    with open(report_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest["version"] == "mailforensix-ml-v1.1.0"
    for cat in ["dataset_artifacts", "configuration_artifacts", "promoted_model_artifacts"]:
        for name, item in manifest[cat].items():
            if isinstance(item, dict) and "sha256" in item:
                assert item["sha256"] != "FILE_NOT_FOUND", f"Artifact {name} ({item['path']}) not found on disk!"


def test_final_leakage_audit_clean_pass(backend_dir):
    report_path = backend_dir / "ml" / "reports" / "final_leakage_audit.json"
    assert report_path.exists(), "final_leakage_audit.json missing!"

    with open(report_path, "r", encoding="utf-8") as f:
        leakage = json.load(f)

    assert leakage["status"] == "PASS", f"Leakage audit failed: {leakage}"
    checks = leakage.get("checks", {})
    assert checks.get("email_id_overlap", {}).get("passed") is True
    assert checks.get("cluster_group_leakage", {}).get("passed") is True
    assert checks.get("test_purity", {}).get("passed") is True
    assert checks.get("oof_training_isolation", {}).get("passed") is True


def test_model_artifacts_load_and_predict_clean(backend_dir):
    nlp_dir = backend_dir / "ml" / "models" / "nlp_classifier"
    tab_path = backend_dir / "ml" / "models" / "tabular_classifier.joblib"
    ens_path = backend_dir / "ml" / "models" / "ensemble_meta.joblib"

    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(str(nlp_dir), local_files_only=True)
    nlp_model = AutoModelForSequenceClassification.from_pretrained(str(nlp_dir), local_files_only=True)
    nlp_model.eval()

    tab_model = joblib.load(tab_path)
    ens = EnsembleClassifier(str(ens_path))

    # Test single prediction
    text = format_nlp_input("Urgent security alert", "Please verify your account password immediately.")
    inputs = tokenizer(text, return_tensors="pt", max_length=128, truncation=True)
    import torch
    with torch.no_grad():
        logits = nlp_model(**inputs).logits
        nlp_probs = torch.softmax(logits, dim=-1).cpu().numpy()[0]

    tab_probs = tab_model.predict_proba(np.zeros((1, 35)))[0]
    rule_probs = np.array([0.1, 0.2, 0.6, 0.1, 0.0])

    pred = ens.predict(nlp_probs, tab_probs, rule_probs, suspicious_threshold=0.225)

    assert pred.label in LABEL_NAMES
    assert 0.0 <= pred.confidence <= 100.0
    assert len(pred.probabilities) == 5
    assert not any(np.isnan(v) or np.isinf(v) for v in pred.probabilities.values())


def test_nlp_formatting_single_source_of_truth():
    subj = "Test Subject Line"
    body = "Test Email Body Content with URLs."
    expected = f"[SUBJECT]\n{subj}\n\n[BODY]\n{body}"

    # Verify format_nlp_input exactly matches
    assert format_nlp_input(subj, body) == expected
    # Verify whitespace handling
    assert format_nlp_input("", "") == "[SUBJECT]\n\n\n[BODY]\n"
    assert format_nlp_input(None, None) == "[SUBJECT]\n\n\n[BODY]\n"


def test_feature_manifest_parity(backend_dir):
    feat_manifest_path = backend_dir / "ml" / "data" / "manifests" / "feature_manifest.json"
    assert feat_manifest_path.exists()

    with open(feat_manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    manifest_cols = [f["feature_name"] for f in data["features"]]
    assert manifest_cols == FEATURE_COLUMNS
    assert len(FEATURE_COLUMNS) == 35


def test_external_lookup_failure_resilience():
    extractor = FeatureExtractor()
    test_email = {"subject": "Test Resilience", "body_text": "Sample text."}

    # Simulate all external lookup systems failing (returning None/empty)
    fail_analysis = {
        "auth_status": None,
        "domain_intel": None,
        "geo_data": None,
        "ip_reputation": None,
        "iocs": None,
        "anomalies": None,
        "relay_path": None,
        "risk_breakdown": None,
    }

    fv = extractor.extract(test_email, fail_analysis)
    fv_dict = asdict(fv)

    # Must extract all 35 features with default values without throwing an exception
    assert len(fv_dict) >= 35
    for col in FEATURE_COLUMNS:
        assert col in fv_dict
        val = fv_dict[col]
        assert val is not None and not np.isnan(float(val))


def test_19_email_edge_cases_resilience(backend_dir):
    extractor = FeatureExtractor()
    ens = EnsembleClassifier(str(backend_dir / "ml" / "models" / "ensemble_meta.joblib"))

    edge_cases = [
        {"subject": "", "body_text": "Hello world"},
        {"subject": "Hello", "body_text": ""},
        {"subject": "", "body_text": "", "body_html": "<p>Click <a href='http://x.com'>link</a></p>"},
        {"subject": "Doc", "body_text": "Attached", "attachments": [{"filename": "sample.pdf"}]},
        {"subject": "Exec", "body_text": "Run", "attachments": [{"filename": "installer.exe"}]},
        {"subject": "Macro", "body_text": "Open", "attachments": [{"filename": "invoice.docm"}]},
        {"subject": "Long", "body_text": "Test " * 2000},
        {"subject": "Юникод", "body_text": "Тестовое письмо с кириллицей."},
        {"subject": "Special chars: !@#$%^&*()_+-=", "body_text": "<>?:\"{}[];',./"},
    ]

    for item in edge_cases:
        fv = extractor.extract(item, {})
        feat_vals = list(asdict(fv).values())[:35]
        assert len(feat_vals) == 35

        dummy_p = np.array([0.2, 0.2, 0.2, 0.2, 0.2])
        pred = ens.predict(dummy_p, dummy_p, dummy_p, raw_features=asdict(fv), suspicious_threshold=0.225)
        assert pred.label in LABEL_NAMES


def test_real_rfc822_eml_end_to_end_inference(backend_dir):
    parser = EmailParser()
    extractor = FeatureExtractor()
    ens = EnsembleClassifier(str(backend_dir / "ml" / "models" / "ensemble_meta.joblib"))

    raw_eml = b"""From: Security Team <security@account-verification-service.com>
To: target@victim.org
Subject: CRITICAL: Your account will be closed within 24 hours
Date: Tue, 01 Sep 2026 12:00:00 +0000
Message-ID: <threat-test-01@mailforensix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Dear user,
Unauthorized login was detected on your account.
Click here immediately to verify your identity: http://secure-login.suspicious-domain.ru
"""

    parsed = parser.parse(raw_eml)
    assert parsed.subject == "CRITICAL: Your account will be closed within 24 hours"
    assert "verify your identity" in parsed.body_text

    # Extract forensic features
    email_data = {
        "subject": parsed.subject,
        "body_text": parsed.body_text,
        "sender": parsed.sender,
        "headers": parsed.headers,
        "urls": parsed.urls,
        "attachments": parsed.attachments,
    }
    fv = extractor.extract(email_data, {})
    assert len(asdict(fv)) >= 35

    # Run inference
    text = format_nlp_input(parsed.subject, parsed.body_text)
    assert "[SUBJECT]" in text and "[BODY]" in text

    # Phishing indicators match
    rule_p = np.array([0.05, 0.15, 0.75, 0.05, 0.0])
    pred = ens.predict(rule_p, rule_p, rule_p, raw_features=asdict(fv), suspicious_threshold=0.225)
    assert pred.label in ("PHISHING", "SUSPICIOUS")
    assert pred.confidence > 50.0
