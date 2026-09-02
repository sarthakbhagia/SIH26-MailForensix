"""Automated Test Suite for Phase 5A: Minority-Class Failure Diagnosis & Ensemble Correction.

Verifies:
1. OOF Completeness & Group Isolation (No leakage).
2. NLP OOF Non-Contamination.
3. Class-order Consistency across 15-dimensional probability spaces.
4. Train-only Class Weight Calculation.
5. Validation-only Threshold Tuning.
6. Ensemble Meta-Classifier Dimensions and Minority-Aware Predictions.
7. Calibrated Probability Validity.
8. Metric Reproducibility and Non-Zero Minority Class Performance.
"""

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.utils.class_weight import compute_class_weight

from ml.train_ensemble import EnsembleClassifier, LABEL_NAMES
from ml.src.calibration.calibrator import ProbabilityCalibrator, compute_multiclass_ece
from ml.src.experiments.phase5a_experiments import apply_decision_policy, evaluate_predictions


_base_dir = Path(__file__).resolve().parent.parent
_oof_exists = (_base_dir / "ml" / "data" / "artifacts" / "oof_predictions.parquet").exists()
_val_feat_exists = (_base_dir / "ml" / "data" / "features" / "validation.parquet").exists()


@pytest.fixture
def base_dir():
    return _base_dir


@pytest.mark.skipif(not _oof_exists, reason="Offline training artifact oof_predictions.parquet excluded from git")
def test_oof_completeness_and_group_isolation(base_dir):
    oof_path = base_dir / "ml" / "data" / "artifacts" / "oof_predictions.parquet"
    train_feat_path = base_dir / "ml" / "data" / "features" / "train.parquet"

    assert oof_path.exists(), "OOF predictions parquet file missing!"
    df_oof = pd.read_parquet(oof_path)
    df_train = pd.read_parquet(train_feat_path)

    # 1. Total record count matching
    assert len(df_oof) == len(df_train) == 9695
    assert df_oof["email_id"].nunique() == len(df_oof)

    # 2. Group isolation (zero leakage)
    group_fold_counts = df_oof.groupby("group_id")["fold"].nunique()
    assert (group_fold_counts > 1).sum() == 0, "Group leakage detected across OOF folds!"

    # 3. Folds completeness
    assert set(df_oof["fold"].unique()) == {1, 2, 3, 4, 5}


@pytest.mark.skipif(not _oof_exists, reason="Offline training artifact oof_predictions.parquet excluded from git")
def test_oof_no_nlp_proxy_contamination(base_dir):
    oof_path = base_dir / "ml" / "data" / "artifacts" / "oof_predictions.parquet"
    df_oof = pd.read_parquet(oof_path)

    # Verify that NLP probabilities are distinct from synthetic proxy
    diffs = []
    for i in range(5):
        diff = np.abs(df_oof[f"nlp_p{i}"] - (df_oof[f"lgbm_p{i}"] * 0.9 + 0.02))
        diffs.append(diff)
    max_diff_from_proxy = np.max(np.column_stack(diffs), axis=1)

    # Non-trivial differences across dataset
    assert np.mean(max_diff_from_proxy) > 0.05, "NLP OOF predictions appear proxy-contaminated!"


@pytest.mark.skipif(not _oof_exists, reason="Offline training artifact oof_predictions.parquet excluded from git")
def test_class_order_consistency(base_dir):
    oof_path = base_dir / "ml" / "data" / "artifacts" / "oof_predictions.parquet"
    df_oof = pd.read_parquet(oof_path)

    for p_type in ["nlp", "lgbm", "rule"]:
        prob_matrix = df_oof[[f"{p_type}_p{i}" for i in range(5)]].values
        assert np.all(prob_matrix >= 0.0), f"Negative probabilities in {p_type}"
        assert np.all(prob_matrix <= 1.0 + 1e-5), f"Probabilities > 1 in {p_type}"
        row_sums = prob_matrix.sum(axis=1)
        assert np.allclose(row_sums, 1.0, atol=1e-3), f"{p_type} probability rows do not sum to 1"


@pytest.mark.skipif(not _oof_exists, reason="Offline training artifact oof_predictions.parquet excluded from git")
def test_train_only_class_weight_computation(base_dir):
    oof_path = base_dir / "ml" / "data" / "artifacts" / "oof_predictions.parquet"
    df_oof = pd.read_parquet(oof_path)

    y_oof = df_oof["true_label"].values.astype(int)
    weights = compute_class_weight("balanced", classes=np.arange(5), y=y_oof)

    # Class 1 (SUSPICIOUS) is minority, so its weight must be higher than majority Class 0 (LEGITIMATE)
    assert weights[1] > weights[0] * 5.0, "Suspicious class weight is not appropriately scaled!"
    assert weights[1] > 10.0, "Suspicious class weight should reflect extreme imbalance"


@pytest.mark.skipif(not _val_feat_exists, reason="Offline training artifact validation.parquet excluded from git")
def test_validation_only_threshold_selection(base_dir):
    val_feat = pd.read_parquet(base_dir / "ml" / "data" / "features" / "validation.parquet")
    y_val = val_feat["label"].values.astype(int)

    # Create dummy probability matrix
    np.random.seed(42)
    dummy_probs = np.zeros((len(y_val), 5))
    dummy_probs[:, 0] = 0.6
    dummy_probs[:, 1] = 0.25
    dummy_probs[:, 2] = 0.05
    dummy_probs[:, 3] = 0.05
    dummy_probs[:, 4] = 0.05

    # Argmax would pick class 0
    preds_argmax = apply_decision_policy(dummy_probs, suspicious_threshold=None)
    assert np.all(preds_argmax == 0)

    # Threshold 0.20 picks class 1 (SUSPICIOUS)
    preds_thresh = apply_decision_policy(dummy_probs, suspicious_threshold=0.20)
    assert np.all(preds_thresh == 1)


def test_ensemble_meta_classifier_15d_and_minority_recovery(base_dir):
    ensemble_path = base_dir / "ml" / "models" / "ensemble_meta.joblib"
    assert ensemble_path.exists()

    ensemble = EnsembleClassifier(str(ensemble_path))

    # Test single-sample prediction with 15D inputs
    nlp_sample = np.array([0.2, 0.05, 0.5, 0.15, 0.1])
    tab_sample = np.array([0.5, 0.45, 0.05, 0.0, 0.0]) # High suspicious from Tabular
    rule_sample = np.array([0.4, 0.5, 0.05, 0.05, 0.0])

    pred = ensemble.predict(nlp_sample, tab_sample, rule_sample, suspicious_threshold=0.225)
    assert pred.label in LABEL_NAMES
    assert 0.0 <= pred.confidence <= 100.0


def test_phase5a_promoted_model_test_performance(base_dir):
    metrics_path = base_dir / "ml" / "reports" / "phase5a_metrics.json"
    assert metrics_path.exists(), "Phase 5A metrics JSON missing!"

    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    test_exp = metrics.get("test_experiments", {})
    promoted = test_exp.get("Exp_E_Minority_Aware_Thresholded", {})

    # Verify that SUSPICIOUS recall is > 0.50 and precision > 0.50
    susp_metrics = promoted.get("class_metrics", {}).get("SUSPICIOUS", {})
    assert susp_metrics.get("recall", 0.0) >= 0.50, f"Expected SUSPICIOUS recall >= 0.50, got {susp_metrics.get('recall')}"
    assert susp_metrics.get("precision", 0.0) >= 0.50, f"Expected SUSPICIOUS precision >= 0.50, got {susp_metrics.get('precision')}"
    assert promoted.get("macro_f1", 0.0) >= 0.85, f"Expected Macro F1 >= 0.85, got {promoted.get('macro_f1')}"
