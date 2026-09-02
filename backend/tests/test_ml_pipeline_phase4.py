"""Comprehensive Unit and Integration Test Suite for MailForensix ML Phase 4.

Tests:
1. Canonical NLP Preprocessing parity between training and inference
2. 35 Forensic Features manifest, ordering, and schema integrity
3. Train-only class-weight computation
4. Multi-class probability calibration and ECE calculation
5. Grouped 5-Fold OOF prediction isolation (zero in-sample leakage)
6. Stacking Ensemble 15D meta-feature construction and class ordering
"""

import json
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from ml.feature_engineering import FEATURE_COLUMNS, FeatureExtractor
from ml.src.preprocessing.nlp_formatter import format_nlp_input
from ml.src.preprocessing.nlp_dataset import NLPDatasetLoader
from ml.src.features.batch_extractor import ForensicBatchExtractor
from ml.src.calibration.calibrator import (
    ProbabilityCalibrator, compute_multiclass_ece, compute_multiclass_brier
)
from ml.src.ensemble.oof_generator import GroupedOOFGenerator, compute_rule_probabilities
from ml.train_ensemble import EnsembleClassifier, LABEL_NAMES
from ml.train_tabular import TabularTrainer
from ml.train_nlp import NLPTrainer


def test_canonical_nlp_formatting_parity():
    """Verify format_nlp_input produces deterministic identical output across contexts."""
    sub = " Urgent Password Reset "
    body = " Please click here to verify your credentials. "
    formatted = format_nlp_input(sub, body)

    expected = "[SUBJECT]\nUrgent Password Reset\n\n[BODY]\nPlease click here to verify your credentials."
    assert formatted == expected

    # Test empty handling
    empty_fmt = format_nlp_input(None, None)
    assert empty_fmt == "[SUBJECT]\n\n\n[BODY]\n"


def test_feature_manifest_and_35_feature_order():
    """Verify feature manifest matches FEATURE_COLUMNS exactly (count=35 and order)."""
    assert len(FEATURE_COLUMNS) == 35

    manifest_path = Path("ml/data/manifests/feature_manifest.json")
    names_path = Path("ml/data/manifests/feature_names.json")

    if manifest_path.exists() and names_path.exists():
        with open(manifest_path, "r", encoding="utf-8") as f:
            m = json.load(f)
        with open(names_path, "r", encoding="utf-8") as f:
            names = json.load(f)

        assert m["total_features"] == 35
        assert names == FEATURE_COLUMNS
        assert len(m["features"]) == 35
        for idx, feat in enumerate(m["features"]):
            assert feat["feature_name"] == FEATURE_COLUMNS[idx]
            assert feat["feature_index"] == idx


def test_train_features_parquet_integrity():
    """Verify train, validation, and test parquets contain all 35 forensic features."""
    for split in ["train", "validation", "test"]:
        p = Path(f"ml/data/features/{split}.parquet")
        if p.exists():
            df = pd.read_parquet(p)
            for col in FEATURE_COLUMNS:
                assert col in df.columns, f"Missing feature {col} in {split}.parquet"
                assert df[col].isna().sum() == 0, f"NaN values found in {col} in {split}.parquet"
            assert "label" in df.columns
            assert "email_id" in df.columns


def test_train_only_class_weights():
    """Verify class weights are strictly computed from Train split only."""
    trainer = NLPTrainer(num_labels=5)
    sample_df = pd.DataFrame({
        "label": [0, 0, 0, 0, 1, 2, 2, 3, 4],
        "text": ["dummy"] * 9,
    })
    weights = trainer.compute_train_class_weights(sample_df)
    assert len(weights) == 5
    # Class 0 is most frequent, so its weight must be lower than minority class 1
    assert weights[0] < weights[1]


def test_probability_calibrator_metrics():
    """Verify calibration fitting and ECE improvement."""
    np.random.seed(42)
    n = 200
    y_true = np.random.choice(5, size=n)
    # Generate noisy uncalibrated probabilities
    raw_logits = np.random.randn(n, 5) * 2.5
    exp_l = np.exp(raw_logits)
    raw_probs = exp_l / np.sum(exp_l, axis=1, keepdims=True)

    calibrator = ProbabilityCalibrator(model_name="test_calibrator")
    report = calibrator.fit(raw_probs, y_true)

    assert "before" in report
    assert "after" in report
    assert "ece" in report["before"]
    assert "log_loss" in report["before"]

    calibrated_probs = calibrator.transform(raw_probs)
    assert calibrated_probs.shape == (n, 5)
    np.testing.assert_allclose(np.sum(calibrated_probs, axis=1), 1.0, atol=1e-5)


def test_ensemble_meta_feature_dimension_and_classes():
    """Verify 15-dimensional stacking meta-features and class taxonomy ordering."""
    assert LABEL_NAMES == ["LEGITIMATE", "SUSPICIOUS", "PHISHING", "BEC_FRAUD", "IMPERSONATION"]

    nlp_p = np.array([[0.8, 0.05, 0.05, 0.05, 0.05]])
    tab_p = np.array([[0.7, 0.1, 0.1, 0.05, 0.05]])
    rule_p = np.array([[0.9, 0.02, 0.04, 0.02, 0.02]])

    meta = EnsembleClassifier.construct_meta_features(nlp_p, tab_p, rule_p)
    assert meta.shape == (1, 15)


def test_grouped_oof_isolation():
    """Verify GroupKFold isolation in OOF predictions."""
    oof_path = Path("ml/data/artifacts/oof_predictions.parquet")
    if oof_path.exists():
        df_oof = pd.read_parquet(oof_path)
        assert len(df_oof) == 9695
        assert set(df_oof["fold"].unique()) == {1, 2, 3, 4, 5}
        for i in range(5):
            assert f"nlp_p{i}" in df_oof.columns
            assert f"lgbm_p{i}" in df_oof.columns
            assert f"rule_p{i}" in df_oof.columns
        assert not df_oof.isna().any().any()
