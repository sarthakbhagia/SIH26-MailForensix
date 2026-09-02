"""Probability Calibration Module for Base Threat Classifiers.

Fits sigmoid/Platt scaling on held-out validation predictions (never on Test),
computes calibration metrics (ECE, Brier score, Multi-class Log Loss),
and applies isotonic/sigmoid transformation.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, log_loss

logger = logging.getLogger(__name__)


def compute_multiclass_ece(probs: np.ndarray, labels: np.ndarray, n_bins: int = 10) -> float:
    """Compute Expected Calibration Error (ECE) across multi-class predictions."""
    confidences = np.max(probs, axis=-1)
    predictions = np.argmax(probs, axis=-1)
    accuracies = (predictions == labels)

    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    total_samples = len(labels)

    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]
        in_bin = (confidences > bin_lower) & (confidences <= bin_upper)
        bin_size = np.sum(in_bin)

        if bin_size > 0:
            bin_acc = np.mean(accuracies[in_bin])
            bin_conf = np.mean(confidences[in_bin])
            ece += (bin_size / total_samples) * np.abs(bin_acc - bin_conf)

    return float(ece)


def compute_multiclass_brier(probs: np.ndarray, labels: np.ndarray, n_classes: int = 5) -> float:
    """Compute mean multi-class Brier score."""
    one_hot = np.zeros((len(labels), n_classes))
    for i, y in enumerate(labels):
        if 0 <= y < n_classes:
            one_hot[i, y] = 1.0
    return float(np.mean(np.sum((probs - one_hot) ** 2, axis=-1)))


class ProbabilityCalibrator:
    """Platt scaling multi-class probability calibrator."""

    def __init__(self, model_name: str = "classifier", output_dir: Optional[Path] = None):
        self.model_name = model_name
        self.output_dir = output_dir or Path("ml/models")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.calibrator = None
        self.metrics_before = {}
        self.metrics_after = {}

    def fit(self, uncalibrated_probs: np.ndarray, true_labels: np.ndarray) -> Dict[str, Any]:
        """Fit calibration mapping on held-out validation predictions."""
        eps = 1e-7
        clipped = np.clip(uncalibrated_probs, eps, 1.0 - eps)
        # Compute log-odds
        log_odds = np.log(clipped / (1.0 - clipped))

        # Evaluate before
        self.metrics_before = {
            "log_loss": float(log_loss(true_labels, clipped)),
            "ece": compute_multiclass_ece(clipped, true_labels),
            "brier_score": compute_multiclass_brier(clipped, true_labels),
        }

        # Fit multi-class Platt calibrator
        self.calibrator = LogisticRegression(
            solver="lbfgs",
            max_iter=1000,
            C=1.0,
            random_state=42,
        )
        self.calibrator.fit(log_odds, true_labels)

        # Evaluate after
        calibrated = self.transform(uncalibrated_probs)
        self.metrics_after = {
            "log_loss": float(log_loss(true_labels, calibrated)),
            "ece": compute_multiclass_ece(calibrated, true_labels),
            "brier_score": compute_multiclass_brier(calibrated, true_labels),
        }

        self.save()
        logger.info(
            f"Calibration ({self.model_name}): ECE {self.metrics_before['ece']:.4f} -> {self.metrics_after['ece']:.4f}, "
            f"LogLoss {self.metrics_before['log_loss']:.4f} -> {self.metrics_after['log_loss']:.4f}"
        )
        return {
            "before": self.metrics_before,
            "after": self.metrics_after,
            "improved_ece": self.metrics_after["ece"] < self.metrics_before["ece"],
        }

    def transform(self, uncalibrated_probs: np.ndarray) -> np.ndarray:
        """Apply fitted calibration mapping to probabilities."""
        if self.calibrator is None:
            return uncalibrated_probs

        eps = 1e-7
        clipped = np.clip(uncalibrated_probs, eps, 1.0 - eps)
        log_odds = np.log(clipped / (1.0 - clipped))

        calibrated = self.calibrator.predict_proba(log_odds)
        # Ensure normalization
        calibrated = calibrated / np.sum(calibrated, axis=-1, keepdims=True)
        return calibrated

    def save(self):
        """Save fitted calibration model to disk."""
        out_file = self.output_dir / f"{self.model_name}_calibrator.joblib"
        joblib.dump({
            "calibrator": self.calibrator,
            "metrics_before": self.metrics_before,
            "metrics_after": self.metrics_after,
        }, str(out_file))

    def load(self):
        """Load calibration model from disk."""
        out_file = self.output_dir / f"{self.model_name}_calibrator.joblib"
        if out_file.exists():
            data = joblib.load(str(out_file))
            self.calibrator = data.get("calibrator")
            self.metrics_before = data.get("metrics_before", {})
            self.metrics_after = data.get("metrics_after", {})
            return self.calibrator
        return None
