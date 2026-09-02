"""Final Model Evaluation and Benchmarking Module for MailForensix.

Evaluates frozen models against the untouched Test split (1,548 real emails, 0 synthetic)
and computes standardized metrics across all model families:
1. Majority Class Baseline
2. Rules-Only Baseline
3. DistilRoBERTa NLP Classifier
4. LightGBM Tabular Classifier
5. Stacking Ensemble
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_recall_fscore_support,
)

logger = logging.getLogger(__name__)

CLASS_NAMES = ["LEGITIMATE", "SUSPICIOUS", "PHISHING", "BEC_FRAUD", "IMPERSONATION"]


class FrozenTestEvaluator:
    """Evaluates fully trained and calibrated models against the untouched Test dataset."""

    def __init__(self, reports_dir: Optional[Path] = None):
        self.reports_dir = reports_dir or Path("ml/reports")
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def evaluate_model(
        self,
        model_name: str,
        y_true: np.ndarray,
        y_probs: np.ndarray,
        is_calibrated: bool = False,
    ) -> Dict[str, Any]:
        """Compute full suite of classification and calibration metrics on Test split."""
        y_pred = np.argmax(y_probs, axis=-1)

        # Basic metrics
        acc = float(accuracy_score(y_true, y_pred))
        bal_acc = float(balanced_accuracy_score(y_true, y_pred))
        macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
        weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

        # Multi-class Log Loss (with epsilon clipping)
        eps = 1e-7
        clipped_probs = np.clip(y_probs, eps, 1.0 - eps)
        clipped_probs = clipped_probs / np.sum(clipped_probs, axis=-1, keepdims=True)
        # Note: Log loss requires classes present or class labels specified
        loss = float(log_loss(y_true, clipped_probs, labels=list(range(len(CLASS_NAMES)))))

        # Per-class breakdown
        per_class = {}
        for c_idx, c_name in enumerate(CLASS_NAMES):
            true_mask = (y_true == c_idx)
            pred_mask = (y_pred == c_idx)
            support = int(np.sum(true_mask))

            if support == 0:
                per_class[c_name] = {
                    "status": "NOT AVAILABLE / INSUFFICIENT REAL TEST DATA",
                    "support": 0,
                    "precision": None,
                    "recall": None,
                    "f1_score": None,
                    "false_positive_count": int(np.sum(pred_mask & ~true_mask)),
                }
            else:
                tp = int(np.sum(true_mask & pred_mask))
                fp = int(np.sum(~true_mask & pred_mask))
                fn = int(np.sum(true_mask & ~pred_mask))
                prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
                rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
                f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

                per_class[c_name] = {
                    "support": support,
                    "precision": round(prec, 4),
                    "recall": round(rec, 4),
                    "f1_score": round(f1, 4),
                    "true_positive_count": tp,
                    "false_positive_count": fp,
                    "false_negative_count": fn,
                }

        # Confusion Matrix
        cm = confusion_matrix(y_true, y_pred, labels=list(range(len(CLASS_NAMES)))).tolist()

        return {
            "model_name": model_name,
            "is_calibrated": is_calibrated,
            "accuracy": round(acc, 4),
            "balanced_accuracy": round(bal_acc, 4),
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "log_loss": round(loss, 4),
            "confusion_matrix": cm,
            "class_metrics": per_class,
        }

    def evaluate_all(
        self,
        y_true: np.ndarray,
        majority_probs: np.ndarray,
        rule_probs: np.ndarray,
        nlp_probs: np.ndarray,
        tabular_probs: np.ndarray,
        ensemble_probs: np.ndarray,
        nlp_calibrated_probs: Optional[np.ndarray] = None,
        tabular_calibrated_probs: Optional[np.ndarray] = None,
    ) -> Dict[str, Any]:
        """Benchmark all baseline and candidate models on Test split."""
        results = {
            "test_sample_count": len(y_true),
            "test_synthetic_count": 0,
            "models": {
                "majority_baseline": self.evaluate_model("Majority Baseline", y_true, majority_probs),
                "rule_heuristic_baseline": self.evaluate_model("Rule Heuristics", y_true, rule_probs),
                "distilroberta_raw": self.evaluate_model("DistilRoBERTa (Raw)", y_true, nlp_probs),
                "lightgbm_raw": self.evaluate_model("LightGBM (Raw)", y_true, tabular_probs),
                "stacking_ensemble": self.evaluate_model("Stacking Ensemble", y_true, ensemble_probs),
            }
        }

        if nlp_calibrated_probs is not None:
            results["models"]["distilroberta_calibrated"] = self.evaluate_model(
                "DistilRoBERTa (Calibrated)", y_true, nlp_calibrated_probs, is_calibrated=True
            )
        if tabular_calibrated_probs is not None:
            results["models"]["lightgbm_calibrated"] = self.evaluate_model(
                "LightGBM (Calibrated)", y_true, tabular_calibrated_probs, is_calibrated=True
            )

        # Save metrics json
        out_json = self.reports_dir / "phase4_metrics.json"
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        logger.info(f"Saved test evaluation metrics to {out_json}")

        return results
