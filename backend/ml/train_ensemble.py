"""Stacking Ensemble Meta-Classifier Training Pipeline for MailForensix.

Combines 15-dimensional out-of-fold probability vectors from NLP (DistilRoBERTa),
Tabular (LightGBM), and Heuristic Rules into a calibrated stacking meta-classifier.
"""

import json
import logging
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, f1_score, log_loss

logger = logging.getLogger(__name__)

# Authoritative 5-Class Label Names matching labels.yaml
LABEL_NAMES: List[str] = ["LEGITIMATE", "SUSPICIOUS", "PHISHING", "BEC_FRAUD", "IMPERSONATION"]
assert LABEL_NAMES == ["LEGITIMATE", "SUSPICIOUS", "PHISHING", "BEC_FRAUD", "IMPERSONATION"], "Ensemble class ordering mismatch!"


@dataclass
class EnsemblePrediction:
    label: str                      # Final predicted threat class
    confidence: float               # 0-100
    probabilities: Dict[str, float] # {class_name: prob}
    nlp_contribution: Dict[str, Any]
    tabular_contribution: Dict[str, Any]
    heuristic_contribution: Dict[str, Any]
    contributing_factors: List[str]


OVERRIDE_RULES: List[Dict[str, Any]] = [
    # 1. DMARC failure + lookalike domain -> force Phishing
    {
        "condition": lambda f: f.get("dmarc_status_encoded") in (1, 2) and f.get("lookalike_domain_count", 0) > 0,
        "override_label": "PHISHING",
        "min_confidence": 85.0,
        "reason": "DMARC failure combined with lookalike domain impersonation",
    },
    # 2. Valid authentication + BEC patterns -> Compromised account / BEC
    {
        "condition": lambda f: f.get("spf_status_encoded") == 0 and f.get("dkim_status_encoded") == 0 and f.get("bec_score", 0) >= 14,
        "override_label": "BEC_FRAUD",
        "min_confidence": 80.0,
        "reason": "Passed authentication with high-risk financial transfer instructions (suspected account compromise)",
    },
    # 3. Executable attachment + suspicious URL -> critical threat
    {
        "condition": lambda f: f.get("has_executable_attachment", False) and f.get("max_url_risk_score", 0) >= 50.0,
        "override_label": "PHISHING",
        "min_confidence": 95.0,
        "reason": "Executable attachment combined with malicious/suspicious URL",
    },
    # 4. TOR exit node + newly registered sender domain
    {
        "condition": lambda f: f.get("is_tor_exit_node", False) and f.get("is_newly_registered", False),
        "override_label": "PHISHING",
        "min_confidence": 80.0,
        "reason": "Originating from TOR exit node with newly registered sender domain",
    },
]


class EnsembleClassifier:
    """Stacking meta-classifier combining NLP text probabilities, Tabular forensic probabilities, and Rule heuristics."""

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = Path(model_path) if model_path else None
        self.meta_classifier = None
        if self.model_path and self.model_path.exists():
            self.load(str(self.model_path))

    @staticmethod
    def construct_meta_features(
        nlp_probs: np.ndarray,
        tabular_probs: np.ndarray,
        heuristic_probs: np.ndarray,
    ) -> np.ndarray:
        """Stack probability distributions into a 15-dimensional meta-feature matrix."""
        nlp_2d = np.atleast_2d(nlp_probs)
        tab_2d = np.atleast_2d(tabular_probs)
        heu_2d = np.atleast_2d(heuristic_probs)
        stacked = np.hstack([nlp_2d, tab_2d, heu_2d])
        assert stacked.shape[1] == 15, f"Expected 15 meta-features, got {stacked.shape[1]}"
        return stacked

    def train(
        self,
        nlp_probs: np.ndarray,
        tabular_probs: np.ndarray,
        heuristic_probs: np.ndarray,
        labels: np.ndarray,
        class_weight: Optional[Any] = "balanced",
        output_path: str = "ml/models/ensemble_meta.joblib",
    ):
        """Train calibrated stacking logistic regression meta-classifier on 15D OOF inputs with Train-only class weighting."""
        meta_features = self.construct_meta_features(nlp_probs, tabular_probs, heuristic_probs)

        base_lr = LogisticRegression(
            solver="lbfgs",
            max_iter=1000,
            C=1.0,
            class_weight=class_weight,
            random_state=42,
        )

        try:
            self.meta_classifier = CalibratedClassifierCV(estimator=base_lr, cv=3)
            self.meta_classifier.fit(meta_features, labels)
        except Exception:
            self.meta_classifier = base_lr
            self.meta_classifier.fit(meta_features, labels)

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.meta_classifier, str(out))
        self.model_path = out
        logger.info(f"Ensemble meta-classifier saved to {out}")
        return self.meta_classifier

    def predict_proba_matrix(
        self,
        nlp_probs: np.ndarray,
        tabular_probs: np.ndarray,
        heuristic_probs: np.ndarray,
    ) -> np.ndarray:
        """Predict multi-class probabilities across multiple samples."""
        meta_features = self.construct_meta_features(nlp_probs, tabular_probs, heuristic_probs)
        if self.meta_classifier is not None:
            probs = self.meta_classifier.predict_proba(meta_features)
        else:
            w_nlp, w_tab, w_heu = 0.50, 0.35, 0.15
            probs = (
                nlp_probs * w_nlp +
                tabular_probs * w_tab +
                heuristic_probs * w_heu
            )
            probs = probs / np.sum(probs, axis=-1, keepdims=True)
        return probs

    def predict(
        self,
        nlp_probs: np.ndarray,
        tabular_probs: np.ndarray,
        heuristic_probs: np.ndarray,
        raw_features: Optional[Dict[str, Any]] = None,
        suspicious_threshold: Optional[float] = None,
    ) -> EnsemblePrediction:
        """Generate single-sample stacking ensemble prediction with domain heuristic overrides."""
        raw_f = raw_features or {}
        meta_features = self.construct_meta_features(nlp_probs, tabular_probs, heuristic_probs)

        if self.meta_classifier is not None:
            probs = self.meta_classifier.predict_proba(meta_features)[0]
        else:
            w_nlp, w_tab, w_heu = 0.50, 0.35, 0.15
            probs = (
                np.array(nlp_probs).flatten() * w_nlp +
                np.array(tabular_probs).flatten() * w_tab +
                np.array(heuristic_probs).flatten() * w_heu
            )
            probs = probs / np.sum(probs)

        # Apply minority decision threshold if specified
        if suspicious_threshold is not None and suspicious_threshold > 0.0:
            if probs[1] >= suspicious_threshold and probs[1] >= probs[2] * 0.7 and probs[1] >= probs[3] * 0.7:
                pred_idx = 1
            else:
                pred_idx = int(np.argmax(probs))
        else:
            pred_idx = int(np.argmax(probs))

        pred_label = LABEL_NAMES[pred_idx] if pred_idx < len(LABEL_NAMES) else "SUSPICIOUS"
        confidence = float(probs[pred_idx] * 100.0)

        # Apply domain expert heuristic override rules
        contributing_factors: List[str] = []
        for rule in OVERRIDE_RULES:
            try:
                if rule["condition"](raw_f):
                    contributing_factors.append(rule["reason"])
                    pred_label = rule["override_label"]
                    confidence = max(confidence, rule["min_confidence"])
            except Exception:
                pass

        prob_dict = {
            name: round(float(p) * 100.0, 1)
            for name, p in zip(LABEL_NAMES, probs)
        }

        return EnsemblePrediction(
            label=pred_label,
            confidence=round(confidence, 1),
            probabilities=prob_dict,
            nlp_contribution={"weight": 0.50, "probabilities": nlp_probs.tolist() if hasattr(nlp_probs, "tolist") else nlp_probs},
            tabular_contribution={"weight": 0.35, "probabilities": tabular_probs.tolist() if hasattr(tabular_probs, "tolist") else tabular_probs},
            heuristic_contribution={"weight": 0.15, "probabilities": heuristic_probs.tolist() if hasattr(heuristic_probs, "tolist") else heuristic_probs},
            contributing_factors=contributing_factors,
        )

    def evaluate(
        self,
        nlp_probs: np.ndarray,
        tabular_probs: np.ndarray,
        heuristic_probs: np.ndarray,
        true_labels: np.ndarray,
        suspicious_threshold: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Evaluate ensemble predictions on evaluation split."""
        probs = self.predict_proba_matrix(nlp_probs, tabular_probs, heuristic_probs)
        if suspicious_threshold is not None and suspicious_threshold > 0.0:
            pred_labels = np.zeros(len(probs), dtype=int)
            for i in range(len(probs)):
                p = probs[i]
                if p[1] >= suspicious_threshold and p[1] >= p[2] * 0.7 and p[1] >= p[3] * 0.7:
                    pred_labels[i] = 1
                else:
                    pred_labels[i] = int(np.argmax(p))
        else:
            pred_labels = np.argmax(probs, axis=-1)

        report = classification_report(
            true_labels,
            pred_labels,
            target_names=LABEL_NAMES,
            output_dict=True,
            zero_division=0,
        )
        return report

    def load(self, path: str):
        """Load trained meta-classifier from disk."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Ensemble artifact not found at {path}")
        self.meta_classifier = joblib.load(str(p))
        self.model_path = p
        return self.meta_classifier


if __name__ == "__main__":
    oof_path = Path("ml/data/artifacts/oof_predictions.parquet")
    if not oof_path.exists():
        print(f"OOF predictions file not found at {oof_path}. Run OOF generator first.")
    else:
        df_oof = pd.read_parquet(oof_path)
        nlp_p = df_oof[[f"nlp_p{i}" for i in range(5)]].values
        tab_p = df_oof[[f"lgbm_p{i}" for i in range(5)]].values
        rule_p = df_oof[[f"rule_p{i}" for i in range(5)]].values
        y_true = df_oof["true_label"].values.astype(int)

        ensemble = EnsembleClassifier()
        print("Training Stacking Ensemble meta-classifier on 15D OOF meta-features...")
        ensemble.train(nlp_p, tab_p, rule_p, y_true)
        print("Ensemble meta-classifier training completed!")
