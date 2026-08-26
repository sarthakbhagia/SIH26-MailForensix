import logging
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV

logger = logging.getLogger(__name__)

LABEL_NAMES = ["Legitimate", "Suspicious", "Phishing", "BEC/Fraud", "Impersonation"]


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
        "override_label": "Phishing",
        "min_confidence": 85.0,
        "reason": "DMARC failure combined with lookalike domain impersonation",
    },
    # 2. Valid authentication + BEC patterns -> Compromised account / BEC
    {
        "condition": lambda f: f.get("spf_status_encoded") == 0 and f.get("dkim_status_encoded") == 0 and f.get("bec_score", 0) >= 14,
        "override_label": "BEC/Fraud",
        "min_confidence": 80.0,
        "reason": "Passed authentication with high-risk financial transfer instructions (suspected account compromise)",
    },
    # 3. Executable attachment + suspicious URL -> critical threat
    {
        "condition": lambda f: f.get("has_executable_attachment", False) and f.get("max_url_risk_score", 0) >= 50.0,
        "override_label": "Phishing",
        "min_confidence": 95.0,
        "reason": "Executable attachment combined with malicious/suspicious URL",
    },
    # 4. TOR exit node + newly registered sender domain
    {
        "condition": lambda f: f.get("is_tor_exit_node", False) and f.get("is_newly_registered", False),
        "override_label": "Phishing",
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
        # Ensure 2D arrays of shape (n_samples, 5)
        nlp_2d = np.atleast_2d(nlp_probs)
        tab_2d = np.atleast_2d(tabular_probs)
        heu_2d = np.atleast_2d(heuristic_probs)
        return np.hstack([nlp_2d, tab_2d, heu_2d])

    def train(
        self,
        nlp_probs: np.ndarray,
        tabular_probs: np.ndarray,
        heuristic_probs: np.ndarray,
        labels: np.ndarray,
        output_path: str = "ml/models/ensemble_meta.joblib",
    ):
        """Train calibrated stacking logistic regression meta-classifier."""
        meta_features = self.construct_meta_features(nlp_probs, tabular_probs, heuristic_probs)

        base_lr = LogisticRegression(
            solver="lbfgs",
            max_iter=1000,
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

    def predict(
        self,
        nlp_probs: np.ndarray,
        tabular_probs: np.ndarray,
        heuristic_probs: np.ndarray,
        raw_features: Optional[Dict[str, Any]] = None,
    ) -> EnsemblePrediction:
        """Generate stacking ensemble prediction with domain heuristic overrides."""
        raw_f = raw_features or {}
        meta_features = self.construct_meta_features(nlp_probs, tabular_probs, heuristic_probs)

        if self.meta_classifier is not None:
            probs = self.meta_classifier.predict_proba(meta_features)[0]
        else:
            # Fallback weighted average if model not trained yet
            w_nlp, w_tab, w_heu = 0.50, 0.35, 0.15
            probs = (
                np.array(nlp_probs).flatten() * w_nlp +
                np.array(tabular_probs).flatten() * w_tab +
                np.array(heuristic_probs).flatten() * w_heu
            )
            probs = probs / np.sum(probs)

        pred_idx = int(np.argmax(probs))
        pred_label = LABEL_NAMES[pred_idx] if pred_idx < len(LABEL_NAMES) else "Suspicious"
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

    def load(self, path: str):
        """Load trained meta-classifier from disk."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Ensemble artifact not found at {path}")
        self.meta_classifier = joblib.load(str(p))
        self.model_path = p
        return self.meta_classifier


if __name__ == "__main__":
    import argparse
    from ml.data.prepare_datasets import DatasetPreparer
    from ml.train_tabular import TabularTrainer
    from ml.feature_engineering import FEATURE_COLUMNS

    parser = argparse.ArgumentParser(description="Train Stacking Ensemble Meta-Classifier.")
    parser.add_argument("--output", type=str, default="ml/models/ensemble_meta.joblib", help="Output model path.")
    parser.add_argument("--tabular-model", type=str, default="ml/models/tabular_classifier.joblib", help="Tabular model path.")
    args = parser.parse_args()

    preparer = DatasetPreparer()
    print("Preparing datasets for stacking...")
    train_df, val_df, test_df = preparer.prepare_tabular_dataset()

    # Load or train tabular model
    tab_trainer = TabularTrainer(output_path=args.tabular_model)
    if Path(args.tabular_model).exists():
        tab_trainer.load()
    else:
        print("Training baseline tabular model...")
        tab_trainer.train(train_df, val_df)

    # Generate probabilities for stacking
    X_train = train_df[FEATURE_COLUMNS].values.astype(float)
    y_train = train_df["label"].map({"Legitimate": 0, "Suspicious": 1, "Phishing": 2, "BEC/Fraud": 3, "Impersonation": 4}).values.astype(int)
    tab_probs = tab_trainer.model.predict_proba(X_train)

    # Simulated NLP & heuristic probabilities
    nlp_probs = tab_probs * 0.9 + np.random.uniform(0, 0.1, size=tab_probs.shape)
    nlp_probs = nlp_probs / nlp_probs.sum(axis=1, keepdims=True)
    heu_probs = tab_probs * 0.85 + np.random.uniform(0, 0.15, size=tab_probs.shape)
    heu_probs = heu_probs / heu_probs.sum(axis=1, keepdims=True)

    ensemble = EnsembleClassifier()
    print("Training Calibrated Logistic Regression stacking meta-classifier...")
    ensemble.train(nlp_probs, tab_probs, heu_probs, y_train, output_path=args.output)
    print(f"Ensemble meta-classifier successfully trained and saved to {args.output}")

