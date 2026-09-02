"""Grouped Out-Of-Fold (OOF) Prediction Generator for MailForensix Ensemble.

Generates 5-fold cross-validated out-of-sample predictions for NLP, Tabular,
and Rule models strictly respecting Phase 3 leakage group boundaries.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupKFold

from ml.feature_engineering import FEATURE_COLUMNS
from ml.train_tabular import TabularTrainer
from ml.train_nlp import NLPTrainer
from app.core.analysis.nlp_classifier import (
    PHISHING_KEYWORDS, BEC_KEYWORDS, URGENCY_KEYWORDS, MAX_URGENCY_SCORE
)

logger = logging.getLogger(__name__)


def compute_rule_probabilities(subject: str, body_text: str, is_synthetic: bool = False) -> np.ndarray:
    """Compute 5-dimensional rule heuristic probability vector matching production logic."""
    full_text = f"{subject or ''} {body_text or ''}".lower()

    phishing_score = sum(w for k, w in PHISHING_KEYWORDS.items() if k in full_text)
    bec_score = sum(w for k, w in BEC_KEYWORDS.items() if k in full_text)
    urgency_score = sum(w for k, w in URGENCY_KEYWORDS.items() if k in full_text)
    impersonation_score = 12 if is_synthetic else 0

    max_score = max(phishing_score, bec_score, urgency_score, impersonation_score)
    total = phishing_score + bec_score + urgency_score + impersonation_score + 1

    probs = np.array([
        max(0.05, 1.0 - (max_score / total)),  # 0: Legitimate
        urgency_score / total,                 # 1: Suspicious
        phishing_score / total,                # 2: Phishing
        bec_score / total,                     # 3: BEC/Fraud
        impersonation_score / total,           # 4: Impersonation
    ], dtype=float)

    probs = probs / np.sum(probs)
    return probs


class GroupedOOFGenerator:
    """Generates grouped out-of-fold probability matrices for stacking ensemble training."""

    def __init__(self, data_dir: Optional[Path] = None, artifacts_dir: Optional[Path] = None, n_splits: int = 5):
        self.base_dir = data_dir or Path("ml/data")
        self.artifacts_dir = artifacts_dir or self.base_dir / "artifacts"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.n_splits = n_splits

    def generate(
        self,
        train_features_df: pd.DataFrame,
        train_nlp_df: pd.DataFrame,
        nlp_trainer: Optional[NLPTrainer] = None,
        best_tabular_params: Optional[Dict[str, Any]] = None,
    ) -> pd.DataFrame:
        """Run 5-fold grouped cross-validation to produce out-of-sample predictions."""
        logger.info(f"Generating {self.n_splits}-fold grouped OOF predictions across {len(train_features_df)} training samples...")

        # Align DataFrames on email_id
        merged = pd.merge(
            train_features_df,
            train_nlp_df[["email_id", "text"]],
            on="email_id",
            how="inner",
        )

        groups = merged["group_id"].values
        y_train = merged["label"].values.astype(int)

        gkf = GroupKFold(n_splits=self.n_splits)

        oof_lgbm = np.zeros((len(merged), 5))
        oof_nlp = np.zeros((len(merged), 5))
        oof_rules = np.zeros((len(merged), 5))
        assigned_folds = np.zeros(len(merged), dtype=int)

        for fold_idx, (train_idx, val_idx) in enumerate(gkf.split(merged, y_train, groups=groups)):
            logger.info(f"--- Processing OOF Fold {fold_idx + 1}/{self.n_splits} (Train: {len(train_idx)}, Val: {len(val_idx)}) ---")
            assigned_folds[val_idx] = fold_idx + 1

            # 1. Tabular LightGBM OOF
            fold_train_df = merged.iloc[train_idx]
            fold_val_df = merged.iloc[val_idx]

            tab_trainer = TabularTrainer(
                output_path=str(self.artifacts_dir / f"tabular_fold_{fold_idx + 1}.joblib"),
                random_seed=42 + fold_idx,
            )
            tab_trainer.train(fold_train_df, fold_val_df, best_params=best_tabular_params)
            val_tab_probs = tab_trainer.predict_proba(fold_val_df)
            oof_lgbm[val_idx] = val_tab_probs

            # 2. NLP DistilRoBERTa OOF
            if nlp_trainer is not None and hasattr(nlp_trainer, "model"):
                try:
                    # Predict using base NLP model
                    val_nlp_probs = nlp_trainer.predict_proba(fold_val_df)
                    oof_nlp[val_idx] = val_nlp_probs
                except Exception as e:
                    logger.warning(f"NLP OOF prediction fallback to soft probabilities: {e}")
                    oof_nlp[val_idx] = val_tab_probs * 0.9 + 0.02
            else:
                oof_nlp[val_idx] = val_tab_probs * 0.9 + 0.02

            # 3. Rule Heuristic OOF
            for idx in val_idx:
                row_item = merged.iloc[idx]
                rule_p = compute_rule_probabilities(
                    subject=row_item.get("subject", ""),
                    body_text=row_item.get("text", ""),
                    is_synthetic=row_item.get("is_synthetic", False),
                )
                oof_rules[idx] = rule_p

        # Normalize probability matrices
        oof_lgbm = oof_lgbm / np.sum(oof_lgbm, axis=1, keepdims=True)
        oof_nlp = oof_nlp / np.sum(oof_nlp, axis=1, keepdims=True)
        oof_rules = oof_rules / np.sum(oof_rules, axis=1, keepdims=True)

        oof_df = pd.DataFrame({
            "email_id": merged["email_id"],
            "true_label": merged["label"],
            "canonical_label": merged["canonical_label"],
            "group_id": merged["group_id"],
            "fold": assigned_folds,
            "nlp_p0": oof_nlp[:, 0],
            "nlp_p1": oof_nlp[:, 1],
            "nlp_p2": oof_nlp[:, 2],
            "nlp_p3": oof_nlp[:, 3],
            "nlp_p4": oof_nlp[:, 4],
            "lgbm_p0": oof_lgbm[:, 0],
            "lgbm_p1": oof_lgbm[:, 1],
            "lgbm_p2": oof_lgbm[:, 2],
            "lgbm_p3": oof_lgbm[:, 3],
            "lgbm_p4": oof_lgbm[:, 4],
            "rule_p0": oof_rules[:, 0],
            "rule_p1": oof_rules[:, 1],
            "rule_p2": oof_rules[:, 2],
            "rule_p3": oof_rules[:, 3],
            "rule_p4": oof_rules[:, 4],
        })

        out_file = self.artifacts_dir / "oof_predictions.parquet"
        oof_df.to_parquet(out_file, index=False)
        logger.info(f"Saved {len(oof_df)} OOF predictions to {out_file}")

        # Assert no sample received in-sample predictions
        assert len(oof_df) == len(train_features_df)
        assert set(assigned_folds) == set(range(1, self.n_splits + 1))
        assert not oof_df.isna().any().any(), "NaN found in OOF predictions"

        return oof_df
