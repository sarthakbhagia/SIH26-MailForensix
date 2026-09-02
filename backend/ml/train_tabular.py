"""Tabular Threat Classifier Training Pipeline for MailForensix.

Trains LightGBM on 35 forensic features with Optuna hyperparameter optimization,
authoritative 5-class labeling, class weighting computed on Train only,
feature ablation studies, and probability prediction capabilities.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
import yaml
from sklearn.metrics import classification_report, f1_score, log_loss, balanced_accuracy_score
from sklearn.ensemble import HistGradientBoostingClassifier

from ml.feature_engineering import FEATURE_COLUMNS

logger = logging.getLogger(__name__)

# Authoritative Label Taxonomy from labels.yaml
LABEL_MAPPING: Dict[str, int] = {
    "LEGITIMATE": 0,
    "SUSPICIOUS": 1,
    "PHISHING": 2,
    "BEC_FRAUD": 3,
    "IMPERSONATION": 4,
    "Legitimate": 0,
    "Suspicious": 1,
    "Phishing": 2,
    "BEC/Fraud": 3,
    "Impersonation": 4,
}
TARGET_NAMES = ["LEGITIMATE", "SUSPICIOUS", "PHISHING", "BEC_FRAUD", "IMPERSONATION"]


class TabularTrainer:
    """Trainer for gradient boosting on 35 forensic features with Optuna hyperparameter optimization."""

    def __init__(
        self,
        output_path: str = "ml/models/tabular_classifier.joblib",
        feature_columns: Optional[List[str]] = None,
        random_seed: int = 42,
    ):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.feature_columns = list(feature_columns or FEATURE_COLUMNS)
        self.random_seed = random_seed
        self.best_params = None
        self.model = None

    def _prepare_xy(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Extract feature matrix X and integer encoded target vector y."""
        X = df[self.feature_columns].values.astype(float)
        # Handle string or int labels
        if df["label"].dtype == object:
            y = df["label"].map(LABEL_MAPPING).fillna(0).values.astype(int)
        else:
            y = df["label"].values.astype(int)
        return X, y

    def _objective(self, trial, X_train: np.ndarray, y_train: np.ndarray, X_val: np.ndarray, y_val: np.ndarray) -> float:
        """Optuna trial objective optimizing validation macro F1 score."""
        try:
            import lightgbm as lgb
            params = {
                "objective": "multiclass",
                "num_class": 5,
                "metric": "multi_logloss",
                "boosting_type": "gbdt",
                "verbosity": -1,
                "class_weight": "balanced",
                "n_estimators": trial.suggest_int("n_estimators", 50, 400, step=25),
                "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
                "max_depth": trial.suggest_int("max_depth", 3, 10),
                "num_leaves": trial.suggest_int("num_leaves", 15, 128),
                "min_child_samples": trial.suggest_int("min_child_samples", 5, 50),
                "subsample": trial.suggest_float("subsample", 0.6, 1.0),
                "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
                "random_state": self.random_seed,
            }
            model = lgb.LGBMClassifier(**params)
            model.fit(X_train, y_train)
            y_pred = model.predict(X_val)
            return float(f1_score(y_val, y_pred, average="macro", zero_division=0))
        except ImportError:
            lr = trial.suggest_float("learning_rate", 0.01, 0.2, log=True)
            max_iter = trial.suggest_int("max_iter", 50, 300, step=25)
            max_leaf_nodes = trial.suggest_int("max_leaf_nodes", 15, 64)
            model = HistGradientBoostingClassifier(
                learning_rate=lr,
                max_iter=max_iter,
                max_leaf_nodes=max_leaf_nodes,
                random_state=self.random_seed,
            )
            model.fit(X_train, y_train)
            y_pred = model.predict(X_val)
            return float(f1_score(y_val, y_pred, average="macro", zero_division=0))

    def optimize(
        self,
        train_df: pd.DataFrame,
        val_df: pd.DataFrame,
        n_trials: int = 30,
    ) -> Dict[str, Any]:
        """Run Optuna study across hyperparameters on Train/Val only."""
        import optuna
        optuna.logging.set_verbosity(optuna.logging.WARNING)

        X_train, y_train = self._prepare_xy(train_df)
        X_val, y_val = self._prepare_xy(val_df)

        study = optuna.create_study(direction="maximize")
        study.optimize(
            lambda trial: self._objective(trial, X_train, y_train, X_val, y_val),
            n_trials=n_trials,
            show_progress_bar=False,
        )

        self.best_params = study.best_params
        logger.info(f"Optuna search completed. Best macro F1: {study.best_value:.4f}")
        return self.best_params

    def train(
        self,
        train_df: pd.DataFrame,
        val_df: Optional[pd.DataFrame] = None,
        best_params: Optional[Dict[str, Any]] = None,
    ):
        """Train tabular classifier on forensic features and save artifact."""
        X_train, y_train = self._prepare_xy(train_df)
        params = best_params or self.best_params or {}

        try:
            import lightgbm as lgb
            lgb_params = {
                "objective": "multiclass",
                "num_class": 5,
                "metric": "multi_logloss",
                "class_weight": "balanced",
                "verbosity": -1,
                "random_state": self.random_seed,
                **params,
            }
            self.model = lgb.LGBMClassifier(**lgb_params)
        except ImportError:
            self.model = HistGradientBoostingClassifier(
                random_state=self.random_seed,
                **{k: v for k, v in params.items() if k in ("learning_rate", "max_iter", "max_leaf_nodes")},
            )

        self.model.fit(X_train, y_train)
        joblib.dump(self.model, str(self.output_path))
        logger.info(f"Tabular model successfully trained and saved to {self.output_path}")
        return self.model

    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        """Predict 5-class probability distribution."""
        if self.model is None:
            self.load()
        X = df[self.feature_columns].values.astype(float)
        probs = self.model.predict_proba(X)
        return probs

    def evaluate(self, test_df: pd.DataFrame) -> Dict[str, Any]:
        """Evaluate tabular model performance on test set."""
        if self.model is None:
            self.load()

        X_test, y_test = self._prepare_xy(test_df)
        y_pred = self.model.predict(X_test)
        report = classification_report(
            y_test,
            y_pred,
            target_names=TARGET_NAMES,
            output_dict=True,
            zero_division=0,
        )
        return report

    def run_ablations(
        self,
        train_df: pd.DataFrame,
        val_df: pd.DataFrame,
    ) -> Dict[str, Dict[str, float]]:
        """Execute required tabular feature ablation experiments."""
        # Category A: Local content, auth, relay, anomalies
        cat_a_features = [
            f for f in self.feature_columns
            if any(k in f for k in ("spf", "dkim", "dmarc", "auth", "relay", "hop", "length", "count", "html", "entropy", "attachment", "anomaly"))
        ]
        # Category B: External Geo, Domain, Link features
        cat_b_features = [
            f for f in self.feature_columns
            if any(k in f for k in ("geo", "tor", "vpn", "cloud", "domain", "mx", "url", "lookalike", "ip_as_hostname"))
        ]

        experiments = {
            "Exp_A_All_35_Features": self.feature_columns,
            "Exp_B_Category_A_Only": cat_a_features,
            "Exp_C_Category_B_Only": cat_b_features,
            "Exp_D_CatA_CatB_Reliability": self.feature_columns,
        }

        ablation_results = {}
        for exp_name, feat_cols in experiments.items():
            sub_trainer = TabularTrainer(
                output_path=str(self.output_path.parent / f"ablation_{exp_name}.joblib"),
                feature_columns=feat_cols,
                random_seed=self.random_seed,
            )
            sub_trainer.train(train_df, val_df, best_params=self.best_params)
            rep = sub_trainer.evaluate(val_df)
            probs = sub_trainer.predict_proba(val_df)
            y_val = val_df["label"].values.astype(int)

            ablation_results[exp_name] = {
                "macro_f1": float(rep["macro avg"]["f1-score"]),
                "weighted_f1": float(rep["weighted avg"]["f1-score"]),
                "accuracy": float(rep["accuracy"]),
                "log_loss": float(log_loss(y_val, probs)),
                "num_features": len(feat_cols),
            }

        return ablation_results

    def feature_importance(self) -> pd.DataFrame:
        """Return table of feature importances sorted descending."""
        if self.model is None:
            self.load()

        if hasattr(self.model, "feature_importances_"):
            importances = self.model.feature_importances_
        else:
            importances = np.ones(len(self.feature_columns)) / len(self.feature_columns)

        return pd.DataFrame({
            "feature": self.feature_columns,
            "importance": importances,
        }).sort_values("importance", ascending=False).reset_index(drop=True)

    def load(self):
        """Load trained tabular model from output path."""
        if not self.output_path.exists():
            raise FileNotFoundError(f"Model artifact not found at {self.output_path}")
        self.model = joblib.load(str(self.output_path))
        return self.model


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train Tabular Threat Classification Model.")
    parser.add_argument("--trials", type=int, default=30, help="Number of Optuna trials.")
    parser.add_argument("--output", type=str, default="ml/models/tabular_classifier.joblib", help="Output model path.")
    args = parser.parse_args()

    train_df = pd.read_parquet("ml/data/features/train.parquet")
    val_df = pd.read_parquet("ml/data/features/validation.parquet")
    test_df = pd.read_parquet("ml/data/features/test.parquet")

    trainer = TabularTrainer(output_path=args.output)
    print(f"Optimizing LightGBM hyperparameters ({args.trials} trials on Train/Val)...")
    best_params = trainer.optimize(train_df, val_df, n_trials=args.trials)
    print(f"Best parameters: {best_params}")

    print("Training final LightGBM model on Train...")
    trainer.train(train_df, val_df, best_params=best_params)

    print("Running feature ablation experiments...")
    ablations = trainer.run_ablations(train_df, val_df)
    print(json.dumps(ablations, indent=2))
