import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, f1_score
from sklearn.ensemble import HistGradientBoostingClassifier

from ml.feature_engineering import FEATURE_COLUMNS

logger = logging.getLogger(__name__)

LABEL_MAPPING = {
    "Legitimate": 0,
    "Suspicious": 1,
    "Phishing": 2,
    "BEC/Fraud": 3,
    "Impersonation": 4,
}


class TabularTrainer:
    """Trainer for gradient boosting on 35 forensic features with Optuna hyperparameter optimization."""

    def __init__(
        self,
        output_path: str = "ml/models/tabular_classifier.joblib",
        feature_columns: Optional[List[str]] = None,
    ):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.feature_columns = feature_columns or FEATURE_COLUMNS
        self.best_params = None
        self.model = None

    def _prepare_xy(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Extract feature matrix X and integer encoded target vector y."""
        X = df[self.feature_columns].values.astype(float)
        y = df["label"].map(LABEL_MAPPING).fillna(0).values.astype(int)
        return X, y

    def _objective(self, trial, X_train: np.ndarray, y_train: np.ndarray, X_val: np.ndarray, y_val: np.ndarray) -> float:
        """Optuna trial objective optimizing macro F1 score."""
        try:
            import lightgbm as lgb
            params = {
                "objective": "multiclass",
                "num_class": 5,
                "metric": "multi_logloss",
                "boosting_type": "gbdt",
                "verbosity": -1,
                "n_estimators": trial.suggest_int("n_estimators", 50, 500, step=25),
                "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
                "max_depth": trial.suggest_int("max_depth", 3, 10),
                "num_leaves": trial.suggest_int("num_leaves", 15, 128),
                "min_child_samples": trial.suggest_int("min_child_samples", 5, 50),
                "subsample": trial.suggest_float("subsample", 0.6, 1.0),
                "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
                "random_state": 42,
            }
            model = lgb.LGBMClassifier(**params)
            model.fit(X_train, y_train)
            y_pred = model.predict(X_val)
            return float(f1_score(y_val, y_pred, average="macro"))
        except ImportError:
            # Fallback to HistGradientBoostingClassifier
            lr = trial.suggest_float("learning_rate", 0.01, 0.2, log=True)
            max_iter = trial.suggest_int("max_iter", 50, 300, step=25)
            max_leaf_nodes = trial.suggest_int("max_leaf_nodes", 15, 64)
            model = HistGradientBoostingClassifier(
                learning_rate=lr,
                max_iter=max_iter,
                max_leaf_nodes=max_leaf_nodes,
                random_state=42,
            )
            model.fit(X_train, y_train)
            y_pred = model.predict(X_val)
            return float(f1_score(y_val, y_pred, average="macro"))

    def optimize(
        self,
        train_df: pd.DataFrame,
        val_df: pd.DataFrame,
        n_trials: int = 30,
    ) -> Dict[str, Any]:
        """Run Optuna study across hyperparameters."""
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
                "verbosity": -1,
                "random_state": 42,
                **params,
            }
            self.model = lgb.LGBMClassifier(**lgb_params)
        except ImportError:
            self.model = HistGradientBoostingClassifier(
                random_state=42,
                **{k: v for k, v in params.items() if k in ("learning_rate", "max_iter", "max_leaf_nodes")},
            )

        self.model.fit(X_train, y_train)
        joblib.dump(self.model, str(self.output_path))
        logger.info(f"Tabular model successfully trained and saved to {self.output_path}")
        return self.model

    def evaluate(self, test_df: pd.DataFrame) -> Dict[str, Any]:
        """Evaluate tabular model performance on test set."""
        if self.model is None:
            self.load()

        X_test, y_test = self._prepare_xy(test_df)
        y_pred = self.model.predict(X_test)
        report = classification_report(
            y_test,
            y_pred,
            target_names=list(LABEL_MAPPING.keys()),
            output_dict=True,
            zero_division=0,
        )
        return report

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
    from ml.data.prepare_datasets import DatasetPreparer

    parser = argparse.ArgumentParser(description="Train Tabular Threat Classification Model.")
    parser.add_argument("--trials", type=int, default=30, help="Number of Optuna trials for hyperparameter search.")
    parser.add_argument("--output", type=str, default="ml/models/tabular_classifier.joblib", help="Output model path.")
    parser.add_argument("--evaluate-only", action="store_true", help="Evaluate existing model without re-training.")
    args = parser.parse_args()

    preparer = DatasetPreparer()
    print("Preparing tabular dataset...")
    train_df, val_df, test_df = preparer.prepare_tabular_dataset()

    trainer = TabularTrainer(output_path=args.output)
    if not args.evaluate_only:
        print(f"Optimizing hyperparameters ({args.trials} trials)...")
        best_params = trainer.optimize(train_df, val_df, n_trials=args.trials)
        print(f"Best parameters: {best_params}")

        print("Training final model...")
        trainer.train(train_df, val_df, best_params=best_params)

    print("\nEvaluating model on test split:")
    report = trainer.evaluate(test_df)
    for cls_name, metrics in report.items():
        if isinstance(metrics, dict):
            print(f"  {cls_name:15s}: Precision={metrics['precision']:.3f}, Recall={metrics['recall']:.3f}, F1={metrics['f1-score']:.3f}")
        else:
            print(f"  {cls_name:15s}: {metrics:.3f}")

    print("\nTop 10 Feature Importances:")
    imp = trainer.feature_importance()
    print(imp.head(10).to_string(index=False))

