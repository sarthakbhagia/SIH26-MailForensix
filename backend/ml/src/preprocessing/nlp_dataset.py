"""NLP Dataset Builder and Loader for MailForensix ML Pipeline.

Loads canonical email records and authoritative Phase 3 splits to construct
clean, leakage-free NLP datasets for transformer fine-tuning and evaluation.
"""

from pathlib import Path
from typing import Optional, Tuple, Dict, Any
import pandas as pd
import yaml

from ml.src.preprocessing.nlp_formatter import format_nlp_input

# Authoritative label map defined in labels.yaml
DEFAULT_LABEL_MAP: Dict[str, int] = {
    "LEGITIMATE": 0,
    "SUSPICIOUS": 1,
    "PHISHING": 2,
    "BEC_FRAUD": 3,
    "IMPERSONATION": 4,
}


class NLPDatasetLoader:
    """Builds and loads training, validation, and test DataFrames for transformer modeling."""

    def __init__(self, data_dir: Optional[Path] = None, label_config_path: Optional[Path] = None):
        self.base_dir = data_dir or Path("ml/data")
        self.label_config_path = label_config_path or Path("ml/config/labels.yaml")
        self.label_to_id = self._load_label_map()
        self.id_to_label = {v: k for k, v in self.label_to_id.items()}

    def _load_label_map(self) -> Dict[str, int]:
        if self.label_config_path.exists():
            try:
                with open(self.label_config_path, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f)
                    name_to_id = cfg.get("taxonomy", {}).get("name_to_id")
                    if name_to_id:
                        return {str(k): int(v) for k, v in name_to_id.items()}
            except Exception:
                pass
        return DEFAULT_LABEL_MAP

    def load_datasets(self) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Load Train, Validation, and Test NLP DataFrames.

        Returns:
            Tuple of (train_df, val_df, test_df) where each DataFrame contains:
            - email_id (str)
            - text (str, formatted with [SUBJECT] ... [BODY])
            - label (int, 0..4)
            - canonical_label (str)
            - body_truncated (bool)
        """
        emails_path = self.base_dir / "normalized" / "canonical_emails.parquet"
        splits_path = self.base_dir / "splits" / "splits.csv"

        if not emails_path.exists():
            raise FileNotFoundError(f"Canonical emails parquet not found at {emails_path}")
        if not splits_path.exists():
            raise FileNotFoundError(f"Splits file not found at {splits_path}")

        df_emails = pd.read_parquet(emails_path)
        df_splits = pd.read_csv(splits_path)

        merged = pd.merge(df_splits, df_emails, on="email_id", how="inner")

        # Filter only usable records with valid canonical labels
        valid_labels = set(self.label_to_id.keys())
        usable_mask = (merged["nlp_usable"] == True) & (merged["canonical_label"].isin(valid_labels))
        df_usable = merged[usable_mask].copy()

        # Format input text using list comprehension for fast and reliable construction
        subjects = df_usable["subject"].fillna("").astype(str).tolist()
        bodies = df_usable["body_plain"].fillna("").astype(str).tolist()
        df_usable["text"] = [format_nlp_input(s, b) for s, b in zip(subjects, bodies)]
        df_usable["body_truncated"] = [len(t) > 3000 for t in df_usable["text"]]
        df_usable["label"] = df_usable["canonical_label"].map(self.label_to_id).astype(int)

        required_cols = ["email_id", "text", "label", "canonical_label", "body_truncated", "is_synthetic"]
        if "group_id" in df_usable.columns:
            required_cols.append("group_id")

        train_df = df_usable[df_usable["split"] == "train"][required_cols].reset_index(drop=True)
        val_df = df_usable[df_usable["split"] == "validation"][required_cols].reset_index(drop=True)
        test_df = df_usable[df_usable["split"] == "test"][required_cols].reset_index(drop=True)

        return train_df, val_df, test_df
