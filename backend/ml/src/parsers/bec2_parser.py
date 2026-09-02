"""BEC-2 Dataset Parser (Rohit Dube 2025).

Handles LLM-generated Business Email Compromise email dataset.
Enforces strict synthetic provenance constraints per implementation.md Section 2.2 and Section 16.2.
"""

import json
from pathlib import Path
from typing import Any, Dict, Iterator
import pandas as pd

from ml.src.parsers.base_parser import BaseDatasetParser
from ml.src.normalization.normalizer import EmailNormalizer
from ml.src.schemas.canonical_email import CanonicalEmail


class BEC2Parser(BaseDatasetParser):
    """Parses BEC-2 dataset JSON/CSV files while enforcing synthetic provenance tracking."""

    def parse(self, dataset_path: Path, config: Dict[str, Any]) -> Iterator[CanonicalEmail]:
        self.reset_stats()
        dataset_name = config.get("name", "bec2")
        source_key = config.get("dataset_key", dataset_name)
        license_str = config.get("license", "Academic research")
        license_verified = config.get("license_verified", False)

        if not dataset_path.exists():
            return

        files = [dataset_path] if dataset_path.is_file() else [
            p for p in dataset_path.rglob("*") if p.is_file() and p.suffix.lower() in (".json", ".csv", ".txt")
        ]

        for file_path in files:
            rel_path = str(file_path.relative_to(dataset_path)) if dataset_path.is_dir() else file_path.name
            try:
                if file_path.suffix.lower() == ".json":
                    content = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
                    records = content if isinstance(content, list) else [content]
                    for idx, rec in enumerate(records):
                        self.stats.discovered_count += 1
                        subject = rec.get("subject") or rec.get("Subject") or ""
                        body = rec.get("body") or rec.get("Body") or rec.get("text") or rec.get("email") or ""
                        sender = rec.get("sender") or rec.get("from") or "executive@synthetic-domain.com"
                        record_id = f"{rel_path}#item_{idx}"

                        canonical = EmailNormalizer.parse_structured_fields(
                            subject=str(subject),
                            body=str(body),
                            sender=str(sender),
                            source_dataset=source_key,
                            source_record_id=record_id,
                            source_path=rel_path,
                            source_label="BEC/Fraud",
                            is_synthetic=True,
                            synthetic_source="BEC-2 (LLM-generated; Rohit Dube 2025)",
                            construction_type="llm_generated",
                            fraud_subtype="synthetic_bec",
                            license_str=license_str,
                            license_verified=license_verified,
                            historical_reliability="low",
                        )
                        self.stats.parseable_count += 1
                        yield canonical

                elif file_path.suffix.lower() == ".csv":
                    df = pd.read_csv(file_path)
                    cols = {c.lower(): c for c in df.columns}
                    body_col = cols.get("body") or cols.get("text") or cols.get("email") or cols.get("message")
                    subject_col = cols.get("subject") or cols.get("title")

                    for idx, row in df.iterrows():
                        self.stats.discovered_count += 1
                        body = str(row[body_col]) if body_col and pd.notna(row[body_col]) else ""
                        subject = str(row[subject_col]) if subject_col and pd.notna(row[subject_col]) else ""
                        record_id = f"{rel_path}#row_{idx}"

                        canonical = EmailNormalizer.parse_structured_fields(
                            subject=subject,
                            body=body,
                            sender="executive@synthetic-domain.com",
                            source_dataset=source_key,
                            source_record_id=record_id,
                            source_path=rel_path,
                            source_label="BEC/Fraud",
                            is_synthetic=True,
                            synthetic_source="BEC-2 (LLM-generated; Rohit Dube 2025)",
                            construction_type="llm_generated",
                            fraud_subtype="synthetic_bec",
                            license_str=license_str,
                            license_verified=license_verified,
                            historical_reliability="low",
                        )
                        self.stats.parseable_count += 1
                        yield canonical

            except Exception as e:
                self.stats.failed_count += 1
                self.stats.parse_errors.append({
                    "file": str(file_path),
                    "error": str(e),
                })
