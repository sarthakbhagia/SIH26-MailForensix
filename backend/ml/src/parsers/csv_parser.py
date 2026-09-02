"""CSV / Tabular format parser (e.g. for zefang-liu, IWSPA-AP TSV/CSV)."""

from pathlib import Path
from typing import Any, Dict, Iterator
import pandas as pd

from ml.src.parsers.base_parser import BaseDatasetParser
from ml.src.normalization.normalizer import EmailNormalizer
from ml.src.schemas.canonical_email import CanonicalEmail


class CSVTabularParser(BaseDatasetParser):
    """Parses structured CSV, TSV, or JSON tabular email datasets."""

    def parse(self, dataset_path: Path, config: Dict[str, Any]) -> Iterator[CanonicalEmail]:
        self.reset_stats()
        dataset_name = config.get("name", "tabular_dataset")
        source_key = config.get("dataset_key", dataset_name)
        default_label = config.get("default_label")
        source_labels = config.get("source_labels", {}) or {}
        is_synthetic = bool(config.get("is_synthetic", False))
        synthetic_source = config.get("synthetic_source")
        construction_type = config.get("construction_type", "authentic")
        license_str = config.get("license")
        license_verified = bool(config.get("license_verified", False))

        if not dataset_path.exists():
            return

        table_files = [dataset_path] if dataset_path.is_file() else [
            p for p in dataset_path.rglob("*") if p.is_file() and p.suffix.lower() in (".csv", ".tsv", ".json", ".parquet")
        ]

        for table_file in table_files:
            rel_path = str(table_file.relative_to(dataset_path)) if dataset_path.is_dir() else table_file.name
            try:
                if table_file.suffix.lower() == ".csv":
                    df = pd.read_csv(table_file)
                elif table_file.suffix.lower() == ".tsv":
                    df = pd.read_csv(table_file, sep="\t")
                elif table_file.suffix.lower() == ".json":
                    df = pd.read_json(table_file)
                elif table_file.suffix.lower() == ".parquet":
                    df = pd.read_parquet(table_file)
                else:
                    continue

                # Auto-detect column names
                cols = {c.lower(): c for c in df.columns}
                body_col = cols.get("body") or cols.get("text") or cols.get("email_text") or cols.get("email") or cols.get("message")
                subject_col = cols.get("subject") or cols.get("title")
                sender_col = cols.get("sender") or cols.get("from") or cols.get("from_address")
                label_col = cols.get("label") or cols.get("target") or cols.get("class") or cols.get("category")

                for idx, row in df.iterrows():
                    self.stats.discovered_count += 1
                    try:
                        raw_body = str(row[body_col]) if body_col and pd.notna(row[body_col]) else ""
                        raw_subject = str(row[subject_col]) if subject_col and pd.notna(row[subject_col]) else ""
                        raw_sender = str(row[sender_col]) if sender_col and pd.notna(row[sender_col]) else ""

                        raw_lbl = str(row[label_col]) if label_col and pd.notna(row[label_col]) else default_label
                        mapped_lbl = source_labels.get(raw_lbl, source_labels.get(str(raw_lbl).lower(), raw_lbl))

                        record_id = f"{rel_path}#row_{idx}"

                        canonical = EmailNormalizer.parse_structured_fields(
                            subject=raw_subject,
                            body=raw_body,
                            sender=raw_sender,
                            source_dataset=source_key,
                            source_record_id=record_id,
                            source_path=rel_path,
                            source_label=mapped_lbl,
                            is_synthetic=is_synthetic,
                            synthetic_source=synthetic_source,
                            construction_type=construction_type,
                            license_str=license_str,
                            license_verified=license_verified,
                            historical_reliability="low" if not sender_col else "medium",
                        )
                        self.stats.parseable_count += 1
                        yield canonical
                    except Exception as row_err:
                        self.stats.failed_count += 1
                        self.stats.parse_errors.append({
                            "file": str(table_file),
                            "row_index": idx,
                            "error": str(row_err),
                        })
            except Exception as file_err:
                self.stats.failed_count += 1
                self.stats.parse_errors.append({
                    "file": str(table_file),
                    "error": str(file_err),
                })
