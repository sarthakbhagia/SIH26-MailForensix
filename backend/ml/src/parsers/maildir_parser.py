"""Maildir format parser (e.g. for Enron Corpus)."""

import os
from pathlib import Path
from typing import Any, Dict, Iterator

from ml.src.parsers.base_parser import BaseDatasetParser
from ml.src.normalization.normalizer import EmailNormalizer
from ml.src.schemas.canonical_email import CanonicalEmail


class MaildirParser(BaseDatasetParser):
    """Recursively scans Maildir directories and parses each email message with streaming iterator."""

    def parse(self, dataset_path: Path, config: Dict[str, Any]) -> Iterator[CanonicalEmail]:
        self.reset_stats()
        dataset_name = config.get("name", "enron")
        source_key = config.get("dataset_key", dataset_name)
        default_label = config.get("default_label", "Legitimate")
        license_str = config.get("license", "Public Domain")
        license_verified = config.get("license_verified", True)

        if not dataset_path.exists():
            return

        if dataset_path.is_file():
            file_paths = [dataset_path]
            for file_path in file_paths:
                self.stats.discovered_count += 1
                try:
                    raw_bytes = file_path.read_bytes()
                    if not raw_bytes or len(raw_bytes.strip()) == 0:
                        continue
                    canonical = EmailNormalizer.parse_raw_eml_bytes(
                        raw_bytes=raw_bytes,
                        source_dataset=source_key,
                        source_record_id=file_path.name,
                        source_path=file_path.name,
                        source_label=default_label,
                        is_synthetic=False,
                        synthetic_source=None,
                        construction_type="authentic",
                        license_str=license_str,
                        license_verified=license_verified,
                        historical_reliability="high",
                    )
                    self.stats.parseable_count += 1
                    yield canonical
                except Exception as e:
                    self.stats.failed_count += 1
                    self.stats.parse_errors.append({"file": str(file_path), "error": str(e)})
        else:
            for root, _, filenames in os.walk(dataset_path):
                for fname in filenames:
                    if fname.startswith("."):
                        continue
                    file_path = Path(root) / fname
                    self.stats.discovered_count += 1
                    try:
                        raw_bytes = file_path.read_bytes()
                        if not raw_bytes or len(raw_bytes.strip()) == 0:
                            continue

                        rel_path = str(file_path.relative_to(dataset_path))

                        canonical = EmailNormalizer.parse_raw_eml_bytes(
                            raw_bytes=raw_bytes,
                            source_dataset=source_key,
                            source_record_id=rel_path,
                            source_path=rel_path,
                            source_label=default_label,
                            is_synthetic=False,
                            synthetic_source=None,
                            construction_type="authentic",
                            license_str=license_str,
                            license_verified=license_verified,
                            historical_reliability="high",
                        )
                        self.stats.parseable_count += 1
                        yield canonical
                    except Exception as e:
                        self.stats.failed_count += 1
                        self.stats.parse_errors.append({"file": str(file_path), "error": str(e)})
