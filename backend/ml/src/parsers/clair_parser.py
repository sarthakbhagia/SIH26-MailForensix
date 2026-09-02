"""CLAIR Collection of Fraud Email parser (ADCR2008T001)."""

import re
from pathlib import Path
from typing import Any, Dict, Iterator

from ml.src.parsers.base_parser import BaseDatasetParser
from ml.src.normalization.normalizer import EmailNormalizer
from ml.src.schemas.canonical_email import CanonicalEmail


class CLAIRParser(BaseDatasetParser):
    """Parses CLAIR 419 / Nigerian advance-fee fraud email collections."""

    def parse(self, dataset_path: Path, config: Dict[str, Any]) -> Iterator[CanonicalEmail]:
        self.reset_stats()
        dataset_name = config.get("name", "clair")
        source_key = config.get("dataset_key", dataset_name)
        license_str = config.get("license", "Creative Commons Attribution-ShareAlike 3.0 US")
        license_verified = config.get("license_verified", True)

        if not dataset_path.exists():
            return

        files = [dataset_path] if dataset_path.is_file() else [
            p for p in dataset_path.rglob("*") if p.is_file() and not p.name.startswith(".")
        ]

        for file_path in files:
            rel_path = str(file_path.relative_to(dataset_path)) if dataset_path.is_dir() else file_path.name
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                
                # Check if file contains multiple messages separated by "From r" or delimiter
                raw_messages = re.split(r'\n(?=From\s+[^\n]+)', content)
                if len(raw_messages) <= 1:
                    raw_messages = [content]

                for idx, msg_text in enumerate(raw_messages):
                    if not msg_text.strip():
                        continue
                    self.stats.discovered_count += 1

                    # Parse headers from top of text
                    lines = msg_text.strip().split("\n")
                    subject = ""
                    sender = ""
                    body_lines = []
                    in_headers = True

                    for line in lines:
                        if in_headers:
                            if not line.strip():
                                in_headers = False
                                continue
                            if line.lower().startswith("subject:"):
                                subject = line[8:].strip()
                            elif line.lower().startswith("from:"):
                                sender = line[5:].strip()
                            elif ":" not in line[:30]:
                                in_headers = False
                                body_lines.append(line)
                        else:
                            body_lines.append(line)

                    body = "\n".join(body_lines)
                    record_id = f"{rel_path}#msg_{idx}"

                    canonical = EmailNormalizer.parse_structured_fields(
                        subject=subject,
                        body=body,
                        sender=sender,
                        source_dataset=source_key,
                        source_record_id=record_id,
                        source_path=rel_path,
                        source_label="BEC/Fraud",
                        is_synthetic=False,
                        synthetic_source=None,
                        construction_type="authentic",
                        fraud_subtype="419_advance_fee",
                        license_str=license_str,
                        license_verified=license_verified,
                        historical_reliability="high",
                    )
                    self.stats.parseable_count += 1
                    yield canonical

            except Exception as e:
                self.stats.failed_count += 1
                self.stats.parse_errors.append({
                    "file": str(file_path),
                    "error": str(e),
                })
