"""RFC 822 / EML format parser (e.g. for TREC 2007, CEAS 2008, phishing_pot, EPVME, SpamAssassin)."""

import os
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from ml.src.parsers.base_parser import BaseDatasetParser
from ml.src.normalization.normalizer import EmailNormalizer
from ml.src.schemas.canonical_email import CanonicalEmail


class RFC822Parser(BaseDatasetParser):
    """Parses individual RFC 822 (.eml, raw txt, inmail.*) files with streaming directory traversal."""

    def _load_label_index(self, dataset_path: Path) -> Dict[str, str]:
        """Load label index if present (e.g. TREC07 'full/index' or 'index' file)."""
        label_map: Dict[str, str] = {}
        index_candidates = [
            dataset_path / "full" / "index",
            dataset_path / "index",
            dataset_path / "labels",
            dataset_path / "SPAMTRAIN.label",
        ]
        for cand in index_candidates:
            if cand.exists() and cand.is_file():
                try:
                    with open(cand, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                lbl = parts[0].strip().lower()
                                path_ref = parts[1].strip()
                                fname = Path(path_ref).name
                                label_map[fname] = lbl
                                label_map[path_ref] = lbl
                except Exception:
                    pass
                break
        return label_map

    def parse(self, dataset_path: Path, config: Dict[str, Any]) -> Iterator[CanonicalEmail]:
        self.reset_stats()
        dataset_name = config.get("name", "rfc822_dataset")
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

        label_index = self._load_label_index(dataset_path)

        def _iter_files():
            if dataset_path.is_file():
                yield dataset_path
            else:
                for root, dirnames, filenames in os.walk(dataset_path):
                    dirnames[:] = [d for d in dirnames if not d.startswith(".") and d.lower() not in ("git", ".git", "img", "images")]
                    for fname in sorted(filenames):
                        if fname.startswith(".") or fname.lower() in ("index", "labels", "readme.md", "license", "licence"):
                            continue
                        if fname.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".zip", ".tar", ".gz")):
                            continue
                        yield Path(root) / fname

        for file_path in _iter_files():
            self.stats.discovered_count += 1
            try:
                raw_bytes = file_path.read_bytes()
                if not raw_bytes or len(raw_bytes.strip()) == 0:
                    continue

                rel_path = str(file_path.relative_to(dataset_path)) if dataset_path.is_dir() else file_path.name
                file_name = file_path.name

                # Determine source label
                raw_label = label_index.get(file_name) or label_index.get(rel_path) or default_label

                # Check path-based heuristic (e.g. spamassassin folders easy_ham, spam, etc.)
                if not raw_label:
                    parent_name = file_path.parent.name.lower()
                    if "ham" in parent_name:
                        raw_label = "ham"
                    elif "spam" in parent_name:
                        raw_label = "spam"
                    elif "phish" in parent_name:
                        raw_label = "phishing"

                mapped_label = source_labels.get(raw_label, raw_label)

                canonical = EmailNormalizer.parse_raw_eml_bytes(
                    raw_bytes=raw_bytes,
                    source_dataset=source_key,
                    source_record_id=rel_path,
                    source_path=rel_path,
                    source_label=mapped_label,
                    is_synthetic=is_synthetic,
                    synthetic_source=synthetic_source,
                    construction_type=construction_type,
                    license_str=license_str,
                    license_verified=license_verified,
                    historical_reliability="high" if not is_synthetic else "low",
                )
                self.stats.parseable_count += 1
                yield canonical
            except Exception as e:
                self.stats.failed_count += 1
                self.stats.parse_errors.append({
                    "file": str(file_path),
                    "error": str(e),
                })
