"""Mbox format parser (e.g. for Nazario Phishing Corpus, SpamAssassin)."""

import mailbox
from pathlib import Path
from typing import Any, Dict, Iterator
import io

from ml.src.parsers.base_parser import BaseDatasetParser
from ml.src.normalization.normalizer import EmailNormalizer
from ml.src.schemas.canonical_email import CanonicalEmail


class MboxParser(BaseDatasetParser):
    """Parses standard Unix mbox files by streaming individual messages with fallback streaming."""

    def _stream_mbox_chunks(self, file_path: Path) -> Iterator[bytes]:
        """Stream raw email byte chunks separated by From delimiter as fallback."""
        current_chunk = []
        with open(file_path, "rb") as f:
            for line in f:
                if line.startswith(b"From ") and current_chunk:
                    yield b"".join(current_chunk)
                    current_chunk = [line]
                else:
                    current_chunk.append(line)
            if current_chunk:
                yield b"".join(current_chunk)

    def parse(self, dataset_path: Path, config: Dict[str, Any]) -> Iterator[CanonicalEmail]:
        self.reset_stats()
        dataset_name = config.get("name", "nazario")
        source_key = config.get("dataset_key", dataset_name)
        default_label = config.get("default_label", "Phishing")
        license_str = config.get("license", "Public research archive")
        license_verified = config.get("license_verified", False)

        if not dataset_path.exists():
            return

        mbox_files = [dataset_path] if dataset_path.is_file() else [
            p for p in dataset_path.rglob("*") if p.is_file() and (p.suffix.lower() in (".mbox", ".txt") or "mbox" in p.name.lower())
        ]

        for mbox_file in mbox_files:
            rel_file_path = str(mbox_file.relative_to(dataset_path)) if dataset_path.is_dir() else mbox_file.name
            try:
                # Try standard mailbox.mbox first
                mb = mailbox.mbox(str(mbox_file), create=False)
                for idx, msg in enumerate(mb):
                    self.stats.discovered_count += 1
                    try:
                        raw_bytes = msg.as_bytes()
                        if not raw_bytes or len(raw_bytes.strip()) == 0:
                            continue

                        record_id = f"{rel_file_path}#msg_{idx}"

                        canonical = EmailNormalizer.parse_raw_eml_bytes(
                            raw_bytes=raw_bytes,
                            source_dataset=source_key,
                            source_record_id=record_id,
                            source_path=rel_file_path,
                            source_label=default_label,
                            is_synthetic=False,
                            synthetic_source=None,
                            construction_type="authentic",
                            license_str=license_str,
                            license_verified=license_verified,
                            historical_reliability="medium",
                        )
                        self.stats.parseable_count += 1
                        yield canonical
                    except Exception as msg_err:
                        self.stats.failed_count += 1
                        self.stats.parse_errors.append({
                            "file": str(mbox_file),
                            "msg_index": idx,
                            "error": str(msg_err),
                        })
            except Exception as file_err:
                # Fallback to streaming mbox chunks
                try:
                    for idx, raw_bytes in enumerate(self._stream_mbox_chunks(mbox_file)):
                        self.stats.discovered_count += 1
                        if not raw_bytes or len(raw_bytes.strip()) == 0:
                            continue
                        record_id = f"{rel_file_path}#msg_{idx}"
                        canonical = EmailNormalizer.parse_raw_eml_bytes(
                            raw_bytes=raw_bytes,
                            source_dataset=source_key,
                            source_record_id=record_id,
                            source_path=rel_file_path,
                            source_label=default_label,
                            is_synthetic=False,
                            synthetic_source=None,
                            construction_type="authentic",
                            license_str=license_str,
                            license_verified=license_verified,
                            historical_reliability="medium",
                        )
                        self.stats.parseable_count += 1
                        yield canonical
                except Exception as stream_err:
                    self.stats.failed_count += 1
                    self.stats.parse_errors.append({
                        "file": str(mbox_file),
                        "error": f"Primary error: {file_err}; Fallback error: {stream_err}",
                    })
