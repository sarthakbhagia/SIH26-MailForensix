"""Dataset Acquisition and Inventory Management for MailForensix ML Pipeline.

Implements reproducible dataset acquisition, Git commit pinning, archive verification,
and raw inventory manifest generation per implementation.md Section 7 and Section 45.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import subprocess
from typing import Any, Dict, List, Optional
import urllib.request
import yaml

from ml.src.parsers.registry import parse_dataset_from_config

logger = logging.getLogger(__name__)


class DatasetAcquisitionManager:
    """Manages downloading, local discovery, checksum verification, and inventory reporting."""

    def __init__(self, config_path: Optional[Path] = None, raw_data_dir: Optional[Path] = None):
        candidates = [
            config_path,
            Path("ml/config/datasets.yaml"),
            Path("backend/ml/config/datasets.yaml"),
            Path(__file__).resolve().parents[2] / "config" / "datasets.yaml",
        ]
        self.config_path = next((p for p in candidates if p and p.exists()), Path("ml/config/datasets.yaml"))

        self.raw_data_dir = raw_data_dir or Path("ml/data/raw")
        if not self.raw_data_dir.exists() and Path("backend/ml/data/raw").exists():
            self.raw_data_dir = Path("backend/ml/data/raw")

        self.raw_data_dir.mkdir(parents=True, exist_ok=True)
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load datasets.yaml configuration."""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Dataset configuration not found at {self.config_path}")
        with open(self.config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("datasets", {})

    @staticmethod
    def compute_sha256(file_path: Path) -> str:
        """Compute SHA256 hex digest of a file in streaming chunks."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def get_git_commit_sha(self, repo_dir: Path) -> Optional[str]:
        """Query Git commit SHA of a local cloned repository."""
        if not (repo_dir / ".git").exists():
            return None
        try:
            res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(repo_dir),
                capture_output=True,
                text=True,
                check=True,
            )
            return res.stdout.strip()
        except Exception:
            return None

    def acquire_git_repo(self, dataset_key: str, ds_cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Acquire or inspect a Git-hosted dataset repository."""
        raw_subdir = ds_cfg.get("raw_subdir", dataset_key)
        target_dir = self.raw_data_dir / raw_subdir
        url = ds_cfg["source_url"]

        if target_dir.exists() and any(target_dir.iterdir()):
            commit = self.get_git_commit_sha(target_dir)
            return {
                "status": "present_local",
                "path": str(target_dir),
                "commit_sha": commit,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        # Attempt shallow clone if git is available
        try:
            target_dir.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(target_dir)],
                capture_output=True,
                text=True,
                check=True,
                timeout=120,
            )
            commit = self.get_git_commit_sha(target_dir)
            return {
                "status": "acquired",
                "path": str(target_dir),
                "commit_sha": commit,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            return {
                "status": "not_acquired",
                "path": str(target_dir),
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    def inspect_dataset(self, dataset_key: str, ds_cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Inspect acquisition status and measure message counts without modifying data."""
        raw_subdir = ds_cfg.get("raw_subdir", dataset_key)
        target_dir = self.raw_data_dir / raw_subdir

        # Check if local directory exists in repository or raw dir
        if not target_dir.exists() and ds_cfg.get("source_type") == "local_dir":
            # Check root sample_emails
            if Path(raw_subdir).exists():
                target_dir = Path(raw_subdir)
            elif Path(f"../{raw_subdir}").exists():
                target_dir = Path(f"../{raw_subdir}")

        requires_manual = bool(ds_cfg.get("requires_manual_acquisition", False))
        present = target_dir.exists() and (target_dir.is_file() or any(target_dir.iterdir()))

        if present:
            status = "present_local"
        elif requires_manual:
            status = "requires_manual_acquisition"
        else:
            status = "not_downloaded"

        file_count = 0
        sha256_val = None
        commit_sha = None

        if present:
            if target_dir.is_file():
                file_count = 1
                sha256_val = self.compute_sha256(target_dir)
            else:
                files = [p for p in target_dir.rglob("*") if p.is_file() and not p.name.startswith(".")]
                file_count = len(files)
                commit_sha = self.get_git_commit_sha(target_dir)

        # Parse test to count parseable messages
        discovered_msg_count = 0
        parseable_msg_count = 0
        failed_msg_count = 0

        if present:
            try:
                stream, parser = parse_dataset_from_config(dataset_key, ds_cfg, target_dir.parent)
                for _ in stream:
                    pass
                discovered_msg_count = parser.stats.discovered_count
                parseable_msg_count = parser.stats.parseable_count
                failed_msg_count = parser.stats.failed_count
            except Exception as parse_err:
                logger.debug(f"Parsing check on {dataset_key} encountered: {parse_err}")

        manual_inst = None
        if requires_manual:
            manual_inst = f"Download archive from {ds_cfg.get('source_url')} (accept agreement) and unpack into {target_dir}"

        return {
            "dataset": dataset_key,
            "name": ds_cfg.get("name", dataset_key),
            "source_url": ds_cfg.get("source_url"),
            "source_type": ds_cfg.get("source_type"),
            "format": ds_cfg.get("format"),
            "parser": ds_cfg.get("parser"),
            "local_path": str(target_dir),
            "acquisition_status": status,
            "requires_manual_acquisition": requires_manual,
            "manual_acquisition_instructions": manual_inst,
            "sha256": sha256_val,
            "git_commit_sha": commit_sha,
            "acquisition_timestamp": datetime.now(timezone.utc).isoformat(),
            "discovered_file_count": file_count,
            "discovered_message_count": discovered_msg_count,
            "parseable_message_count": parseable_msg_count,
            "parse_failure_count": failed_msg_count,
            "is_synthetic": ds_cfg.get("is_synthetic", False),
            "synthetic_source": ds_cfg.get("synthetic_source"),
            "license": ds_cfg.get("license"),
            "license_verified": ds_cfg.get("license_verified", False),
            "notes": ds_cfg.get("notes", ""),
        }

    def generate_inventory(self, output_path: Optional[Path] = None) -> Dict[str, Any]:
        """Generate raw_inventory.json manifest across all configured datasets."""
        out_file = output_path or Path("ml/data/manifests/raw_inventory.json")
        if not out_file.parent.exists() and Path("backend/ml/data/manifests").exists():
            out_file = Path("backend/ml/data/manifests/raw_inventory.json")

        out_file.parent.mkdir(parents=True, exist_ok=True)

        inventory: Dict[str, Any] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "dataset_count": len(self.config),
            "datasets": {},
        }

        for ds_key, ds_cfg in self.config.items():
            ds_info = self.inspect_dataset(ds_key, ds_cfg)
            inventory["datasets"][ds_key] = ds_info

        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(inventory, f, indent=2)

        logger.info(f"Saved raw dataset inventory manifest to {out_file}")
        return inventory
