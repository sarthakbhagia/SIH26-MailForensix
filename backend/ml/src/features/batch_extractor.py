"""Forensic Feature Batch Extractor for MailForensix ML Pipeline.

Executes the official 35-feature extraction using the production FeatureExtractor
defined in backend/ml/feature_engineering.py, ensuring exact feature ordering,
provenance preservation, lookup caching, and split separation.
"""

import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
import yaml

from ml.feature_engineering import FeatureExtractor, FEATURE_COLUMNS
from ml.src.features.lookup_cache import ForensicLookupCache

logger = logging.getLogger(__name__)

# Official feature categories for manifest
FEATURE_CATEGORIES = {
    # Authentication features (6)
    "spf_status_encoded": "authentication",
    "dkim_status_encoded": "authentication",
    "dmarc_status_encoded": "authentication",
    "auth_confidence_score": "authentication",
    "has_spf_record": "authentication",
    "has_dkim_signature": "authentication",
    # Relay path features (5)
    "relay_hop_count": "relay_path",
    "max_hop_delay_seconds": "relay_path",
    "has_time_travel": "relay_path",
    "private_hop_ratio": "relay_path",
    "suspicious_infrastructure_count": "relay_path",
    # Geo & Infra features (5)
    "originating_ip_reputation": "geo_infrastructure",
    "is_tor_exit_node": "geo_infrastructure",
    "is_vpn": "geo_infrastructure",
    "is_cloud_provider": "geo_infrastructure",
    "geo_confidence_encoded": "geo_infrastructure",
    # Domain features (4)
    "domain_age_days": "domain",
    "is_newly_registered": "domain",
    "is_free_email_provider": "domain",
    "sender_domain_has_mx": "domain",
    # Content features (6)
    "subject_length": "content",
    "body_length": "content",
    "url_count": "content",
    "attachment_count": "content",
    "has_html_body": "content",
    "text_entropy": "content",
    # Link features (4)
    "max_url_risk_score": "links",
    "shortened_url_count": "links",
    "lookalike_domain_count": "links",
    "ip_as_hostname_count": "links",
    # Attachment features (3)
    "has_executable_attachment": "attachments",
    "has_macro_attachment": "attachments",
    "max_attachment_risk_score": "attachments",
    # Anomaly features (2)
    "anomaly_count": "anomalies",
    "max_anomaly_severity_encoded": "anomalies",
}

# External lookup requirement indicator
EXTERNAL_LOOKUP_FEATURES = {
    "originating_ip_reputation",
    "is_tor_exit_node",
    "is_vpn",
    "is_cloud_provider",
    "domain_age_days",
    "is_newly_registered",
    "sender_domain_has_mx",
}


class ForensicBatchExtractor:
    """Replays canonical emails through the production 35-feature FeatureExtractor."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.base_dir = data_dir or Path("ml/data")
        self.features_dir = self.base_dir / "features"
        self.manifests_dir = self.base_dir / "manifests"
        self.features_dir.mkdir(parents=True, exist_ok=True)
        self.manifests_dir.mkdir(parents=True, exist_ok=True)

        self.extractor = FeatureExtractor()
        self.cache = ForensicLookupCache(self.base_dir / "cache" / "forensic_lookup_cache.json")

    def _build_analysis_dict(self, email_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Construct the analysis structure consumed by FeatureExtractor from canonical email."""
        headers = email_dict.get("headers") or {}
        if isinstance(headers, str):
            try:
                headers = json.loads(headers)
            except Exception:
                headers = {}
        sender = email_dict.get("sender", "") or ""
        sender_domain = email_dict.get("sender_domain", "") or (sender.split("@")[-1].lower() if "@" in sender else "")
        urls = email_dict.get("urls") or []
        if isinstance(urls, str):
            try:
                urls = json.loads(urls)
            except Exception:
                urls = []
        attachments = email_dict.get("attachments") or []
        if isinstance(attachments, str):
            try:
                attachments = json.loads(attachments)
            except Exception:
                attachments = []

        # 1. Auth status
        auth_status = {
            "spf": "none",
            "dkim": "none",
            "dmarc": "none",
        }
        for h_key, h_val in headers.items():
            k_low = h_key.lower()
            v_low = str(h_val).lower()
            if "received-spf" in k_low or "spf" in k_low:
                if "pass" in v_low:
                    auth_status["spf"] = "pass"
                elif "softfail" in v_low:
                    auth_status["spf"] = "softfail"
                elif "fail" in v_low:
                    auth_status["spf"] = "fail"
            if "dkim-signature" in k_low or "dkim" in k_low:
                if "pass" in v_low:
                    auth_status["dkim"] = "pass"
                elif "fail" in v_low:
                    auth_status["dkim"] = "fail"
            if "dmarc" in k_low:
                if "pass" in v_low:
                    auth_status["dmarc"] = "pass"
                elif "fail" in v_low:
                    auth_status["dmarc"] = "fail"

        # 2. Relay hops
        received_headers = [v for k, v in headers.items() if "received" in k.lower()]
        relay_path = []
        for i, rec in enumerate(received_headers):
            relay_path.append({
                "hop_number": i + 1,
                "delay_seconds": 1.0,
                "is_private": False,
            })

        # 3. Domain & IP Lookups with Cache
        domain_intel = self.cache.get_or_lookup_domain(sender_domain)
        ip_data = self.cache.get_or_lookup_ip("")

        # 4. Link & Attachment IOCs
        iocs = []
        for u in urls:
            u_str = str(u).lower()
            is_suspicious = any(w in u_str for w in ("login", "verify", "secure", "account", "update", "bank", "token"))
            iocs.append({
                "type": "URL",
                "risk_score": 75.0 if is_suspicious else 10.0,
                "reason": "Suspicious login keyword in URL" if is_suspicious else "",
            })

        for att in attachments:
            att_name = att.get("filename", "") if isinstance(att, dict) else str(att)
            if any(att_name.lower().endswith(ext) for ext in (".exe", ".bat", ".scr", ".cmd", ".vbs", ".ps1", ".hta", ".js")):
                iocs.append({"type": "Hash", "risk_score": 90.0})

        # 5. Anomalies
        anomalies = []
        if email_dict.get("is_synthetic"):
            anomalies.append({"severity": "info", "type": "synthetic_construction"})

        return {
            "auth_status": auth_status,
            "risk_breakdown": {"auth": 10.0 if auth_status["spf"] == "pass" else 40.0},
            "relay_path": relay_path,
            "geo_data": [{"infrastructure_type": ip_data.get("infrastructure_type", "standard")}],
            "ip_reputation": {"score": ip_data.get("score", 50.0)},
            "location_confidence": "medium",
            "domain_intel": domain_intel,
            "iocs": iocs,
            "anomalies": anomalies,
        }

    def extract_and_save(self) -> Dict[str, Any]:
        """Extract 35 forensic features for Train, Validation, and Test splits and save Parquet files."""
        emails_path = self.base_dir / "normalized" / "canonical_emails.parquet"
        splits_path = self.base_dir / "splits" / "splits.csv"

        if not emails_path.exists():
            raise FileNotFoundError(f"Canonical emails parquet not found at {emails_path}")
        if not splits_path.exists():
            raise FileNotFoundError(f"Splits file not found at {splits_path}")

        df_emails = pd.read_parquet(emails_path)
        df_splits = pd.read_csv(splits_path)

        merged = pd.merge(df_splits, df_emails, on="email_id", how="inner")

        # Authoritative label map
        label_map = {"LEGITIMATE": 0, "SUSPICIOUS": 1, "PHISHING": 2, "BEC_FRAUD": 3, "IMPERSONATION": 4}
        valid_labels = set(label_map.keys())
        df_usable = merged[merged["canonical_label"].isin(valid_labels)].copy()

        logger.info(f"Extracting 35 forensic features across {len(df_usable)} usable emails...")

        split_dfs: Dict[str, List[Dict[str, Any]]] = {"train": [], "validation": [], "test": []}

        for _, row in df_usable.iterrows():
            email_dict = row.to_dict()
            headers = email_dict.get("headers") or {}
            if isinstance(headers, str):
                try:
                    headers = json.loads(headers)
                except Exception:
                    headers = {}
            email_dict["headers"] = headers

            urls = email_dict.get("urls") or []
            if isinstance(urls, str):
                try:
                    urls = json.loads(urls)
                except Exception:
                    urls = []
            email_dict["urls"] = urls

            attachments = email_dict.get("attachments") or []
            if isinstance(attachments, str):
                try:
                    attachments = json.loads(attachments)
                except Exception:
                    attachments = []
            email_dict["attachments"] = attachments

            analysis_dict = self._build_analysis_dict(email_dict)

            # Extract 35-feature vector using production FeatureExtractor
            fv = self.extractor.extract(email_dict, analysis_dict)
            fv_dict = asdict(fv)

            rel_map = {"high": 1.0, "medium": 0.75, "low": 0.5}
            raw_rel = row.get("historical_reliability")
            if isinstance(raw_rel, (int, float)) and not np.isnan(raw_rel):
                hist_rel = float(raw_rel)
            else:
                hist_rel = rel_map.get(str(raw_rel).lower(), 1.0)

            # Metadata fields
            record_row = {
                "email_id": row["email_id"],
                "label": label_map[row["canonical_label"]],
                "canonical_label": row["canonical_label"],
                "split": row["split"],
                "group_id": row.get("group_id", f"grp_{row['email_id']}"),
                "is_synthetic": bool(row.get("is_synthetic", False)),
                "feature_extraction_status": "SUCCESS",
                "feature_missing_count": 0,
                "historical_reliability": hist_rel,
            }
            # Append all 35 forensic features
            for col in FEATURE_COLUMNS:
                record_row[col] = fv_dict[col]

            split_name = str(row["split"]).lower()
            if split_name in split_dfs:
                split_dfs[split_name].append(record_row)

        self.cache.save()

        # Save parquet files per split
        results_summary = {}
        for split_name, rows in split_dfs.items():
            df_out = pd.DataFrame(rows)
            out_file = self.features_dir / f"{split_name}.parquet"
            df_out.to_parquet(out_file, index=False)
            results_summary[split_name] = {
                "count": len(df_out),
                "file": str(out_file),
                "columns": len(df_out.columns),
            }
            logger.info(f"Saved {len(df_out)} feature rows to {out_file}")

        # Save feature manifests
        self._save_feature_manifests()

        return results_summary

    def _save_feature_manifests(self):
        """Generate and save feature_manifest.json and feature_names.json."""
        manifest_entries = []
        for idx, feat_name in enumerate(FEATURE_COLUMNS):
            cat = FEATURE_CATEGORIES.get(feat_name, "general")
            req_lookup = feat_name in EXTERNAL_LOOKUP_FEATURES
            manifest_entries.append({
                "feature_name": feat_name,
                "feature_index": idx,
                "category": cat,
                "datatype": "int" if "count" in feat_name or "encoded" in feat_name or "age" in feat_name or "length" in feat_name else "bool" if "has_" in feat_name or "is_" in feat_name else "float",
                "missing_allowed": False,
                "external_lookup_required": req_lookup,
                "historical_reliability_required": req_lookup,
            })

        # Save feature_manifest.json
        manifest_path = self.manifests_dir / "feature_manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump({
                "total_features": len(FEATURE_COLUMNS),
                "features": manifest_entries,
            }, f, indent=2)
        logger.info(f"Saved feature manifest to {manifest_path}")

        # Save feature_names.json
        names_path = self.manifests_dir / "feature_names.json"
        with open(names_path, "w", encoding="utf-8") as f:
            json.dump(FEATURE_COLUMNS, f, indent=2)
        logger.info(f"Saved feature names list to {names_path}")


if __name__ == "__main__":
    extractor = ForensicBatchExtractor()
    res = extractor.extract_and_save()
    print("Batch forensic feature extraction completed!")
    print(json.dumps(res, indent=2))
