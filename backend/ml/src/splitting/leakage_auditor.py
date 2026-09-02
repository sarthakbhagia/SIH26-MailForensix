"""Automated Leakage Audit and Assertion Engine for MailForensix ML Pipeline.

Implements Part S of Phase 3 specification:
- Enforces strict leakage invariants across Train, Validation, and Test splits
- Verifies exact duplicate, near duplicate, group, and synthetic test isolation
- Generates machine-readable ml/reports/leakage_audit.json
"""

from collections import defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import pandas as pd

from ml.src.schemas.canonical_email import CanonicalEmail


class LeakageAuditor:
    """Audits split assignments for data leakage and generates compliance reports."""

    def __init__(self):
        self.violations: List[Dict[str, Any]] = []
        self.check_results: Dict[str, bool] = {}

    def audit(
        self,
        emails: List[CanonicalEmail],
        splits_df: pd.DataFrame,
    ) -> Dict[str, Any]:
        """Run all automated leakage assertions over the split dataframe."""
        self.violations.clear()
        self.check_results.clear()

        email_by_id = {em.email_id: em for em in emails}
        split_map = dict(zip(splits_df["email_id"], splits_df["split"]))
        group_map = dict(zip(splits_df["email_id"], splits_df["group_id"]))
        exact_map = dict(zip(splits_df["email_id"], splits_df["duplicate_cluster_id"]))
        near_map = dict(zip(splits_df["email_id"], splits_df["near_duplicate_cluster_id"]))

        # -----------------------------------------------------------------------
        # Check 1: No email_id overlap across splits
        # -----------------------------------------------------------------------
        split_emails: Dict[str, Set[str]] = defaultdict(set)
        for eid, s in split_map.items():
            split_emails[s].add(eid)

        train_val_overlap = split_emails["train"] & split_emails["validation"]
        train_test_overlap = split_emails["train"] & split_emails["test"]
        val_test_overlap = split_emails["validation"] & split_emails["test"]

        has_email_leak = bool(train_val_overlap or train_test_overlap or val_test_overlap)
        self.check_results["no_email_id_overlap"] = not has_email_leak
        if has_email_leak:
            self.violations.append({
                "check": "no_email_id_overlap",
                "severity": "CRITICAL",
                "message": f"Email ID overlap detected: train-val={len(train_val_overlap)}, train-test={len(train_test_overlap)}, val-test={len(val_test_overlap)}",
            })

        # -----------------------------------------------------------------------
        # Check 2: No exact duplicate cluster crossings
        # -----------------------------------------------------------------------
        exact_cluster_splits: Dict[str, Set[str]] = defaultdict(set)
        for eid, s in split_map.items():
            cid = exact_map.get(eid)
            if cid and not cid.startswith("exact_single_"):
                exact_cluster_splits[cid].add(s)

        exact_crossings = [cid for cid, splits in exact_cluster_splits.items() if len(splits) > 1]
        self.check_results["no_exact_duplicate_crossings"] = (len(exact_crossings) == 0)
        if exact_crossings:
            self.violations.append({
                "check": "no_exact_duplicate_crossings",
                "severity": "CRITICAL",
                "message": f"{len(exact_crossings)} exact duplicate clusters cross split boundaries.",
                "sample_clusters": exact_crossings[:5],
            })

        # -----------------------------------------------------------------------
        # Check 3: No near duplicate cluster crossings
        # -----------------------------------------------------------------------
        near_cluster_splits: Dict[str, Set[str]] = defaultdict(set)
        for eid, s in split_map.items():
            nid = near_map.get(eid)
            if nid and not nid.startswith("near_single_"):
                near_cluster_splits[nid].add(s)

        near_crossings = [nid for nid, splits in near_cluster_splits.items() if len(splits) > 1]
        self.check_results["no_near_duplicate_crossings"] = (len(near_crossings) == 0)
        if near_crossings:
            self.violations.append({
                "check": "no_near_duplicate_crossings",
                "severity": "CRITICAL",
                "message": f"{len(near_crossings)} near duplicate clusters cross split boundaries.",
                "sample_clusters": near_crossings[:5],
            })

        # -----------------------------------------------------------------------
        # Check 4: No group_id crossings
        # -----------------------------------------------------------------------
        group_splits: Dict[str, Set[str]] = defaultdict(set)
        for eid, s in split_map.items():
            gid = group_map.get(eid)
            if gid:
                group_splits[gid].add(s)

        group_crossings = [gid for gid, splits in group_splits.items() if len(splits) > 1]
        self.check_results["no_group_id_crossings"] = (len(group_crossings) == 0)
        if group_crossings:
            self.violations.append({
                "check": "no_group_id_crossings",
                "severity": "CRITICAL",
                "message": f"{len(group_crossings)} leakage groups cross split boundaries.",
                "sample_groups": group_crossings[:5],
            })

        # -----------------------------------------------------------------------
        # Check 5: Strict Synthetic Test Set Isolation Policy
        # -----------------------------------------------------------------------
        test_eids = split_emails["test"]
        synthetic_in_test = [
            eid for eid in test_eids
            if email_by_id[eid].is_synthetic or email_by_id[eid].source_dataset == "bec2"
        ]
        self.check_results["no_synthetic_in_test_split"] = (len(synthetic_in_test) == 0)
        if synthetic_in_test:
            self.violations.append({
                "check": "no_synthetic_in_test_split",
                "severity": "HIGH",
                "message": f"{len(synthetic_in_test)} synthetic/BEC-2 records were found in the Test split.",
            })

        # -----------------------------------------------------------------------
        # Check 6: All records have valid split assignment
        # -----------------------------------------------------------------------
        unassigned = [em.email_id for em in emails if em.email_id not in split_map or split_map[em.email_id] not in ("train", "validation", "test")]
        self.check_results["all_records_assigned"] = (len(unassigned) == 0)
        if unassigned:
            self.violations.append({
                "check": "all_records_assigned",
                "severity": "CRITICAL",
                "message": f"{len(unassigned)} emails have missing or invalid split assignments.",
            })

        overall_status = "PASS" if all(self.check_results.values()) else "FAIL"

        audit_report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": overall_status,
            "checks": self.check_results,
            "violations": self.violations,
            "counts": {
                "total_records": len(emails),
                "train_count": len(split_emails["train"]),
                "validation_count": len(split_emails["validation"]),
                "test_count": len(split_emails["test"]),
            },
            "grouping_statistics": {
                "unique_leakage_groups": len(group_splits),
                "multi_member_exact_clusters": len(exact_cluster_splits),
                "multi_member_near_clusters": len(near_cluster_splits),
            },
        }

        return audit_report

    def save_audit_report(self, audit_dict: Dict[str, Any], output_path: Path) -> Path:
        """Save audit report as JSON."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(audit_dict, f, indent=2)
        return output_path
