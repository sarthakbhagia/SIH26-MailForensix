"""Group-Aware Leakage-Safe Dataset Splitting for MailForensix ML Pipeline.

Implements Parts O, P, Q, R, T of Phase 3 specification:
- Constructs unified leakage groups using exact clusters, near-duplicate clusters, and sender campaigns
- Partitions corpus into Train (70%), Validation (15%), Test (15%)
- Strict synthetic data policy: BEC-2/synthetic data is restricted to Train/Val only
- Generates authoritative splits.csv and split distribution reports
"""

from collections import defaultdict
import hashlib
import random
from typing import Any, Dict, List, Optional, Set, Tuple
import numpy as np
import pandas as pd

from ml.src.schemas.canonical_email import CanonicalEmail


# Generic/public domains that should not be grouped globally to avoid collapsing the entire dataset
GENERIC_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "enron.com", "speedy.uwaterloo.ca", "gvc.ceas-challenge.cc", "comcast.net",
    "sbcglobal.net", "msn.com", "verizon.net", "att.net", "earthlink.net",
}


class GroupAwareSplitter:
    """Partitions emails into leakage-safe Train/Val/Test splits using graph-connected groups."""

    def __init__(
        self,
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        random_seed: int = 42,
    ):
        self.train_ratio = train_ratio
        self.val_ratio = val_ratio
        self.test_ratio = test_ratio
        self.random_seed = random_seed

    def build_groups(
        self,
        emails: List[CanonicalEmail],
        exact_cluster_map: Dict[str, str],
        near_cluster_map: Dict[str, str],
    ) -> Dict[str, str]:
        """Construct unified connected leakage groups across duplicate and campaign boundaries."""
        parent: Dict[str, str] = {}

        def find(item: str) -> str:
            if item not in parent:
                parent[item] = item
            elif parent[item] != item:
                parent[item] = find(parent[item])
            return parent[item]

        def union(item1: str, item2: str):
            root1 = find(item1)
            root2 = find(item2)
            if root1 != root2:
                parent[root2] = root1

        # 1. Group by exact duplicate clusters
        exact_clusters: Dict[str, List[str]] = defaultdict(list)
        for em in emails:
            cid = exact_cluster_map.get(em.email_id) or f"exact_single_{em.email_id}"
            exact_clusters[cid].append(em.email_id)

        for cid, member_ids in exact_clusters.items():
            first_id = member_ids[0]
            for other_id in member_ids[1:]:
                union(first_id, other_id)

        # 2. Group by near duplicate clusters
        near_clusters: Dict[str, List[str]] = defaultdict(list)
        for em in emails:
            nid = near_cluster_map.get(em.email_id) or f"near_single_{em.email_id}"
            near_clusters[nid].append(em.email_id)

        for nid, member_ids in near_clusters.items():
            first_id = member_ids[0]
            for other_id in member_ids[1:]:
                union(first_id, other_id)

        # 3. Group by targeted/anomalous sender domains (excluding generic providers)
        domain_groups: Dict[str, List[str]] = defaultdict(list)
        for em in emails:
            dom = (em.sender_domain or "").lower().strip()
            if dom and dom not in GENERIC_DOMAINS and not dom.endswith(".edu") and not dom.endswith(".gov"):
                domain_groups[dom].append(em.email_id)

        for dom, member_ids in domain_groups.items():
            # Group specific domains if small/medium campaign (< 200 emails)
            if len(member_ids) <= 200:
                first_id = member_ids[0]
                for other_id in member_ids[1:]:
                    union(first_id, other_id)

        # Assign deterministic group IDs
        email_to_group: Dict[str, str] = {}
        group_members: Dict[str, List[str]] = defaultdict(list)
        for em in emails:
            root = find(em.email_id)
            group_members[root].append(em.email_id)

        for root, member_ids in group_members.items():
            sorted_mids = sorted(member_ids)
            seed = "|".join(sorted_mids)
            group_id = f"group_{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:16]}"
            for mid in sorted_mids:
                email_to_group[mid] = group_id

        return email_to_group

    def split(
        self,
        emails: List[CanonicalEmail],
        email_to_group: Dict[str, str],
        exact_cluster_map: Dict[str, str],
        near_cluster_map: Dict[str, str],
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Perform stratified group splitting and return (splits_df, split_report_df)."""
        rng = random.Random(self.random_seed)

        # Aggregate group level statistics: (group_id, size, primary_class, is_synthetic)
        email_by_id = {em.email_id: em for em in emails}
        group_to_emails: Dict[str, List[CanonicalEmail]] = defaultdict(list)
        for em in emails:
            gid = email_to_group[em.email_id]
            group_to_emails[gid].append(em)

        # Separate synthetic groups from real groups to enforce Synthetic Test Policy
        synthetic_group_ids = []
        real_groups_by_class: Dict[str, List[str]] = defaultdict(list)

        for gid, group_em_list in group_to_emails.items():
            is_any_synth = any(e.is_synthetic for e in group_em_list)
            if is_any_synth:
                synthetic_group_ids.append(gid)
            else:
                # Majority class in group
                class_counts = defaultdict(int)
                for e in group_em_list:
                    lbl = e.canonical_label or "UNLABELED"
                    class_counts[lbl] += 1
                primary_lbl = max(class_counts.items(), key=lambda x: x[1])[0]
                real_groups_by_class[primary_lbl].append(gid)

        train_groups: Set[str] = set()
        val_groups: Set[str] = set()
        test_groups: Set[str] = set()

        # 1. Allocate Synthetic groups (80% Train, 20% Val, 0% Test)
        rng.shuffle(synthetic_group_ids)
        synth_train_cutoff = int(len(synthetic_group_ids) * 0.80)
        for i, gid in enumerate(synthetic_group_ids):
            if i < synth_train_cutoff:
                train_groups.add(gid)
            else:
                val_groups.add(gid)

        # 2. Stratified group allocation for real data
        for class_name, gids in real_groups_by_class.items():
            rng.shuffle(gids)
            total_emails_in_class = sum(len(group_to_emails[g]) for g in gids)
            target_test = total_emails_in_class * self.test_ratio
            target_val = total_emails_in_class * self.val_ratio

            curr_test_count = 0
            curr_val_count = 0

            for gid in gids:
                g_size = len(group_to_emails[gid])
                if curr_test_count + g_size <= target_test * 1.05 and curr_test_count < target_test:
                    test_groups.add(gid)
                    curr_test_count += g_size
                elif curr_val_count + g_size <= target_val * 1.05 and curr_val_count < target_val:
                    val_groups.add(gid)
                    curr_val_count += g_size
                else:
                    train_groups.add(gid)

        # Build final split assignments dataframe
        split_rows = []
        for em in emails:
            gid = email_to_group[em.email_id]
            if gid in test_groups:
                split_name = "test"
            elif gid in val_groups:
                split_name = "validation"
            else:
                split_name = "train"

            exact_cid = exact_cluster_map.get(em.email_id, f"exact_single_{em.email_id}")
            near_cid = near_cluster_map.get(em.email_id, f"near_single_{em.email_id}")

            split_rows.append({
                "email_id": em.email_id,
                "split": split_name,
                "group_id": gid,
                "duplicate_cluster_id": exact_cid,
                "near_duplicate_cluster_id": near_cid,
                "provenance_cluster_id": f"prov_{em.source_dataset}",
                "temporal_split": "standard",
            })

        df_splits = pd.DataFrame(split_rows)

        # Build split summary report
        report_rows = []
        for split_name in ["train", "validation", "test"]:
            sub_ids = set(df_splits[df_splits["split"] == split_name]["email_id"])
            sub_emails = [email_by_id[eid] for eid in sub_ids]

            class_dist = defaultdict(int)
            source_dist = defaultdict(int)
            real_count = 0
            synth_count = 0

            for e in sub_emails:
                lbl = e.canonical_label or "UNLABELED"
                class_dist[lbl] += 1
                source_dist[e.source_dataset] += 1
                if e.is_synthetic:
                    synth_count += 1
                else:
                    real_count += 1

            unique_groups = len({email_to_group[e.email_id] for e in sub_emails})

            report_rows.append({
                "split": split_name,
                "total_records": len(sub_emails),
                "unique_groups": unique_groups,
                "real_count": real_count,
                "synthetic_count": synth_count,
                "class_distribution": dict(class_dist),
                "source_distribution": dict(source_dist),
            })

        df_report = pd.DataFrame(report_rows)
        return df_splits, df_report
