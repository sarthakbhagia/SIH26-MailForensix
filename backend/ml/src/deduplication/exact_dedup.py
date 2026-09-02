"""Global Exact Deduplication Engine for MailForensix ML Pipeline.

Implements Section 10 and Part C of Phase 3 specification:
- Multi-level exact duplicate detection across the entire unified corpus
- Uses raw_message_sha256, normalized_full_sha256, and normalized_body_sha256
- Preserves full provenance across all source datasets
- Produces stable duplicate_cluster_id
"""

from collections import defaultdict
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import pandas as pd

from ml.src.schemas.canonical_email import CanonicalEmail


@dataclass
class DuplicateCluster:
    cluster_id: str
    cluster_type: str                          # "exact_raw", "exact_normalized_full", "exact_normalized_body"
    canonical_email_id: str
    email_ids: List[str] = field(default_factory=list)
    datasets_involved: Set[str] = field(default_factory=set)
    record_count: int = 0
    provenance_entries: List[Dict[str, Any]] = field(default_factory=list)


class ExactDeduplicator:
    """Performs global multi-level exact deduplication over a corpus of CanonicalEmail records."""

    def __init__(self):
        self.clusters: Dict[str, DuplicateCluster] = {}
        self.email_to_cluster: Dict[str, str] = {}

    def deduplicate(
        self,
        emails: List[CanonicalEmail],
    ) -> Tuple[List[CanonicalEmail], List[DuplicateCluster], pd.DataFrame]:
        """Run multi-level exact deduplication and return (deduped_emails, clusters, duplicate_report_df)."""
        # 1. Group by raw_message_sha256, normalized_full_sha256, and normalized_body_sha256
        raw_map: Dict[str, List[CanonicalEmail]] = defaultdict(list)
        full_map: Dict[str, List[CanonicalEmail]] = defaultdict(list)
        body_map: Dict[str, List[CanonicalEmail]] = defaultdict(list)

        for em in emails:
            if em.raw_message_sha256:
                raw_map[em.raw_message_sha256].append(em)
            if em.normalized_full_sha256:
                full_map[em.normalized_full_sha256].append(em)
            if em.normalized_body_sha256:
                body_map[em.normalized_body_sha256].append(em)

        # Union-Find / Disjoint Set Union to merge matches across all 3 levels
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

        # Connect items matching on any exact level
        # A. Raw bytes exact match
        for hash_val, group in raw_map.items():
            first_id = group[0].email_id
            for other in group[1:]:
                union(first_id, other.email_id)

        # B. Normalized full match (canonical headers + body)
        for hash_val, group in full_map.items():
            first_id = group[0].email_id
            for other in group[1:]:
                union(first_id, other.email_id)

        # C. Normalized body match (subject + body)
        for hash_val, group in body_map.items():
            first_id = group[0].email_id
            for other in group[1:]:
                union(first_id, other.email_id)

        # Build final clusters
        cluster_groups: Dict[str, List[CanonicalEmail]] = defaultdict(list)
        for em in emails:
            root = find(em.email_id)
            cluster_groups[root].append(em)

        deduped_emails: List[CanonicalEmail] = []
        cluster_list: List[DuplicateCluster] = []
        report_rows: List[Dict[str, Any]] = []

        for root_id, members in cluster_groups.items():
            # Deterministic cluster ID from sorted member email_ids
            sorted_member_ids = sorted(m.email_id for m in members)
            cluster_seed = "|".join(sorted_member_ids)
            cluster_id = f"exact_cluster_{hashlib.sha256(cluster_seed.encode('utf-8')).hexdigest()[:16]}"

            # Determine cluster type
            raw_hashes = {m.raw_message_sha256 for m in members if m.raw_message_sha256}
            full_hashes = {m.normalized_full_sha256 for m in members if m.normalized_full_sha256}
            body_hashes = {m.normalized_body_sha256 for m in members if m.normalized_body_sha256}

            if len(raw_hashes) == 1 and len(members) > 1:
                ctype = "exact_raw_bytes"
            elif len(full_hashes) == 1 and len(members) > 1:
                ctype = "exact_normalized_full"
            elif len(body_hashes) == 1 and len(members) > 1:
                ctype = "exact_normalized_body"
            else:
                ctype = "single_unique" if len(members) == 1 else "exact_multi_level"

            # Select canonical representative (prefer authentic over synthetic, rich headers over no-headers)
            def rep_priority(e: CanonicalEmail) -> Tuple[int, int, int]:
                # (is_authentic: 1/0, has_headers: 1/0, body_length)
                is_auth = 0 if e.is_synthetic else 1
                has_hdr = 1 if (e.headers and len(e.headers) > 2) else 0
                return (is_auth, has_hdr, len(e.body_plain or ""))

            canonical_rep = max(members, key=rep_priority)
            deduped_emails.append(canonical_rep)

            # Record provenance for all members
            prov_entries = []
            datasets_involved = set()
            for m in members:
                self.email_to_cluster[m.email_id] = cluster_id
                datasets_involved.add(m.source_dataset)
                prov_entries.append({
                    "email_id": m.email_id,
                    "source_dataset": m.source_dataset,
                    "source_record_id": m.source_record_id,
                    "source_path": m.source_path,
                    "source_label": m.source_label,
                    "is_canonical_representative": (m.email_id == canonical_rep.email_id),
                })

            cluster = DuplicateCluster(
                cluster_id=cluster_id,
                cluster_type=ctype,
                canonical_email_id=canonical_rep.email_id,
                email_ids=sorted_member_ids,
                datasets_involved=datasets_involved,
                record_count=len(members),
                provenance_entries=prov_entries,
            )
            self.clusters[cluster_id] = cluster
            cluster_list.append(cluster)

            if len(members) > 1:
                report_rows.append({
                    "cluster_id": cluster_id,
                    "cluster_type": ctype,
                    "record_count": len(members),
                    "canonical_email_id": canonical_rep.email_id,
                    "datasets_involved": "|".join(sorted(datasets_involved)),
                    "member_email_ids": "|".join(sorted_member_ids),
                    "evidence": f"raw_hashes={len(raw_hashes)}, full_hashes={len(full_hashes)}, body_hashes={len(body_hashes)}",
                })

        report_df = pd.DataFrame(report_rows)
        return deduped_emails, cluster_list, report_df
