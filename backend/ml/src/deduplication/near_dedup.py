"""Near-Duplicate Detection and Cross-Dataset Provenance Analyzer.

Implements Part D and Part E of Phase 3 specification:
- Linear-complexity MinHash + LSH near-duplicate clustering
- Detects template reuse, modified phishing campaigns, and cross-dataset derivations
- Analyzes cross-dataset relationships (Nazario ↔ EPVME, TREC07 ↔ EPVME, etc.)
- Produces near_duplicate_cluster_id and provenance_report.csv
"""

from collections import defaultdict
from dataclasses import dataclass, field
import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import pandas as pd

from ml.src.schemas.canonical_email import CanonicalEmail


@dataclass
class NearDuplicateCluster:
    cluster_id: str
    canonical_email_id: str
    member_email_ids: List[str] = field(default_factory=list)
    datasets_involved: Set[str] = field(default_factory=set)
    record_count: int = 0
    representative_subject: str = ""


class MinHashLSHDeduplicator:
    """MinHash Locality-Sensitive Hashing for sub-linear near-duplicate clustering."""

    def __init__(
        self,
        num_perm: int = 64,
        num_bands: int = 16,
        jaccard_threshold: float = 0.70,
        shingle_size: int = 2,
    ):
        self.num_perm = num_perm
        self.num_bands = num_bands
        self.rows_per_band = num_perm // num_bands
        self.jaccard_threshold = jaccard_threshold
        self.shingle_size = shingle_size

        # Generate deterministic linear hash coefficients: h_i(x) = (a_i * x + b_i) % prime
        self.prime = 4294967311  # 2^32 - 5
        self.a_coeffs = [(i * 10007 + 3) % (self.prime - 1) + 1 for i in range(1, num_perm + 1)]
        self.b_coeffs = [(i * 20011 + 7) % self.prime for i in range(1, num_perm + 1)]

    def _get_shingles(self, text: str) -> Set[int]:
        """Extract word and character n-gram shingles."""
        clean = re.sub(r'\s+', ' ', text.lower()).strip()
        if not clean:
            return set()
        tokens = clean.split()
        shingles = set()
        # Word shingles
        if len(tokens) >= self.shingle_size:
            for i in range(len(tokens) - self.shingle_size + 1):
                s = " ".join(tokens[i : i + self.shingle_size])
                shingles.add(int(hashlib.md5(s.encode('utf-8')).hexdigest()[:8], 16))
        else:
            # Fallback to character 4-grams for short text
            for i in range(max(1, len(clean) - 3)):
                s = clean[i : i + 4]
                shingles.add(int(hashlib.md5(s.encode('utf-8')).hexdigest()[:8], 16))
        return shingles

    def _compute_minhash(self, shingles: Set[int]) -> List[int]:
        """Compute signature vector of minimum hash values."""
        if not shingles:
            return [0] * self.num_perm
        signature = []
        for a, b in zip(self.a_coeffs, self.b_coeffs):
            min_val = min(((a * s + b) % self.prime) for s in shingles)
            signature.append(min_val)
        return signature

    def cluster(
        self,
        emails: List[CanonicalEmail],
    ) -> Tuple[Dict[str, str], List[NearDuplicateCluster], pd.DataFrame, pd.DataFrame]:
        """Run LSH near-duplicate clustering and return (email_to_near_cluster, clusters, near_report_df, prov_report_df)."""
        # 1. Compute MinHash signatures
        signatures: Dict[str, List[int]] = {}
        shingles_map: Dict[str, Set[int]] = {}
        email_by_id: Dict[str, CanonicalEmail] = {}

        for em in emails:
            email_by_id[em.email_id] = em
            content = f"{em.subject} {em.body_plain}"
            sh = self._get_shingles(content)
            shingles_map[em.email_id] = sh
            signatures[em.email_id] = self._compute_minhash(sh)

        # 2. LSH Bucketing across bands
        band_buckets: Dict[Tuple[int, str], List[str]] = defaultdict(list)
        for email_id, sig in signatures.items():
            for band_idx in range(self.num_bands):
                start = band_idx * self.rows_per_band
                end = start + self.rows_per_band
                band_slice = sig[start:end]
                band_hash = hashlib.md5(str(band_slice).encode('utf-8')).hexdigest()[:12]
                band_buckets[(band_idx, band_hash)].append(email_id)

        # 3. Candidate verification with Jaccard similarity & Union-Find
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

        # Track verified pairwise matches for provenance reporting
        pairwise_matches: List[Dict[str, Any]] = []

        seen_pairs = set()
        for bucket, member_ids in band_buckets.items():
            if len(member_ids) > 1:
                # If bucket is large (>30 members), compare members to cluster leader linearly
                if len(member_ids) > 30:
                    leader_id = member_ids[0]
                    leader_sh = shingles_map[leader_id]
                    for other_id in member_ids[1:]:
                        pair = tuple(sorted([leader_id, other_id]))
                        if pair in seen_pairs:
                            continue
                        seen_pairs.add(pair)
                        other_sh = shingles_map[other_id]
                        if not leader_sh or not other_sh:
                            continue
                        jaccard = len(leader_sh & other_sh) / float(len(leader_sh | other_sh))
                        if jaccard >= self.jaccard_threshold:
                            union(leader_id, other_id)
                            pairwise_matches.append({
                                "email_id_a": leader_id,
                                "source_dataset_a": email_by_id[leader_id].source_dataset,
                                "email_id_b": other_id,
                                "source_dataset_b": email_by_id[other_id].source_dataset,
                                "jaccard_similarity": round(jaccard, 4),
                            })
                else:
                    for i in range(len(member_ids)):
                        for j in range(i + 1, len(member_ids)):
                            id1, id2 = member_ids[i], member_ids[j]
                            pair = tuple(sorted([id1, id2]))
                            if pair in seen_pairs:
                                continue
                            seen_pairs.add(pair)

                            sh1, sh2 = shingles_map[id1], shingles_map[id2]
                            if not sh1 or not sh2:
                                continue
                            jaccard = len(sh1 & sh2) / float(len(sh1 | sh2))

                            if jaccard >= self.jaccard_threshold:
                                union(id1, id2)
                                em1 = email_by_id[id1]
                                em2 = email_by_id[id2]
                                pairwise_matches.append({
                                    "email_id_a": id1,
                                    "source_dataset_a": em1.source_dataset,
                                    "email_id_b": id2,
                                    "source_dataset_b": em2.source_dataset,
                                    "jaccard_similarity": round(jaccard, 4),
                                })

        # Build near-duplicate clusters
        cluster_groups: Dict[str, List[str]] = defaultdict(list)
        for em in emails:
            root = find(em.email_id)
            cluster_groups[root].append(em.email_id)

        email_to_near_cluster: Dict[str, str] = {}
        cluster_list: List[NearDuplicateCluster] = []
        near_report_rows: List[Dict[str, Any]] = []

        for root_id, member_ids in cluster_groups.items():
            sorted_member_ids = sorted(member_ids)
            cluster_seed = "|".join(sorted_member_ids)
            near_cluster_id = f"near_cluster_{hashlib.sha256(cluster_seed.encode('utf-8')).hexdigest()[:16]}"

            datasets_involved = {email_by_id[mid].source_dataset for mid in sorted_member_ids}
            for mid in sorted_member_ids:
                email_to_near_cluster[mid] = near_cluster_id

            canonical_rep_id = sorted_member_ids[0]
            cluster_obj = NearDuplicateCluster(
                cluster_id=near_cluster_id,
                canonical_email_id=canonical_rep_id,
                member_email_ids=sorted_member_ids,
                datasets_involved=datasets_involved,
                record_count=len(sorted_member_ids),
                representative_subject=email_by_id[canonical_rep_id].subject,
            )
            cluster_list.append(cluster_obj)

            if len(sorted_member_ids) > 1:
                near_report_rows.append({
                    "cluster_id": near_cluster_id,
                    "record_count": len(sorted_member_ids),
                    "datasets_involved": "|".join(sorted(datasets_involved)),
                    "canonical_email_id": canonical_rep_id,
                    "representative_subject": email_by_id[canonical_rep_id].subject[:60],
                    "member_email_ids": "|".join(sorted_member_ids),
                })

        near_report_df = pd.DataFrame(near_report_rows)

        # 4. Generate Cross-Dataset Provenance Report
        prov_report_rows: List[Dict[str, Any]] = []
        cross_dataset_counts: Dict[Tuple[str, str], List[float]] = defaultdict(list)

        for match in pairwise_matches:
            ds_a = match["source_dataset_a"]
            ds_b = match["source_dataset_b"]
            if ds_a != ds_b:
                pair_key = tuple(sorted([ds_a, ds_b]))
                cross_dataset_counts[pair_key].append(match["jaccard_similarity"])

        for (ds_a, ds_b), similarities in cross_dataset_counts.items():
            avg_sim = sum(similarities) / len(similarities)
            max_sim = max(similarities)
            if max_sim >= 0.99:
                rel_class = "derived_copy"
            elif avg_sim >= 0.90:
                rel_class = "template_overlap"
            else:
                rel_class = "near_duplicate"

            prov_report_rows.append({
                "source_dataset_a": ds_a,
                "source_dataset_b": ds_b,
                "matching_records": len(similarities),
                "match_method": "minhash_lsh_shingle_jaccard",
                "similarity_evidence": f"avg_jaccard={avg_sim:.4f}, max_jaccard={max_sim:.4f}, threshold={self.jaccard_threshold}",
                "relationship_classification": rel_class,
            })

        # Add explicitly investigated known pairs even if 0 matches to document inspection
        known_investigated_pairs = [
            ("nazario", "epvme"),
            ("trec07", "epvme"),
            ("spamassassin", "epvme"),
            ("nazario", "iwspa_ap"),
            ("clair", "zefang_liu"),
            ("bec2", "enron"),
        ]
        existing_pairs = {tuple(sorted([r["source_dataset_a"], r["source_dataset_b"]])) for r in prov_report_rows}
        for (ds_a, ds_b) in known_investigated_pairs:
            pair_key = tuple(sorted([ds_a, ds_b]))
            if pair_key not in existing_pairs:
                prov_report_rows.append({
                    "source_dataset_a": ds_a,
                    "source_dataset_b": ds_b,
                    "matching_records": 0,
                    "match_method": "minhash_lsh_shingle_jaccard",
                    "similarity_evidence": f"no pairs met jaccard threshold >= {self.jaccard_threshold}",
                    "relationship_classification": "independent",
                })

        prov_report_df = pd.DataFrame(prov_report_rows)
        return email_to_near_cluster, cluster_list, near_report_df, prov_report_df
