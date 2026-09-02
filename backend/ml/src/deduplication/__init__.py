"""Deduplication Package."""
from ml.src.deduplication.exact_dedup import ExactDeduplicator, DuplicateCluster
from ml.src.deduplication.near_dedup import MinHashLSHDeduplicator, NearDuplicateCluster

__all__ = [
    "ExactDeduplicator",
    "DuplicateCluster",
    "MinHashLSHDeduplicator",
    "NearDuplicateCluster",
]
