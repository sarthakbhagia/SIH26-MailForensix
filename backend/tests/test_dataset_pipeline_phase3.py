"""Phase 3 Test Suite: Deduplication, 5-Class Labeling, Suspicious Curation & Leakage Splitting.

Verifies:
- Canonical schema & provenance preservation
- Multi-level exact duplicate hashing & clustering
- MinHash LSH near-duplicate clustering & cross-dataset provenance
- Authoritative 5-class taxonomy & labels.yaml consistency
- Interpretable Semantic Suspicious candidate scoring & benign penalties
- Suspicious review queue generation & human review label import
- Group-aware stratified splitting into Train/Val/Test
- Automated leakage audit assertions (email_id, duplicate, near-duplicate, group, synthetic test isolation)
"""

from pathlib import Path
import tempfile
import pytest
import pandas as pd
import yaml

from ml.src.schemas.canonical_email import CanonicalEmail, compute_deterministic_email_id
from ml.src.normalization.normalizer import EmailNormalizer
from ml.src.deduplication.exact_dedup import ExactDeduplicator
from ml.src.deduplication.near_dedup import MinHashLSHDeduplicator
from ml.src.curation.suspicious_scorer import SemanticSuspiciousScorer
from ml.src.curation.review_manager import ReviewManager
from ml.src.splitting.group_splitter import GroupAwareSplitter
from ml.src.splitting.leakage_auditor import LeakageAuditor


# ---------------------------------------------------------------------------
# 1. Exact & Near-Duplicate Deduplication Tests
# ---------------------------------------------------------------------------

def test_multi_level_exact_deduplication():
    """Verify that exact byte, normalized full, and normalized body matches cluster together while preserving provenance."""
    # Email 1: Original authentic
    em1 = EmailNormalizer.parse_structured_fields(
        subject="Urgent: Wire Transfer Required",
        body="Please process wire transfer of $50,000 immediately to account 12345.",
        sender="cfo@corp.com",
        source_dataset="enron",
        source_record_id="msg_001",
    )
    # Email 2: Exact copy in another dataset with different source record ID
    em2 = EmailNormalizer.parse_structured_fields(
        subject="Urgent: Wire Transfer Required",
        body="Please process wire transfer of $50,000 immediately to account 12345.",
        sender="cfo@corp.com",
        source_dataset="trec07",
        source_record_id="inmail.999",
    )
    # Email 3: Completely distinct message
    em3 = EmailNormalizer.parse_structured_fields(
        subject="Weekly Project Status",
        body="Here is the weekly update on the software engineering sprint.",
        sender="dev@corp.com",
        source_dataset="enron",
        source_record_id="msg_002",
    )

    dedup = ExactDeduplicator()
    canonical_list, clusters, df_report = dedup.deduplicate([em1, em2, em3])

    assert len(canonical_list) == 2
    assert len(clusters) == 2

    multi_cluster = next(c for c in clusters if c.record_count == 2)
    assert len(multi_cluster.provenance_entries) == 2
    assert "enron" in multi_cluster.datasets_involved
    assert "trec07" in multi_cluster.datasets_involved


def test_minhash_lsh_near_duplicate_clustering():
    """Verify MinHash LSH detects campaign mutations and template variations."""
    # Template base
    em1 = EmailNormalizer.parse_structured_fields(
        subject="Security Notice: Account Alert",
        body="Dear customer, unusual sign-in activity was detected on your online account. Please click here to verify your identity and prevent suspension.",
        sender="support@service1.com",
        source_dataset="nazario",
        source_record_id="msg_1",
    )
    # Minor mutation (changed sender and customer name)
    em2 = EmailNormalizer.parse_structured_fields(
        subject="Security Notice: Account Alert",
        body="Dear client, unusual sign-in activity was detected on your online account. Please click here to verify your identity and prevent suspension immediately.",
        sender="support@service2.com",
        source_dataset="phishing_pot",
        source_record_id="sample_10",
    )
    # Distinct message
    em3 = EmailNormalizer.parse_structured_fields(
        subject="Lunch Menu for Wednesday",
        body="Today's cafeteria special includes grilled salmon and seasonal vegetables.",
        sender="cafeteria@corp.com",
        source_dataset="enron",
        source_record_id="msg_2",
    )

    lsh = MinHashLSHDeduplicator(jaccard_threshold=0.75)
    near_map, clusters, df_near, df_prov = lsh.cluster([em1, em2, em3])

    assert near_map[em1.email_id] == near_map[em2.email_id]
    assert near_map[em1.email_id] != near_map[em3.email_id]


# ---------------------------------------------------------------------------
# 2. Five-Class Taxonomy & Label Configuration Tests
# ---------------------------------------------------------------------------

def test_labels_yaml_taxonomy_consistency():
    """Verify labels.yaml contains the exact 5 canonical classes and IDs."""
    labels_file = Path(__file__).resolve().parents[1] / "ml" / "config" / "labels.yaml"
    with open(labels_file, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    taxonomy = cfg.get("taxonomy", {})
    id_to_name = taxonomy.get("id_to_name", {})

    expected = {
        0: "LEGITIMATE",
        1: "SUSPICIOUS",
        2: "PHISHING",
        3: "BEC_FRAUD",
        4: "IMPERSONATION",
    }
    assert id_to_name == expected

    # Check that source mappings exist for all key datasets
    src_mappings = cfg.get("source_mappings", {})
    for ds in ["enron", "trec07", "nazario", "phishing_pot", "epvme", "clair", "bec2"]:
        assert ds in src_mappings


# ---------------------------------------------------------------------------
# 3. Semantic Suspicious Scorer & Review Queue Tests
# ---------------------------------------------------------------------------

def test_semantic_suspicious_scorer_rules():
    """Verify that security cues score high while commercial benign cues receive penalties."""
    scorer = SemanticSuspiciousScorer()

    # 1. Suspicious security alert
    susp_email = EmailNormalizer.parse_structured_fields(
        subject="URGENT: Your account has been restricted",
        body="Immediate action required. Unusual login detected. Click here to confirm your password and avoid account termination within 24 hours.",
        sender="alert@security-check.com",
    )
    res_susp = scorer.score_email(susp_email)
    assert res_susp.candidate_score >= 3.0
    assert res_susp.is_suspicious_candidate is True
    assert any("SE_ACCOUNT_SUSPENSION" in c or "SE_CREDENTIAL_VERIFY" in c for c in res_susp.reason_codes)

    # 2. Benign commercial spam / newsletter
    promo_email = EmailNormalizer.parse_structured_fields(
        subject="Summer Super Sale: 50% Off Everything!",
        body="Shop now and save 50% on all shoes and apparel. Free shipping on orders over $50. Click here to view online. If you wish to opt-out, click unsubscribe.",
        sender="promo@retailstore.com",
    )
    res_promo = scorer.score_email(promo_email)
    assert res_promo.candidate_score <= 1.0
    assert res_promo.suggested_label == "ORDINARY_SPAM"
    assert "BENIGN_UNSUBSCRIBE" in res_promo.reason_codes


def test_review_manager_export_and_import(tmp_path):
    """Verify export of review queue and application of human review labels."""
    scorer = SemanticSuspiciousScorer()

    em1 = EmailNormalizer.parse_structured_fields(
        subject="Urgent: Account locked",
        body="Verify your account immediately.",
        sender="admin@alert.com",
        source_dataset="trec07",
        source_record_id="inmail.1",
    )
    res1 = scorer.score_email(em1)

    queue_csv = tmp_path / "test_review_queue.csv"
    ReviewManager.export_review_queue([em1], {em1.email_id: res1}, queue_csv)
    assert queue_csv.exists()

    # Simulate human reviewer editing the CSV
    df = pd.read_csv(queue_csv, dtype=str)
    assert len(df) == 1
    df.loc[0, "review_label"] = "suspicious"
    df.loc[0, "reviewer"] = "expert_analyst"
    df.loc[0, "review_notes"] = "Confirmed suspicious security urgency"
    df.to_csv(queue_csv, index=False)

    email_map = {em1.email_id: em1}
    applied, skipped, warns = ReviewManager.import_review_labels(queue_csv, email_map)

    assert applied == 1
    assert skipped == 0
    assert em1.canonical_label == "SUSPICIOUS"
    assert em1.label_source == "manual_review"
    assert em1.label_confidence == 1.0


# ---------------------------------------------------------------------------
# 4. Group-Aware Splitting & Leakage Audit Tests
# ---------------------------------------------------------------------------

def test_group_aware_splitting_and_leakage_audit(tmp_path):
    """Verify group-aware partitioning into 70/15/15 and execution of leakage assertions."""
    # Create 10 mock emails with shared clusters and synthetic BEC-2
    emails = []
    for i in range(8):
        em = EmailNormalizer.parse_structured_fields(
            subject=f"Legitimate Email {i}",
            body=f"This is authentic corporate text number {i}.",
            sender=f"user_{i}@company.com",
            source_dataset="enron",
            source_record_id=f"msg_{i}",
        )
        em.canonical_label = "LEGITIMATE"
        emails.append(em)

    # 2 synthetic BEC-2 emails
    for i in range(2):
        em_synth = EmailNormalizer.parse_structured_fields(
            subject=f"Synthetic Wire Request {i}",
            body="Please execute immediate wire payment.",
            sender="ceo@synthetic.com",
            source_dataset="bec2",
            source_record_id=f"bec_{i}",
            is_synthetic=True,
            synthetic_source="BEC-2",
        )
        em_synth.canonical_label = "BEC_FRAUD"
        emails.append(em_synth)

    exact_cluster_map = {e.email_id: f"exact_{e.email_id}" for e in emails}
    near_cluster_map = {e.email_id: f"near_{e.email_id}" for e in emails}

    splitter = GroupAwareSplitter(train_ratio=0.70, val_ratio=0.15, test_ratio=0.15)
    email_to_group = splitter.build_groups(emails, exact_cluster_map, near_cluster_map)
    df_splits, df_report = splitter.split(emails, email_to_group, exact_cluster_map, near_cluster_map)

    assert len(df_splits) == 10
    assert set(df_splits["split"].unique()).issubset({"train", "validation", "test"})

    # Run Leakage Auditor
    auditor = LeakageAuditor()
    audit_res = auditor.audit(emails, df_splits)

    assert audit_res["status"] == "PASS"
    assert audit_res["checks"]["no_email_id_overlap"] is True
    assert audit_res["checks"]["no_exact_duplicate_crossings"] is True
    assert audit_res["checks"]["no_group_id_crossings"] is True
    assert audit_res["checks"]["no_synthetic_in_test_split"] is True
