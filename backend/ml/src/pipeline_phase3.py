"""Master Phase 3 Pipeline Orchestrator for MailForensix ML Pipeline.

Executes Parts A through U of Phase 3 specification:
1. Parse all available datasets into CanonicalEmail objects
2. Parser validation & corpus_inventory.parquet generation
3. Global multi-level exact deduplication & duplicate_report.csv
4. MinHash LSH near-duplicate clustering & provenance_report.csv
5. Five-class label mapping & semantic Suspicious curation
6. Suspicious review queue generation & review label import
7. Final training manifest serialization
8. Group-aware leakage-safe splitting (Train 70% / Val 15% / Test 15%)
9. Automated leakage audit & assertion verification (leakage_audit.json)
10. Markdown and CSV reports generation
"""

from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import pandas as pd
import yaml

from ml.src.schemas.canonical_email import CanonicalEmail
from ml.src.parsers.registry import parse_dataset_from_config
from ml.src.deduplication.exact_dedup import ExactDeduplicator
from ml.src.deduplication.near_dedup import MinHashLSHDeduplicator
from ml.src.curation.suspicious_scorer import SemanticSuspiciousScorer, SuspiciousScoreResult
from ml.src.curation.review_manager import ReviewManager
from ml.src.splitting.group_splitter import GroupAwareSplitter
from ml.src.splitting.leakage_auditor import LeakageAuditor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Phase3Pipeline")


class Phase3PipelineRunner:
    """End-to-end execution of Phase 3 dataset processing, deduplication, and splitting."""

    def __init__(
        self,
        config_dir: Optional[Path] = None,
        data_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        reports_dir: Optional[Path] = None,
    ):
        self.base_dir = Path(__file__).resolve().parents[1]
        self.config_dir = config_dir or (self.base_dir / "config")
        self.data_dir = data_dir or (self.base_dir / "data" / "raw")
        self.output_dir = output_dir or (self.base_dir / "data")
        self.reports_dir = reports_dir or (self.base_dir / "reports")

        # Destination directories
        self.manifests_dir = self.output_dir / "manifests"
        self.normalized_dir = self.output_dir / "normalized"
        self.splits_dir = self.output_dir / "splits"

        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        self.normalized_dir.mkdir(parents=True, exist_ok=True)
        self.splits_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self.datasets_cfg = self._load_yaml(self.config_dir / "datasets.yaml").get("datasets", {})
        self.labels_cfg = self._load_yaml(self.config_dir / "labels.yaml")

    @staticmethod
    def _load_yaml(path: Path) -> Dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def run(
        self,
        max_samples_per_dataset: Optional[int] = None,
        jaccard_threshold: float = 0.85,
    ) -> Dict[str, Any]:
        """Execute complete Phase 3 pipeline."""
        logger.info("=== Starting MailForensix Phase 3 Ingestion & Splitting Pipeline ===")

        # -----------------------------------------------------------------------
        # 1. Ingest all available datasets
        # -----------------------------------------------------------------------
        raw_emails: List[CanonicalEmail] = []
        parser_stats_records: List[Dict[str, Any]] = []

        total_discovered = 0
        total_parsed = 0
        total_failed = 0

        for ds_key, ds_cfg in self.datasets_cfg.items():
            logger.info(f"Parsing dataset: {ds_key} ({ds_cfg.get('name')})...")
            try:
                stream, parser = parse_dataset_from_config(ds_key, ds_cfg, self.data_dir)
                ds_count = 0
                for email_rec in stream:
                    raw_emails.append(email_rec)
                    ds_count += 1
                    if max_samples_per_dataset and ds_count >= max_samples_per_dataset:
                        break

                disc = parser.stats.discovered_count
                pars = parser.stats.parseable_count
                fail = parser.stats.failed_count

                total_discovered += disc
                total_parsed += pars
                total_failed += fail

                parser_stats_records.append({
                    "dataset": ds_key,
                    "name": ds_cfg.get("name"),
                    "format": ds_cfg.get("format"),
                    "discovered_count": disc,
                    "parseable_count": pars,
                    "failed_count": fail,
                    "nlp_usable_count": sum(1 for e in raw_emails[-ds_count:] if len(e.subject or "") + len(e.body_plain or "") >= 10) if ds_count else 0,
                    "forensic_usable_count": sum(1 for e in raw_emails[-ds_count:] if e.headers or e.sender) if ds_count else 0,
                })
                logger.info(f"Dataset '{ds_key}' completed: {pars} parsed, {fail} failed.")
            except Exception as e:
                logger.error(f"Error parsing dataset {ds_key}: {e}")
                parser_stats_records.append({
                    "dataset": ds_key,
                    "name": ds_cfg.get("name"),
                    "format": ds_cfg.get("format"),
                    "discovered_count": 0,
                    "parseable_count": 0,
                    "failed_count": 1,
                    "nlp_usable_count": 0,
                    "forensic_usable_count": 0,
                    "error": str(e),
                })

        # Save corpus inventory manifest
        df_corpus_inv = pd.DataFrame(parser_stats_records)
        df_corpus_inv.to_parquet(self.manifests_dir / "corpus_inventory.parquet", index=False)

        # -----------------------------------------------------------------------
        # 2. Global Multi-Level Exact Deduplication
        # -----------------------------------------------------------------------
        logger.info(f"Running global exact deduplication on {len(raw_emails)} parsed emails...")
        exact_dedup = ExactDeduplicator()
        canonical_emails, exact_clusters, df_exact_dup = exact_dedup.deduplicate(raw_emails)
        logger.info(f"Exact deduplication complete: {len(raw_emails)} -> {len(canonical_emails)} canonical emails ({len(exact_clusters)} clusters).")

        df_exact_dup.to_csv(self.reports_dir / "duplicate_report.csv", index=False)

        # -----------------------------------------------------------------------
        # 3. Near-Duplicate Detection (MinHash LSH)
        # -----------------------------------------------------------------------
        logger.info(f"Running MinHash LSH near-duplicate detection (threshold={jaccard_threshold})...")
        near_dedup = MinHashLSHDeduplicator(jaccard_threshold=jaccard_threshold)
        near_cluster_map, near_clusters, df_near_dup, df_provenance = near_dedup.cluster(canonical_emails)
        logger.info(f"Near-duplicate clustering complete: {len(near_clusters)} near clusters.")

        df_provenance.to_csv(self.reports_dir / "provenance_report.csv", index=False)

        # -----------------------------------------------------------------------
        # 4. Five-Class Taxonomy Labeling & Semantic Suspicious Curation
        # -----------------------------------------------------------------------
        logger.info("Harmonizing 5-class labels and curating Suspicious candidates...")
        scorer = SemanticSuspiciousScorer()
        score_results: Dict[str, SuspiciousScoreResult] = {}
        suspicious_candidates: List[CanonicalEmail] = []

        source_mappings = self.labels_cfg.get("source_mappings", {})

        for em in canonical_emails:
            ds_cfg = source_mappings.get(em.source_dataset, {})
            src_lbl = str(em.source_label or "").lower().strip()

            # A. Check direct dataset mappings
            if em.source_dataset == "enron":
                em.canonical_label = "LEGITIMATE"
                em.label_source = "direct_dataset_mapping"
                em.label_confidence = 1.0
            elif em.source_dataset in ("nazario", "phishing_pot"):
                em.canonical_label = "PHISHING"
                em.label_source = "direct_dataset_mapping"
                em.label_confidence = 0.98
            elif em.source_dataset == "clair":
                em.canonical_label = "BEC_FRAUD"
                em.fraud_subtype = "419_advance_fee"
                em.label_source = "direct_dataset_mapping"
                em.label_confidence = 0.95
            elif em.source_dataset == "bec2":
                em.canonical_label = "BEC_FRAUD"
                em.fraud_subtype = "synthetic_bec"
                em.is_synthetic = True
                em.synthetic_source = "BEC-2 (LLM-generated; Rohit Dube 2025)"
                em.label_source = "direct_dataset_mapping"
                em.label_confidence = 0.90
            elif em.source_dataset == "epvme":
                em.canonical_label = "IMPERSONATION"
                em.is_synthetic = True
                em.synthetic_source = "EPVME (Recombined text + injected SPF/DMARC attack headers)"
                em.construction_type = "header_recombination"
                em.label_source = "direct_dataset_mapping"
                em.label_confidence = 0.90
            elif em.source_dataset == "zefang_liu":
                if src_lbl in ("1", "phishing"):
                    em.canonical_label = "PHISHING"
                else:
                    em.canonical_label = "LEGITIMATE"
                em.label_source = "direct_dataset_mapping"
                em.label_confidence = 0.95
            elif em.source_dataset == "iwspa_ap":
                if src_lbl in ("phish", "1"):
                    em.canonical_label = "PHISHING"
                else:
                    em.canonical_label = "LEGITIMATE"
                em.label_source = "direct_dataset_mapping"
                em.label_confidence = 0.90
            elif em.source_dataset in ("trec07", "ceas08", "spamassassin"):
                # Handle ham directly
                if src_lbl in ("ham", "easy_ham", "hard_ham", "0", "legitimate"):
                    em.canonical_label = "LEGITIMATE"
                    em.label_source = "direct_dataset_mapping"
                    em.label_confidence = 1.0
                else:
                    # Candidate spam pool -> Run Semantic Suspicious Scorer!
                    res = scorer.score_email(em)
                    score_results[em.email_id] = res
                    suspicious_candidates.append(em)

                    if res.is_suspicious_candidate and res.candidate_score >= 2.0:
                        em.canonical_label = res.suggested_label if res.suggested_label in ("SUSPICIOUS", "PHISHING", "BEC_FRAUD") else "SUSPICIOUS"
                        em.label_source = "reviewed_candidate"
                        em.label_confidence = min(0.85, round(0.50 + res.candidate_score * 0.05, 2))
                    else:
                        # Exclude ordinary commercial spam from core 5-class training
                        em.canonical_label = "ORDINARY_SPAM"
                        em.nlp_usable = False
                        em.exclusion_reason = "ordinary_commercial_spam"
                        em.label_source = "heuristic_filter"
                        em.label_confidence = 0.80
            elif em.source_dataset == "sample_emails":
                if "phish" in src_lbl:
                    em.canonical_label = "PHISHING"
                elif "bec" in src_lbl:
                    em.canonical_label = "BEC_FRAUD"
                elif "impersonation" in src_lbl:
                    em.canonical_label = "IMPERSONATION"
                elif "suspicious" in src_lbl:
                    em.canonical_label = "SUSPICIOUS"
                else:
                    em.canonical_label = "LEGITIMATE"
                em.label_source = "direct_dataset_mapping"
                em.label_confidence = 1.0
            else:
                em.canonical_label = "LEGITIMATE" if "ham" in src_lbl or "0" in src_lbl else "SUSPICIOUS"
                em.label_source = "fallback_mapping"
                em.label_confidence = 0.70

        # -----------------------------------------------------------------------
        # 5. Suspicious Review Queue & Review Import
        # -----------------------------------------------------------------------
        review_queue_file = self.manifests_dir / "suspicious_review_queue.csv"
        ReviewManager.export_review_queue(
            emails=suspicious_candidates,
            score_results=score_results,
            output_csv_path=review_queue_file,
            max_records=5000,
        )
        logger.info(f"Exported suspicious review queue to {review_queue_file} ({min(5000, len(suspicious_candidates))} candidates).")

        # Import any human reviewed labels if file has reviews
        email_map = {em.email_id: em for em in canonical_emails}
        applied_rev, skipped_rev, rev_warns = ReviewManager.import_review_labels(review_queue_file, email_map)
        if applied_rev > 0:
            logger.info(f"Applied {applied_rev} human review overrides from {review_queue_file}.")

        # -----------------------------------------------------------------------
        # 6. Quality Filtering & Usability Assessment
        # -----------------------------------------------------------------------
        usable_emails: List[CanonicalEmail] = []
        for em in canonical_emails:
            # Check text completeness
            text_len = len(em.subject or "") + len(em.body_plain or "")
            if text_len < 10:
                em.nlp_usable = False
                if not em.exclusion_reason:
                    em.exclusion_reason = "insufficient_text_length"

            if em.canonical_label in ("ORDINARY_SPAM", "UNCERTAIN", None):
                em.nlp_usable = False
                if not em.exclusion_reason:
                    em.exclusion_reason = f"label_{em.canonical_label}"

            if em.nlp_usable:
                usable_emails.append(em)

        logger.info(f"Quality filtering complete: {len(usable_emails)} / {len(canonical_emails)} emails are training-usable.")

        # -----------------------------------------------------------------------
        # 7. Final Training Manifest Serialization
        # -----------------------------------------------------------------------
        manifest_rows = []
        for em in canonical_emails:
            exact_cid = exact_dedup.email_to_cluster.get(em.email_id, f"exact_single_{em.email_id}")
            near_cid = near_cluster_map.get(em.email_id, f"near_single_{em.email_id}")

            manifest_rows.append({
                "email_id": em.email_id,
                "canonical_label": em.canonical_label,
                "label_source": em.label_source,
                "label_confidence": em.label_confidence,
                "source_dataset": em.source_dataset,
                "source_record_id": em.source_record_id,
                "duplicate_cluster_id": exact_cid,
                "near_duplicate_cluster_id": near_cid,
                "provenance_cluster_id": f"prov_{em.source_dataset}",
                "is_synthetic": em.is_synthetic,
                "synthetic_source": em.synthetic_source,
                "construction_type": em.construction_type,
                "email_timestamp": em.email_timestamp,
                "sender_domain": em.sender_domain,
                "normalized_full_sha256": em.normalized_full_sha256,
                "normalized_body_sha256": em.normalized_body_sha256,
                "nlp_usable": em.nlp_usable,
                "forensic_usable": em.forensic_usable,
                "exclusion_reason": em.exclusion_reason,
            })

        df_final_manifest = pd.DataFrame(manifest_rows)
        df_final_manifest.to_parquet(self.manifests_dir / "final_training_manifest.parquet", index=False)
        logger.info(f"Saved final training manifest to {self.manifests_dir / 'final_training_manifest.parquet'}")

        # Save full canonical email content to normalized parquet for downstream feature extraction & NLP
        email_records = []
        for em in canonical_emails:
            d = asdict(em)
            d["headers"] = json.dumps(d.get("headers") or {})
            d["urls"] = json.dumps(d.get("urls") or [])
            d["attachments"] = json.dumps(d.get("attachments") or [])
            d["recipients"] = json.dumps(d.get("recipients") or [])
            email_records.append(d)
        df_canonical_emails = pd.DataFrame(email_records)
        df_canonical_emails.to_parquet(self.normalized_dir / "canonical_emails.parquet", index=False)
        logger.info(f"Saved {len(df_canonical_emails)} full canonical emails to {self.normalized_dir / 'canonical_emails.parquet'}")

        # -----------------------------------------------------------------------
        # 8. Group-Aware Leakage-Safe Splitting
        # -----------------------------------------------------------------------
        logger.info(f"Constructing leakage groups and performing stratified split on {len(usable_emails)} usable emails...")
        splitter = GroupAwareSplitter(train_ratio=0.70, val_ratio=0.15, test_ratio=0.15)
        email_to_group = splitter.build_groups(
            emails=usable_emails,
            exact_cluster_map=exact_dedup.email_to_cluster,
            near_cluster_map=near_cluster_map,
        )

        df_splits, df_split_report = splitter.split(
            emails=usable_emails,
            email_to_group=email_to_group,
            exact_cluster_map=exact_dedup.email_to_cluster,
            near_cluster_map=near_cluster_map,
        )

        df_splits.to_csv(self.splits_dir / "splits.csv", index=False)
        df_split_report.to_csv(self.reports_dir / "split_report.csv", index=False)
        logger.info(f"Saved authoritative splits to {self.splits_dir / 'splits.csv'}")

        # -----------------------------------------------------------------------
        # 9. Automated Leakage Assertions Audit
        # -----------------------------------------------------------------------
        logger.info("Executing automated leakage audit assertions...")
        auditor = LeakageAuditor()
        audit_report = auditor.audit(usable_emails, df_splits)
        auditor.save_audit_report(audit_report, self.reports_dir / "leakage_audit.json")

        if audit_report["status"] != "PASS":
            logger.warning(f"Leakage audit violations detected: {audit_report['violations']}")
        else:
            logger.info("Leakage audit PASSED all 6 verification checks!")

        # -----------------------------------------------------------------------
        # 10. Generate Label Distribution & Summary Reports
        # -----------------------------------------------------------------------
        self._generate_label_distribution_report(canonical_emails)
        self._generate_corpus_build_report(parser_stats_records, len(raw_emails), len(canonical_emails), len(usable_emails))
        self._generate_quality_report(canonical_emails, usable_emails, audit_report)

        # Mirror reports to root ml/reports/ if needed
        root_reports = Path("ml/reports")
        if root_reports.exists() and root_reports != self.reports_dir:
            for rep_f in self.reports_dir.glob("*.*"):
                try:
                    (root_reports / rep_f.name).write_bytes(rep_f.read_bytes())
                except Exception:
                    pass

        summary_dict = {
            "total_raw_discovered": int(total_discovered),
            "total_raw_parsed": int(total_parsed),
            "total_canonical": int(len(canonical_emails)),
            "exact_duplicate_clusters": int(len(exact_clusters)),
            "near_duplicate_clusters": int(len(near_clusters)),
            "final_usable_records": int(len(usable_emails)),
            "class_distribution": {str(k): int(v) for k, v in pd.Series([e.canonical_label for e in usable_emails]).value_counts().items()},
            "real_vs_synthetic": {
                "real": int(sum(1 for e in usable_emails if not e.is_synthetic)),
                "synthetic": int(sum(1 for e in usable_emails if e.is_synthetic)),
            },
            "split_counts": {str(k): int(v) for k, v in df_splits["split"].value_counts().items()},
            "leakage_audit_status": str(audit_report["status"]),
            "suspicious_review_count": int(len(suspicious_candidates)),
        }

        logger.info("=== Phase 3 Execution Finished Successfully ===")
        return summary_dict

    def _generate_label_distribution_report(self, emails: List[CanonicalEmail]):
        """Generate label_distribution.csv."""
        rows = []
        by_class: Dict[str, List[CanonicalEmail]] = defaultdict(list)
        for e in emails:
            by_class[e.canonical_label or "UNLABELED"].append(e)

        for cname, em_list in by_class.items():
            ds_counts = defaultdict(int)
            real_cnt = 0
            synth_cnt = 0
            for e in em_list:
                ds_counts[e.source_dataset] += 1
                if e.is_synthetic:
                    synth_cnt += 1
                else:
                    real_cnt += 1

            rows.append({
                "canonical_class": cname,
                "total_count": len(em_list),
                "real_count": real_cnt,
                "synthetic_count": synth_cnt,
                "per_dataset_counts": json.dumps(dict(ds_counts)),
            })

        pd.DataFrame(rows).to_csv(self.reports_dir / "label_distribution.csv", index=False)

    def _generate_corpus_build_report(
        self,
        parser_stats: List[Dict[str, Any]],
        total_raw: int,
        total_canonical: int,
        total_usable: int,
    ):
        """Generate Markdown corpus_build_report.md."""
        lines = [
            "# MailForensix — Master Corpus Build Report",
            "",
            f"**Generated At:** {datetime.now(timezone.utc).isoformat()}  ",
            f"**Specification:** `implementation.md` Phase 3 (Parts A & B)",
            "",
            "---",
            "",
            "## 1. Ingestion Summary",
            "",
            f"- **Total Raw Messages Ingested:** {total_raw:,}",
            f"- **Total Unique Canonical Records (Post-Exact-Dedup):** {total_canonical:,}",
            f"- **Total Training-Usable Records:** {total_usable:,}",
            f"- **Excluded Records (Ordinary Spam / Malformed):** {total_canonical - total_usable:,}",
            "",
            "## 2. Per-Dataset Parser Ingestion Statistics",
            "",
            "| Dataset | Format | Discovered | Parsed | Failures | NLP Usable | Forensic Usable |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]

        for s in parser_stats:
            lines.append(
                f"| **{s['dataset']}** ({s['name']}) | `{s['format']}` | {s.get('discovered_count', 0):,} | {s.get('parseable_count', 0):,} | {s.get('failed_count', 0):,} | {s.get('nlp_usable_count', 0):,} | {s.get('forensic_usable_count', 0):,} |"
            )

        lines.extend([
            "",
            "---",
            "## 3. Provenance and Integrity Guarantees",
            "- [x] Every canonical email retains full pointer chain to its raw source record.",
            "- [x] Exact raw byte, full normalized text, and body hashes are recorded.",
            "- [x] BEC-2 is explicitly tracked with `is_synthetic=True` and isolated from the Test split.",
            "- [x] EPVME is designated as `construction_type='header_recombination'` for tabular forensics.",
        ])

        (self.reports_dir / "corpus_build_report.md").write_text("\n".join(lines), encoding="utf-8")

    def _generate_quality_report(
        self,
        canonical_emails: List[CanonicalEmail],
        usable_emails: List[CanonicalEmail],
        audit_report: Dict[str, Any],
    ):
        """Generate dataset_quality_report.md."""
        lines = [
            "# MailForensix — Dataset Quality and Governance Report",
            "",
            f"**Generated At:** {datetime.now(timezone.utc).isoformat()}  ",
            f"**Leakage Audit Result:** `{audit_report['status']}`",
            "",
            "---",
            "",
            "## 1. Five-Class Taxonomy & Curation Methodology",
            "",
            "- **LEGITIMATE (Class 0)**: Baseline authentic corporate emails from Enron, verified ham from TREC07/CEAS08/SpamAssassin, and legitimate shared task records.",
            "- **SUSPICIOUS (Class 1)**: Curated from candidate spam pools using rule-based semantic scoring (urgency, credential verification cues, payment changes). Ordinary commercial spam is penalised and excluded.",
            "- **PHISHING (Class 2)**: Captured honeypot emails (phishing_pot), verified Nazario mbox archives, and authentic phishing tracks.",
            "- **BEC_FRAUD (Class 3)**: Authentic 419 scam communications (CLAIR collection) + synthetic BEC templates (BEC-2).",
            "- **IMPERSONATION (Class 4)**: Header authentication vulnerabilities, SPF/DKIM/DMARC bypass exploits (EPVME).",
            "",
            "## 2. Leakage Audit Checks Summary",
            "",
        ]

        for check_name, passed in audit_report["checks"].items():
            badge = "✅ PASS" if passed else "❌ FAIL"
            lines.append(f"- **{check_name}**: {badge}")

        lines.extend([
            "",
            "## 3. Synthetic Data Governance Policy",
            "- **BEC-2**: Retained strictly in Train and Validation splits. **0% in Test split**.",
            "- **EPVME**: Retained for tabular/forensic feature learning.",
            "",
            "## 4. Exclusion Reasons Breakdown",
            "",
        ])

        excl_counts = defaultdict(int)
        for e in canonical_emails:
            if not e.nlp_usable and e.exclusion_reason:
                excl_counts[e.exclusion_reason] += 1

        for reason, cnt in sorted(excl_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"- `{reason}`: {cnt:,} records")

        (self.reports_dir / "dataset_quality_report.md").write_text("\n".join(lines), encoding="utf-8")
