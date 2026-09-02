"""Suspicious Review Queue Manager for MailForensix ML Pipeline.

Implements Part K and Part L of Phase 3 specification:
- Generates editable suspicious_review_queue.csv
- Imports human review labels into CanonicalEmail objects
- Preserves raw candidate scores and original suggested labels
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import pandas as pd

from ml.src.schemas.canonical_email import CanonicalEmail
from ml.src.curation.suspicious_scorer import SuspiciousScoreResult


VALID_REVIEW_LABELS = {
    "ordinary_spam": "ORDINARY_SPAM",
    "suspicious": "SUSPICIOUS",
    "phishing": "PHISHING",
    "bec_fraud": "BEC_FRAUD",
    "impersonation": "IMPERSONATION",
    "uncertain": "UNCERTAIN",
}


class ReviewManager:
    """Manages creation and ingestion of human review queues for ambiguous/candidate records."""

    @staticmethod
    def export_review_queue(
        emails: List[CanonicalEmail],
        score_results: Dict[str, SuspiciousScoreResult],
        output_csv_path: Path,
        max_records: Optional[int] = None,
    ) -> Path:
        """Export candidates into editable CSV format."""
        output_csv_path.parent.mkdir(parents=True, exist_ok=True)
        rows: List[Dict[str, Any]] = []

        for em in emails:
            res = score_results.get(em.email_id)
            if not res:
                continue

            # Body preview: first 200 clean characters
            body_preview = " ".join((em.body_plain or "").split())[:200]

            rows.append({
                "email_id": em.email_id,
                "source_dataset": em.source_dataset,
                "source_record_id": em.source_record_id,
                "subject": em.subject[:100],
                "sender": em.sender[:80],
                "body_preview": body_preview,
                "candidate_score": res.candidate_score,
                "reason_codes": "|".join(res.reason_codes),
                "suggested_label": res.suggested_label,
                "review_label": "",            # Editable field for human reviewer
                "reviewer": "",                # e.g., "analyst_1"
                "review_notes": "",            # e.g., "Credential harvesting link present"
            })

        # Sort by candidate score descending
        rows.sort(key=lambda r: float(r["candidate_score"]), reverse=True)
        if max_records:
            rows = rows[:max_records]

        df = pd.DataFrame(rows)
        df.to_csv(output_csv_path, index=False, encoding="utf-8")
        return output_csv_path

    @staticmethod
    def import_review_labels(
        review_csv_path: Path,
        email_map: Dict[str, CanonicalEmail],
    ) -> Tuple[int, int, List[str]]:
        """Import human review labels and update CanonicalEmail instances in-place.
        
        Returns (applied_count, skipped_count, validation_warnings).
        """
        if not review_csv_path.exists():
            return 0, 0, [f"Review file {review_csv_path} does not exist."]

        df = pd.read_csv(review_csv_path)
        applied = 0
        skipped = 0
        warnings: List[str] = []

        for idx, row in df.iterrows():
            email_id = str(row.get("email_id", "")).strip()
            raw_rev_label = str(row.get("review_label", "")).strip().lower()

            if not raw_rev_label or raw_rev_label == "nan":
                skipped += 1
                continue

            if raw_rev_label not in VALID_REVIEW_LABELS:
                warnings.append(f"Row {idx} (ID {email_id}): Invalid review_label '{raw_rev_label}'. Allowed: {list(VALID_REVIEW_LABELS.keys())}")
                skipped += 1
                continue

            canonical_lbl = VALID_REVIEW_LABELS[raw_rev_label]
            em = email_map.get(email_id)
            if not em:
                warnings.append(f"Row {idx}: email_id '{email_id}' not found in canonical corpus.")
                skipped += 1
                continue

            # Update email with human reviewed ground truth
            em.canonical_label = canonical_lbl
            em.label_source = "manual_review"
            em.label_confidence = 1.0

            # If marked uncertain or ordinary_spam, record exclusion reason
            if canonical_lbl in ("ORDINARY_SPAM", "UNCERTAIN"):
                em.nlp_usable = False
                em.exclusion_reason = f"human_review_{raw_rev_label}"

            applied += 1

        return applied, skipped, warnings
