# MailForensix ML Model Card: mailforensix-ml-v1.1.0

## Model Details
* **Model Name:** MailForensix Minority-Aware Stacking Threat Classifier
* **Version:** `mailforensix-ml-v1.1.0` (Phase 5A Promoted Release)
* **Architecture:** Multi-Tiered Stacking Ensemble combining:
  1. **DistilRoBERTa NLP Classifier** (512 max seq length, class-weighted cross-entropy on Train text)
  2. **LightGBM Tabular Classifier** (35 forensic features tuned via Optuna 30 trials on Train/Val)
  3. **Domain Forensic Rule Layer** (Authentication, BEC, Urgency, Phishing heuristics)
  4. **Minority-Aware Logistic Regression Meta-Classifier** (15D OOF inputs, Train-only balanced class weighting, validation-tuned threshold $\tau = 0.225$)
* **License:** Apache-2.0 / Academic & Enterprise Security Research
* **Release Date:** 2026-09-01
* **Git SHA:** `d08a53c96a63696a2fde58740e8a92819cb71ada`

---

## Intended Use & Threat Taxonomy
The model classifies incoming RFC822/EML email messages into five canonical security categories:
1. `0: LEGITIMATE` — Normal business and personal correspondence.
2. `1: SUSPICIOUS` — Borderline messages with anomalous routing/infrastructure or ambiguous urgency, requiring security analyst inspection.
3. `2: PHISHING` — Credential harvesting, deceptive links, lookalike domains, or malicious attachments.
4. `3: BEC_FRAUD` — Business Email Compromise, CEO fraud, wire transfer redirection, gift card scams.
5. `4: IMPERSONATION` — Brand and executive identity spoofing.

---

## Training and Evaluation Data Composition

* **Total Usable Canonical Corpus:** 14,069 emails (12,105 real, 1,964 synthetic)
* **Leakage-Safe Partitioning:** Group-aware 70/15/15 split:
  - **Train:** 9,695 records (8,232 real, 1,463 synthetic)
  - **Validation:** 2,826 records (2,325 real, 501 synthetic)
  - **Frozen Test:** 1,548 records (**1,548 real emails, 0.0% synthetic — 100% clean test set**)

---

## Frozen Test Benchmark Performance (1,548 Real Emails)

| Threat Class | Real Test Support | Precision | Recall | F1 Score | Notes & Limitations |
|---|---:|---:|---:|---:|---|
| **LEGITIMATE** | 775 | **0.9675** | **1.0000** | **0.9835** | 100% clean test support |
| **SUSPICIOUS** | 14 | **0.8182** | **0.6429** | **0.7200** | Recovered 9/14 real test samples |
| **PHISHING** | 423 | **0.9892** | **0.9892** | **0.9892** | High-precision credential threat detection |
| **BEC_FRAUD** | 336 | **0.9970** | **0.9911** | **0.9940** | High-precision financial fraud detection |
| **IMPERSONATION** | 0 | **N/A** | **N/A** | **N/A** | *NOT AVAILABLE / INSUFFICIENT REAL TEST DATA (0 real test emails)* |

### Aggregate Metrics:
* **Accuracy:** `0.9871` (98.71%)
* **Balanced Accuracy:** `0.9022`
* **Macro F1 Score:** `0.9226`
* **Weighted F1 Score:** `0.9868`
* **Multi-Class Log Loss:** `0.0862`
* **Expected Calibration Error (ECE):** `0.0098`

---

## Explicit Limitations & Caveats

1. **SUSPICIOUS Class Population:**
   - The test split contains 14 real curated SUSPICIOUS emails. While the model achieved `0.7200` F1 (64.3% recall), this sample size is small and represents an initial benchmark rather than statistically asymptotic future performance.
2. **IMPERSONATION Real Test Availability:**
   - The canonical test split contains **0 real Impersonation emails** (to uphold the zero-synthetic test policy). Real-world generalization on pure impersonation must be monitored in production.
3. **BEC/Fraud Synthetic Provenance:**
   - Training contains synthetic BEC examples from controlled scenarios. Test BEC emails are 100% real (CLAIR / Nazario / Enron).
4. **Historical External Enrichment Time Shift:**
   - Historical emails evaluated with live DNS/WHOIS lookups may experience missing domain records or changed IP ownership. The feature extractor handles missing values gracefully with default encodings.
