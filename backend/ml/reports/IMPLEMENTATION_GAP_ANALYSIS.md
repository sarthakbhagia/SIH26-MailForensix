# MailForensix — ML Pipeline Implementation Gap Analysis

**Version:** 1.0  
**Date:** 2026-08-31  
**Audit Scope:** Repository-wide audit of existing ML code (`backend/ml/`), production ingestion/analysis pipeline (`backend/app/core/`), configuration, requirements, and gap analysis against `implementation.md`.

---

## 1. Executive Summary

MailForensix is an AI-powered email threat forensic and correlation platform designed to classify emails into five distinct threat classes:
```text
0 = Legitimate
1 = Suspicious
2 = Phishing
3 = BEC/Fraud
4 = Impersonation
```

The repository audit confirms that:
1. **Core ML model training architectures are already fully implemented**:
   - DistilRoBERTa fine-tuning with Hugging Face `Trainer` (`backend/ml/train_nlp.py`)
   - LightGBM / HistGradientBoosting with Optuna hyperparameter optimization on 35 forensic features (`backend/ml/train_tabular.py`)
   - Stacking meta-classifier combining 15 probability meta-features with heuristic overrides (`backend/ml/train_ensemble.py`)
2. **Production feature extraction and analysis modules are operational**:
   - RFC 822 / MIME parsing, normalization, and hashing (`backend/app/core/ingestion/`)
   - Header forensics (SPF, DKIM, DMARC, relay hop reconstruction) (`backend/app/core/analysis/header_forensics.py`)
   - Geo-intelligence and domain intelligence (`backend/app/core/analysis/geo_intel.py`)
   - Link and attachment risk analyzers (`backend/app/core/analysis/link_analyzer.py`, `attachment_analyzer.py`)
   - Risk scoring and graph correlation engines (`backend/app/core/correlation/`)
3. **The primary implementation gap is in the data layer and pipeline surrounding training**:
   - `backend/ml/data/prepare_datasets.py` currently only generates 500 toy synthetic examples and uses a naive random `train_test_split`.
   - Real dataset acquisition, format parsing, global deduplication, canonical schema normalization, GroupKFold/temporal leakage-safe splitting, suspicious candidate filtering, batch forensic replay with caching, and out-of-fold probability generation are **not yet built**.

Per the project instructions, **no existing model training architectures will be redesigned**. Instead, this audit establishes the blueprint for building the surrounding dataset, preprocessing, leakage-control, feature-generation, evaluation, and integration pipeline.

---

## 2. Current System Architecture

```
                                  INCOMING EMAIL (RFC 822 / EML)
                                                │
                                                ▼
                                    EmailParser & Preprocessor
                               (Unicode NFKC, IDNA, URL extraction)
                                                │
                                                ▼
                                    Canonical ParsedEmail
                                                │
        ┌───────────────────────────────┬───────┴───────────────────────────────┐
        │                               │                                       │
        ▼                               ▼                                       ▼
 ┌──────────────┐             ┌─────────────────────┐                 ┌──────────────────┐
 │ NLP Pipeline │             │  Forensic Pipeline  │                 │ Domain Heuristics│
 ├──────────────┤             ├─────────────────────┤                 ├──────────────────┤
 │ Subject+Body │             │ • HeaderForensics   │                 │ • DMARC + Spoof  │
 │ Tokenization │             │   (SPF, DKIM, DMARC)│                 │ • Exec + URL Risk│
 │ DistilRoBERTa│             │ • GeoIntelligence   │                 │ • Auth + BEC     │
 │  (5-class)   │             │   (IP Rep, WHOIS)   │                 │ • Keyword Scores │
 └──────┬───────┘             │ • Link & Attachment │                 └────────┬─────────┘
        │                     │ • FeatureExtractor  │                          │
        │                     │   (35-feature vector)                          │
        │                     │ • LightGBM Model    │                          │
        │                     └──────────┬──────────┘                          │
        ▼                                ▼                                     ▼
   P_nlp (5-dim)                   P_lgbm (5-dim)                        P_rule (5-dim)
        │                                │                                     │
        └────────────────────────────────┼─────────────────────────────────────┘
                                         ▼
                             15-Dimensional Meta-Vector
                                         │
                                         ▼
                      Stacking Ensemble (Calibrated LogReg)
                                         │
                                         ▼
                             Domain Override Evaluator
                                         │
                                         ▼
                        EnsemblePrediction (5-Class + Conf)
                                         │
                                         ▼
                       RiskScorer & Graph Attribution Engine
```

---

## 3. Existing ML Components Audit

### 3.1 `backend/ml/train_nlp.py`
- **Class**: `NLPTrainer`
- **Architecture**: `AutoModelForSequenceClassification.from_pretrained("distilroberta-base", num_labels=5)`
- **Dataset Handler**: Converts Pandas DataFrame (`text`, `label`) to Hugging Face `Dataset` with tokenization (`truncation=True`, `padding="max_length"`, `max_length=512`).
- **Optimization & Evaluation**: Hugging Face `Trainer` with `eval_strategy="epoch"`, `save_strategy="epoch"`, `EarlyStoppingCallback(patience=2)`, and macro F1 metric tracking.
- **Class Taxonomy**:
  ```python
  LABEL2ID = {"Legitimate": 0, "Suspicious": 1, "Phishing": 2, "BEC/Fraud": 3, "Impersonation": 4}
  ```
- **State**: **Complete and functional**. No structural changes required.

### 3.2 `backend/ml/train_tabular.py`
- **Class**: `TabularTrainer`
- **Architecture**: LightGBM `LGBMClassifier` (multiclass, `num_class=5`, `metric="multi_logloss"`) with scikit-learn `HistGradientBoostingClassifier` fallback.
- **Hyperparameter Optimization**: Optuna study optimizing `learning_rate`, `num_leaves`, `max_depth`, `n_estimators`, `subsample`, `colsample_bytree`, and `min_child_samples` for macro F1 on validation split.
- **Inputs**: 35-feature numerical matrix extracted via `FEATURE_COLUMNS`.
- **Feature Importance**: Native `feature_importances_` extraction and reporting.
- **State**: **Complete and functional**. Needs only calibration artifact integration.

### 3.3 `backend/ml/train_ensemble.py`
- **Class**: `EnsembleClassifier`
- **Architecture**: `CalibratedClassifierCV(estimator=LogisticRegression(...), cv=3)` fitted on a 15-dimensional concatenated probability vector (`[P_nlp (5), P_lgbm (5), P_rule (5)]`).
- **Domain Override Rules**: 4 expert rule conditions (DMARC fail + lookalike domain, Auth pass + high BEC score, Executable attachment + dangerous URL, Tor exit node + newly registered domain).
- **Inference Output**: `EnsemblePrediction` dataclass containing predicted label, calibrated confidence (0–100), per-class probability breakdown, individual model contributions, and contributing factors.
- **State**: **Complete and functional**. Current `__main__` entrypoint used toy perturbations; needs OOF prediction input pipeline.

### 3.4 `backend/ml/feature_engineering.py`
- **Classes**: `ForensicFeatureVector`, `FeatureExtractor`
- **Features Defined**: Exactly 35 forensic features categorized into 8 domains:
  1. *Authentication* (6): `spf_status_encoded`, `dkim_status_encoded`, `dmarc_status_encoded`, `auth_confidence_score`, `has_spf_record`, `has_dkim_signature`
  2. *Relay Path* (5): `relay_hop_count`, `max_hop_delay_seconds`, `has_time_travel`, `private_hop_ratio`, `suspicious_infrastructure_count`
  3. *Geo & Infrastructure* (5): `originating_ip_reputation`, `is_tor_exit_node`, `is_vpn`, `is_cloud_provider`, `geo_confidence_encoded`
  4. *Domain* (4): `domain_age_days`, `is_newly_registered`, `is_free_email_provider`, `sender_domain_has_mx`
  5. *Content* (6): `subject_length`, `body_length`, `url_count`, `attachment_count`, `has_html_body`, `text_entropy`
  6. *Links* (4): `max_url_risk_score`, `shortened_url_count`, `lookalike_domain_count`, `ip_as_hostname_count`
  7. *Attachments* (3): `has_executable_attachment`, `has_macro_attachment`, `max_attachment_risk_score`
  8. *Anomalies* (2): `anomaly_count`, `max_anomaly_severity_encoded`
- **State**: **Complete and functional**. Matches production data structures.

### 3.5 `backend/ml/data/prepare_datasets.py`
- **Class**: `DatasetPreparer`
- **Current Role**: Synthetic corpus generation (`BEC_TEMPLATES`, `PHISHING_TEMPLATES`, `IMPERSONATION_TEMPLATES`, `SUSPICIOUS_TEMPLATES`, `LEGITIMATE_TEMPLATES`) generating 500 toy samples with random 70/15/15 `train_test_split`.
- **State**: **Placeholder/Toy implementation**. Must be replaced/surrounded by the canonical pipeline.

---

## 4. Audit of Production Ingestion & Analysis Paths

| Component | File Path | Status | Reusability |
|---|---|---|---|
| RFC 822 Email Parser | `backend/app/core/ingestion/parser.py` | Complete | Direct reuse for parsing EML / RFC822 messages in corpus extraction |
| Unicode Normalizer | `backend/app/core/ingestion/preprocessor.py` | Complete | Direct reuse for NFKC, URL unquoting, and IDNA conversion |
| Evidence Hasher | `backend/app/core/ingestion/hasher.py` | Complete | Direct reuse for SHA256 message and attachment fingerprinting |
| Header Forensics | `backend/app/core/analysis/header_forensics.py` | Complete | Direct reuse for SPF/DKIM/DMARC and relay hop reconstruction |
| Geo Intelligence | `backend/app/core/analysis/geo_intel.py` | Complete | Direct reuse for IP reputation and domain metadata |
| Link Analyzer | `backend/app/core/analysis/link_analyzer.py` | Complete | Direct reuse for IOC URL risk scoring |
| Attachment Analyzer | `backend/app/core/analysis/attachment_analyzer.py` | Complete | Direct reuse for executable/macro detection |
| NLP Classifier | `backend/app/core/analysis/nlp_classifier.py` | Complete | Direct production inference entrypoint combining rules, transformer, and ensemble |
| Composite Risk Scorer | `backend/app/core/correlation/risk_scorer.py` | Complete | Production multi-factor risk scoring engine |
| Pipeline Orchestrator | `backend/app/core/pipeline.py` | Complete | Production `asyncio.gather` parallel execution pipeline |

---

## 5. Detailed Gap Analysis Against `implementation.md`

### Section A: What is ALREADY Implemented

1. **Target 5-Class Taxonomy**: Uniform label-to-ID mapping across all files:
   `{0: Legitimate, 1: Suspicious, 2: Phishing, 3: BEC/Fraud, 4: Impersonation}`.
2. **Model Training Code**:
   - DistilRoBERTa sequence classification trainer with HuggingFace Trainer API (`ml/train_nlp.py`).
   - LightGBM / HistGradientBoosting tabular classifier with Optuna hyperparameter optimization (`ml/train_tabular.py`).
   - Calibrated stacking ensemble meta-classifier combining 15-dimensional probability features + domain override rules (`ml/train_ensemble.py`).
3. **35 Forensic Feature Definitions**: Implemented in `ml/feature_engineering.py` (`FEATURE_COLUMNS`) and aligned with production analysis outputs.
4. **Production Inference Engine**: Multi-tiered classification with fallback from Transformer/Ensemble to heuristic rules (`nlp_classifier.py`).
5. **No Hardcoded 100% Confidences**: Production pipelines and report generators already guard against synthetic 100% confidence on clean emails (verified in `test_confidence_pipeline.py`).

---

### Section B: What is PARTIALLY Implemented

1. **Dataset Ingestion (`ml/data/prepare_datasets.py`)**:
   - *Implemented*: Functions to extract tabular features from dictionary records and split into train/val/test.
   - *Missing*: Handling real external datasets, deduplication, provenance tracking, group-aware partitioning, and schema compliance.
2. **Tabular Probability Calibration**:
   - *Implemented*: Ensemble classifier uses `CalibratedClassifierCV`.
   - *Missing*: Standalone Platt/sigmoid calibration fitting on held-out validation data for the base LightGBM model.
3. **Ensemble Probability Inputs**:
   - *Implemented*: `construct_meta_features` handles 15-dim concatenation.
   - *Missing*: Out-of-Fold (OOF) cross-validation pipeline to generate realistic uncorrupted base probabilities for meta-classifier training.
4. **Configuration System**:
   - *Implemented*: Basic environment settings in `backend/app/config.py`.
   - *Missing*: Declarative YAML configs (`datasets.yaml`, `labels.yaml`, `split.yaml`, `suspicious_filter.yaml`, `training.yaml`).

---

### Section C: What is MISSING

| Item | `implementation.md` Ref | Description |
|---|---|---|
| **1. Declarative YAML Configs** | §6 | `datasets.yaml`, `labels.yaml`, `split.yaml`, `suspicious_filter.yaml`, `training.yaml` |
| **2. Acquisition Scripts & Manifests** | §7, §45 | Automated fetchers, archive hash verifiers, commit SHA pinners, and `download_manifest.json` |
| **3. Dataset-Specific Parsers** | §8, §9 | Parsers for Maildir (Enron), RFC822/EML (TREC07, CEAS08, phishing_pot, EPVME), Mbox (Nazario, SpamAssassin), and CSV (CLAIR, BEC-2, zefang-liu, IWSPA-AP) |
| **4. Canonical Email Schema** | §8 | Standard JSONL/Parquet schema with provenance, synthetic flags, license status, and hashes |
| **5. Global Deduplication Engine** | §10, §11 | Exact SHA256 deduplication + 5-gram MinHash near-duplicate clustering across all source corpora |
| **6. Suspicious-Class Semantic Filter** | §15, §51 | Multi-factor candidate scoring on spam pool (TREC07, CEAS08, SpamAssassin), commercial spam exclusions, and review queue export (`review_queue.csv`) |
| **7. BEC & Impersonation Augmentation Controls** | §16, §17 | Subtype tagging (`419_advance_fee` vs `synthetic_bec`), synthetic tagging, and EPVME header recombination tracking |
| **8. Group-Aware & Temporal Splitter** | §18, §19 | `StratifiedGroupKFold` using `leakage_group_id` (duplicate cluster, domain, provenance), temporal holdouts, and 100% real test set purity |
| **9. Split Validation & Leakage Auditor** | §19, §40 | Automated assertions ensuring zero cross-split overlap (`leakage_audit.json`) |
| **10. Batch Forensic Replay & Lookup Cache** | §22, §24 | Replaying corpus through production analysis with cached DNS/WHOIS/Geo lookups (`lookup_cache/`) and rate limiting |
| **11. Historical Reliability Tagging** | §21, §23 | Tagging Category B features with `historical_reliability` flags to prevent historical time-travel bias |
| **12. NLP Formatter & Truncation Tracker** | §25, §27 | Standard `[SUBJECT]\n<subject>\n\n[BODY]\n<body>` formatting with `body_truncated` tracking |
| **13. 5-Fold Grouped OOF Generator** | §34, §55 | Generating out-of-fold predictions (`oof_predictions.parquet`) for clean ensemble training |
| **14. Reporting & Verification Tooling** | §41, §43, §46 | Generating `dataset_quality_report.md`, `duplicate_report.csv`, `feature_coverage.csv`, `model_metrics.json`, `training_run.json` |

---

### Section D: Reusable Components (Do NOT Duplicate)

The following existing components must be directly imported and reused:
1. `backend/ml/train_nlp.py` (`NLPTrainer`): Reused as the core NLP training engine.
2. `backend/ml/train_tabular.py` (`TabularTrainer`): Reused as the core LightGBM training and Optuna optimization engine.
3. `backend/ml/train_ensemble.py` (`EnsembleClassifier`, `OVERRIDE_RULES`): Reused as the stacking ensemble engine.
4. `backend/ml/feature_engineering.py` (`FeatureExtractor`, `ForensicFeatureVector`, `FEATURE_COLUMNS`): Reused as the single source of truth for the 35 tabular features.
5. `backend/app/core/ingestion/parser.py` (`EmailParser`): Reused for RFC822 parsing.
6. `backend/app/core/ingestion/preprocessor.py` (`EmailPreprocessor`): Reused for text and URL normalization.
7. `backend/app/core/ingestion/hasher.py` (`EvidenceHasher`): Reused for payload hashing.
8. `backend/app/core/analysis/header_forensics.py` (`HeaderForensics`): Reused for header authentication.
9. `backend/app/core/analysis/geo_intel.py` (`GeoIntelligence`): Reused for IP/domain lookups.
10. `backend/app/core/analysis/link_analyzer.py` (`LinkAnalyzer`) & `attachment_analyzer.py` (`AttachmentAnalyzer`): Reused for link/attachment risk.

---

### Section E: Compatibility Risks (Training vs Production Inference)

| Risk Area | Training Pipeline | Production Inference | Severity | Mitigation |
|---|---|---|---|---|
| **NLP Text Framing** | `prepare_datasets.py` used `f"{subject}\n\n{body}"` | `nlp_classifier.py` uses `f"{subject} [SEP] {body_text}"` | High | Standardize both training and production inference on `[SUBJECT]\n{subject}\n\n[BODY]\n{body}` per `implementation.md` §25. |
| **Feature Missingness & Encodings** | LightGBM handles NaN natively, but `FeatureExtractor` maps missing to specific defaults (e.g. SPF=3, DKIM=2, domain_age=-1) | Production `pipeline.py` provides defaults (`_get_default_header`, etc.) | Medium | Create `feature_manifest.json` to lock feature definitions and default values across both environments. |
| **Probability Scale & Calibration** | Tabular and NLP models output raw softmax probabilities in `[0.0, 1.0]` | `risk_scorer.py` and `nlp_classifier.py` handle both `0–1.0` and `0–100` scales | Medium | Explicitly document and enforce `0.0–1.0` for all internal model math and `0–100` for user-facing outputs. |
| **Feature Column Ordering** | `FEATURE_COLUMNS` list in `feature_engineering.py` dictates array order | Tabular model expects exact column order matching training | High | Lock `feature_names.json` during training and validate at model load time. |

---

### Section F: Data Leakage, Label Leakage & Contamination Analysis

```
                              POTENTIAL LEAKAGE VECTORS & SAFEGUARDS

 ┌───────────────────────────┐         ┌───────────────────────────────┐
 │   Cross-Corpus Overlap    │ ──────> │ Global SHA256 & MinHash Dedup │
 │ (Nazario, IWSPA-AP, EPVME)│         │ (Before Train/Test Splitting) │
 └───────────────────────────┘         └───────────────────────────────┘

 ┌───────────────────────────┐         ┌───────────────────────────────┐
 │  Spam-to-Threat Labeling  │ ──────> │ Semantic Suspicious Filter    │
 │ (TREC07, CEAS08, SpamAss.)│         │ (Exclude Commercial Ads)      │
 └───────────────────────────┘         └───────────────────────────────┘

 ┌───────────────────────────┐         ┌───────────────────────────────┐
 │  Synthetic BEC / Attacks  │ ──────> │ Strict Provenance Flags       │
 │   (BEC-2, EPVME Injected) │         │ (Exclude from Final Test Set) │
 └───────────────────────────┘         └───────────────────────────────┘

 ┌───────────────────────────┐         ┌───────────────────────────────┐
 │  Historical Feature Shift │ ──────> │ Reliability Indicators        │
 │ (Current DNS on 2007 mail)│         │ (Ablation on Category-B Feats)│
 └───────────────────────────┘         └───────────────────────────────┘

 ┌───────────────────────────┐         ┌───────────────────────────────┐
 │   In-Sample Meta-Model    │ ──────> │ 5-Fold Grouped Out-of-Fold    │
 │    (Optimistic Stacking)  │         │ (OOF Cross-Validation Only)   │
 └───────────────────────────┘         └───────────────────────────────┘
```

1. **Cross-Corpus Data Leakage**:
   - *Risk*: Nazario phishing messages appear inside IWSPA-AP and EPVME. CLAIR has multiple mirrors. Enron has duplicate threads. A random split would place identical emails in both train and test.
   - *Control*: Execute global exact SHA256 deduplication and 5-gram MinHash near-duplicate clustering *prior* to splitting. Use `leakage_group_id` for GroupKFold.
2. **Label Leakage (Spam != Suspicious)**:
   - *Risk*: Mapping raw spam directly to Suspicious or Phishing pollutes threat classes with commercial newsletters and coupon offers.
   - *Control*: Candidate pool filtering using semantic urgency, credential-harvesting signals, and URL risk, with explicit human review queue.
3. **Synthetic Test Pollution**:
   - *Risk*: BEC-2 is LLM-generated; EPVME uses synthetic header injections. Testing on synthetic data creates artificial benchmark inflation.
   - *Control*: Enforce `is_synthetic == false` on all final evaluation test sets where real samples exist.
4. **Historical Feature Leakage (Time-Travel)**:
   - *Risk*: Performing live DNS/WHOIS lookups today for historical emails (Enron 2001, TREC 2007) yields non-existent domains or modern IP reputations that did not exist at message transmission.
   - *Control*: Tag all Category B features with `historical_reliability` flags and perform ablation experiments (Category A only vs Category A+B).
5. **In-Sample Stacking Leakage**:
   - *Risk*: Training the ensemble meta-classifier on base model predictions fitted on the same training set produces severe over-optimism.
   - *Control*: Implement 5-fold grouped cross-validation to generate true Out-of-Fold (`oof_predictions.parquet`) probabilities.
6. **Metadata Leakage in NLP**:
   - *Risk*: Including source dataset names, file paths, or synthetic tags in the NLP text allows the transformer to learn dataset shortcuts.
   - *Control*: NLP text input must contain exclusively `[SUBJECT]\n<subject>\n\n[BODY]\n<body>` with all metadata stripped.

---

## 6. Critical Bugs, Blockers & Incompatibilities Identified

1. **`prepare_datasets.py` is Synthetic-Only**:
   - The current dataset preparer generates only toy template data (500 rows) and performs random `train_test_split`. It cannot ingest real corpora or prevent cross-dataset leakage.
2. **Lack of OOF Pipeline in `train_ensemble.py`**:
   - The standalone execution script in `train_ensemble.py` generates synthetic random noise on top of training probabilities (`nlp_probs = tab_probs * 0.9 + noise`) rather than reading true out-of-fold predictions.
3. **NLP Text Representation Inconsistency**:
   - Production inference uses `[SEP]` delimiter while training used `\n\n`. Both must be aligned with the specification `[SUBJECT]\n...\n\n[BODY]\n...`.
4. **Historical Lookup Missingness in Feature Extraction**:
   - In `feature_engineering.py`, missing DNS/WHOIS/IP values must not default to values that mimic legitimate infrastructure (e.g. `domain_age_days = -1` vs default `0`).

---

## 7. Recommended Implementation Order

The implementation must proceed in modular, sequential phases with verification gates:

```
Phase 1: Configuration & Canonical Schemas
  ├── ml/config/ (datasets.yaml, labels.yaml, split.yaml, training.yaml)
  └── ml/src/schemas/ (canonical email schema, manifest definitions)
         │
Phase 2: Acquisition & Parsers
  ├── ml/src/acquisition/ (downloaders, hash verifiers, inventory manifests)
  └── ml/src/parsers/ (Maildir, RFC822/EML, Mbox, CSV format adapters)
         │
Phase 3: Deduplication & Provenance Engine
  ├── ml/src/dedup/ (exact SHA256, 5-gram MinHash clustering)
  └── ml/src/provenance/ (provenance graph, cross-corpus tracking)
         │
Phase 4: Semantic Labeling & Suspicious Filter
  ├── ml/src/labeling/ (direct mappings, BEC/Impersonation subtyping)
  └── ml/src/suspicious_filter/ (scoring, commercial spam rejection, review tooling)
         │
Phase 5: Leakage-Safe Splitting & Auditing
  ├── ml/src/splitting/ (StratifiedGroupKFold, temporal split, real-only test set)
  └── ml/src/audit/ (leakage_audit.py -> leakage_audit.json)
         │
Phase 6: Forensic Feature Batch Replay
  ├── ml/src/forensic/ (replay CLI using production FeatureExtractor)
  └── ml/src/cache/ (external lookup caching for DNS/WHOIS/Geo)
         │
Phase 7: Base Model Training & Calibration
  ├── NLP fine-tuning via existing ml/train_nlp.py
  └── LightGBM training & Platt calibration via existing ml/train_tabular.py
         │
Phase 8: 5-Fold Grouped OOF & Ensemble Stacking
  ├── ml/src/ensemble/oof.py (5-fold out-of-fold probability generator)
  └── Ensemble training via existing ml/train_ensemble.py
         │
Phase 9: Evaluation Reports & Production Integration
  └── ml/reports/ (dataset_quality_report, model_metrics, training_run)
```

---

## 8. Explicit List of Files That Should NOT Be Modified Unless Strictly Necessary

The following files represent verified, stable core components:
1. `backend/ml/train_nlp.py` — Existing DistilRoBERTa training architecture.
2. `backend/ml/train_tabular.py` — Existing LightGBM + Optuna hyperparameter tuning engine.
3. `backend/ml/train_ensemble.py` — Existing Stacking Ensemble + Override Rules classifier.
4. `backend/ml/feature_engineering.py` — Existing 35-feature extraction logic and schema.
5. `backend/app/core/ingestion/parser.py` — Production email parser.
6. `backend/app/core/ingestion/preprocessor.py` — Production preprocessor.
7. `backend/app/core/ingestion/hasher.py` — Production evidence hasher.
8. `backend/app/core/analysis/header_forensics.py` — Production header analysis engine.
9. `backend/app/core/analysis/geo_intel.py` — Production geo-intelligence engine.
10. `backend/app/core/analysis/link_analyzer.py` — Production link analysis engine.
11. `backend/app/core/analysis/attachment_analyzer.py` — Production attachment analysis engine.
12. `backend/app/core/correlation/risk_scorer.py` — Production composite risk scoring engine.
13. `backend/app/core/correlation/graph_engine.py` — Production attribution graph engine.
14. `backend/app/core/pipeline.py` — Production async analysis pipeline.

---

## 9. Summary for Phase Execution

### 1. What is Already Complete
- Three-tier ML architecture (DistilRoBERTa NLP + LightGBM Tabular + Stacking Logistic Regression Ensemble).
- 35 forensic feature definitions and extraction logic.
- Production parsing, header forensics, geo-intelligence, link analysis, attachment inspection, and composite risk scoring.
- Consistent 5-class target taxonomy (`0: Legitimate, 1: Suspicious, 2: Phishing, 3: BEC/Fraud, 4: Impersonation`).

### 2. What Must Be Implemented Next (Milestone 1 & 2)
- **Configuration & Schemas**: Declarative YAML files defining datasets, label mappings, and training parameters.
- **Acquisition & Parsers**: Download verification scripts and format adapters for Maildir, RFC 822, Mbox, and tabular datasets.
- **Deduplication & Provenance**: Global exact hashing, MinHash near-duplicate clustering, and cross-corpus provenance tracking.
- **Suspicious-Class Filter**: Threat-scoring filter to extract true suspicious candidates from spam pools while excluding bulk marketing.
- **Group-Aware Splitting**: Single canonical split assignment using `StratifiedGroupKFold` on duplicate/domain clusters with 100% real test purity.
- **Batch Forensic Replay & Lookup Cache**: Replay system using the production `FeatureExtractor` with external lookup caching.
- **Out-of-Fold Pipeline**: 5-fold cross-validation runner to generate clean base probabilities for the ensemble meta-classifier.

### 3. Exact Files to be Created/Modified in the Next Phase
**New Files to Create under `backend/ml/` (and mirrored at `ml/`)**:
- `ml/config/datasets.yaml`
- `ml/config/labels.yaml`
- `ml/config/split.yaml`
- `ml/config/suspicious_filter.yaml`
- `ml/config/training.yaml`
- `ml/src/acquisition/download_datasets.py`
- `ml/src/parsers/base_parser.py`
- `ml/src/parsers/maildir_parser.py`
- `ml/src/parsers/rfc822_parser.py`
- `ml/src/parsers/mbox_parser.py`
- `ml/src/parsers/csv_parser.py`
- `ml/src/dedup/deduplicator.py`
- `ml/src/dedup/minhash_cluster.py`
- `ml/src/labeling/suspicious_filter.py`
- `ml/src/splitting/split_generator.py`
- `ml/src/forensic/batch_extractor.py`
- `ml/src/forensic/lookup_cache.py`
- `ml/src/ensemble/oof_generator.py`
- `ml/src/audit/leakage_audit.py`

**Files to Modify Only for Alignment**:
- `backend/app/core/analysis/nlp_classifier.py` (ensure exact `[SUBJECT]\n...\n\n[BODY]\n...` formatting matching training).
