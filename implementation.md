# MailForensix — ML Dataset Acquisition, Construction & Training Implementation Plan

**Version:** 1.0  
**Date:** 2026-08-31  
**Status:** Implementation specification  
**Scope:** Dataset acquisition → normalization → labeling → deduplication → Suspicious filtering → train/validation/test construction → LightGBM 35-feature corpus → DistilRoBERTa 5-class corpus → ensemble-ready probability artifacts.

---

# 1. Purpose

This document converts the verified `ML_DATASET_VERIFICATION_REPORT` into an implementation specification that another coding agent can execute without having to repeat the dataset-research phase.

The objective is to produce a **single canonical, provenance-aware, leakage-safe five-class email corpus** and then derive:

1. an NLP dataset for the DistilRoBERTa classifier,
2. a forensic/tabular dataset for the 35-feature LightGBM classifier,
3. paired out-of-fold/base-model probability outputs for the ensemble.

The five target classes are:

```text
0 = Legitimate
1 = Suspicious
2 = Phishing
3 = BEC/Fraud
4 = Impersonation
```

Do not change the existing ML architecture merely because some classes have weaker public data. The verified research identifies the main problem as **corpus construction**, not model architecture.

---

# 2. Non-Negotiable Constraints

These rules are implementation invariants.

## 2.1 Never map raw spam directly to Suspicious

TREC 2007, CEAS 2008, and SpamAssassin provide `ham/spam`, not MailForensix's five-class semantic labels.

Therefore:

```text
spam != automatically Suspicious
spam != automatically Phishing
```

Spam becomes a **candidate pool** only. A filtering/scoring process must identify messages whose semantics and threat signals fit the Suspicious definition.

The research report explicitly identifies this as the largest unaddressed labeling gap. The implementation must not bypass it. 

## 2.2 Never treat BEC-2 as real incident data

BEC-2 contains 279 LLM-generated emails. It is useful synthetic BEC-style training material, but must retain:

```text
is_synthetic = true
synthetic_source = "BEC-2"
```

It must never be described as a real-world incident corpus.

## 2.3 Never use PhishTank as email training data

PhishTank is a URL reputation source, not an email-content corpus.

Use it only in the existing/runtime URL-reputation enrichment path if the application already supports it.

## 2.4 Do not use EPVME as the main NLP corpus

EPVME's own documentation says its malicious emails use randomly selected existing From/To/Subject/body material while inserting attack payloads into selected fields. That makes it highly useful for forensic/header feature training but unsuitable as a primary source of coherent attack narratives. citeturn708804search6

## 2.5 The split happens before model-specific processing

Create exactly one canonical split assignment:

```text
email_id -> train / validation / test
```

Both DistilRoBERTa and LightGBM must consume the same membership.

Do not independently split the NLP and tabular datasets.

## 2.6 Deduplicate before splitting

Cross-corpus overlap has been identified, particularly:

```text
Nazario <-> IWSPA-AP
Nazario <-> EPVME
CLAIR <-> Kaggle fraud mirror
Enron derived/thread folders <-> original maildirs
```

A random split before deduplication can leak near-duplicates across train/test.

## 2.7 Synthetic data is training-only

Synthetic records may enter training and, where explicitly justified, validation.

They must not enter the **real-world evaluation test set**.

At minimum:

```text
test.is_synthetic == false
```

for classes where a real test subset exists.

## 2.8 Historical runtime enrichment is not historical truth

Many of the 35 forensic features depend on current DNS, WHOIS, IP reputation, geo-IP, SPF, DKIM, or DMARC observations.

For a historical email, today's value may not represent the state when the email was sent.

Every forensic record must therefore carry:

```text
feature_observation_timestamp
historical_reliability
```

and the training pipeline must be able to exclude or down-weight historically unreliable Category-B features.

---

# 3. Research Findings That Drive the Implementation

The verified report establishes the following operational dataset roles.

| Dataset | Primary role | Target class/usage | Header availability | Synthetic? |
|---|---|---|---|---|
| Enron | Legitimate baseline | Legitimate | Partial / dataset-specific limitations must be measured | No |
| TREC07 | Ham baseline + spam candidate pool | Legitimate + Suspicious candidate pool | Yes | No |
| Nazario | Historical phishing | Phishing | Yes | No |
| phishing_pot | Modern phishing | Phishing | Yes | No |
| EPVME | Header/auth attack source | Phishing + Impersonation forensic signals | Yes | Semi-synthetic/recombined |
| CEAS08 | Ham + spam supplement | Legitimate + Suspicious candidate pool | Yes | No |
| IWSPA-AP | Header/no-header phishing | Legitimate + Phishing | Both tracks | No |
| zefang-liu | Text-only volume | Legitimate + Phishing | No | No |
| CLAIR | Fraud narrative | BEC/Fraud sub-flavor | Limited | No |
| BEC-2 | BEC language seed | BEC/Fraud | No | Yes |
| SpamAssassin | Small supplement | Legitimate + Suspicious candidate pool | Yes | No |
| Cambridge Cybercrime Centre | Optional future source | Spam/phishing | Access-controlled | No |
| PhishTank | Runtime enrichment only | None for email training | N/A | No |

The research report identifies `phishing_pot` as an especially important addition because it provides modern, real, header-containing phishing email material. 

---

# 4. Target MVP Dataset

Do not attempt to process hundreds of thousands of messages through expensive external lookups just because they are available.

The implementation should first produce a **high-quality MVP corpus**.

Recommended targets:

| Class | MVP target | Preferred source strategy |
|---|---:|---|
| Legitimate | 3,000–5,000 | Enron + TREC07 ham + CEAS08 ham |
| Suspicious | 500–1,000 | TREC07/CEAS08/SpamAssassin candidate pool + validated filter |
| Phishing | 2,000–4,000 | Nazario + phishing_pot + IWSPA-AP + zefang-liu |
| BEC/Fraud | 300–600 | Carefully filtered CLAIR + BEC-2 + validated augmentation if needed |
| Impersonation | 200–500 | Real/suitable source fragments + EPVME header attack construction |

These are planning targets, not claims about the final number of usable records. The final count is determined only after parsing, deduplication, quality filtering, and provenance checks.

---

# 5. Repository Layout

Add a dedicated ML data/training area without disturbing existing production ingestion code.

Recommended:

```text
ml/
├── README.md
├── config/
│   ├── datasets.yaml
│   ├── labels.yaml
│   ├── split.yaml
│   ├── suspicious_filter.yaml
│   └── training.yaml
│
├── data/
│   ├── raw/
│   │   ├── enron/
│   │   ├── trec07/
│   │   ├── nazario/
│   │   ├── phishing_pot/
│   │   ├── epvme/
│   │   ├── ceas08/
│   │   ├── iwspa_ap/
│   │   ├── zefang_liu/
│   │   ├── clair/
│   │   ├── bec2/
│   │   └── spamassassin/
│   │
│   ├── normalized/
│   ├── deduplicated/
│   ├── manifests/
│   ├── splits/
│   ├── features/
│   ├── tokenizer_cache/
│   └── artifacts/
│
├── src/
│   ├── acquisition/
│   ├── parsers/
│   ├── normalization/
│   ├── labeling/
│   ├── dedup/
│   ├── suspicious_filter/
│   ├── splitting/
│   ├── forensic/
│   ├── nlp/
│   ├── ensemble/
│   └── evaluation/
│
├── models/
│   ├── lightgbm/
│   ├── distilroberta/
│   └── ensemble/
│
└── reports/
    ├── dataset_inventory.json
    ├── label_distribution.csv
    ├── duplicate_report.csv
    ├── split_report.csv
    ├── feature_coverage.csv
    ├── model_metrics.json
    └── training_run.json
```

Do not put downloaded raw datasets into the Git repository.

---

# 6. Configuration-First Design

Do not hard-code dataset URLs, labels, or counts into Python files.

Create `datasets.yaml`:

```yaml
datasets:

  enron:
    source: "https://www.cs.cmu.edu/~enron/"
    parser: "maildir"
    synthetic: false
    default_label: "legitimate"
    capability: ["nlp", "tabular"]

  trec07:
    source: "https://plg.uwaterloo.ca/~gvcormac/treccorpus07/"
    parser: "rfc822"
    synthetic: false
    source_labels:
      ham: "legitimate"
      spam: "candidate_suspicious"
    capability: ["nlp", "tabular"]

  nazario:
    source: "https://monkey.org/~jose/phishing/"
    parser: "mbox"
    synthetic: false
    default_label: "phishing"
    capability: ["nlp", "tabular"]

  phishing_pot:
    source: "https://github.com/rf-peixoto/phishing_pot"
    parser: "email_files"
    synthetic: false
    default_label: "phishing"
    capability: ["nlp", "tabular"]

  epvme:
    source: "https://github.com/sunknighteric/EPVME-Dataset/"
    parser: "eml"
    synthetic: true
    default_label: null
    capability: ["tabular"]

  clair:
    source: "https://aclweb.org/aclwiki/CLAIR_collection_of_fraud_email_(Repository)"
    parser: "dataset_specific"
    synthetic: false
    default_label: "bec_fraud_candidate"
    capability: ["nlp"]

  bec2:
    source: "https://github.com/r-dube/bec"
    parser: "dataset_specific"
    synthetic: true
    default_label: "bec_fraud"
    capability: ["nlp"]
```

Important:

The configuration should record the **actual download commit/hash/version** after acquisition.

---

# 7. Acquisition Phase

## 7.1 Download only from approved sources

Primary sources:

```text
Enron:
https://www.cs.cmu.edu/~enron/

TREC 2007:
https://plg.uwaterloo.ca/~gvcormac/treccorpus07/

CEAS 2008:
https://plg.uwaterloo.ca/~gvcormac/ceascorpus/

Nazario:
https://monkey.org/~jose/phishing/

CLAIR:
https://aclweb.org/aclwiki/CLAIR_collection_of_fraud_email_(Repository)

BEC-2:
https://github.com/r-dube/bec

EPVME:
https://github.com/sunknighteric/EPVME-Dataset/

IWSPA-AP:
https://github.com/dasavisha/IWSPA-sharedtask

phishing_pot:
https://github.com/rf-peixoto/phishing_pot

zefang-liu:
https://huggingface.co/datasets/zefang-liu/phishing-email-dataset

SpamAssassin:
https://spamassassin.apache.org/old/publiccorpus/
```

The previous mistaken instruction to use `github.com/r-dube/bec` for Nazario must be permanently removed.

That URL is BEC-2.

## 7.2 Never trust a cited sample count

After download, compute:

```text
actual_file_count
actual_message_count
actual_valid_email_count
actual_empty_message_count
actual_parse_error_count
actual_duplicate_count
```

Store these in:

```text
ml/data/manifests/raw_inventory.json
```

## 7.3 Pin repository datasets

For GitHub sources:

```bash
git clone <repo>
cd <repo>
git rev-parse HEAD
```

Record:

```text
repository_url
commit_sha
download_timestamp_utc
```

EPVME has no GitHub Releases, so the exact repository commit is particularly important. citeturn708804search0

---

# 8. Canonical Email Schema

Every message must be converted to one schema before labeling.

Use a JSONL/Parquet representation conceptually equivalent to:

```json
{
  "email_id": "sha256:...",
  "source_dataset": "trec07",
  "source_record_id": "...",
  "source_path": "...",

  "raw_message_sha256": "...",
  "normalized_body_sha256": "...",
  "normalized_full_sha256": "...",

  "headers": {},
  "subject": "...",
  "body_plain": "...",
  "body_html": "...",

  "sender": "...",
  "sender_domain": "...",
  "reply_to": "...",
  "mail_from": "...",
  "to": [],
  "cc": [],
  "date": null,
  "message_id": null,

  "urls": [],
  "attachments": [],

  "source_label": "...",
  "canonical_label": null,
  "label_confidence": null,

  "is_synthetic": false,
  "synthetic_source": null,

  "collection_timestamp": null,
  "email_timestamp": null,

  "historical_reliability": "unknown",

  "license": "...",
  "license_verified": false
}
```

Do not throw away the raw headers.

If a field is unavailable, use:

```text
null
```

not an invented value.

---

# 9. Email Normalization

The normalizer must:

1. parse RFC 822/MIME correctly,
2. decode transfer encodings,
3. decode common character sets,
4. extract plain text and HTML separately,
5. identify attachments,
6. extract URLs,
7. preserve the original raw message hash,
8. preserve original header values,
9. normalize whitespace only in derived fields,
10. never rewrite the original evidence.

Create:

```text
raw_message
normalized_message
```

as conceptually separate layers.

The original message should remain immutable.

---

# 10. Email Identity and Hashing

Create deterministic IDs.

Recommended:

```python
email_id = sha256(
    canonicalized_message_identity
)
```

Do not use only the filename.

For exact duplicate detection:

```text
full_hash = SHA256(normalized full RFC822 message)
```

For body duplication:

```text
body_hash = SHA256(normalized subject + "\n" + normalized body)
```

For near-duplicates:

```text
SimHash / MinHash
```

Use multiple hashes because each catches a different class of duplication.

---

# 11. Global Deduplication

Run deduplication after normalization but **before splitting**.

## 11.1 Exact duplicates

Remove exact duplicates globally.

When two datasets contain identical records, retain one canonical record and keep all provenance references:

```json
{
  "canonical_email_id": "...",
  "sources": ["nazario", "iwspa_ap"]
}
```

## 11.2 Near-duplicate detection

Run body-level similarity.

Recommended process:

```text
normalize
    ↓
tokenize
    ↓
5-gram shingles
    ↓
MinHash
    ↓
candidate buckets
    ↓
exact/near similarity
    ↓
duplicate cluster
```

Do not compare every message pair directly if the corpus becomes large.

## 11.3 EPVME special handling

EPVME intentionally reuses content from Nazario, SpamAssassin, and TREC07.

Therefore ordinary message hashing is insufficient.

Create a second provenance relation:

```text
derived_from_dataset
derived_from_email_id (when recoverable)
```

At minimum, compare normalized body/subject text against source corpora.

A test sample from Nazario cannot be allowed to have its underlying text represented inside an EPVME training sample merely because the top-level EML files have different hashes.

---

# 12. Provenance Graph

Create a lightweight provenance graph/table:

```text
email_id
source_dataset
source_record_id
derived_from_email_id
derived_from_dataset
is_synthetic
synthetic_method
```

This is required for:

- leakage analysis,
- reproducibility,
- synthetic-data exclusion,
- model cards,
- future dataset updates.

---

# 13. Label Taxonomy

Use a strict canonical label dictionary.

```yaml
labels:
  0: legitimate
  1: suspicious
  2: phishing
  3: bec_fraud
  4: impersonation
```

Add a separate **quality/provenance label**, not a sixth ML class:

```text
real
synthetic
semi_synthetic
derived
uncertain
```

Do not use this provenance field as the classifier target.

---

# 14. Direct Label Mapping

The initial label policy is:

## Legitimate

Allowed:

```text
Enron
TREC07 ham
CEAS08 ham
SpamAssassin ham
legitimate IWSPA-AP subset
legitimate zefang-liu rows
```

## Phishing

Allowed:

```text
Nazario
phishing_pot
IWSPA-AP phishing subset
zefang-liu phishing rows
appropriate EPVME attack rows for forensic/tabular training
```

## BEC/Fraud

Allowed:

```text
BEC-2
selected CLAIR fraud messages
validated additional BEC material
```

But CLAIR must retain a sublabel:

```text
fraud_subtype = "419_advance_fee"
```

and BEC-2:

```text
fraud_subtype = "synthetic_bec"
```

Do not claim that all CLAIR records are internal BEC.

## Impersonation

Use only records with a defensible impersonation mechanism.

Examples:

```text
executive-name spoofing
trusted-contact impersonation
From/MailFrom inconsistency
header-level impersonation attacks
```

Do not bulk-relabel entire datasets as Impersonation.

---

# 15. Suspicious-Class Construction

This is the most important new component.

## 15.1 Definition

The class should represent emails that are more concerning than ordinary bulk spam but do not meet the evidence threshold for clear Phishing, BEC/Fraud, or Impersonation.

Operationally:

```text
Suspicious =
    threat-relevant or anomalous
    AND not confidently assignable to another malicious class
```

## 15.2 Candidate pool

Start from:

```text
TREC07 spam
CEAS08 spam
SpamAssassin spam
```

Do not label them directly.

## 15.3 First-stage exclusion rules

Exclude obvious:

```text
bulk commercial newsletters
advertising
ordinary coupon/promotional mail
mass marketing
benign opt-in announcements
```

Keep candidates showing signals such as:

```text
credential-related language
account urgency
security-warning language
payment/account anomalies
unusual call-to-action
login/update/verify requests
suspicious URL structures
identity anomalies
unexpected attachments
social-engineering language
```

The filter must not rely on only keyword matching.

## 15.4 Candidate scoring

Build an interpretable score:

```text
suspicious_score =
    semantic_risk
  + url_risk
  + sender_anomaly
  + urgency
  + credential_request
  + financial_request
  - commercial_bulk_score
  - clearly_benign_score
```

Normalize to:

```text
0.0 - 1.0
```

## 15.5 Three-way review

Do not automatically accept all high-scoring candidates.

Partition:

```text
score < low_threshold:
    reject / ordinary spam

low_threshold <= score < high_threshold:
    manual-review pool

score >= high_threshold:
    high-priority manual-review pool
```

Human review labels each reviewed candidate:

```text
ordinary_spam
suspicious
phishing
bec_fraud
impersonation
uncertain
```

Only confidently reviewed records enter the supervised five-class dataset.

## 15.6 Reviewer requirement

The first Suspicious dataset should have human-reviewed examples.

Do not bootstrap the classifier from its own predictions and then call those labels ground truth.

---

# 16. BEC/Fraud Construction

## 16.1 Real floor

Start with the highest-quality real material available:

```text
CLAIR
selected real fraud material from other approved sources
```

Keep:

```text
fraud_subtype
```

so that downstream analysis can distinguish:

```text
419 / advance fee
BEC
other financial social engineering
```

## 16.2 Synthetic floor

Use BEC-2 as a seed dataset.

It must retain:

```text
is_synthetic = true
```

and must be included primarily in training.

## 16.3 Additional augmentation

Only generate more BEC examples after proving that the real/synthetic seed is insufficient.

Recommended diversity:

```text
CEO fraud
invoice fraud
vendor impersonation
payment redirection
account-change request
urgent wire-transfer request
executive travel scenario
payroll/account-change scenario
```

Do not generate only one prompt template.

Use multiple independent scenario families.

## 16.4 Validation

Every generated message must be evaluated before entry.

Required checks:

```text
correct class semantics
realistic business context
no accidental contradictory cues
no obvious LLM boilerplate
no duplicate scenario skeleton
no leakage of generation prompt
```

Synthetic messages failing review are discarded.

---

# 17. Impersonation Construction

This class should be treated as a **compound signal**:

```text
trusted-contact-like language
+
sender/header inconsistency
```

EPVME is useful for the second component. Its README specifically documents attacks involving inconsistencies between Mail From and From headers and confirms header/body availability. citeturn708804search6

Where a real email body is available:

```text
real body
+
realistic trusted-contact scenario
+
controlled header manipulation
```

may be used for training augmentation.

Record:

```text
construction_type = "header_recombination"
```

and:

```text
is_synthetic = true
```

for the derived record.

Do not put these constructed examples into the real evaluation set.

---

# 18. Train/Validation/Test Split

## 18.1 Recommended split

Start with:

```text
70% train
15% validation
15% test
```

but make the split **group-aware** rather than purely random.

Scikit-learn provides `GroupKFold` for non-overlapping groups and `StratifiedGroupKFold` when preserving class proportions under group constraints matters. citeturn810318search5turn810318search7

## 18.2 Group key

Build:

```text
leakage_group_id
```

from:

1. exact duplicate cluster,
2. near-duplicate cluster,
3. sender/domain where enough data exists,
4. provenance cluster,
5. derived-from relationship.

No group may cross train/test.

## 18.3 Temporal evaluation

Add a second evaluation regime:

```text
train = older period
test = newer period
```

when timestamps permit.

This is important because current phishing differs from older corpora.

## 18.4 Final test purity

For the final test set:

```text
is_synthetic == false
```

whenever enough real samples exist.

Do not let a synthetic-heavy class produce an impressive score on synthetic test data.

---

# 19. Split Validation Checks

Before accepting `split.csv`, automatically assert:

```python
assert train_ids.isdisjoint(test_ids)
assert val_ids.isdisjoint(test_ids)
assert train_ids.isdisjoint(val_ids)

assert no_duplicate_cluster_crosses_split
assert no_provenance_cluster_crosses_split
assert no_synthetic_test_records_where_real_exists
```

Also produce:

```text
split_report.csv
```

with:

```text
class
dataset
train_count
val_count
test_count
real_count
synthetic_count
unique_domains
unique_senders
date_min
date_max
```

---

# 20. Dataset Weighting

Do not try to make every class numerically equal by oversampling immediately.

The verified corpus has a naturally severe imbalance.

Start with:

```text
class-weighted learning
```

and inspect results.

For LightGBM, class weighting is directly supported for multiclass classification. Its documentation also warns that weighting can produce poor probability estimates, which is why calibration is important for this application. citeturn810318search0

Recommended starting principle:

```text
weight_c = N / (K * N_c)
```

Then cap extreme weights so the smallest classes do not completely dominate.

Example:

```python
weight = min(raw_weight, 5.0)
```

Tune the cap on validation data.

---

# 21. Historical Feature Reliability

Create:

```text
historical_reliability:
    current_auth_reliable
    current_reputation_reliable
    current_domain_age_reliable
    current_geo_reliable
```

A historical email may have:

```text
current_dns_valid = false
```

because its domain no longer exists.

That does not mean:

```text
domain_was_invalid_at_delivery = true
```

Those are different propositions.

## 21.1 MVP policy

For the first model:

- retain the raw runtime values,
- add historical-reliability flags,
- add missingness indicators,
- compare performance with and without Category-B features,
- report the difference.

If historical features strongly dominate older corpora but fail on a modern temporal test set, reduce their training influence or exclude them for historical samples.

---

# 22. Forensic Feature Extraction

The 35-feature extractor must be treated as the source of truth.

Do not recreate a second implementation of the same feature logic inside the dataset builder.

Use:

```text
canonical email
    ↓
MailForensix parser
    ↓
existing FeatureExtractor
    ↓
35-feature vector
```

This guarantees that training and production inference share the same feature semantics.

## 22.1 Required output

For every eligible email:

```text
email_id
feature_01
...
feature_35
feature_extraction_status
feature_missing_count
feature_error
historical_reliability
```

## 22.2 Null policy

Never silently replace unavailable historical evidence with:

```text
0
```

unless zero genuinely means false.

Use explicit missing values.

For LightGBM, missingness can be represented directly where appropriate, but the exact behavior must be consistent with the existing production extractor.

---

# 23. Category-A vs Category-B

The verified research establishes:

```text
Category A:
message/header/body/attachment/URL-derived features

Category B:
SPF
DKIM
DMARC
WHOIS
DNS
geo
IP reputation
other current external enrichment
```

19/35 features are in Category B according to the existing project analysis.

## 23.1 Processing rule

Category A:

```text
safe to compute from the archived message
```

Category B:

```text
compute through existing runtime enrichment
AND
record observation timestamp
AND
record reliability
```

## 23.2 Failure handling

External lookup failure must not crash batch extraction.

Every lookup should produce:

```text
value
status
error_code
latency_ms
source
timestamp
```

Example:

```json
{
  "dmarc": null,
  "status": "timeout",
  "error_code": "DNS_TIMEOUT",
  "timestamp": "2026-08-31T..."
}
```

---

# 24. Batch Feature Extraction

Do not process the corpus using one huge synchronous loop.

Use:

```text
producer -> queue -> extractor workers -> feature writer
```

with:

```text
checkpointing
retry
timeout
rate limit
cache
resume
```

## 24.1 Cache external lookups

Create:

```text
lookup_cache/
```

keyed by:

```text
query_type + normalized_query
```

Example:

```text
DNS:example.com
WHOIS:example.com
GEO:1.2.3.4
REPUTATION:1.2.3.4
```

This prevents repeatedly querying the same domain/IP.

## 24.2 Never exceed provider limits

The feature extraction layer must respect the existing API provider limits.

Do not parallelize DNS/reputation calls without a rate limiter.

---

# 25. NLP Dataset Construction

The NLP input should be:

```text
[SUBJECT]
<subject>

[BODY]
<body>
```

Do not include forensic features.

Do not include dataset name.

Do not include the label in the text.

Do not include:

```text
"this is phishing"
"source=..."
"class=..."
```

because that would leak metadata.

---

# 26. DistilRoBERTa Model

Use a pretrained DistilRoBERTa sequence-classification model.

Hugging Face documents the standard sequence-classification workflow using `AutoModelForSequenceClassification`, tokenizer preprocessing, truncation, and dynamic padding. citeturn581375search1

The available `distilbert/distilroberta-base` model is explicitly available for use with Transformers and is Apache-2.0 licensed. citeturn581375search6

Recommended initialization:

```python
AutoModelForSequenceClassification.from_pretrained(
    "distilbert/distilroberta-base",
    num_labels=5,
    id2label={
        0: "LEGITIMATE",
        1: "SUSPICIOUS",
        2: "PHISHING",
        3: "BEC_FRAUD",
        4: "IMPERSONATION",
    },
    label2id={
        "LEGITIMATE": 0,
        "SUSPICIOUS": 1,
        "PHISHING": 2,
        "BEC_FRAUD": 3,
        "IMPERSONATION": 4,
    },
)
```

---

# 27. DistilRoBERTa Input Length

Start with:

```text
max_length = 512
```

This is the safe first-pass sequence budget.

For long emails, do not simply destroy all tail content.

Use a deterministic strategy:

```text
subject
+
first body window
+
last body window
```

or chunk long emails and aggregate chunk probabilities.

For MVP, use:

```text
subject + truncated body
```

and record:

```text
body_truncated = true/false
```

so later experiments can measure truncation effects.

---

# 28. NLP Training Strategy

Start with:

```text
1–3 epochs
learning_rate around 2e-5
weight_decay around 0.01
warmup_ratio around 0.1
early stopping
mixed precision when supported
```

Do not lock these values permanently.

Tune only a small search space because the primary challenge is data quality.

Suggested first experiment:

```text
Run A:
class-weighted cross entropy

Run B:
unweighted cross entropy

Run C:
weighted loss + calibrated probabilities
```

Compare on the same validation set.

---

# 29. NLP Class Weighting

Because BEC/Fraud and Impersonation will be small, use class-weighted loss.

Conceptually:

```python
CrossEntropyLoss(weight=class_weights)
```

but ensure the weights are computed **only from training data**.

Never calculate weights from train + validation + test together.

---

# 30. LightGBM Training

Use:

```text
objective = multiclass
num_class = 5
```

Starting parameters:

```yaml
num_leaves: 31
learning_rate: 0.03
n_estimators: 500
subsample: 0.8
colsample_bytree: 0.8
min_child_samples: 20
reg_alpha: 0.1
reg_lambda: 1.0
```

These are starting values, not final claims.

Use early stopping against validation.

The LightGBM classifier exposes multiclass class weighting and explicitly cautions that class/sample weighting may damage probability estimates. citeturn810318search0

Therefore the pipeline must separate:

```text
classification performance
```

from:

```text
probability quality
```

---

# 31. LightGBM Ablation Experiments

Do not train one model and assume all 35 features help.

Train at least:

```text
Model A:
all available features

Model B:
Category A only

Model C:
Category B only

Model D:
A + B + historical reliability flags

Model E:
A + B without historically unreliable rows
```

Record:

```text
macro_f1
weighted_f1
per_class_f1
balanced_accuracy
log_loss
Brier score where applicable
confusion matrix
```

The point is to discover whether current external enrichment is genuinely helping rather than allowing it to dominate historical artifacts.

---

# 32. Probability Calibration

Calibration is required because the ensemble needs probabilities, not merely class IDs.

Scikit-learn's calibration documentation emphasizes fitting calibration on data independent of the base training data, and provides calibration methods including sigmoid, isotonic, and temperature scaling. citeturn810318search1turn810318search3

For the MVP:

```text
Use sigmoid calibration first.
```

Do not use isotonic automatically for tiny classes; the scikit-learn documentation warns that isotonic can overfit when the calibration sample is too small. citeturn810318search3

Calibration data must not be the same samples used to fit the underlying model.

---

# 33. Ensemble Inputs

The ensemble should receive, per `email_id`:

```text
p_nlp_0
p_nlp_1
p_nlp_2
p_nlp_3
p_nlp_4

p_lgbm_0
p_lgbm_1
p_lgbm_2
p_lgbm_3
p_lgbm_4

rule_score_0
...
rule_score_4
```

plus only explicitly approved metadata.

Do not feed:

```text
dataset_name
source_dataset
synthetic_source
file_path
label_encoder artifacts
```

into the ensemble because those can become dataset shortcuts.

---

# 34. Out-of-Fold Predictions

This is essential.

Do not train the ensemble using:

```text
base model predictions on the same data used to train the base model
```

That creates optimistic leakage.

Instead:

```text
5-fold grouped CV

Fold 1:
train base models on folds 2–5
predict fold 1

Fold 2:
train on 1,3,4,5
predict fold 2

...

Fold 5:
train on 1–4
predict fold 5
```

Then concatenate the out-of-fold probabilities.

These are the ensemble training features.

Use the same groups as the dataset split.

---

# 35. Ensemble Model

Start simple.

Recommended MVP:

```text
multiclass Logistic Regression
```

Input:

```text
10 base probabilities
+
5 rule probabilities/scores
```

This gives:

```text
15-dimensional ensemble input
```

Advantages:

- interpretable,
- low overfitting risk,
- easy to debug,
- easy to calibrate.

Only move to a nonlinear meta-model after proving a linear ensemble is insufficient.

---

# 36. Rule Layer

The existing deterministic/rule layer should remain independent.

Examples of high-confidence signals:

```text
malformed authentication
known-dangerous URL
strong header mismatch
obvious attachment hazard
domain/header contradiction
```

Rules should not silently rewrite the ML label.

Instead they contribute:

```text
rule_scores
rule_evidence
```

The ensemble decides the final class.

---

# 37. Evaluation Strategy

Do not report accuracy alone.

Required metrics:

```text
macro F1
weighted F1
per-class precision
per-class recall
per-class F1
balanced accuracy
confusion matrix
log loss
probability calibration
```

Macro F1 is particularly important because a large Legitimate class can make overall accuracy look excellent while BEC/Impersonation are unusable.

For probability quality, use proper scoring rules such as log loss and Brier score alongside discrimination metrics. Scikit-learn documents Brier loss as the mean squared difference between predicted probability and actual outcome. citeturn810318search1turn810318search4

---

# 38. Class-Specific Acceptance Criteria

Do not declare the model "done" merely because aggregate F1 is good.

Minimum checks:

```text
Legitimate:
    strong recall

Suspicious:
    measurable recall without collapsing into Phishing

Phishing:
    strong recall and precision

BEC/Fraud:
    non-trivial recall on a real-data test subset

Impersonation:
    non-trivial recall on a real/controlled-real test subset
```

If a class has too little real test data for statistically meaningful evaluation, explicitly report:

```text
INSUFFICIENT REAL TEST DATA
```

Do not manufacture confidence with synthetic evaluation.

---

# 39. Critical Baselines

Before the final architecture is evaluated, create:

```text
Baseline 1:
majority-class predictor

Baseline 2:
keyword/heuristic-only classifier

Baseline 3:
LightGBM only

Baseline 4:
DistilRoBERTa only

Baseline 5:
LightGBM + NLP ensemble
```

The ensemble should demonstrate that it adds value over both base models.

---

# 40. Leakage Audit

Create an automated audit.

Check:

```text
exact duplicate overlap
near-duplicate overlap
same sender/domain across splits
same provenance cluster across splits
same source email behind EPVME and source corpus
synthetic test records
source-dataset metadata leakage
label-text leakage
```

Output:

```text
leakage_audit.json
```

with:

```json
{
  "exact_cross_split_duplicates": 0,
  "near_duplicate_cross_split_clusters": 0,
  "provenance_cross_split_clusters": 0,
  "synthetic_test_records": 0,
  "metadata_leakage_detected": false
}
```

Any non-zero critical leakage count is a release blocker.

---

# 41. Dataset Manifest

Final manifest must contain one row per usable message.

Recommended columns:

```text
email_id
split
canonical_label
source_dataset
source_record_id
source_license
license_verified

is_synthetic
synthetic_source
construction_type

email_timestamp
sender
sender_domain
reply_to_domain

raw_message_sha256
normalized_full_sha256
normalized_body_sha256
near_duplicate_cluster_id
provenance_cluster_id

has_headers
has_subject
has_body
has_urls
has_attachments

historical_reliability

nlp_usable
forensic_usable
exclusion_reason
```

Save as:

```text
ml/data/manifests/final_training_manifest.parquet
ml/data/manifests/final_training_manifest.csv
```

---

# 42. Feature Manifest

Create:

```text
feature_manifest.json
```

For every one of the 35 LightGBM features:

```json
{
  "name": "feature_name",
  "source": "MailForensix FeatureExtractor",
  "category": "A",
  "requires_external_lookup": false,
  "missing_allowed": true,
  "historical_reliability_required": false
}
```

This prevents feature meaning from drifting between training and inference.

---

# 43. Dataset Quality Report

Generate automatically:

```text
dataset_quality_report.md
```

Include:

```text
raw count by dataset
valid count
parse failure count
duplicate count
near-duplicate count
final count by class
final count by source
real/synthetic counts
header availability
subject availability
attachment availability
URL availability
timestamp coverage
domain coverage
feature coverage
license status
```

---

# 44. License Gate

Before final training:

```text
license_verified == true
```

must be required for datasets whose terms were previously flagged as uncertain.

The report specifically identifies licensing/access uncertainties around:

```text
Nazario
BEC-2
EPVME
IWSPA-AP
phishing_pot
```

Do not silently convert "public GitHub repository" into "licensed for redistribution."

For a hackathon training environment, retain the source datasets locally if licensing remains unresolved and do not bundle/re-publish their raw content.

---

# 45. Download Manifest

Create:

```text
download_manifest.json
```

Example:

```json
{
  "dataset": "epvme",
  "source_url": "...",
  "commit_sha": "...",
  "download_timestamp_utc": "...",
  "sha256": "...",
  "actual_message_count": 0,
  "license_file_present": false
}
```

For direct archives:

```text
archive_sha256
archive_size_bytes
```

must be recorded.

---

# 46. Reproducibility

Every training run must record:

```text
git commit
Python version
PyTorch version
Transformers version
LightGBM version
scikit-learn version
CUDA version
dataset manifest hash
feature manifest hash
split hash
training config hash
random seed
model checkpoint
```

Create:

```text
training_run.json
```

Do not rely on memory of how a model was trained.

---

# 47. Random Seeds

Set one master seed:

```text
42
```

and propagate it through:

```text
Python
NumPy
PyTorch
LightGBM
dataset splitting
```

For CUDA experiments, enable deterministic behavior where practical, while documenting any operations that remain nondeterministic.

---

# 48. Checkpointing

The dataset pipeline must be resumable.

Every long-running stage should use checkpoints:

```text
01_download_complete
02_parse_complete
03_normalize_complete
04_dedup_complete
05_labels_complete
06_split_complete
07_forensic_features_complete
08_nlp_tokenization_complete
09_base_models_complete
10_ensemble_complete
```

If the process stops halfway, restart from the latest valid checkpoint.

---

# 49. Recommended Execution Order

Do not mix all phases into one huge script.

Execute these phases sequentially.

## Phase A — Acquisition

```text
download
verify hashes
record versions
inventory files
```

Gate:

```text
all source manifests exist
```

## Phase B — Parsing

```text
dataset-specific parsers
canonical schema
parse report
```

Gate:

```text
>99% expected files parsed
or
every failure is explained
```

## Phase C — Deduplication

```text
exact hashes
MinHash/SimHash
provenance clusters
```

Gate:

```text
no duplicate crosses future split
```

## Phase D — Labeling

```text
direct labels
Suspicious candidate filter
manual review
BEC/Fraud subtyping
Impersonation selection
```

Gate:

```text
all five classes have verified training examples
```

## Phase E — Split

```text
group-aware split
temporal holdout
real-only final test
```

Gate:

```text
leakage audit passes
```

## Phase F — Forensic corpus

```text
replay eligible EML
FeatureExtractor
external enrichment cache
35-feature matrix
```

Gate:

```text
feature manifest matches production
```

## Phase G — NLP corpus

```text
subject+body
tokenization
DistilRoBERTa fine-tuning
```

Gate:

```text
macro/per-class metrics acceptable
```

## Phase H — Calibration

```text
calibrate base probabilities
```

Gate:

```text
probability quality improves or does not materially regress
```

## Phase I — Ensemble

```text
OOF probabilities
meta-model
real held-out evaluation
```

Gate:

```text
ensemble beats or meaningfully complements both base models
```

---

# 50. Recommended First Coding Milestone

The first coding milestone is **not model training**.

Build and finish:

```text
dataset_acquisition/
dataset_parsers/
canonical_schema/
deduplication/
manifest_generation/
```

The milestone is successful only when the project can produce:

```text
final_training_manifest.parquet
```

with:

```text
email_id
label
source
synthetic flag
duplicate/provenance cluster
split
```

but before expensive ML feature extraction.

---

# 51. Second Coding Milestone

Build:

```text
suspicious_filter/
manual_review_export/
```

Input:

```text
TREC07 spam
CEAS08 spam
SpamAssassin spam
```

Output:

```text
suspicious_candidates.parquet
review_queue.csv
reviewed_labels.parquet
```

Human reviewers should be able to inspect:

```text
subject
body
sender
reply-to
URL summary
candidate score
reason codes
```

without changing the raw evidence.

---

# 52. Third Coding Milestone

Build the forensic replay system.

Command concept:

```bash
python -m ml.src.forensic.extract \
  --manifest ml/data/manifests/final_training_manifest.parquet \
  --split train \
  --output ml/data/features/train.parquet
```

Then:

```bash
python -m ml.src.forensic.extract --split validation
python -m ml.src.forensic.extract --split test
```

The feature extractor must use the exact same code path as production.

---

# 53. Fourth Coding Milestone

Train the NLP model.

Command concept:

```bash
python -m ml.src.nlp.train \
  --manifest ml/data/manifests/final_training_manifest.parquet \
  --config ml/config/training.yaml
```

Save:

```text
model/
tokenizer/
label_map.json
training_metrics.json
```

---

# 54. Fifth Coding Milestone

Train LightGBM:

```bash
python -m ml.src.forensic.train_lgbm \
  --features ml/data/features \
  --config ml/config/training.yaml
```

Save:

```text
model.txt
feature_names.json
class_weights.json
metrics.json
```

---

# 55. Sixth Coding Milestone

Generate OOF predictions:

```bash
python -m ml.src.ensemble.oof
```

Output:

```text
oof_predictions.parquet
```

Required key:

```text
email_id
```

Required columns:

```text
nlp_p0 ... nlp_p4
lgbm_p0 ... lgbm_p4
rule_p0 ... rule_p4
true_label
fold
```

---

# 56. Seventh Coding Milestone

Train the ensemble:

```bash
python -m ml.src.ensemble.train
```

Output:

```text
ensemble_model.joblib
ensemble_calibrator.joblib
ensemble_metrics.json
```

---

# 57. Production Integration Rule

The final trained model must not introduce a second preprocessing path.

Production inference should be:

```text
incoming email
      ↓
existing parser
      ↓
canonical representation
      ↓
┌──────────────────┬──────────────────┐
│                  │                  │
NLP preprocessing  FeatureExtractor   Rules
│                  │                  │
DistilRoBERTa      LightGBM           evidence
│                  │                  │
└──────────────────┴──────────────────┘
              ↓
          Ensemble
              ↓
      class probabilities
              ↓
       final classification
```

This is the same architectural relationship established by the research report.

---

# 58. Confidence Handling

Do not hard-code:

```text
confidence = 100
```

The ensemble confidence must come from the actual probability distribution.

Example:

```text
prediction = argmax(P)
confidence = max(P)
```

but expose the full distribution internally.

For example:

```json
{
  "prediction": "PHISHING",
  "confidence": 0.81,
  "probabilities": {
    "LEGITIMATE": 0.02,
    "SUSPICIOUS": 0.09,
    "PHISHING": 0.81,
    "BEC_FRAUD": 0.03,
    "IMPERSONATION": 0.05
  }
}
```

If calibration is used, confidence should be derived from the calibrated probabilities.

---

# 59. Low-Confidence Policy

A five-class classifier should not be forced to pretend certainty where the model has none.

Define:

```text
confidence >= high_threshold:
    normal prediction

medium:
    prediction + caution

low:
    prediction + "uncertain"
```

The uncertainty threshold should be learned from validation behavior, not invented after looking at the test set.

---

# 60. Error Analysis

After each training run, automatically collect examples from:

```text
false Legitimate
false Suspicious
false Phishing
false BEC/Fraud
false Impersonation
```

Sort by:

```text
confidence descending
confidence ascending
```

Manually inspect at least:

```text
20 highest-confidence errors
20 lowest-confidence errors
```

for each sufficiently populated class.

Look specifically for:

```text
dataset artifacts
template artifacts
header leakage
source-specific wording
LLM-style fingerprints
domain memorization
historical-age effects
```

---

# 61. Dataset-Shift Experiments

At minimum compare:

```text
random/group-aware test
temporal test
modern-phishing test
synthetic-excluded test
```

This is important because modern phishing is one of the gaps the dataset research identified.

`phishing_pot` should be used heavily in this analysis because it is intended to reduce the modern-phishing gap.

---

# 62. Ablation of Synthetic Data

Train:

```text
Model 1:
real-only training

Model 2:
real + BEC-2

Model 3:
real + all approved synthetic augmentation
```

Compare against the **same real-only test set**.

This determines whether synthetic data actually helps.

Do not judge synthetic augmentation on a synthetic test set.

---

# 63. Ablation of Modern Data

Train:

```text
without phishing_pot
with phishing_pot
```

Evaluate specifically on:

```text
modern/temporal phishing subset
```

The point is to test whether the added dataset closes the intended domain gap rather than simply inflating training volume.

---

# 64. Acceptance Gates

The complete implementation is ready for application integration only when:

### Data

```text
[ ] every dataset has a source record
[ ] actual counts recorded
[ ] all usable messages have email_id
[ ] exact duplicates removed
[ ] near-duplicates clustered
[ ] provenance graph created
[ ] five-class labels justified
[ ] Suspicious labels human-reviewed
[ ] synthetic provenance tracked
```

### Split

```text
[ ] train/val/test generated once
[ ] no duplicate cluster crosses splits
[ ] no provenance cluster crosses splits
[ ] final test is real where feasible
[ ] temporal evaluation exists
```

### Forensic model

```text
[ ] same FeatureExtractor as production
[ ] all 35 feature names verified
[ ] external lookup cache implemented
[ ] historical reliability tracked
[ ] ablation completed
```

### NLP model

```text
[ ] DistilRoBERTa fine-tuned
[ ] class weighting compared
[ ] long-email handling documented
[ ] validation metrics recorded
```

### Ensemble

```text
[ ] base probabilities calibrated
[ ] OOF probabilities generated
[ ] meta-model trained only on OOF data
[ ] ensemble tested on untouched real data
```

### Security/reproducibility

```text
[ ] leakage audit passes
[ ] license inventory complete
[ ] source hashes recorded
[ ] training configuration stored
[ ] model artifact versioned
[ ] dataset manifest versioned
```

---

# 65. What Must Not Be Done

Do **not**:

```text
map all spam -> Suspicious
map all spam -> Phishing

train on duplicates
split first and deduplicate later

put synthetic BEC/Impersonation data into final test

use source_dataset as an NLP input feature

use filename as label

replace unavailable forensic values with arbitrary zeros

reimplement production feature extraction for training

fit calibration on base-model training predictions

train ensemble on in-sample base-model predictions

use today's reputation result as unquestioned historical truth

claim BEC-2 is a real-incident corpus

claim CLAIR is equivalent to internal BEC

use EPVME as ordinary natural-language phishing prose

use PhishTank as email training data

hard-code confidence to 100%
```

---

# 66. Research/Implementation Decisions That Are Intentionally Conservative

The implementation should prefer:

```text
fewer high-quality records
```

over:

```text
more weakly labeled records
```

especially for:

```text
Suspicious
BEC/Fraud
Impersonation
```

For Legitimate and Phishing, volume can be increased much more aggressively.

The most valuable engineering work is not adding another generic spam corpus. It is:

```text
better Suspicious labeling
better BEC/Fraud data quality
better Impersonation construction
better modern phishing coverage
better leakage control
```

---

# 67. Expected MVP Dataset

The first successful training run should aim approximately for:

```text
Legitimate:
3k–5k

Suspicious:
500–1k

Phishing:
2k–4k

BEC/Fraud:
300–600

Impersonation:
200–500
```

The exact final numbers must be taken from the generated manifest.

Never put estimated counts into the model card as if they were measured counts.

---

# 68. Final Deliverables

At the end of this implementation phase the repository should contain:

```text
ml/data/manifests/raw_inventory.json
ml/data/manifests/final_training_manifest.parquet
ml/data/manifests/final_training_manifest.csv

ml/data/splits/splits.csv

ml/data/features/train.parquet
ml/data/features/validation.parquet
ml/data/features/test.parquet

ml/data/artifacts/oof_predictions.parquet

ml/reports/dataset_quality_report.md
ml/reports/duplicate_report.csv
ml/reports/leakage_audit.json
ml/reports/feature_coverage.csv
ml/reports/model_metrics.json
ml/reports/training_run.json

ml/models/lightgbm/model.txt
ml/models/lightgbm/feature_names.json

ml/models/distilroberta/
ml/models/ensemble/
```

---

# 69. Recommended Git Commit Sequence

Keep the work reviewable.

```text
commit 1:
ML data configuration + schemas

commit 2:
dataset acquisition + inventories

commit 3:
dataset parsers + normalization

commit 4:
global deduplication + provenance

commit 5:
Suspicious candidate filter + review tooling

commit 6:
five-class manifest + leakage-safe split

commit 7:
forensic feature extraction

commit 8:
DistilRoBERTa training

commit 9:
LightGBM training + calibration

commit 10:
OOF ensemble

commit 11:
evaluation + audit reports

commit 12:
production integration
```

Do not combine all ML changes into one opaque commit.

---

# 70. Bottom Line

The verified research does **not** justify another architecture redesign.

The correct implementation is:

```text
                  DATASETS
                      │
                      ▼
              dataset-specific parsers
                      │
                      ▼
              canonical email schema
                      │
                      ▼
              provenance + hashing
                      │
                      ▼
             GLOBAL DEDUPLICATION
                      │
                      ▼
            five-class label system
                      │
          ┌───────────┴────────────┐
          │                        │
          ▼                        ▼
  Suspicious review          BEC/Impersonation
  + manual validation        controlled augmentation
          │                        │
          └───────────┬────────────┘
                      ▼
             FINAL LABEL MANIFEST
                      │
                      ▼
        GROUP/TEMPORAL LEAKAGE-SAFE SPLIT
                      │
          ┌───────────┴────────────┐
          │                        │
          ▼                        ▼
    NLP corpus                EML corpus
          │                        │
          ▼                        ▼
   DistilRoBERTa              35 features
          │                        │
          ▼                        ▼
    calibrated P_nlp         calibrated P_lgbm
          │                        │
          └───────────┬────────────┘
                      ▼
                 RULE SCORES
                      │
                      ▼
             OOF ENSEMBLE
                      │
                      ▼
             REAL TEST SET
                      │
                      ▼
              FINAL MODEL
```

The critical invariant is:

> **One email, one canonical `email_id`, one authoritative label, one split assignment, and the same underlying record feeding both NLP and forensic models.**

That invariant prevents the most dangerous class of errors in this project: silent label contamination, cross-corpus leakage, mismatched model training populations, and artificially inflated ensemble performance.

---

# 71. External Technical References Used to Refine This Implementation

The implementation decisions above were informed by current official documentation and the verified dataset report:

- Hugging Face's current sequence-classification workflow supports tokenizer preprocessing, truncation, dynamic padding, and `AutoModelForSequenceClassification`. citeturn581375search1
- `distilbert/distilroberta-base` is available for Transformers and is listed with an Apache-2.0 license. citeturn581375search6
- LightGBM's current `LGBMClassifier` supports multiclass classification and class weighting; its documentation explicitly cautions that weighting can degrade probability estimates, motivating calibration. citeturn810318search0
- Scikit-learn's calibration documentation recommends calibrating on data independent from the data used to fit the base estimator and documents sigmoid/isotonic/temperature approaches. citeturn810318search1turn810318search3
- Scikit-learn provides non-overlapping group-aware splitting through `GroupKFold` and class-aware group splitting through `StratifiedGroupKFold`. citeturn810318search5turn810318search7
- The current EPVME GitHub README explicitly describes the 37,283-email malicious dataset, header/body availability, and random recombination of content, confirming its role as a forensic/header-focused source. citeturn708804search6

---

# 72. Handoff Instruction for the Coding Agent

Treat this document as the implementation specification.

Before changing application code:

1. Inspect the existing MailForensix ML/feature-extraction code.
2. Reuse existing parsers and FeatureExtractor components where possible.
3. Do not modify working production email ingestion unless a concrete compatibility problem is demonstrated.
4. Implement dataset work in the dedicated ML data/training area.
5. Preserve raw evidence immutably.
6. Build the manifest before expensive model training.
7. Stop at each acceptance gate and produce its report.
8. Do not claim success until the generated reports demonstrate the stated gates.

**Most important:** do not shortcut the Suspicious labeling, global deduplication, or shared `email_id` split. Those three controls are foundational to the credibility of the final five-class model.