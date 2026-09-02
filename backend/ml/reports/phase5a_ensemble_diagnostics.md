# MailForensix Phase 5A Ensemble Diagnostics & Root Cause Analysis

**Generated:** 2026-09-01T18:35:05.957691  
**Target:** Minority-Class (SUSPICIOUS) Failure Diagnosis, OOF Integrity Audit & Metric Reconciliation

---

## 1. Executive Summary: Core Root Causes Identified

1. **Platt Calibration Collapse on Minority Class**:
   - `LightGBM (Raw)` achieved **0.6429 Recall (9/14 test detections)** on the 14 real SUSPICIOUS test emails.
   - However, Platt scaling (`ProbabilityCalibrator`) fitted on validation (where SUSPICIOUS prevalence is only ~0.56%) severely damped raw probabilities, shifting all SUSPICIOUS probabilities from ~0.30–0.45 down to <0.05.
   - When calibrated probabilities were passed to argmax or the ensemble, **every single SUSPICIOUS email was converted to LEGITIMATE** (0/14 recall).

2. **Unweighted Logistic Stacking Meta-Classifier**:
   - The stacking ensemble meta-classifier was trained with unweighted `LogisticRegression` inside `CalibratedClassifierCV`.
   - On the training OOF dataset (4,537 LEGITIMATE vs. 72 SUSPICIOUS), the unweighted meta-learner learned that predicting LEGITIMATE incurs negligible loss on the 72 minority examples compared to risking false positives on 4,537 majority examples.
   - Consequently, the ensemble attained a near-zero recall (0.0556 on Train OOF, 0.0000 on Test).

3. **Explanation of LightGBM Metric Discrepancy**:
   - **Final Test Metric** (`Macro F1 = 0.8139`, `Accuracy = 0.9645`): Evaluated on the **Frozen Test Split (1,548 Real Emails)**.
   - **Ablation Exp_A Metric** (`Macro F1 = 0.8515`, `Accuracy = 0.9689`): Evaluated on the **Held-out Validation Split (2,826 Emails)**.
   - *Conclusion*: This is a legitimate experimental evaluation difference across separate splits. The ablation experiments measured feature importance on the Validation split during tuning, whereas the final baseline was tested on the untouchable Test split.

---

## 2. OOF Predictions Integrity & Leakage Audit

* **Total OOF Records**: `9,695` (Matches expected training set: `9,695`)
* **Duplicate Email IDs**: `0` (0% duplicates)
* **Missing Email IDs**: `0`
* **Self-Prediction / Group Leakage Violations**: `0` (**ZERO leakage across groups**)
* **Class Ordering Invariance**: `True` (**100% verified non-negative & sum=1.0**)

### Fold Distribution by Threat Class

| Fold | LEGITIMATE | SUSPICIOUS | PHISHING | BEC_FRAUD | IMPERSONATION | Total |
|---|---:|---:|---:|---:|---:|---:|
| **fold_1** | 951 | 8 | 400 | 348 | 232 | 1,939 |
| **fold_2** | 973 | 37 | 342 | 334 | 253 | 1,939 |
| **fold_3** | 809 | 6 | 470 | 423 | 231 | 1,939 |
| **fold_4** | 966 | 13 | 412 | 320 | 228 | 1,939 |
| **fold_5** | 838 | 8 | 431 | 372 | 290 | 1,939 |

---

## 3. Base Model Probability Distributions by True Class (OOF Analysis)

For true samples of each class, how did each constituent model distribute its predicted probabilities?

| True Class | Sample Count | Model | P(LEGITIMATE) | P(SUSPICIOUS) | P(PHISHING) | P(BEC_FRAUD) | P(IMPERSONATION) |
|---|---:|---|---:|---:|---:|---:|---:|
| **LEGITIMATE** | 4,537 | DistilRoBERTa (NLP) | 0.2843 | **0.0229** | 0.2523 | 0.1787 | 0.2618 |
| | | LightGBM (Tabular 35) | 0.9429 | **0.0351** | 0.0207 | 0.0012 | 0.0000 |
| | | Rule Heuristics | 0.9531 | **0.0296** | 0.0014 | 0.0158 | 0.0000 |
| **SUSPICIOUS** | 72 | DistilRoBERTa (NLP) | 0.2196 | **0.0293** | 0.2681 | 0.2055 | 0.2775 |
| | | LightGBM (Tabular 35) | 0.6764 | **0.3135** | 0.0000 | 0.0100 | 0.0000 |
| | | Rule Heuristics | 0.5790 | **0.3385** | 0.0344 | 0.0481 | 0.0000 |
| **PHISHING** | 2,055 | DistilRoBERTa (NLP) | 0.2154 | **0.0240** | 0.3416 | 0.1758 | 0.2433 |
| | | LightGBM (Tabular 35) | 0.0326 | **0.0000** | 0.9674 | 0.0000 | 0.0000 |
| | | Rule Heuristics | 0.7547 | **0.0963** | 0.1094 | 0.0396 | 0.0000 |
| **BEC_FRAUD** | 1,797 | DistilRoBERTa (NLP) | 0.2070 | **0.0247** | 0.2378 | 0.2970 | 0.2335 |
| | | LightGBM (Tabular 35) | 0.0017 | **0.0005** | 0.0000 | 0.9865 | 0.0112 |
| | | Rule Heuristics | 0.7096 | **0.1598** | 0.0000 | 0.0817 | 0.0488 |
| **IMPERSONATION** | 1,234 | DistilRoBERTa (NLP) | 0.2352 | **0.0247** | 0.2637 | 0.1837 | 0.2927 |
| | | LightGBM (Tabular 35) | 0.0000 | **0.0000** | 0.0000 | 0.0169 | 0.9831 |
| | | Rule Heuristics | 0.1011 | **0.0156** | 0.0042 | 0.0094 | 0.8697 |

### Key Diagnostic Findings:
1. **LightGBM Sensitivity**: On true `SUSPICIOUS` training emails, LightGBM assigns **31.35% average probability** to SUSPICIOUS (versus 0.0% on Phishing and 0.05% on BEC). This demonstrates that LightGBM's 35 forensic features capture real, distinct suspicious markers.
2. **Rule Heuristics Sensitivity**: Heuristic rules assign **33.85% average probability** to SUSPICIOUS.
3. **DistilRoBERTa NLP Limitation**: The transformer assigns only **2.93% average probability** to SUSPICIOUS on true Suspicious emails, behaving almost identically to its baseline background probability. This indicates text alone struggles to distinguish curated suspicious emails from borderline legitimate/phishing text without forensic headers.
4. **Meta-Model Suppression**: In unweighted argmax, because `P(LEGITIMATE)` averages 0.6764 on Suspicious emails, argmax selects LEGITIMATE unless an explicit minority threshold or class-weighting is applied.

---

## 4. Meta-Classifier Coefficients Table (15D Input Space)

| Input Meta-Feature | Target: LEGITIMATE | Target: SUSPICIOUS | Target: PHISHING | Target: BEC_FRAUD | Target: IMPERSONATION |
|---|---:|---:|---:|---:|---:|
| `nlp_p_legitimate` | +5.9329 | -1.7525 | -3.6516 | -0.7057 | +0.1769 |
| `nlp_p_suspicious` | -0.2968 | +0.2030 | +0.0907 | +0.0031 | -0.0000 |
| `nlp_p_phishing` | -3.0857 | +0.2217 | +3.1274 | -0.4685 | +0.2051 |
| `nlp_p_bec_fraud` | -2.0415 | +0.5532 | +0.4776 | +2.0284 | -1.0177 |
| `nlp_p_impersonation` | -0.4252 | +0.6765 | -0.0186 | -0.8988 | +0.6661 |
| `lgbm_p_legitimate` | +2.8068 | +1.0070 | -0.1873 | -2.2191 | -1.4075 |
| `lgbm_p_suspicious` | +0.9913 | +2.1289 | -1.5460 | -1.0539 | -0.5204 |
| `lgbm_p_phishing` | -0.4700 | -1.4690 | +4.5430 | -1.7236 | -0.8804 |
| `lgbm_p_bec_fraud` | -2.0290 | -0.9869 | -1.7628 | +4.6676 | +0.1111 |
| `lgbm_p_impersonation` | -1.2155 | -0.7782 | -1.0214 | +0.2876 | +2.7275 |
| `rule_p_legitimate` | +1.6503 | -0.6591 | +0.4294 | +0.6050 | -2.0256 |
| `rule_p_suspicious` | -0.3448 | +1.0378 | -0.3556 | +0.8997 | -1.2371 |
| `rule_p_phishing` | -0.6957 | +0.2935 | +0.7406 | -0.3150 | -0.0235 |
| `rule_p_bec_fraud` | +0.2336 | -0.1968 | -0.0840 | +0.4070 | -0.3598 |
| `rule_p_impersonation` | -0.7599 | -0.5735 | -0.7048 | -1.6382 | +3.6764 |

---

## 5. Suspicious Class Data Analysis & Corpus Representation

* **Total Curated SUSPICIOUS Emails**: `102` across entire canonical corpus.
* **Split Allocation**:
  - Train: `72` emails (70.6%)
  - Validation: `16` emails (15.7%)
  - Test: `14` emails (13.7%)

### Source Dataset Representation of Suspicious Emails:

| Source Dataset | Count | Percentage |
|---|---:|---:|
| `trec07` | 71 | 69.6% |
| `ceas08` | 31 | 30.4% |

### Qualitative Insights:
- Suspicious emails predominantly exhibit ambiguous forensic indicators (e.g., authentication neutral/none, free webmail relay, medium urgency text, missing or partial routing metadata).
- Because they do not have overt phishing domains or severe spoofing failures, they naturally fall between LEGITIMATE and PHISHING in feature space.
- Correcting this requires **minority-aware meta-weighting** and **principled validation-tuned decision thresholds**, rather than altering the frozen data.
