# MailForensix Phase 4 Model Training, Calibration & Evaluation Report

**Generated:** 2026-09-01T12:37:25.270845+00:00  
**Git Commit SHA:** `d08a53c96a63696a2fde58740e8a92819cb71ada`  
**Elapsed Pipeline Time:** 970.3 seconds  
**Test Set Integrity:** 1,548 Real Emails (0.0% Synthetic)  

---

## 1. Executive Summary & Benchmark Results

| Model | Accuracy | Balanced Acc | Macro F1 | Weighted F1 | Multi-Class Log Loss |
|---|---:|---:|---:|---:|---:|
| **Majority Baseline** | 0.5006 | 0.2500 | 0.1668 | 0.3341 | 8.0486 |
| **Rule Heuristics** | 0.5006 | 0.2500 | 0.1668 | 0.3341 | 8.0486 |
| **DistilRoBERTa (NLP)** | 0.5988 | 0.4978 | 0.4238 | 0.6697 | 1.2506 |
| **LightGBM (Tabular 35)** | 0.9645 | 0.8909 | 0.8139 | 0.9709 | 0.1504 |
| **Stacking Ensemble (15D)** | **0.9832** | **0.7424** | **0.7421** | **0.9788** | **0.0890** |

---

## 2. Per-Class Performance Breakdown (Stacking Ensemble on Test Split)

| Class Name | Support (Real Test) | Precision | Recall | F1 Score | Notes / Limitations |
|---|---:|---:|---:|---:|---|
| **LEGITIMATE** | 775 | 0.9675 | 1.0000 | 0.9835 | Standard evaluated class |
| **SUSPICIOUS** | 14 | 0.0000 | 0.0000 | 0.0000 | Minority curated class |
| **PHISHING** | 423 | 1.0000 | 0.9787 | 0.9892 | Standard evaluated class |
| **BEC_FRAUD** | 336 | 1.0000 | 0.9911 | 0.9955 | Standard evaluated class |
| **IMPERSONATION** | 0 | N/A | N/A | N/A | *NOT AVAILABLE / INSUFFICIENT REAL TEST DATA (0 real test emails)* |

---

## 3. Probability Calibration Impact (Held-Out Validation Set)

* **DistilRoBERTa**: ECE improved from `0.3812` to `0.0577`.
* **LightGBM**: ECE improved from `0.0254` to `0.0060`.

---

## 4. Tabular Feature Ablation Studies

| Experiment | Features | Macro F1 | Weighted F1 | Accuracy | Log Loss |
|---|---:|---:|---:|---:|---:|
| **Exp_A_All_35_Features** | 35 | 0.8515 | 0.9730 | 0.9689 | 0.1460 |
| **Exp_B_Category_A_Only** | 24 | 0.8226 | 0.9592 | 0.9519 | 0.1862 |
| **Exp_C_Category_B_Only** | 11 | 0.4730 | 0.5935 | 0.5223 | 0.9163 |
| **Exp_D_CatA_CatB_Reliability** | 35 | 0.8515 | 0.9730 | 0.9689 | 0.1460 |

---

## 5. Architectural & Training Safeguards Summary

1. **Leakage-Free NLP Inputs**: All text inputs follow canonical `[SUBJECT] ... [BODY]` representation without metadata or dataset tags.
2. **Train-Only Class Weights**: Class weights calculated strictly on Train split to prevent test set distribution leakage.
3. **Group-Aware 5-Fold OOF Predictions**: Stacking meta-classifier trained exclusively on cross-validated out-of-sample predictions respecting `leakage_group_id`.
4. **Frozen Evaluation**: All base model parameters, Optuna trials, calibration mappings, and meta-weights were frozen prior to touching the Test split.
