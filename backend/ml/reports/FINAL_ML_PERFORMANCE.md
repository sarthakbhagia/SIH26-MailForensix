# MailForensix ML Final Performance & Model Comparison Report

**Generated:** 2026-09-01T13:20:04.462851+00:00  
**Version:** `mailforensix-ml-v1.1.0`  
**Dataset:** Frozen Test Split (1,548 Real Emails, 0 Synthetic)

---

## 1. Complete Comparative Performance Matrix

| Model / Architecture | Accuracy | Balanced Acc | Macro F1 | Weighted F1 | Suspicious Prec | Suspicious Rec | Suspicious F1 | Phishing F1 | BEC F1 | Log Loss | ECE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Majority Baseline** | 0.5006 | 0.2500 | 0.1668 | 0.3341 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 8.0486 | 0.4994 |
| **Rule Baseline** | 0.5006 | 0.2500 | 0.1668 | 0.3341 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 8.0486 | 0.4994 |
| **DistilRoBERTa (NLP)** | 0.5988 | 0.4978 | 0.4238 | 0.6697 | 0.0000 | 0.0000 | 0.0000 | 0.6993 | 0.8187 | 1.2506 | 0.3812 |
| **LightGBM (Tabular 35)** | 0.9645 | 0.8909 | 0.8139 | 0.9709 | 0.2045 | 0.6429 | 0.3103 | 0.9857 | 0.9955 | 0.1504 | 0.0254 |
| **Phase 4 Stacking Ensemble** | 0.9832 | 0.7424 | 0.7421 | 0.9788 | 0.0000 | 0.0000 | 0.0000 | 0.9892 | 0.9955 | 0.0890 | 0.0105 |
| **Phase 5A Promoted Ensemble** | **0.9871** | **0.9022** | **0.9226** | **0.9868** | **0.8182** | **0.6429 (9/14)** | **0.7200** | **0.9892** | **0.9940** | **0.0862** | **0.0098** |

---

## 2. Progression from Phase 4 to Phase 5A Promoted Release

* **Macro F1 Score:** `0.7421` $ightarrow$ **`0.9226` (+18.05% absolute gain)**
* **Balanced Accuracy:** `0.7424` $ightarrow$ **`0.9022` (+15.98% absolute gain)**
* **SUSPICIOUS F1 Score:** `0.0000` $ightarrow$ **`0.7200` (Recovered 9/14 real test samples)**
* **Overall Accuracy:** `0.9832` $ightarrow$ **`0.9871`**
* **Primary Threat Retention:** Phishing F1 = **`0.9892`**, BEC_Fraud F1 = **`0.9940`**, Legitimate F1 = **`0.9835`**
