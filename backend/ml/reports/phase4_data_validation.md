# Phase 4 Pre-Training Data Validation Report

**Generated:** 2026-09-01T17:22:11.578470  
**Dataset Manifest SHA256:** b4c520fddc5eb5706837cd181c5b2fbc9e0aedacace3bd17e9b37533d6f08cef  
**Splits Manifest SHA256:** bc0d2ce5d3f2087968e2a8ddd51df3cbd5d6508c6fa93a68ba495f4c7f3e1949  
**Leakage Audit Status:** PASS  

---

## 1. Verified Record Counts

- **Total Usable Records:** 14,069
- **Train Records (70%):** 9,695
- **Validation Records (15%):** 2,826
- **Test Records (15%):** 1,548

## 2. Target Class Distribution (Usable Corpus)

| Canonical Label | Total Count | Train | Validation | Test |
|---|---:|---:|---:|---:|
| **LEGITIMATE** | 6,202 | 4,537 | 890 | 775 |
| **PHISHING** | 3,561 | 2,055 | 1,083 | 423 |
| **BEC_FRAUD** | 2,519 | 1,797 | 386 | 336 |
| **IMPERSONATION** | 1,685 | 1,234 | 451 | 0 |
| **SUSPICIOUS** | 102 | 72 | 16 | 14 |

## 3. Real vs. Synthetic Breakdown

- **Real Records:** 12,105 (86.0%)
- **Synthetic Records:** 1,964 (14.0%)
- **Synthetic Records in Test Set:** **0 (0.0%)**

## 4. Leakage Verification Checklist

- [x] 
o_email_id_overlap: **True**
- [x] 
o_exact_duplicate_crossings: **True**
- [x] 
o_near_duplicate_crossings: **True**
- [x] 
o_group_id_crossings: **True**
- [x] 
o_synthetic_in_test_split: **True**
- [x] ll_records_assigned: **True**

**Decision:** Hand-off verification PASSED. Dataset is clean, group-isolated, and ready for model training.
