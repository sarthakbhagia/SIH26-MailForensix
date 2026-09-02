# MailForensix — Master Corpus Build Report

**Generated At:** 2026-09-01T12:06:15.224389+00:00  
**Specification:** `implementation.md` Phase 3 (Parts A & B)

---

## 1. Ingestion Summary

- **Total Raw Messages Ingested:** 22,571
- **Total Unique Canonical Records (Post-Exact-Dedup):** 17,042
- **Total Training-Usable Records:** 14,069
- **Excluded Records (Ordinary Spam / Malformed):** 2,973

## 2. Per-Dataset Parser Ingestion Statistics

| Dataset | Format | Discovered | Parsed | Failures | NLP Usable | Forensic Usable |
|---|---|---:|---:|---:|---:|---:|
| **enron** (Enron Email Dataset) | `maildir` | 2,500 | 2,500 | 0 | 2,500 | 2,500 |
| **trec07** (TREC 2007 Public Spam Corpus (trec07p)) | `rfc822` | 2,500 | 2,500 | 0 | 2,500 | 2,500 |
| **nazario** (Jose Nazario Phishing Corpus) | `mbox` | 2,293 | 2,292 | 1 | 2,266 | 2,292 |
| **phishing_pot** (Phishing Pot Honeypot Collection) | `rfc822` | 2,501 | 2,500 | 0 | 2,495 | 2,500 |
| **epvme** (EPVME Email Security Vulnerability Dataset) | `eml` | 2,500 | 2,500 | 0 | 2,496 | 2,371 |
| **ceas08** (CEAS 2008 Spam Conference Corpus) | `rfc822` | 2,500 | 2,500 | 0 | 2,500 | 2,500 |
| **iwspa_ap** (IWSPA-AP Shared Task Phishing Dataset) | `tsv_csv_eml` | 0 | 0 | 0 | 0 | 0 |
| **zefang_liu** (Zefang Liu Phishing Email Dataset (HuggingFace)) | `csv` | 2,500 | 2,500 | 0 | 0 | 0 |
| **clair** (CLAIR Collection of Fraud Email (ADCR2008T001)) | `txt_collection` | 2,500 | 2,500 | 0 | 2,310 | 0 |
| **bec2** (BEC-2 Dataset (Rohit Dube 2025)) | `json_csv` | 279 | 279 | 0 | 279 | 279 |
| **spamassassin** (Apache SpamAssassin Public Corpus) | `rfc822` | 2,500 | 2,500 | 0 | 2,500 | 2,498 |
| **sample_emails** (MailForensix Local Sample Emails) | `eml` | 0 | 0 | 0 | 0 | 0 |

---
## 3. Provenance and Integrity Guarantees
- [x] Every canonical email retains full pointer chain to its raw source record.
- [x] Exact raw byte, full normalized text, and body hashes are recorded.
- [x] BEC-2 is explicitly tracked with `is_synthetic=True` and isolated from the Test split.
- [x] EPVME is designated as `construction_type='header_recombination'` for tabular forensics.