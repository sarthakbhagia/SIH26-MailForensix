# MailForensix — Master Dataset Inventory Report

**Generated At:** 2026-08-31T16:33:05.675533+00:00  
**Total Datasets Configured:** 12  
**Specification:** `implementation.md` Section 7, 8, and 45

---

## 1. Dataset Status Overview

| Dataset | Role | Format | Status | Discovered Msg | Parseable Msg | Failures | Synthetic? | License Verified? |
|---|---|---|---|---:|---:|---:|---|---|
| **enron** (Enron Email Dataset) | maildir | `maildir` | `not_downloaded` | 0 | 0 | 0 | No (Authentic) | Yes |
| **trec07** (TREC 2007 Public Spam Corpus (trec07p)) | rfc822 | `rfc822` | `requires_manual_acquisition` | 0 | 0 | 0 | No (Authentic) | Yes |
| **nazario** (Jose Nazario Phishing Corpus) | mbox | `mbox` | `not_downloaded` | 0 | 0 | 0 | No (Authentic) | Needs Confirmation |
| **phishing_pot** (Phishing Pot Honeypot Collection) | rfc822 | `rfc822` | `not_downloaded` | 0 | 0 | 0 | No (Authentic) | Yes |
| **epvme** (EPVME Email Security Vulnerability Dataset) | eml | `rfc822` | `not_downloaded` | 0 | 0 | 0 | Yes (LLM/Injected) | Needs Confirmation |
| **ceas08** (CEAS 2008 Spam Conference Corpus) | rfc822 | `rfc822` | `requires_manual_acquisition` | 0 | 0 | 0 | No (Authentic) | Yes |
| **iwspa_ap** (IWSPA-AP Shared Task Phishing Dataset) | tsv_csv_eml | `csv` | `not_downloaded` | 0 | 0 | 0 | No (Authentic) | Needs Confirmation |
| **zefang_liu** (Zefang Liu Phishing Email Dataset (HuggingFace)) | csv | `csv` | `not_downloaded` | 0 | 0 | 0 | No (Authentic) | Yes |
| **clair** (CLAIR Collection of Fraud Email (ADCR2008T001)) | txt_collection | `clair` | `not_downloaded` | 0 | 0 | 0 | No (Authentic) | Yes |
| **bec2** (BEC-2 Dataset (Rohit Dube 2025)) | json_csv | `bec2` | `not_downloaded` | 0 | 0 | 0 | Yes (LLM/Injected) | Needs Confirmation |
| **spamassassin** (Apache SpamAssassin Public Corpus) | rfc822 | `rfc822` | `not_downloaded` | 0 | 0 | 0 | No (Authentic) | Yes |
| **sample_emails** (MailForensix Local Sample Emails) | eml | `rfc822` | `present_local` | 4 | 4 | 0 | No (Authentic) | Yes |

**Totals Measured on Disk:** 4 discovered, 4 parseable, 0 failures.

---

## 2. Dataset-by-Dataset Detailed Findings

### ENRON — Enron Email Dataset
- **Source URL:** https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz
- **Source Type:** `archive_download`
- **Expected Format / Parser:** `maildir` / `maildir`
- **Local Path:** `ml\data\raw\enron`
- **Acquisition Status:** `not_downloaded`
- **SHA256:** `N/A`
- **Git Commit SHA:** `N/A`
- **License:** Public Domain (FERC Record) (Verified: True)
- **Synthetic Flag:** False (Source: None)
- **Notes:** Baseline authentic corporate legitimate emails. Header chain is internal/partial.

### TREC07 — TREC 2007 Public Spam Corpus (trec07p)
- **Source URL:** https://plg.uwaterloo.ca/~gvcormac/treccorpus07/
- **Source Type:** `restricted_archive`
- **Expected Format / Parser:** `rfc822` / `rfc822`
- **Local Path:** `ml\data\raw\trec07`
- **Acquisition Status:** `requires_manual_acquisition`
- **SHA256:** `N/A`
- **Git Commit SHA:** `N/A`
- **License:** Research-only, non-redistributable (Waterloo Usage Agreement) (Verified: True)
- **Synthetic Flag:** False (Source: None)
- **Notes:** Requires accepting Waterloo web agreement. Spam portion serves as candidate pool for Suspicious class filtering.
- ⚠️ **Manual Acquisition Required:** Download archive from https://plg.uwaterloo.ca/~gvcormac/treccorpus07/ (accept agreement) and unpack into ml\data\raw\trec07

### NAZARIO — Jose Nazario Phishing Corpus
- **Source URL:** https://monkey.org/~jose/phishing/
- **Source Type:** `archive_download`
- **Expected Format / Parser:** `mbox` / `mbox`
- **Local Path:** `ml\data\raw\nazario`
- **Acquisition Status:** `not_downloaded`
- **SHA256:** `N/A`
- **Git Commit SHA:** `N/A`
- **License:** Public research archive (Verified: False)
- **Synthetic Flag:** False (Source: None)
- **Notes:** Canonical historical phishing collection in mbox format. Note: NOT github.com/r-dube/bec.

### PHISHING_POT — Phishing Pot Honeypot Collection
- **Source URL:** https://github.com/rf-peixoto/phishing_pot
- **Source Type:** `git_repository`
- **Expected Format / Parser:** `rfc822` / `rfc822`
- **Local Path:** `ml\data\raw\phishing_pot`
- **Acquisition Status:** `not_downloaded`
- **SHA256:** `N/A`
- **Git Commit SHA:** `N/A`
- **License:** GPL-3.0 (Verified: True)
- **Synthetic Flag:** False (Source: None)
- **Notes:** Modern honeypot-captured phishing emails with complete RFC822 headers and PII redaction.

### EPVME — EPVME Email Security Vulnerability Dataset
- **Source URL:** https://github.com/sunknighteric/EPVME-Dataset/
- **Source Type:** `git_repository`
- **Expected Format / Parser:** `eml` / `rfc822`
- **Local Path:** `ml\data\raw\epvme`
- **Acquisition Status:** `not_downloaded`
- **SHA256:** `N/A`
- **Git Commit SHA:** `N/A`
- **License:** Academic research / GitHub public repo (Verified: False)
- **Synthetic Flag:** True (Source: EPVME (Recombined text + injected SPF/DMARC attack headers))
- **Notes:** Primary source for forensic/header authentication attacks. Do NOT use as primary NLP prose corpus.

### CEAS08 — CEAS 2008 Spam Conference Corpus
- **Source URL:** https://plg.uwaterloo.ca/~gvcormac/ceascorpus/
- **Source Type:** `restricted_archive`
- **Expected Format / Parser:** `rfc822` / `rfc822`
- **Local Path:** `ml\data\raw\ceas08`
- **Acquisition Status:** `requires_manual_acquisition`
- **SHA256:** `N/A`
- **Git Commit SHA:** `N/A`
- **License:** Research-only, non-redistributable (CEAS Agreement) (Verified: True)
- **Synthetic Flag:** False (Source: None)
- **Notes:** Supplementary ham and candidate spam pool.
- ⚠️ **Manual Acquisition Required:** Download archive from https://plg.uwaterloo.ca/~gvcormac/ceascorpus/ (accept agreement) and unpack into ml\data\raw\ceas08

### IWSPA_AP — IWSPA-AP Shared Task Phishing Dataset
- **Source URL:** https://github.com/dasavisha/IWSPA-sharedtask
- **Source Type:** `git_repository`
- **Expected Format / Parser:** `tsv_csv_eml` / `csv`
- **Local Path:** `ml\data\raw\iwspa_ap`
- **Acquisition Status:** `not_downloaded`
- **SHA256:** `N/A`
- **Git Commit SHA:** `N/A`
- **License:** Academic research (CEUR-WS Vol-2124) (Verified: False)
- **Synthetic Flag:** False (Source: None)
- **Notes:** Contains both header and no-header tracks with realistic imbalance.

### ZEFANG_LIU — Zefang Liu Phishing Email Dataset (HuggingFace)
- **Source URL:** https://huggingface.co/datasets/zefang-liu/phishing-email-dataset
- **Source Type:** `huggingface`
- **Expected Format / Parser:** `csv` / `csv`
- **Local Path:** `ml\data\raw\zefang_liu`
- **Acquisition Status:** `not_downloaded`
- **SHA256:** `N/A`
- **Git Commit SHA:** `N/A`
- **License:** LGPL-3.0 (Verified: True)
- **Synthetic Flag:** False (Source: None)
- **Notes:** NLP volume dataset. Body text and subject only; no forensic headers.

### CLAIR — CLAIR Collection of Fraud Email (ADCR2008T001)
- **Source URL:** https://aclweb.org/aclwiki/CLAIR_collection_of_fraud_email_(Repository)
- **Source Type:** `archive_download`
- **Expected Format / Parser:** `txt_collection` / `clair`
- **Local Path:** `ml\data\raw\clair`
- **Acquisition Status:** `not_downloaded`
- **SHA256:** `N/A`
- **Git Commit SHA:** `N/A`
- **License:** Creative Commons Attribution-ShareAlike 3.0 US (Verified: True)
- **Synthetic Flag:** False (Source: None)
- **Notes:** Authentic advance-fee / 419 fraud scam emails. Must retain fraud_subtype='419_advance_fee'.

### BEC2 — BEC-2 Dataset (Rohit Dube 2025)
- **Source URL:** https://github.com/r-dube/bec
- **Source Type:** `git_repository`
- **Expected Format / Parser:** `json_csv` / `bec2`
- **Local Path:** `ml\data\raw\bec2`
- **Acquisition Status:** `not_downloaded`
- **SHA256:** `N/A`
- **Git Commit SHA:** `N/A`
- **License:** Academic research (Verified: False)
- **Synthetic Flag:** True (Source: BEC-2 (LLM-generated; Rohit Dube 2025))
- **Notes:** 279 LLM-generated BEC emails. Training-only; must be excluded from real evaluation test set.

### SPAMASSASSIN — Apache SpamAssassin Public Corpus
- **Source URL:** https://spamassassin.apache.org/old/publiccorpus/
- **Source Type:** `archive_download`
- **Expected Format / Parser:** `rfc822` / `rfc822`
- **Local Path:** `ml\data\raw\spamassassin`
- **Acquisition Status:** `not_downloaded`
- **SHA256:** `N/A`
- **Git Commit SHA:** `N/A`
- **License:** Apache-2.0 / Public (Verified: True)
- **Synthetic Flag:** False (Source: None)
- **Notes:** Canonical snapshots (~6,047 messages). Spam subset feeds Suspicious candidate pool.

### SAMPLE_EMAILS — MailForensix Local Sample Emails
- **Source URL:** local://sample_emails
- **Source Type:** `local_dir`
- **Expected Format / Parser:** `eml` / `rfc822`
- **Local Path:** `..\sample_emails`
- **Acquisition Status:** `present_local`
- **SHA256:** `N/A`
- **Git Commit SHA:** `N/A`
- **License:** Internal Project Fixture (Verified: True)
- **Synthetic Flag:** False (Source: None)
- **Notes:** Local EML samples included in the repository for validation.

---

## 3. Provenance & Compliance Invariants Checked

- [x] `github.com/r-dube/bec` is strictly tracked as **BEC-2** (synthetic), never confused with Nazario.
- [x] PhishTank is excluded from email content training.
- [x] EPVME is designated as semi-synthetic header attack material for tabular/forensic features.
- [x] Immutable raw evidence is preserved; all normalization occurs on derived representations.
- [x] Deterministic `email_id` computation guarantees reproducibility across runs.