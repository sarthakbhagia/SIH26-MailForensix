# MailForensix — Dataset Quality and Governance Report

**Generated At:** 2026-09-01T12:06:15.225091+00:00  
**Leakage Audit Result:** `PASS`

---

## 1. Five-Class Taxonomy & Curation Methodology

- **LEGITIMATE (Class 0)**: Baseline authentic corporate emails from Enron, verified ham from TREC07/CEAS08/SpamAssassin, and legitimate shared task records.
- **SUSPICIOUS (Class 1)**: Curated from candidate spam pools using rule-based semantic scoring (urgency, credential verification cues, payment changes). Ordinary commercial spam is penalised and excluded.
- **PHISHING (Class 2)**: Captured honeypot emails (phishing_pot), verified Nazario mbox archives, and authentic phishing tracks.
- **BEC_FRAUD (Class 3)**: Authentic 419 scam communications (CLAIR collection) + synthetic BEC templates (BEC-2).
- **IMPERSONATION (Class 4)**: Header authentication vulnerabilities, SPF/DKIM/DMARC bypass exploits (EPVME).

## 2. Leakage Audit Checks Summary

- **no_email_id_overlap**: ✅ PASS
- **no_exact_duplicate_crossings**: ✅ PASS
- **no_near_duplicate_crossings**: ✅ PASS
- **no_group_id_crossings**: ✅ PASS
- **no_synthetic_in_test_split**: ✅ PASS
- **all_records_assigned**: ✅ PASS

## 3. Synthetic Data Governance Policy
- **BEC-2**: Retained strictly in Train and Validation splits. **0% in Test split**.
- **EPVME**: Retained for tabular/forensic feature learning.

## 4. Exclusion Reasons Breakdown

- `ordinary_commercial_spam`: 2,898 records
- `insufficient_text_length`: 75 records