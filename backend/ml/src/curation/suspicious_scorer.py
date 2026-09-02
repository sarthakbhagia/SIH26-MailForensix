"""Interpretable Semantic Suspicious Scorer for MailForensix ML Pipeline.

Implements Parts I, J, K of Phase 3 specification:
- Rule-based interpretable candidate scoring for spam candidate pool (TREC07, CEAS08, SpamAssassin)
- Distinguishes security-suspicious emails from ordinary commercial bulk spam
- Evaluates urgency, account security, financial cues, technical anomalies, and benign penalties
- Generates candidate_score, reason_codes, and suggested_label
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Tuple

from ml.src.schemas.canonical_email import CanonicalEmail


@dataclass
class SuspiciousScoreResult:
    email_id: str
    candidate_score: float
    reason_codes: List[str]
    suggested_label: str                       # "SUSPICIOUS", "PHISHING", "BEC_FRAUD", "ORDINARY_SPAM"
    is_suspicious_candidate: bool
    summary: str


class SemanticSuspiciousScorer:
    """Evaluates candidate spam emails with interpretable security and benign heuristics."""

    # 1. Social Engineering & Urgency Patterns
    URGENCY_PATTERNS = [
        (re.compile(r'\b(urgent|immediate|immediately|action required|act now|24 hours?|48 hours?|deadline)\b', re.IGNORECASE), "SE_URGENT_DEADLINE", 1.5),
        (re.compile(r'\b(account (suspended|locked|terminated|disabled|frozen|restricted|flagged))\b', re.IGNORECASE), "SE_ACCOUNT_SUSPENSION", 2.5),
        (re.compile(r'\b(verify|confirm|validate|reactivate|update) (your )?(account|details|identity|security|password|profile|information)\b', re.IGNORECASE), "SE_CREDENTIAL_VERIFY", 2.5),
        (re.compile(r'\b(unauthorized|suspicious|unusual) (activity|access|logins?|sign-in)\b', re.IGNORECASE), "SE_SECURITY_ALERT", 2.0),
        (re.compile(r'\b(click (here|below|this link)|login immediately|follow the instructions)\b', re.IGNORECASE), "SE_SUSPICIOUS_CTA", 1.2),
        (re.compile(r'\b(reset (your )?password|temporary password|security key)\b', re.IGNORECASE), "SE_PASSWORD_RESET", 1.5),
    ]

    # 2. Financial & BEC Fraud Patterns
    FINANCIAL_PATTERNS = [
        (re.compile(r'\b(wire transfer|bank transfer|remittance|swift|routing number|iban)\b', re.IGNORECASE), "FIN_WIRE_TRANSFER", 2.0),
        (re.compile(r'\b(invoice|payment (overdue|pending|due|receipt|statement)|billing error)\b', re.IGNORECASE), "FIN_INVOICE_CUE", 1.5),
        (re.compile(r'\b(million (dollars|usd|\$|pounds|gbp|euros?|€)|beneficiary|fund transfer|inheritance|lottery winner|next of kin)\b', re.IGNORECASE), "FIN_419_FRAUD", 3.0),
        (re.compile(r'\b(crypto|bitcoin|btc|wallet address|confidential acquisition)\b', re.IGNORECASE), "FIN_CRYPTO_ANOMALY", 1.5),
    ]

    # 3. Technical & Obfuscation Patterns
    TECH_PATTERNS = [
        (re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.IGNORECASE), "TECH_IP_URL", 2.0),
        (re.compile(r'https?://[^\s/]+\.(ru|xyz|top|work|click|info|cc|tk|ml|ga|cf|gq)/', re.IGNORECASE), "TECH_SUSPICIOUS_TLD", 1.5),
        (re.compile(r'\.(exe|vbs|bat|cmd|scr|pif|hta|dll|iso|jar|wsf)\b', re.IGNORECASE), "TECH_DANGEROUS_EXT", 3.0),
    ]

    # 4. Benign Commercial & Bulk Indicators (Penalties)
    BENIGN_PATTERNS = [
        (re.compile(r'\b(unsubscribe|opt[ -]out|manage (your )?preferences|email preferences|email newsletter)\b', re.IGNORECASE), "BENIGN_UNSUBSCRIBE", -2.5),
        (re.compile(r'\b(view (this|online) in browser|privacy policy|terms (of service|and conditions)|all rights reserved)\b', re.IGNORECASE), "BENIGN_COMMERCIAL_FOOTER", -1.5),
        (re.compile(r'\b(discount|sale|clearance|free shipping|promo code|coupon|save \d+%|\d+% off|shop now|special offer)\b', re.IGNORECASE), "BENIGN_ADVERTISEMENT", -2.0),
        (re.compile(r'\b(mailing list|digest|listserv|debian-mirrors|apache\.org|sourceforge)\b', re.IGNORECASE), "BENIGN_MAILING_LIST", -3.0),
    ]

    def score_email(self, email: CanonicalEmail) -> SuspiciousScoreResult:
        """Score a single email for forensic/security suspiciousness."""
        text_content = f"{email.subject} {email.body_plain} {email.body_html}"
        score = 0.0
        reason_codes: List[str] = []

        # 1. Social engineering checks
        for pattern, code, weight in self.URGENCY_PATTERNS:
            if pattern.search(text_content):
                score += weight
                reason_codes.append(code)

        # 2. Financial checks
        for pattern, code, weight in self.FINANCIAL_PATTERNS:
            if pattern.search(text_content):
                score += weight
                reason_codes.append(code)

        # 3. Technical checks
        for pattern, code, weight in self.TECH_PATTERNS:
            if pattern.search(text_content):
                score += weight
                reason_codes.append(code)

        # 4. URL count heuristic
        if len(email.urls) > 5:
            score += 1.0
            reason_codes.append("TECH_HIGH_URL_COUNT")
        elif len(email.urls) >= 1 and any("SE_" in c for c in reason_codes):
            score += 1.0
            reason_codes.append("TECH_CTA_WITH_URL")

        # 5. Attachment heuristic
        for att in email.attachments:
            fname = att.get("filename", "").lower()
            if any(fname.endswith(ext) for ext in [".exe", ".zip", ".iso", ".scr", ".vbs", ".html", ".htm"]):
                score += 2.5
                reason_codes.append("TECH_SUSPICIOUS_ATTACHMENT")
                break

        # 6. Apply benign penalties
        for pattern, code, penalty in self.BENIGN_PATTERNS:
            if pattern.search(text_content):
                score += penalty
                reason_codes.append(code)

        score = max(0.0, round(score, 2))

        # Classification decision
        if "FIN_419_FRAUD" in reason_codes and score >= 3.0:
            suggested = "BEC_FRAUD"
            is_susp = True
        elif ("SE_CREDENTIAL_VERIFY" in reason_codes or "SE_ACCOUNT_SUSPENSION" in reason_codes) and "TECH_CTA_WITH_URL" in reason_codes and score >= 3.5:
            suggested = "PHISHING"
            is_susp = True
        elif score >= 2.0:
            suggested = "SUSPICIOUS"
            is_susp = True
        else:
            suggested = "ORDINARY_SPAM"
            is_susp = False

        summary = f"Score: {score} | Reasons: {', '.join(reason_codes) if reason_codes else 'None'}"

        return SuspiciousScoreResult(
            email_id=email.email_id,
            candidate_score=score,
            reason_codes=reason_codes,
            suggested_label=suggested,
            is_suspicious_candidate=is_susp,
            summary=summary,
        )
