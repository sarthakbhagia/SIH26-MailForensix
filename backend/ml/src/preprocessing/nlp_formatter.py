"""Shared NLP text formatting utility for MailForensix.

Ensures strict mathematical and textual parity between training and production inference.
Canonical format:
[SUBJECT]
<subject>

[BODY]
<body>
"""

from typing import Optional


def format_nlp_input(subject: Optional[str], body_text: Optional[str]) -> str:
    """Construct the standard canonical NLP input representation for DistilRoBERTa.

    Args:
        subject: Email subject string (or None/empty).
        body_text: Email plain text body string (or None/empty).

    Returns:
        Structured string formatted with [SUBJECT] and [BODY] sections.
    """
    clean_sub = (subject or "").strip()
    clean_body = (body_text or "").strip()
    return f"[SUBJECT]\n{clean_sub}\n\n[BODY]\n{clean_body}"
