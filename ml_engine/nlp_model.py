import re

# Intent keyword patterns for fast intent detection fallback & feature extraction
INTENT_PATTERNS = {
    "Urgency": [
        r"\b(urgent|immediately|action required|suspended|24 hours|account limitation|asap|critical|alert)\b"
    ],
    "Financial Action": [
        r"\b(wire transfer|bank account|invoice|payment|gift card|crypto|bitcoin|payroll|transaction|refund)\b"
    ],
    "Credential Request": [
        r"\b(verify your account|login|password|credentials|security update|sign in|confirm password)\b"
    ],
    "Executive Impersonation": [
        r"\b(ceo|director|president|vip|manager|board member|confidential request)\b"
    ]
}

# Hugging Face Pipeline initialization wrapper
_classifier_pipeline = None

def get_huggingface_pipeline():
    """Lazy initializer for Hugging Face transformer pipeline."""
    global _classifier_pipeline
    if _classifier_pipeline is None:
        try:
            from transformers import pipeline
            # Use a lightweight classifier pipeline
            _classifier_pipeline = pipeline(
                "text-classification",
                model="mrm8488/bert-tiny-finetuned-sms-spam-detection",
                tokenizer="mrm8488/bert-tiny-finetuned-sms-spam-detection"
            )
        except Exception:
            _classifier_pipeline = False  # Soft fallback flag
    return _classifier_pipeline if _classifier_pipeline is not False else None


def analyze_text_intents(text: str) -> list:
    """Detects specific phishing intent cues in text using pattern matching."""
    detected_intents = []
    text_lower = text.lower()

    for intent, patterns in INTENT_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                detected_intents.append(intent)
                break

    return detected_intents


def evaluate_email_nlp(subject: str, body: str) -> dict:
    """
    Evaluates Subject + Body text for spam/phishing probability and intent cues.
    Returns NLP Risk Score (0-100) and detected intent labels.
    """
    combined_text = f"{subject}\n{body}".strip()
    intents = analyze_text_intents(combined_text)

    nlp_score = 0.0
    hf_confidence = None

    # Try Hugging Face Transformer model inference first
    pipeline_model = get_huggingface_pipeline()
    if pipeline_model:
        try:
            # Truncate text for model max tokens
            truncated_text = combined_text[:512]
            results = pipeline_model(truncated_text)
            if results and isinstance(results, list):
                top_pred = results[0]
                label = top_pred.get("label", "").upper()
                score = top_pred.get("score", 0.5)

                if "LABEL_1" in label or "SPAM" in label or "PHISH" in label:
                    nlp_score = score * 100.0
                else:
                    nlp_score = (1.0 - score) * 30.0
                hf_confidence = score
        except Exception:
            pass

    # Heuristic NLP Intent-Based Scoring Boost/Fallback
    intent_penalty = len(intents) * 22.0
    if hf_confidence is None:
        # Pure rule-based NLP evaluation fallback
        nlp_score = min(100.0, intent_penalty)
    else:
        # Hybrid combination of transformer confidence and intent penalties
        nlp_score = min(100.0, max(nlp_score, intent_penalty))

    return {
        "nlp_score": round(float(nlp_score), 2),
        "intents": intents,
        "hf_evaluated": hf_confidence is not None
    }
