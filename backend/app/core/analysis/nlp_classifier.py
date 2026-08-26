import logging
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional
import numpy as np
import httpx

from app.config import settings

logger = logging.getLogger(__name__)

PHISHING_KEYWORDS = {
    "verify your account": 8,
    "verify your identity": 8,
    "click here immediately": 7,
    "confirm your identity": 7,
    "account suspended": 8,
    "unusual activity": 6,
    "security alert": 5,
    "update your payment": 8,
    "verify your email": 7,
    "reset your password": 5,
    "unauthorized access": 7,
    "unauthorized login": 8,
    "account restricted": 8,
    "account termination": 8,
    "permanent account termination": 9,
    "irreversible suspension": 8,
    "your account will be closed": 9,
    "within 24 hours": 6,
    "click below": 4,
    "log in to your account": 5,
}

BEC_KEYWORDS = {
    "wire transfer": 9,
    "bank details": 8,
    "invoice attached": 6,
    "payment due": 7,
    "change of bank": 10,
    "updated account": 9,
    "urgent payment": 9,
    "confidential": 5,
    "do not share": 6,
    "between us": 7,
    "gift cards": 8,
    "itunes card": 9,
    "western union": 8,
    "bitcoin": 7,
}

URGENCY_KEYWORDS = {
    "immediately": 8,
    "urgent": 7,
    "asap": 7,
    "right away": 6,
    "time sensitive": 7,
    "act now": 8,
    "don't delay": 6,
    "limited time": 5,
    "expires today": 8,
    "final notice": 7,
    "last warning": 8,
}

MAX_URGENCY_SCORE = sum(URGENCY_KEYWORDS.values())
CLASS_ORDER = ["Legitimate", "Suspicious", "Phishing", "BEC/Fraud", "Impersonation"]


@dataclass
class NLPClassificationResult:
    label: str
    confidence: float
    probabilities: Dict[str, float]
    urgency_score: float
    bec_indicators: List[str]
    impersonation_signals: List[str]
    contributing_factors: List[str]


class NLPClassifier:
    """Multi-tiered threat classifier combining ML Transformer, Stacking Ensemble, and Rule Heuristics."""

    def __init__(
        self,
        model_path: Optional[str] = None,
        ensemble_path: Optional[str] = None,
    ):
        self.model_path = model_path
        self.ensemble_path = ensemble_path
        self.tokenizer = None
        self.transformer_model = None
        self.ensemble_classifier = None
        self.rule_based_only = True

        # Load transformer model if present on disk
        if model_path and Path(model_path).exists():
            try:
                from transformers import AutoModelForSequenceClassification, AutoTokenizer
                self.tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
                self.transformer_model = AutoModelForSequenceClassification.from_pretrained(
                    model_path, local_files_only=True
                )
                self.transformer_model.eval()
                self.rule_based_only = False
                logger.info(f"Loaded NLP transformer model from {model_path}")
            except Exception as e:
                logger.debug(f"Transformer model load skipped ({e}); using rule fallback.")

        # Load ensemble meta-classifier if present on disk
        if ensemble_path and Path(ensemble_path).exists():
            try:
                from ml.train_ensemble import EnsembleClassifier
                self.ensemble_classifier = EnsembleClassifier(ensemble_path)
                self.rule_based_only = False
                logger.info(f"Loaded Ensemble meta-classifier from {ensemble_path}")
            except Exception as e:
                logger.debug(f"Ensemble meta-classifier load skipped ({e}); using rule fallback.")

        # External inference endpoint configuration (overrides local model if set)
        try:
            self.external_url = settings.NLP_INFERENCE_URL or None
            self.external_auth = settings.NLP_INFERENCE_AUTH or None
        except Exception:
            self.external_url = None
            self.external_auth = None

    def classify(
        self,
        subject: str,
        body_text: str,
        sender: str,
        headers: dict,
    ) -> NLPClassificationResult:
        full_text = (subject + " " + body_text).lower()

        # If configured, call external FastAPI inference endpoint
        if getattr(self, "external_url", None):
            try:
                headers = {}
                if getattr(self, "external_auth", None):
                    headers["Authorization"] = self.external_auth
                resp = httpx.post(self.external_url, json={"text": full_text}, headers=headers, timeout=10.0)
                if resp.status_code == 200:
                    data = resp.json()
                    label = data.get("label", "Legitimate")
                    conf = float(data.get("confidence", 0.0))
                    if conf <= 1.0:
                        conf = conf * 100.0
                    probs = data.get("probabilities")
                    if probs:
                        for k, v in list(probs.items()):
                            v_f = float(v)
                            probs[k] = round(v_f * 100.0, 1) if v_f <= 1.0 else round(v_f, 1)
                    else:
                        probs = {label: round(conf, 1)}
                    return NLPClassificationResult(
                        label=label,
                        confidence=round(conf, 1),
                        probabilities=probs,
                        urgency_score=float(data.get("urgency_score", 0.0)),
                        bec_indicators=data.get("bec_indicators", []),
                        impersonation_signals=data.get("impersonation_signals", []),
                        contributing_factors=data.get("contributing_factors", []),
                    )
            except Exception as e:
                logger.warning(f"External NLP inference failed, falling back to local heuristics: {e}")

        # 1. Rule Heuristic Analysis
        phishing_score = 0
        matched_phishing: List[str] = []
        for keyword, weight in PHISHING_KEYWORDS.items():
            if keyword.lower() in full_text:
                phishing_score += weight
                matched_phishing.append(keyword)

        bec_score = 0
        matched_bec: List[str] = []
        for keyword, weight in BEC_KEYWORDS.items():
            if keyword.lower() in full_text:
                bec_score += weight
                matched_bec.append(keyword)

        urgency_total = 0
        matched_urgency: List[str] = []
        for keyword, weight in URGENCY_KEYWORDS.items():
            if keyword.lower() in full_text:
                urgency_total += weight
                matched_urgency.append(keyword)
        urgency_score = round((urgency_total / MAX_URGENCY_SCORE) * 100, 1) if MAX_URGENCY_SCORE > 0 else 0.0

        # Impersonation checks
        impersonation_signals: List[str] = []
        from_header = headers.get("from", "") if isinstance(headers, dict) else ""
        display_name = ""
        actual_email = ""

        display_match = re.match(r"(.*)\<([^>]+)\>", from_header)
        if display_match:
            display_name = display_match.group(1).strip()
            actual_email = display_match.group(2)
        else:
            actual_email_match = re.search(r"<([^>]+)>", from_header)
            if actual_email_match:
                actual_email = actual_email_match.group(1)

        sender_domain = ""
        if sender:
            sender_domain = sender.split("@")[-1] if "@" in sender else ""

        # Display name vs actual email mismatch
        if display_name and actual_email and display_name.lower() != actual_email.lower():
            impersonation_signals.append("display_name_email_mismatch")

        # Lookalike domain check
        try:
            import tldextract
            ext = tldextract.extract(sender_domain) if sender_domain else None
            from_domain = getattr(ext, "top_domain_under_public_suffix", getattr(ext, "registered_domain", "")) if ext else ""
            for brand in {"google.com", "microsoft.com", "apple.com", "paypal.com", "amazon.com"}:
                if from_domain and from_domain != brand:
                    from_ratio = self._levenshtein(from_domain, brand)
                    from_sim = from_ratio / max(len(from_domain), len(brand))
                    if from_sim > 0.75:
                        impersonation_signals.append(f"lookalike_domain_{brand}")
                        break
        except Exception:
            pass

        # 2. Compute Rule Probability Vector
        max_score = max(phishing_score, bec_score, urgency_total)
        total = phishing_score + bec_score + urgency_total + 1
        rule_probs = np.array([
            max(0.05, 1.0 - (max_score / total)),                    # Legitimate
            urgency_total / total,                                   # Suspicious
            phishing_score / total,                                  # Phishing
            bec_score / total,                                       # BEC/Fraud
            len(impersonation_signals) * 0.4 / (total + 1),          # Impersonation
        ])
        rule_probs = rule_probs / np.sum(rule_probs)

        # 3. Model Inference (if available)
        nlp_probs = rule_probs
        if self.transformer_model and self.tokenizer:
            try:
                import torch
                inputs = self.tokenizer(
                    f"{subject} [SEP] {body_text}",
                    truncation=True,
                    max_length=512,
                    return_tensors="pt",
                )
                with torch.no_grad():
                    logits = self.transformer_model(**inputs).logits
                    nlp_probs = torch.softmax(logits, dim=-1).cpu().numpy()[0]
            except Exception as e:
                logger.debug(f"Transformer inference error: {e}")

        # 4. Stacking Ensemble Prediction (if available)
        if self.ensemble_classifier:
            raw_features = {
                "bec_score": bec_score,
                "phishing_score": phishing_score,
                "urgency_score": urgency_score,
                "lookalike_domain_count": sum(1 for s in impersonation_signals if "lookalike" in s),
                "impersonation_count": len(impersonation_signals),
            }
            # Dummy/heuristic tabular probabilities based on header signals
            tab_probs = rule_probs
            ensemble_pred = self.ensemble_classifier.predict(
                nlp_probs=nlp_probs,
                tabular_probs=tab_probs,
                heuristic_probs=rule_probs,
                raw_features=raw_features,
            )
            return NLPClassificationResult(
                label=ensemble_pred.label,
                confidence=ensemble_pred.confidence,
                probabilities=ensemble_pred.probabilities,
                urgency_score=urgency_score,
                bec_indicators=matched_bec,
                impersonation_signals=impersonation_signals,
                contributing_factors=ensemble_pred.contributing_factors or self._build_factors(
                    phishing_score, bec_score, urgency_score, display_name, actual_email, impersonation_signals
                ),
            )

        # 5. Rule-Based Classification Baseline
        if bec_score >= 14:
            label = "BEC/Fraud"
        elif len(impersonation_signals) >= 2:
            label = "Impersonation"
        elif phishing_score >= 15:
            label = "Phishing"
        elif phishing_score >= 8 or urgency_score >= 40:
            label = "Suspicious"
        else:
            label = "Legitimate"

        confidence = min(100.0, max_score * 3.0) if max_score > 0 else 0.0

        probabilities = {
            CLASS_ORDER[i]: round(float(rule_probs[i]) * 100.0, 1)
            for i in range(len(CLASS_ORDER))
        }

        contributing = self._build_factors(
            phishing_score, bec_score, urgency_score, display_name, actual_email, impersonation_signals
        )

        return NLPClassificationResult(
            label=label,
            confidence=round(confidence, 1),
            probabilities=probabilities,
            urgency_score=urgency_score,
            bec_indicators=matched_bec,
            impersonation_signals=impersonation_signals,
            contributing_factors=contributing,
        )

    def _build_factors(
        self,
        phishing_score: int,
        bec_score: int,
        urgency_score: float,
        display_name: str,
        actual_email: str,
        impersonation_signals: List[str],
    ) -> List[str]:
        contributing: List[str] = []
        if phishing_score >= 5:
            contributing.append(f"phishing_keywords ({phishing_score} points)")
        if bec_score >= 5:
            contributing.append(f"bec_keywords ({bec_score} points)")
        if urgency_score >= 30:
            contributing.append(f"urgency_keywords ({urgency_score}%)")
        if display_name and actual_email and display_name.lower() != actual_email.lower():
            contributing.append("display_name_email_mismatch")
        if impersonation_signals:
            contributing.append(f"impersonation_signals ({len(impersonation_signals)})")
        return contributing

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if not a or not b:
            return max(len(a), len(b))
        n, m = len(a), len(b)
        dp = [[0] * (m + 1) for _ in range(n + 1)]
        for i in range(n + 1):
            dp[i][0] = i
        for j in range(m + 1):
            dp[0][j] = j
        for i in range(1, n + 1):
            for j in range(1, m + 1):
                cost = 0 if a[i - 1] == b[j - 1] else 1
                dp[i][j] = min(
                    dp[i - 1][j] + 1,
                    dp[i][j - 1] + 1,
                    dp[i - 1][j - 1] + cost,
                )
        return dp[n][m]