import logging
import os
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
from app.config import settings
from app.core.correlation.threat_intel import ThreatIntelReport

logger = logging.getLogger(__name__)


@dataclass
class RiskFactorScore:
    name: str               # "NLP Threat Classification", "Authentication Verification", etc.
    raw_score: float        # 0-100 raw score
    weight: float           # 0.0-1.0 weight
    weighted_score: float   # raw * weight
    details: str            # Human-readable explanation
    severity: str           # "low" | "medium" | "high" | "critical"


@dataclass
class CompositeRiskScore:
    overall_score: float            # 0-100 weighted composite score
    severity: str                   # "low" | "medium" | "high" | "critical"
    factors: List[RiskFactorScore]
    recommended_action: str         # Human-readable recommended action
    threat_intel_enhanced: bool     # Whether external TI feeds enhanced the score


def normalize_threat_label(label: Optional[str]) -> str:
    """Canonical normalization of threat classification labels across MailForensix.
    
    Guarantees mapping of all variants (uppercase, title-case, snake_case, slash-separated, abbreviations)
    to the canonical uppercase taxonomy:
      - 'LEGITIMATE'
      - 'SUSPICIOUS'
      - 'PHISHING'
      - 'BEC_FRAUD'
      - 'IMPERSONATION'
    """
    if not label:
        return "LEGITIMATE"
    
    cleaned = str(label).strip().upper().replace(" ", "_").replace("-", "_").replace("/", "_")
    
    if cleaned in ("LEGITIMATE", "CLEAN", "BENIGN", "NORMAL", "SAFE", "HAM"):
        return "LEGITIMATE"
    elif cleaned in ("PHISHING", "PHISH", "CREDENTIAL_HARVESTING"):
        return "PHISHING"
    elif cleaned in ("BEC_FRAUD", "BEC", "FRAUD", "WIRE_FRAUD", "CEO_FRAUD", "FINANCIAL_FRAUD"):
        return "BEC_FRAUD"
    elif cleaned in ("IMPERSONATION", "SPOOF", "SPOOFING", "BRAND_IMPERSONATION", "EXECUTIVE_IMPERSONATION"):
        return "IMPERSONATION"
    elif cleaned in ("SUSPICIOUS", "ANOMALOUS", "SUSPICION", "WARNING"):
        return "SUSPICIOUS"
    
    if "PHISH" in cleaned:
        return "PHISHING"
    if "BEC" in cleaned or "FRAUD" in cleaned:
        return "BEC_FRAUD"
    if "IMPERSONAT" in cleaned or "SPOOF" in cleaned:
        return "IMPERSONATION"
    if "SUSPIC" in cleaned or "WARN" in cleaned:
        return "SUSPICIOUS"
    if "LEGIT" in cleaned or "CLEAN" in cleaned:
        return "LEGITIMATE"
        
    return "LEGITIMATE"


class RiskScorer:
    """Computes a multi-factor composite threat risk score across all Phase 2 and Phase 3 signals."""

    DEFAULT_WEIGHTS = {
        "nlp_threat": getattr(settings, "RISK_WEIGHT_NLP", 0.35),
        "auth_confidence": getattr(settings, "RISK_WEIGHT_AUTH", 0.25),
        "ip_reputation": getattr(settings, "RISK_WEIGHT_IP", 0.20),
        "link_risk": getattr(settings, "RISK_WEIGHT_LINK", 0.10),
        "attachment_risk": getattr(settings, "RISK_WEIGHT_GEO", 0.10),  # 0.10 default
    }

    SEVERITY_THRESHOLDS = {
        "low": (0, 25),
        "medium": (26, 50),
        "high": (51, 75),
        "critical": (76, 100),
    }

    ACTION_MAP = {
        "low": "No action needed — email appears legitimate",
        "medium": "Review recommended — some suspicious indicators detected",
        "high": "Quarantine — significant threat indicators present",
        "critical": "Block & Investigate — high-confidence threat detection",
    }

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights or dict(self.DEFAULT_WEIGHTS)
        # Normalize weights to sum to 1.0
        total_w = sum(self.weights.values()) or 1.0
        self.weights = {k: v / total_w for k, v in self.weights.items()}

    def _score_to_severity(self, score: float) -> str:
        if score >= 76:
            return "critical"
        elif score >= 51:
            return "high"
        elif score >= 26:
            return "medium"
        return "low"

    def score(self, *args, **kwargs) -> Any:
        """Backward-compatible alias for compute()."""
        return self.compute(*args, **kwargs)

    def compute(
        self,
        nlp_result: Any,
        header_result: Any,
        geo_result: Any,
        link_result: Any = None,
        attachment_result: Any = None,
        threat_intel: Optional[ThreatIntelReport] = None,
    ) -> CompositeRiskScore:
        """Compute weighted composite threat risk score."""
        factors: List[RiskFactorScore] = []

        # 1. NLP Threat Score
        nlp_risk, nlp_details = self._compute_nlp_risk(nlp_result)
        w_nlp = self.weights.get("nlp_threat", 0.35)
        factors.append(RiskFactorScore(
            name="NLP Threat Classification",
            raw_score=round(nlp_risk, 1),
            weight=round(w_nlp, 2),
            weighted_score=round(nlp_risk * w_nlp, 2),
            details=nlp_details,
            severity=self._score_to_severity(nlp_risk),
        ))

        # 2. Authentication Confidence (inverted — lower auth confidence = higher risk)
        auth_score = getattr(header_result, "auth_confidence_score", 50.0) if header_result else 50.0
        if isinstance(header_result, dict):
            auth_score = header_result.get("auth_confidence_score", 50.0)
        auth_risk = max(0.0, min(100.0, 100.0 - float(auth_score)))

        auth_details = self._extract_auth_details(header_result)
        w_auth = self.weights.get("auth_confidence", 0.25)
        factors.append(RiskFactorScore(
            name="Authentication Verification",
            raw_score=round(auth_risk, 1),
            weight=round(w_auth, 2),
            weighted_score=round(auth_risk * w_auth, 2),
            details=auth_details,
            severity=self._score_to_severity(auth_risk),
        ))

        # 3. IP & Geo Intelligence (inverted — lower IP reputation = higher risk)
        ip_rep = getattr(geo_result, "ip_reputation_score", 50.0) if geo_result else 50.0
        if isinstance(geo_result, dict):
            ip_rep = geo_result.get("ip_reputation_score", 50.0)
        ip_risk = max(0.0, min(100.0, 100.0 - float(ip_rep)))

        if threat_intel:
            ip_risk = self._enhance_ip_risk(ip_risk, threat_intel)

        ip_details = self._extract_geo_details(geo_result)
        w_ip = self.weights.get("ip_reputation", 0.20)
        factors.append(RiskFactorScore(
            name="IP & Geo Intelligence",
            raw_score=round(ip_risk, 1),
            weight=round(w_ip, 2),
            weighted_score=round(ip_risk * w_ip, 2),
            details=ip_details,
            severity=self._score_to_severity(ip_risk),
        ))

        # 4. Link Analysis
        link_risk = float(getattr(link_result, "overall_link_risk", 0.0) if link_result else 0.0)
        if isinstance(link_result, dict):
            link_risk = float(link_result.get("overall_link_risk", 0.0))
        if threat_intel:
            link_risk = self._enhance_link_risk(link_risk, threat_intel)

        urls_analyzed = getattr(link_result, "urls_analyzed", 0) if link_result else 0
        phish_urls = getattr(link_result, "phishing_urls_found", 0) if link_result else 0
        w_link = self.weights.get("link_risk", 0.10)
        factors.append(RiskFactorScore(
            name="Link Analysis",
            raw_score=round(link_risk, 1),
            weight=round(w_link, 2),
            weighted_score=round(link_risk * w_link, 2),
            details=f"URLs analyzed: {urls_analyzed}, Phishing: {phish_urls}",
            severity=self._score_to_severity(link_risk),
        ))

        # 5. Attachment Analysis
        att_risk = float(getattr(attachment_result, "overall_attachment_risk", 0.0) if attachment_result else 0.0)
        if isinstance(attachment_result, dict):
            att_risk = float(attachment_result.get("overall_attachment_risk", 0.0))
        if threat_intel:
            att_risk = self._enhance_attachment_risk(att_risk, threat_intel)

        tot_atts = getattr(attachment_result, "total_attachments", 0) if attachment_result else 0
        w_att = self.weights.get("attachment_risk", 0.10)
        factors.append(RiskFactorScore(
            name="Attachment Analysis",
            raw_score=round(att_risk, 1),
            weight=round(w_att, 2),
            weighted_score=round(att_risk * w_att, 2),
            details=f"Total attachments: {tot_atts}",
            severity=self._score_to_severity(att_risk),
        ))

        # Composite overall calculation
        overall = sum(f.weighted_score for f in factors)
        overall = round(min(100.0, max(0.0, overall)), 1)
        severity = self._score_to_severity(overall)

        return CompositeRiskScore(
            overall_score=overall,
            severity=severity,
            factors=factors,
            recommended_action=self.ACTION_MAP[severity],
            threat_intel_enhanced=threat_intel is not None,
        )

    def _compute_nlp_risk(self, nlp_result: Any) -> tuple[float, str]:
        """Compute NLP risk score and details from NLP classification result using canonical label normalization."""
        if not nlp_result:
            return 0.0, "NLP analysis unavailable"

        raw_label = getattr(nlp_result, "label", "LEGITIMATE")
        raw_conf = getattr(nlp_result, "confidence", None)
        raw_evidence = getattr(nlp_result, "evidence_score", None)
        raw_urgency = getattr(nlp_result, "urgency_score", 0.0)

        if isinstance(nlp_result, dict):
            raw_label = nlp_result.get("label", "LEGITIMATE")
            raw_conf = nlp_result.get("confidence", None)
            raw_evidence = nlp_result.get("evidence_score", None)
            raw_urgency = nlp_result.get("urgency_score", 0.0)

        confidence = float(raw_conf) if raw_conf is not None else None
        evidence_score = float(raw_evidence) if raw_evidence is not None else 0.0
        urgency = float(raw_urgency) if raw_urgency is not None else 0.0

        if confidence is not None and 0.0 < confidence <= 1.0:
            confidence = confidence * 100.0
        if 0.0 < evidence_score <= 1.0:
            evidence_score = evidence_score * 100.0

        score_to_use = confidence if confidence is not None else evidence_score
        canonical_label = normalize_threat_label(raw_label)

        if canonical_label == "LEGITIMATE":
            risk = max(0.0, score_to_use * 0.15) if score_to_use > 0 else 0.0
        elif canonical_label in ("PHISHING", "BEC_FRAUD"):
            risk = min(100.0, max(75.0, score_to_use))
        elif canonical_label == "IMPERSONATION":
            risk = min(100.0, max(65.0, score_to_use * 0.9))
        elif canonical_label == "SUSPICIOUS":
            risk = min(100.0, max(50.0, score_to_use * 0.8))
        else:
            risk = 30.0

        if urgency >= 70:
            risk = min(100.0, risk + 10.0)

        if confidence is not None:
            details = f"Classification: {canonical_label} (confidence: {confidence:.1f}%)"
        elif evidence_score > 0:
            details = f"Classification: {canonical_label} (evidence score: {evidence_score:.1f}%)"
        else:
            details = f"Classification: {canonical_label}"
        return risk, details

    def _extract_auth_details(self, header_result: Any) -> str:
        if not header_result:
            return "Authentication data unavailable"
        spf = getattr(header_result, "spf", None)
        dkim = getattr(header_result, "dkim", None)
        dmarc = getattr(header_result, "dmarc", None)
        
        spf_st = getattr(spf, "status", "unknown") if spf else "unknown"
        dkim_st = getattr(dkim, "status", "unknown") if dkim else "unknown"
        dmarc_st = getattr(dmarc, "status", "unknown") if dmarc else "unknown"

        if isinstance(header_result, dict):
            auth_st = header_result.get("auth_status", {})
            spf_st = auth_st.get("spf", "unknown")
            dkim_st = auth_st.get("dkim", "unknown")
            dmarc_st = auth_st.get("dmarc", "unknown")

        return f"SPF: {spf_st}, DKIM: {dkim_st}, DMARC: {dmarc_st}"

    def _extract_geo_details(self, geo_result: Any) -> str:
        if not geo_result:
            return "Geo intel unavailable"
        orig_ip = getattr(geo_result, "originating_ip", "IP Unavailable")
        infra = getattr(geo_result, "infrastructure_flags", [])
        if isinstance(geo_result, dict):
            orig_ip = geo_result.get("originating_ip", "IP Unavailable")
            infra = geo_result.get("infrastructure_flags", [])
        
        if orig_ip == "IP Unavailable":
            return "Originating IP: Unavailable (Webmail/Internal Relay)"
        
        infra_str = ", ".join(infra) if infra else "residential/standard"
        return f"Originating IP: {orig_ip} ({infra_str})"

    def _enhance_ip_risk(self, base_risk: float, threat_intel: ThreatIntelReport) -> float:
        """Boost IP risk score based on external threat intel."""
        boost = 0.0
        for ip, result in getattr(threat_intel, "ip_results", {}).items():
            if result.abuse_confidence_score >= 75:
                boost = max(boost, 30.0)
            elif result.abuse_confidence_score >= 50:
                boost = max(boost, 15.0)
            if result.total_reports >= 10:
                boost = max(boost, 10.0)
        return min(100.0, base_risk + boost)

    def _enhance_link_risk(self, base_risk: float, threat_intel: ThreatIntelReport) -> float:
        """Boost link risk score based on VirusTotal and PhishTank."""
        boost = 0.0
        for url, result in getattr(threat_intel, "url_results", {}).items():
            if result.detection_ratio >= 0.3:
                boost = max(boost, 40.0)
            elif result.detection_ratio >= 0.1:
                boost = max(boost, 20.0)
        for url, result in getattr(threat_intel, "phishtank_results", {}).items():
            if result.is_phishing:
                boost = max(boost, 50.0)
        return min(100.0, base_risk + boost)

    def _enhance_attachment_risk(self, base_risk: float, threat_intel: ThreatIntelReport) -> float:
        """Boost attachment risk based on VirusTotal file hash detections."""
        boost = 0.0
        for h, result in getattr(threat_intel, "hash_results", {}).items():
            if result.detection_ratio >= 0.2 or result.malicious_count >= 3:
                boost = max(boost, 40.0)
            elif result.malicious_count >= 1:
                boost = max(boost, 20.0)
        return min(100.0, base_risk + boost)
