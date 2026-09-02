"""End-to-End Verification of ML Output -> Risk Score -> Final Verdict Integration."""

import asyncio
import sys
import os
from datetime import datetime, timezone
from uuid import uuid4
import json

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from app.core.correlation.risk_scorer import RiskScorer, normalize_threat_label
from app.core.reporting.alert_engine import AlertEngine
from app.schemas.analysis import AnalysisResponse, NLPResult


def simulate_frontend_mapping(composite_score: float, nlp_label: str):
    """Simulates frontend/src/lib/severity.ts and VerdictBadge.tsx mapping."""
    # getRiskTier
    if composite_score >= 76:
        tier = "critical"
    elif composite_score >= 51:
        tier = "high"
    elif composite_score >= 26:
        tier = "medium"
    elif composite_score > 0:
        tier = "low"
    else:
        tier = "clean"
    
    # getVerdictForScore
    if composite_score >= 76:
        verdict = "MALICIOUS"
    elif composite_score >= 51:
        verdict = "SUSPICIOUS"
    elif composite_score >= 26:
        verdict = "ELEVATED"
    elif composite_score >= 10:
        verdict = "LOW RISK"
    else:
        verdict = "CLEAN"

    return tier, verdict


def run_cases():
    scorer = RiskScorer()
    alert_engine = AlertEngine()

    test_cases = [
        {
            "name": "Case 1: Phishing High Confidence",
            "raw_label": "PHISHING",
            "confidence": 98.7,
            "calibrated": True,
            "method": "ensemble_stacking",
            "header_auth_conf": 25.0,  # 75 risk
            "ip_rep": 20.0,            # 80 risk
            "link_risk": 85.0,
            "att_risk": 0.0,
        },
        {
            "name": "Case 2: Legitimate High Confidence",
            "raw_label": "LEGITIMATE",
            "confidence": 99.2,
            "calibrated": True,
            "method": "ensemble_stacking",
            "header_auth_conf": 100.0,  # 0 risk
            "ip_rep": 95.0,             # 5 risk
            "link_risk": 0.0,
            "att_risk": 0.0,
        },
        {
            "name": "Case 3: Suspicious Moderate Confidence",
            "raw_label": "SUSPICIOUS",
            "confidence": 66.0,
            "calibrated": True,
            "method": "ensemble_stacking",
            "header_auth_conf": 70.0,  # 30 risk
            "ip_rep": 60.0,            # 40 risk
            "link_risk": 20.0,
            "att_risk": 0.0,
        },
        {
            "name": "Case 4: BEC / Fraud Urgent Wire",
            "raw_label": "BEC_FRAUD",
            "confidence": 96.5,
            "calibrated": True,
            "method": "ensemble_stacking",
            "urgency": 85.0,
            "header_auth_conf": 10.0,  # 90 risk
            "ip_rep": 30.0,            # 70 risk
            "link_risk": 0.0,
            "att_risk": 0.0,
        },
        {
            "name": "Case 5: Legacy Title-Case Phishing",
            "raw_label": "Phishing",
            "confidence": 91.5,
            "calibrated": False,
            "method": "rule_heuristic",
            "header_auth_conf": 40.0,  # 60 risk
            "ip_rep": 45.0,            # 55 risk
            "link_risk": 70.0,
            "att_risk": 0.0,
        },
    ]

    print("=== END-TO-END VERIFICATION: ML OUTPUT -> RISK SCORE -> FRONTEND TIER ===\n")
    results_summary = []

    for tc in test_cases:
        # 1. Label Normalization
        canonical = normalize_threat_label(tc["raw_label"])
        
        # 2. NLP Threat Score Computation
        nlp_mock = type('N', (), {
            'label': tc["raw_label"],
            'confidence': tc["confidence"],
            'evidence_score': tc["confidence"],
            'urgency_score': tc.get("urgency", 0.0),
        })()
        nlp_risk, nlp_details = scorer._compute_nlp_risk(nlp_mock)
        
        # 3. Forensics & Composite Scoring
        hdr_mock = type('H', (), {'auth_confidence_score': tc["header_auth_conf"], 'spf': None, 'dkim': None, 'dmarc': None})()
        geo_mock = type('G', (), {'ip_reputation_score': tc["ip_rep"], 'infrastructure_flags': []})()
        link_mock = type('L', (), {'overall_link_risk': tc["link_risk"], 'urls_analyzed': 1, 'phishing_urls_found': 1 if tc["link_risk"] > 50 else 0})()
        att_mock = type('A', (), {'overall_attachment_risk': tc["att_risk"], 'total_attachments': 0})()

        composite = scorer.compute(nlp_mock, hdr_mock, geo_mock, link_mock, att_mock)

        # 4. Alert Title
        alert_title = alert_engine._build_title(canonical, composite.severity, composite.overall_score)

        # 5. Frontend Mapping
        frontend_tier, frontend_verdict = simulate_frontend_mapping(composite.overall_score, canonical)

        rec = {
            "Case": tc["name"],
            "Raw ML Label": tc["raw_label"],
            "Canonical Label": canonical,
            "Confidence": f"{tc['confidence']:.1f}% ({tc['method']})",
            "NLP Risk (0-100)": nlp_risk,
            "Auth Risk": round(100.0 - tc["header_auth_conf"], 1),
            "IP Risk": round(100.0 - tc["ip_rep"], 1),
            "Composite Risk Score": composite.overall_score,
            "Backend Severity": composite.severity,
            "Recommended Action": composite.recommended_action,
            "Alert Title": alert_title,
            "Frontend Tier": frontend_tier,
            "Frontend Verdict": frontend_verdict,
        }
        results_summary.append(rec)

        print(f"--- {tc['name']} ---")
        print(f"  Input: {tc['raw_label']} @ {tc['confidence']:.1f}% [{tc['method']}]")
        print(f"  Canonical Normalized Label: {canonical}")
        print(f"  NLP Risk Contribution: {nlp_risk:.1f} / 100.0")
        print(f"  Composite Threat Score: {composite.overall_score:.1f} / 100.0")
        print(f"  Backend Risk Severity: {composite.severity.upper()}")
        print(f"  Alert Title: {alert_title}")
        print(f"  Frontend Display: [{frontend_verdict}] ({frontend_tier.upper()} tier)\n")

    return results_summary


if __name__ == "__main__":
    run_cases()
