import pytest
import pandas as pd
from ml.feature_engineering import (
    FeatureExtractor,
    ForensicFeatureVector,
    FEATURE_COLUMNS,
)


def test_feature_extractor_single():
    extractor = FeatureExtractor()
    email_data = {
        "subject": "Urgent: Verify Your Account",
        "body_text": "Please click here immediately to reset your password. http://evil.com/login",
        "sender": "support@evil.com",
        "headers": {
            "from": "CEO <support@evil.com>",
            "received-spf": "fail",
        },
        "urls": ["http://evil.com/login"],
        "attachments": [{"filename": "payload.exe", "size": 2048}],
    }
    analysis_result = {
        "auth_status": {"spf": "fail", "dkim": "none", "dmarc": "none"},
        "risk_breakdown": {"auth": 80.0},
        "ip_reputation": {"score": 25.0},
        "geo_data": [{"ip": "198.51.100.1", "infrastructure_type": "known_vpn"}],
        "domain_intel": {"domain_age_days": 12, "is_newly_registered": True, "mx_records": []},
        "iocs": [
            {"type": "URL", "risk_score": 85.0, "reason": "lookalike domain"},
            {"type": "Hash", "risk_score": 95.0, "reason": "executable attachment"},
        ],
        "anomalies": [{"type": "time_travel", "severity": "warning"}],
    }

    vector = extractor.extract(email_data, analysis_result)
    assert isinstance(vector, ForensicFeatureVector)

    # Verify key extracted features
    assert vector.spf_status_encoded == 2  # fail
    assert vector.dkim_status_encoded == 2  # none
    assert vector.auth_confidence_score == 20.0  # 100 - 80
    assert vector.is_vpn is True
    assert vector.is_newly_registered is True
    assert vector.url_count == 1
    assert vector.attachment_count == 1
    assert vector.has_executable_attachment is True
    assert vector.max_url_risk_score == 85.0
    assert vector.max_attachment_risk_score == 95.0
    assert vector.anomaly_count == 1
    assert vector.text_entropy > 0.0


def test_feature_extractor_batch():
    extractor = FeatureExtractor()
    records = [
        {
            "email": {"subject": "Test 1", "body_text": "Body text 1", "sender": "user1@company.com"},
            "analysis": {"auth_status": {"spf": "pass"}},
            "label": "Legitimate",
        },
        {
            "email": {"subject": "Test 2", "body_text": "Body text 2", "sender": "user2@bad.com"},
            "analysis": {"auth_status": {"spf": "fail"}},
            "label": "Phishing",
        },
    ]

    df = extractor.extract_batch(records)
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 2
    for col in FEATURE_COLUMNS:
        assert col in df.columns
    assert "label" in df.columns
    assert list(df["label"]) == ["Legitimate", "Phishing"]


def test_entropy_computation():
    extractor = FeatureExtractor()
    # Empty string has 0 entropy
    assert extractor._compute_text_entropy("") == 0.0
    # Single repeating character has 0 entropy
    assert extractor._compute_text_entropy("aaaaaaa") == 0.0
    # Diverse text has higher entropy
    ent = extractor._compute_text_entropy("The quick brown fox jumps over the lazy dog 123456!@#$%")
    assert ent > 3.0
