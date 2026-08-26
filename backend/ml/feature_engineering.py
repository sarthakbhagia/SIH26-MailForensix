import math
from collections import Counter
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
import pandas as pd


@dataclass
class ForensicFeatureVector:
    # Authentication features (6)
    spf_status_encoded: int          # 0=pass, 1=softfail, 2=fail, 3=none
    dkim_status_encoded: int         # 0=pass, 1=fail, 2=none
    dmarc_status_encoded: int        # 0=pass, 1=fail, 2=none
    auth_confidence_score: float     # 0-100 from header forensics
    has_spf_record: bool
    has_dkim_signature: bool

    # Relay path features (5)
    relay_hop_count: int
    max_hop_delay_seconds: float
    has_time_travel: bool
    private_hop_ratio: float         # fraction of hops with private IPs
    suspicious_infrastructure_count: int  # TOR/VPN/proxy hops

    # Geo features (5)
    originating_ip_reputation: float  # 0-100
    is_tor_exit_node: bool
    is_vpn: bool
    is_cloud_provider: bool
    geo_confidence_encoded: int       # 0=low, 1=medium, 2=high

    # Domain features (4)
    domain_age_days: int
    is_newly_registered: bool         # < 30 days
    is_free_email_provider: bool      # gmail, yahoo, etc.
    sender_domain_has_mx: bool

    # Content features (6)
    subject_length: int
    body_length: int
    url_count: int
    attachment_count: int
    has_html_body: bool
    text_entropy: float               # Shannon entropy of body text

    # Link features (4)
    max_url_risk_score: float
    shortened_url_count: int
    lookalike_domain_count: int
    ip_as_hostname_count: int

    # Attachment features (3)
    has_executable_attachment: bool
    has_macro_attachment: bool
    max_attachment_risk_score: float

    # Anomaly features (2)
    anomaly_count: int
    max_anomaly_severity_encoded: int  # 0=none, 1=info, 2=warning, 3=critical


SPF_STATUS_MAP = {"pass": 0, "softfail": 1, "fail": 2, "none": 3, "temperror": 3, "permerror": 3, "unknown": 3}
DKIM_STATUS_MAP = {"pass": 0, "fail": 1, "none": 2, "unknown": 2}
DMARC_STATUS_MAP = {"pass": 0, "fail": 1, "none": 2, "unknown": 2}
GEO_CONFIDENCE_MAP = {"high": 2, "medium": 1, "low": 0}
ANOMALY_SEVERITY_MAP = {"critical": 3, "warning": 2, "info": 1, "none": 0}

FEATURE_COLUMNS = [
    "spf_status_encoded", "dkim_status_encoded", "dmarc_status_encoded",
    "auth_confidence_score", "has_spf_record", "has_dkim_signature",
    "relay_hop_count", "max_hop_delay_seconds", "has_time_travel",
    "private_hop_ratio", "suspicious_infrastructure_count",
    "originating_ip_reputation", "is_tor_exit_node", "is_vpn",
    "is_cloud_provider", "geo_confidence_encoded",
    "domain_age_days", "is_newly_registered", "is_free_email_provider",
    "sender_domain_has_mx",
    "subject_length", "body_length", "url_count", "attachment_count",
    "has_html_body", "text_entropy",
    "max_url_risk_score", "shortened_url_count", "lookalike_domain_count",
    "ip_as_hostname_count",
    "has_executable_attachment", "has_macro_attachment", "max_attachment_risk_score",
    "anomaly_count", "max_anomaly_severity_encoded",
]


class FeatureExtractor:
    """Extracts 35 forensic features from email data and analysis results for tabular modeling."""

    FREE_EMAIL_PROVIDERS = {
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
        "aol.com", "protonmail.com", "mail.com", "zoho.com",
        "icloud.com", "yandex.com", "gmx.com", "tutanota.com"
    }

    def _compute_text_entropy(self, text: str) -> float:
        """Compute Shannon entropy of text (higher = more obfuscated/random)."""
        if not text:
            return 0.0
        freq = Counter(text.lower())
        total = len(text)
        return round(-sum((c / total) * math.log2(c / total) for c in freq.values()), 4)

    def _encode_status(self, status: Optional[str], mapping: Dict[str, int], default: int) -> int:
        if not status:
            return default
        return mapping.get(str(status).lower(), default)

    def extract(self, email_data: Dict[str, Any], analysis_result: Dict[str, Any]) -> ForensicFeatureVector:
        """Extract a single ForensicFeatureVector from raw email and analysis dictionary."""
        # 1. Authentication
        auth_status = analysis_result.get("auth_status", {}) or {}
        spf_encoded = self._encode_status(auth_status.get("spf"), SPF_STATUS_MAP, 3)
        dkim_encoded = self._encode_status(auth_status.get("dkim"), DKIM_STATUS_MAP, 2)
        dmarc_encoded = self._encode_status(auth_status.get("dmarc"), DMARC_STATUS_MAP, 2)

        risk_breakdown = analysis_result.get("risk_breakdown", {}) or {}
        auth_confidence = 100.0 - float(risk_breakdown.get("auth", 20.0))

        headers = email_data.get("headers", {}) or {}
        has_spf_record = bool(headers.get("received-spf") or auth_status.get("spf") not in ("none", None))
        has_dkim_signature = bool(headers.get("dkim-signature") or auth_status.get("dkim") not in ("none", None))

        # 2. Relay path
        relay_path = analysis_result.get("relay_path", []) or []
        relay_count = len(relay_path)
        delays = [float(h.get("delay_seconds", 0.0)) for h in relay_path if isinstance(h, dict)]
        max_delay = max(delays, default=0.0)
        has_time_travel = any(d < 0 for d in delays)
        private_hops = sum(1 for h in relay_path if isinstance(h, dict) and h.get("is_private"))
        private_ratio = round(private_hops / max(1, relay_count), 3)

        # 3. Geo & Infrastructure
        geo_data = analysis_result.get("geo_data", []) or []
        infra_types = [g.get("infrastructure_type", "") for g in geo_data if isinstance(g, dict)]
        suspicious_infra = sum(1 for t in infra_types if t in ("known_vpn", "tor_exit_node", "proxy", "datacenter"))

        ip_rep_dict = analysis_result.get("ip_reputation", {}) or {}
        ip_rep_score = float(ip_rep_dict.get("score", 50.0))
        is_tor = "tor_exit_node" in infra_types
        is_vpn = "known_vpn" in infra_types
        is_cloud = "datacenter" in infra_types or "cloud" in infra_types
        geo_conf = self._encode_status(analysis_result.get("location_confidence", "medium"), GEO_CONFIDENCE_MAP, 1)

        # 4. Domain
        domain_intel = analysis_result.get("domain_intel", {}) or {}
        domain_age = int(domain_intel.get("domain_age_days", -1))
        is_new_domain = bool(domain_intel.get("is_newly_registered", False) or (0 <= domain_age < 30))

        sender = email_data.get("sender", "") or ""
        sender_domain = sender.split("@")[-1].lower() if "@" in sender else sender.lower()
        is_free_provider = sender_domain in self.FREE_EMAIL_PROVIDERS
        has_mx = bool(domain_intel.get("mx_records") or domain_intel.get("has_mx", True))

        # 5. Content
        subject = email_data.get("subject", "") or ""
        body_text = email_data.get("body_text", "") or ""
        urls = email_data.get("urls", []) or []
        attachments = email_data.get("attachments", []) or []
        has_html = bool(email_data.get("body_html") or "<html" in body_text.lower())
        entropy = self._compute_text_entropy(body_text)

        # 6. Links
        iocs = analysis_result.get("iocs", []) or []
        url_risk_scores = [float(ioc.get("risk_score", 0)) for ioc in iocs if isinstance(ioc, dict) and ioc.get("type") == "URL"]
        max_url_risk = max(url_risk_scores, default=0.0)

        shortened_count = sum(1 for u in urls if any(s in str(u).lower() for s in ("bit.ly", "t.co", "tinyurl", "ow.ly", "is.gd")))
        lookalike_count = sum(1 for ioc in iocs if isinstance(ioc, dict) and "lookalike" in str(ioc.get("reason", "")).lower())
        ip_hostname_count = sum(1 for u in urls if any(part.replace(".", "").isdigit() for part in str(u).split("/")[2:3]))

        # 7. Attachments
        att_risks = [float(ioc.get("risk_score", 0)) for ioc in iocs if isinstance(ioc, dict) and ioc.get("type") == "Hash"]
        max_att_risk = max(att_risks, default=0.0)

        exec_exts = {".exe", ".bat", ".scr", ".cmd", ".vbs", ".ps1", ".hta", ".js"}
        macro_exts = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
        has_exec = False
        has_macro = False
        for att in attachments:
            fname = att.get("filename", "") if isinstance(att, dict) else getattr(att, "filename", "")
            fname_lower = fname.lower()
            if any(fname_lower.endswith(ext) for ext in exec_exts):
                has_exec = True
            if any(fname_lower.endswith(ext) for ext in macro_exts):
                has_macro = True

        # 8. Anomalies
        anomalies = analysis_result.get("anomalies", []) or []
        anomaly_count = len(anomalies)
        severities = [self._encode_status(a.get("severity"), ANOMALY_SEVERITY_MAP, 1) for a in anomalies if isinstance(a, dict)]
        max_anomaly_sev = max(severities, default=0)

        return ForensicFeatureVector(
            spf_status_encoded=spf_encoded,
            dkim_status_encoded=dkim_encoded,
            dmarc_status_encoded=dmarc_encoded,
            auth_confidence_score=auth_confidence,
            has_spf_record=has_spf_record,
            has_dkim_signature=has_dkim_signature,
            relay_hop_count=relay_count,
            max_hop_delay_seconds=max_delay,
            has_time_travel=has_time_travel,
            private_hop_ratio=private_ratio,
            suspicious_infrastructure_count=suspicious_infra,
            originating_ip_reputation=ip_rep_score,
            is_tor_exit_node=is_tor,
            is_vpn=is_vpn,
            is_cloud_provider=is_cloud,
            geo_confidence_encoded=geo_conf,
            domain_age_days=domain_age,
            is_newly_registered=is_new_domain,
            is_free_email_provider=is_free_provider,
            sender_domain_has_mx=has_mx,
            subject_length=len(subject),
            body_length=len(body_text),
            url_count=len(urls),
            attachment_count=len(attachments),
            has_html_body=has_html,
            text_entropy=entropy,
            max_url_risk_score=max_url_risk,
            shortened_url_count=shortened_count,
            lookalike_domain_count=lookalike_count,
            ip_as_hostname_count=ip_hostname_count,
            has_executable_attachment=has_exec,
            has_macro_attachment=has_macro,
            max_attachment_risk_score=max_att_risk,
            anomaly_count=anomaly_count,
            max_anomaly_severity_encoded=max_anomaly_sev,
        )

    def extract_batch(self, records: List[Dict[str, Any]]) -> pd.DataFrame:
        """Convert a list of combined email + analysis dictionaries into a pandas DataFrame."""
        rows = []
        for rec in records:
            email_data = rec.get("email", rec)
            analysis_data = rec.get("analysis", rec)
            fv = self.extract(email_data, analysis_data)
            row = asdict(fv)
            if "label" in rec:
                row["label"] = rec["label"]
            rows.append(row)
        return pd.DataFrame(rows)
