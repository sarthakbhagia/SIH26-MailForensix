import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.core.analysis.attachment_analyzer import AttachmentAnalysisReport, AttachmentAnalysisResult
from app.core.analysis.geo_intel import DomainIntelResult, GeoIntelResult, IPGeoResult
from app.core.analysis.header_forensics import DKIMResult, DMARCResult, HeaderForensicsResult, RelayHop, SPFResult
from app.core.analysis.link_analyzer import LinkAnalysisResult
from app.core.analysis.nlp_classifier import NLPClassificationResult
from app.core.pipeline import AnalysisPipeline
from app.models.alert import Alert
from app.models.analysis_result import AnalysisResult
from app.models.audit_log import AuditLog
from app.models.email_case import Email, EmailStatus


class MockPipelineDb:
    def __init__(self, email: Email):
        self.email = email
        self.added_objects = []
        self.audit_logs = []
        self.alerts = []

    def add(self, obj):
        self.added_objects.append(obj)
        if isinstance(obj, AuditLog):
            self.audit_logs.append(obj)
        elif isinstance(obj, Alert):
            self.alerts.append(obj)

    async def commit(self):
        pass

    async def refresh(self, obj):
        if not getattr(obj, "id", None):
            obj.id = uuid4()

    async def execute(self, stmt):
        stmt_str = str(stmt).lower()
        mock_res = MagicMock()

        # Email query
        if "from emails" in stmt_str or "emails.id" in stmt_str:
            mock_res.scalar_one_or_none.return_value = self.email
            mock_res.scalar.return_value = self.email
            mock_res.scalars.return_value.all.return_value = [self.email]
            return mock_res

        # AuditLog query
        if "from audit_logs" in stmt_str:
            last = self.audit_logs[-1] if self.audit_logs else None
            mock_res.scalar_one_or_none.return_value = last
            mock_res.scalar.return_value = last
            mock_res.scalars.return_value.all.return_value = [last] if last else []
            return mock_res

        mock_res.scalar_one_or_none.return_value = None
        mock_res.scalar.return_value = None
        mock_res.scalars.return_value.all.return_value = []
        return mock_res


@pytest.mark.asyncio
async def test_pipeline_phishing_triggers_alert():
    """Verify that analyzing a phishing email with high risk triggers an alert and audit log."""
    phishing_id = uuid4()
    phishing_email = Email(
        id=phishing_id,
        sender="attacker@fake-bank-login.com",
        recipients=["victim@target.org"],
        subject="URGENT: Your Account Has Been Suspended",
        body_text="Your account has been locked. Click http://fake-bank-login.com/reset to unlock immediately.",
        body_html="<p>Click <a href='http://fake-bank-login.com/reset'>here</a></p>",
        headers={
            "from": "Security Alert <attacker@fake-bank-login.com>",
            "to": "victim@target.org",
            "received_hops": [{"ip": "185.220.101.5", "is_private": False, "hop_number": 1}],
        },
        raw_eml=b"From: attacker@fake-bank-login.com\nSubject: URGENT: Account Suspended\n\nBody",
        status=EmailStatus.pending,
        ingested_at=datetime.now(timezone.utc),
    )

    db = MockPipelineDb(phishing_email)

    # Mock high threat forensic results
    mock_header = HeaderForensicsResult(
        spf=SPFResult(status="fail", domain="fake-bank-login.com", ip="185.220.101.5", record="", details="SPF Fail"),
        dkim=DKIMResult(status="fail", domain="fake-bank-login.com", selector="s1", details="DKIM Fail"),
        dmarc=DMARCResult(status="fail", policy="reject", domain="fake-bank-login.com", alignment_spf=False, alignment_dkim=False, record=""),
        relay_path=[
            RelayHop(hop_number=1, from_host="tor.exit", by_host="relay.host", ip="185.220.101.5", timestamp="2026-08-26T00:00:00Z", protocol="ESMTP", delay_seconds=0.1, is_private=False)
        ],
        anomalies=[],
        auth_confidence_score=0.0,
    )

    mock_geo = GeoIntelResult(
        originating_ip="185.220.101.5",
        geo_locations=[
            IPGeoResult(ip="185.220.101.5", country="NL", country_code="NL", region="NH", city="Amsterdam", latitude=52.3, longitude=4.9, isp="Tor Exit", asn="12345", org="Tor Org", is_private=False, infrastructure_type="tor_exit_node", confidence="high")
        ],
        domain_intel=DomainIntelResult(domain="fake-bank-login.com", registrar="Anon Registrar", registration_date="2026-08-20", expiration_date="2027-08-20", registrant_country="RU", name_servers=[], mx_records=[], a_records=[], domain_age_days=6, is_newly_registered=True),
        infrastructure_flags=["tor_exit_node"],
        location_confidence="high",
        ip_reputation_score=10.0,
    )

    mock_nlp = NLPClassificationResult(
        label="Phishing",
        confidence=0.98,
        probabilities={"Phishing": 0.98, "Legitimate": 0.01, "Suspicious": 0.01},
        urgency_score=85.0,
        bec_indicators=[],
        impersonation_signals=["lookalike_domain"],
        contributing_factors=["high_urgency", "credential_harvesting"],
    )

    mock_link = LinkAnalysisResult(
        urls_analyzed=1,
        url_results=[],
        overall_link_risk=90.0,
        phishing_urls_found=1,
        suspicious_urls_found=0,
    )

    mock_att = AttachmentAnalysisReport(
        total_attachments=1,
        results=[
            AttachmentAnalysisResult(
                filename="invoice.exe",
                declared_content_type="application/pdf",
                actual_content_type="application/x-dosexec",
                size_bytes=10240,
                sha256="fake_sha256",
                risk_score=95.0,
                risk_reasons=["executable_attachment"],
                has_macros=False,
                extension_mismatch=True,
                is_double_extension=False,
                vt_detections=5,
            )
        ],
        overall_attachment_risk=95.0,
    )

    with patch("app.core.pipeline.HeaderForensics.analyze", new_callable=AsyncMock) as mock_hdr, \
         patch("app.core.pipeline.GeoIntelligence.analyze", new_callable=AsyncMock) as mock_geo_p, \
         patch("app.core.pipeline.NLPClassifier.classify") as mock_nlp_p, \
         patch("app.core.pipeline.LinkAnalyzer.analyze", new_callable=AsyncMock) as mock_lnk, \
         patch("app.core.pipeline.AttachmentAnalyzer.analyze") as mock_att_p, \
         patch("app.workers.tasks.enrich_threat_intel_task.apply_async"):

        mock_hdr.return_value = mock_header
        mock_geo_p.return_value = mock_geo
        mock_nlp_p.return_value = mock_nlp
        mock_lnk.return_value = mock_link
        mock_att_p.return_value = mock_att

        pipeline = AnalysisPipeline()
        analysis = await pipeline.run(str(phishing_id), db)

        assert analysis is not None
        assert isinstance(analysis, AnalysisResult)
        assert analysis.composite_risk_score >= 75.0  # High or Critical severity

        # Verify an Alert was added to DB
        alerts = [obj for obj in db.added_objects if isinstance(obj, Alert)]
        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert.risk_score >= 75.0
        assert alert.severity.value in ("high", "critical")

        # Verify an AuditLog was created with alert_triggered = True
        audit_entries = [obj for obj in db.added_objects if isinstance(obj, AuditLog)]
        assert len(audit_entries) >= 1
        audit = audit_entries[0]
        assert audit.action == "email_analysis_completed"
        assert audit.action_data["alert_triggered"] is True
        assert audit.action_data["risk_score"] >= 75.0


@pytest.mark.asyncio
async def test_pipeline_legitimate_no_alert():
    """Verify that analyzing a legitimate email with low risk score does NOT trigger an alert."""
    legit_id = uuid4()
    legit_email = Email(
        id=legit_id,
        sender="notifications@legitimate-company.com",
        recipients=["employee@target.org"],
        subject="Monthly Team All-Hands Meeting Agenda",
        body_text="Hi team, here is the agenda for our upcoming quarterly meeting.",
        body_html="<p>Hi team, here is the agenda for our upcoming quarterly meeting.</p>",
        headers={
            "from": "Internal Team <notifications@legitimate-company.com>",
            "to": "employee@target.org",
            "received_hops": [{"ip": "192.0.2.1", "is_private": False, "hop_number": 1}],
        },
        raw_eml=b"From: notifications@legitimate-company.com\nSubject: Monthly Meeting\n\nBody",
        status=EmailStatus.pending,
        ingested_at=datetime.now(timezone.utc),
    )

    db = MockPipelineDb(legit_email)

    # Mock clean legitimate forensic results
    mock_header = HeaderForensicsResult(
        spf=SPFResult(status="pass", domain="legitimate-company.com", ip="192.0.2.1", record="", details="SPF Pass"),
        dkim=DKIMResult(status="pass", domain="legitimate-company.com", selector="default", details="DKIM Pass"),
        dmarc=DMARCResult(status="pass", policy="reject", domain="legitimate-company.com", alignment_spf=True, alignment_dkim=True, record=""),
        relay_path=[
            RelayHop(hop_number=1, from_host="mail.legitimate-company.com", by_host="relay.host", ip="192.0.2.1", timestamp="2026-08-26T00:00:00Z", protocol="ESMTP", delay_seconds=0.1, is_private=False)
        ],
        anomalies=[],
        auth_confidence_score=100.0,
    )

    mock_geo = GeoIntelResult(
        originating_ip="192.0.2.1",
        geo_locations=[
            IPGeoResult(ip="192.0.2.1", country="US", country_code="US", region="CA", city="San Francisco", latitude=37.7, longitude=-122.4, isp="Trusted ISP", asn="13335", org="Cloudflare", is_private=False, infrastructure_type="clean", confidence="high")
        ],
        domain_intel=DomainIntelResult(domain="legitimate-company.com", registrar="MarkMonitor", registration_date="2010-01-01", expiration_date="2030-01-01", registrant_country="US", name_servers=[], mx_records=[], a_records=[], domain_age_days=5000, is_newly_registered=False),
        infrastructure_flags=[],
        location_confidence="high",
        ip_reputation_score=95.0,
    )

    mock_nlp = NLPClassificationResult(
        label="Legitimate",
        confidence=0.99,
        probabilities={"Legitimate": 0.99, "Phishing": 0.0, "Suspicious": 0.01},
        urgency_score=0.0,
        bec_indicators=[],
        impersonation_signals=[],
        contributing_factors=[],
    )

    mock_link = LinkAnalysisResult(urls_analyzed=0, url_results=[], overall_link_risk=0.0, phishing_urls_found=0, suspicious_urls_found=0)
    mock_att = AttachmentAnalysisReport(total_attachments=0, results=[], overall_attachment_risk=0.0)

    with patch("app.core.pipeline.HeaderForensics.analyze", new_callable=AsyncMock) as mock_hdr, \
         patch("app.core.pipeline.GeoIntelligence.analyze", new_callable=AsyncMock) as mock_geo_p, \
         patch("app.core.pipeline.NLPClassifier.classify") as mock_nlp_p, \
         patch("app.core.pipeline.LinkAnalyzer.analyze", new_callable=AsyncMock) as mock_lnk, \
         patch("app.core.pipeline.AttachmentAnalyzer.analyze") as mock_att_p, \
         patch("app.workers.tasks.enrich_threat_intel_task.apply_async"):

        mock_hdr.return_value = mock_header
        mock_geo_p.return_value = mock_geo
        mock_nlp_p.return_value = mock_nlp
        mock_lnk.return_value = mock_link
        mock_att_p.return_value = mock_att

        pipeline = AnalysisPipeline()
        analysis = await pipeline.run(str(legit_id), db)

        assert analysis is not None
        assert isinstance(analysis, AnalysisResult)
        assert analysis.composite_risk_score < 75.0  # Low risk score

        # Verify NO Alert was created
        alerts = [obj for obj in db.added_objects if isinstance(obj, Alert)]
        assert len(alerts) == 0

        # Verify AuditLog recorded alert_triggered = False
        audit_entries = [obj for obj in db.added_objects if isinstance(obj, AuditLog)]
        assert len(audit_entries) >= 1
        audit = audit_entries[0]
        assert audit.action == "email_analysis_completed"
        assert audit.action_data["alert_triggered"] is False
        assert audit.action_data["risk_score"] < 75.0


@pytest.mark.asyncio
async def test_pipeline_alert_or_audit_failure_resilience():
    """Verify that failures in AlertEngine or AuditService do not abort the email analysis or crash the pipeline."""
    eid = uuid4()
    email = Email(
        id=eid,
        sender="attacker@phish.com",
        recipients=["victim@target.org"],
        subject="Alert Test",
        body_text="Click link",
        body_html="<p>Click link</p>",
        headers={"from": "attacker@phish.com", "to": "victim@target.org", "received_hops": []},
        raw_eml=b"From: attacker@phish.com\nSubject: Alert Test\n\nBody",
        status=EmailStatus.pending,
        ingested_at=datetime.now(timezone.utc),
    )

    db = MockPipelineDb(email)

    mock_header = HeaderForensicsResult(
        spf=SPFResult(status="none", domain="phish.com", ip="1.2.3.4", record="", details=""),
        dkim=DKIMResult(status="none", domain="phish.com", selector="", details=""),
        dmarc=DMARCResult(status="none", policy="none", domain="phish.com", alignment_spf=False, alignment_dkim=False, record=""),
        relay_path=[],
        anomalies=[],
        auth_confidence_score=0.0,
    )
    mock_geo = GeoIntelResult(originating_ip="1.2.3.4", geo_locations=[], domain_intel=None, infrastructure_flags=[], location_confidence="low", ip_reputation_score=50.0)
    mock_nlp = NLPClassificationResult(label="Phishing", confidence=0.9, probabilities={}, urgency_score=50.0, bec_indicators=[], impersonation_signals=[], contributing_factors=[])
    mock_link = LinkAnalysisResult(urls_analyzed=0, url_results=[], overall_link_risk=0.0, phishing_urls_found=0, suspicious_urls_found=0)
    mock_att = AttachmentAnalysisReport(total_attachments=0, results=[], overall_attachment_risk=0.0)

    with patch("app.core.pipeline.HeaderForensics.analyze", new_callable=AsyncMock) as mock_hdr, \
         patch("app.core.pipeline.GeoIntelligence.analyze", new_callable=AsyncMock) as mock_geo_p, \
         patch("app.core.pipeline.NLPClassifier.classify") as mock_nlp_p, \
         patch("app.core.pipeline.LinkAnalyzer.analyze", new_callable=AsyncMock) as mock_lnk, \
         patch("app.core.pipeline.AttachmentAnalyzer.analyze") as mock_att_p, \
         patch("app.core.reporting.alert_engine.AlertEngine.evaluate", side_effect=RuntimeError("Redis down")), \
         patch("app.services.audit_service.AuditService.log_action", side_effect=RuntimeError("Audit disk full")), \
         patch("app.workers.tasks.enrich_threat_intel_task.apply_async"):

        mock_hdr.return_value = mock_header
        mock_geo_p.return_value = mock_geo
        mock_nlp_p.return_value = mock_nlp
        mock_lnk.return_value = mock_link
        mock_att_p.return_value = mock_att

        pipeline = AnalysisPipeline()
        # Should complete successfully despite alert/audit exceptions
        analysis = await pipeline.run(str(eid), db)

        assert analysis is not None
        assert isinstance(analysis, AnalysisResult)
        assert email.status == EmailStatus.analyzed

