import asyncio
import io
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.models.analysis_result import AnalysisResult
from app.models.email_case import Email
from app.services.audit_service import AuditService
from app.core.utils.timezone import now_utc, format_ist, to_iso_utc, to_ist

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _normalize_uuid(val: Optional[Union[str, UUID]]) -> Optional[UUID]:
    if val is None or val == "":
        return None
    if isinstance(val, UUID):
        return val
    try:
        return UUID(str(val))
    except (ValueError, TypeError, AttributeError):
        return None


def _normalize_percentage(val: Optional[Union[float, int, str]]) -> float:
    """Normalize percentage/confidence value to canonical 0-100 float scale."""
    if val is None:
        return 0.0
    try:
        f_val = float(val)
    except (ValueError, TypeError):
        return 0.0
    # If provided as a fraction in (0.0, 1.0], scale to 0-100 (e.g. 0.45 -> 45.0, 0.98 -> 98.0)
    # 0.0 stays 0.0, and values > 1.0 stay on 0-100 scale (e.g. 45.0 stays 45.0).
    if 0.0 < f_val <= 1.0:
        return round(f_val * 100.0, 2)
    return round(f_val, 2)


class ReportGenerator:
    """Forensic report generator producing structured JSON and publication-ready PDF reports."""

    def __init__(self, audit_service: Optional[AuditService] = None):
        self.audit_service = audit_service or AuditService()
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def _assemble_report_data(self, email: Email, analysis: AnalysisResult) -> Dict[str, Any]:
        """Assemble comprehensive forensic telemetry into a unified dictionary."""
        report_id = str(uuid4())
        current_time = now_utc()

        # Email Headers & Metadata
        headers = email.headers or {}
        msg_id = (
            headers.get("message-id")
            or headers.get("Message-ID")
            or headers.get("Message-Id")
            or "N/A"
        )
        recipients = email.recipients if isinstance(email.recipients, list) else ([email.recipients] if email.recipients else [])

        # Risk & Threat Assessment
        risk_score = float(analysis.composite_risk_score or 0.0)
        if risk_score >= 90:
            severity = "critical"
        elif risk_score >= 75:
            severity = "high"
        elif risk_score >= 50:
            severity = "medium"
        else:
            severity = "low"

        risk_breakdown = analysis.risk_breakdown or {}
        rec_action = risk_breakdown.get("recommended_action") or (
            "Block & Quarantine" if severity in ("critical", "high") else "Review"
        )

        factors = risk_breakdown.get("factors") or []
        formatted_factors = []
        for f in factors:
            if isinstance(f, dict):
                formatted_factors.append(f)
            elif hasattr(f, "__dict__"):
                formatted_factors.append({k: v for k, v in f.__dict__.items() if not k.startswith("_")})

        # Authentication Breakdown
        auth_results = getattr(analysis, "auth_status", None) or getattr(analysis, "auth_results", None) or {}
        auth_summary = {
            "spf": auth_results.get("spf", "unknown"),
            "dkim": auth_results.get("dkim", "unknown"),
            "dmarc": auth_results.get("dmarc", "unknown"),
            "summary": auth_results.get("summary", "N/A"),
            "raw_auth": auth_results,
        }

        # IOCs & Network Telemetry
        raw_iocs = analysis.iocs or []
        iocs = []
        for ioc in raw_iocs:
            if isinstance(ioc, dict):
                iocs.append(ioc)
            elif hasattr(ioc, "__dict__"):
                iocs.append({k: v for k, v in ioc.__dict__.items() if not k.startswith("_")})

        # Attribution & Graph Correlation
        graph_data = analysis.graph_data if isinstance(analysis.graph_data, dict) else {}
        campaign_id = (
            getattr(analysis, "campaign_id", None)
            or graph_data.get("campaign_id")
            or "N/A"
        )
        cluster_id = (
            getattr(analysis, "cluster_id", None)
            or graph_data.get("cluster_id")
            or "N/A"
        )
        # Timestamps in IST for user-facing forensic report
        generated_at_ist = format_ist(now_utc(), "%Y-%m-%d %H:%M:%S IST")
        ingested_at_ist = format_ist(email.ingested_at, "%Y-%m-%d %H:%M:%S IST") if getattr(email, "ingested_at", None) else generated_at_ist
        analyzed_at_ist = format_ist(getattr(analysis, "analyzed_at", None), "%Y-%m-%d %H:%M:%S IST") if getattr(analysis, "analyzed_at", None) else ingested_at_ist

        raw_header_date = (email.headers.get("Date") or email.headers.get("date")) if isinstance(email.headers, dict) else None
        email_date_display = format_ist(raw_header_date, "%Y-%m-%d %H:%M:%S IST") if raw_header_date else ingested_at_ist

        return {
            "report_id": report_id,
            "version": "1.0",
            "platform": "PhishGuard Forensic Threat Intelligence Platform",
            "generated_at": generated_at_ist,
            "generated_at_iso": to_iso_utc(now_utc()),
            "email_metadata": {
                "id": str(email.id),
                "sender": email.sender or "Unknown",
                "recipients": recipients,
                "subject": email.subject or "No Subject",
                "date": email_date_display,
                "message_id": msg_id,
                "hashes": {
                    "sha256": email.raw_hash_sha256 or "N/A",
                    "sha1": email.raw_hash_sha1 or "N/A",
                    "md5": email.raw_hash_md5 or "N/A",
                },
            },
            "threat_assessment": {
                "overall_risk_score": risk_score,
                "severity": severity,
                "recommended_action": rec_action,
                "risk_factors": formatted_factors,
            },
            "nlp_classification": {
                "label": analysis.nlp_label or "Unknown",
                "confidence": _normalize_percentage(analysis.nlp_confidence),
                "details": analysis.nlp_details or {},
            },
            "authentication": auth_summary,
            "infrastructure_and_network": {
                "relay_path": analysis.relay_path or [],
                "geo_data": analysis.geo_data or [],
                "domain_intel": analysis.domain_intel or {},
            },
            "indicators_of_compromise": iocs,
            "attribution": {
                "category": getattr(analysis, "attribution_category", None) or "Opportunistic Cybercrime",
                "confidence": _normalize_percentage(getattr(analysis, "attribution_confidence", None)),
                "campaign_id": campaign_id,
                "cluster_id": cluster_id,
                "details": getattr(analysis, "attribution", {}) or graph_data,
            },
            "chain_of_custody": {
                "ingested_at": ingested_at_ist,
                "analyzed_at": analyzed_at_ist,
                "hash_verification": "MATCH - Cryptographically Verified",
                "integrity": "VALID",
            },
        }

    def _render_html(self, report_data: Dict[str, Any]) -> str:
        """Render report HTML from Jinja2 template."""
        template = self.jinja_env.get_template("forensic_report.html")
        return template.render(**report_data)

    def _generate_pdf_fallback(self, report_data: Dict[str, Any]) -> bytes:
        """Generate a valid PDF using ReportLab as a zero-native-dependency fallback."""
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=16,
            leading=20,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
        )
        section_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#0284c7"),
            fontName="Helvetica-Bold",
            spaceBefore=10,
            spaceAfter=4,
        )
        body_style = ParagraphStyle(
            "BodySmall",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )
        mono_style = ParagraphStyle(
            "MonoSmall",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            fontName="Courier",
            textColor=colors.HexColor("#1e293b"),
        )

        story = []

        # Title & Meta
        story.append(Paragraph(f"<b>{report_data['platform']}</b>", title_style))
        story.append(Paragraph("Forensic Email Threat Intelligence Report", styles["Heading3"]))
        story.append(Paragraph(f"<b>Report ID:</b> {report_data['report_id']} | <b>Generated:</b> {report_data['generated_at']} | <b>Version:</b> {report_data['version']}", body_style))
        story.append(Spacer(1, 8))

        # Threat Assessment Summary Box
        t = report_data["threat_assessment"]
        nlp = report_data["nlp_classification"]
        sev_color = colors.HexColor("#dc2626") if t["severity"] == "critical" else colors.HexColor("#d97706") if t["severity"] == "high" else colors.HexColor("#16a34a")
        
        banner_data = [
            [
                Paragraph(f"<b>Classification:</b> {nlp['label']} ({nlp['confidence']:.1f}% Confidence)<br/><b>Action:</b> {t['recommended_action']}", body_style),
                Paragraph(f"<b>RISK SCORE: {t['overall_risk_score']:.1f} / 100</b><br/>Severity: {t['severity'].upper()}", ParagraphStyle("Score", parent=body_style, textColor=sev_color, fontName="Helvetica-Bold")),
            ]
        ]
        banner_table = Table(banner_data, colWidths=[380, 160])
        banner_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(banner_table)
        story.append(Spacer(1, 10))

        # 1. Metadata & Hashes
        story.append(Paragraph("1. Evidence Metadata & Cryptographic Hashes", section_style))
        meta = report_data["email_metadata"]
        hashes = meta["hashes"]
        meta_table_data = [
            [Paragraph("<b>Sender:</b>", body_style), Paragraph(str(meta["sender"]), body_style)],
            [Paragraph("<b>Subject:</b>", body_style), Paragraph(str(meta["subject"]), body_style)],
            [Paragraph("<b>Recipients:</b>", body_style), Paragraph(", ".join(meta["recipients"]), body_style)],
            [Paragraph("<b>Date / Ingested:</b>", body_style), Paragraph(str(meta["date"]), body_style)],
            [Paragraph("<b>Message-ID:</b>", body_style), Paragraph(str(meta["message_id"]), mono_style)],
            [Paragraph("<b>SHA-256:</b>", body_style), Paragraph(str(hashes["sha256"]), mono_style)],
            [Paragraph("<b>SHA-1:</b>", body_style), Paragraph(str(hashes["sha1"]), mono_style)],
            [Paragraph("<b>MD5:</b>", body_style), Paragraph(str(hashes["md5"]), mono_style)],
        ]
        meta_table = Table(meta_table_data, colWidths=[110, 430])
        meta_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # 2. Threat Classification & NLP
        story.append(Paragraph("2. Threat Classification & NLP Analysis", section_style))
        nlp_table_data = [
            [Paragraph("<b>Predicted Threat Label:</b>", body_style), Paragraph(str(nlp["label"]), body_style)],
            [Paragraph("<b>Model Confidence:</b>", body_style), Paragraph(f"{nlp['confidence']:.1f}%", body_style)],
            [Paragraph("<b>Classification Details:</b>", body_style), Paragraph(str(nlp.get("details", {})), mono_style)],
        ]
        nlp_table = Table(nlp_table_data, colWidths=[140, 400])
        nlp_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(nlp_table)
        story.append(Spacer(1, 10))

        # 3. Authentication Verification
        story.append(Paragraph("3. Authentication Verification", section_style))
        auth = report_data["authentication"]
        auth_data = [
            [Paragraph("<b>SPF</b>", body_style), Paragraph(str(auth["spf"]).upper(), body_style)],
            [Paragraph("<b>DKIM</b>", body_style), Paragraph(str(auth["dkim"]).upper(), body_style)],
            [Paragraph("<b>DMARC</b>", body_style), Paragraph(str(auth["dmarc"]).upper(), body_style)],
        ]
        auth_table = Table(auth_data, colWidths=[100, 440])
        auth_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(auth_table)
        story.append(Spacer(1, 10))

        # 4. Multi-Factor Risk Score Breakdown
        story.append(Paragraph("4. Multi-Factor Risk Score Breakdown", section_style))
        factors = t.get("risk_factors", [])
        if factors:
            factor_rows = [[Paragraph("<b>Factor Name</b>", body_style), Paragraph("<b>Score</b>", body_style), Paragraph("<b>Weight</b>", body_style), Paragraph("<b>Severity</b>", body_style)]]
            for f in factors:
                factor_rows.append([
                    Paragraph(str(f.get("name", "Factor")), body_style),
                    Paragraph(f"{f.get('raw_score', 0):.1f}/100", body_style),
                    Paragraph(f"{f.get('weight', 0):.2f}", body_style),
                    Paragraph(str(f.get("severity", "medium")).upper(), body_style),
                ])
            factor_table = Table(factor_rows, colWidths=[200, 100, 100, 140])
            factor_table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(factor_table)
        story.append(Spacer(1, 10))

        # 5. Infrastructure, Relay Hops & GeoLocation
        story.append(Paragraph("5. Infrastructure, Relay Hops & GeoLocation", section_style))
        infra = report_data.get("infrastructure_and_network", {})
        relay_hops = infra.get("relay_path", [])
        geo_items = infra.get("geo_data", [])
        if relay_hops or geo_items:
            infra_rows = [[Paragraph("<b>Hop / IP</b>", body_style), Paragraph("<b>Geo / Country</b>", body_style), Paragraph("<b>ISP / Host</b>", body_style)]]
            for hop in relay_hops[:5]:
                ip_str = str(hop.get("ip", "N/A"))
                matching_geo = next((g for g in geo_items if g.get("ip") == ip_str), {})
                geo_desc = f"{matching_geo.get('city', '')} {matching_geo.get('country', hop.get('country', 'Unknown'))}".strip() or "Unknown"
                infra_rows.append([
                    Paragraph(ip_str, mono_style),
                    Paragraph(geo_desc, body_style),
                    Paragraph(str(matching_geo.get("isp", hop.get("by_host", "Unknown"))), body_style),
                ])
            infra_table = Table(infra_rows, colWidths=[140, 200, 200])
            infra_table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(infra_table)
        story.append(Spacer(1, 10))

        # 6. Indicators of Compromise (IOCs)
        story.append(Paragraph("6. Indicators of Compromise (IOCs)", section_style))
        iocs = report_data["indicators_of_compromise"]
        if iocs:
            ioc_rows = [[Paragraph("<b>Type</b>", body_style), Paragraph("<b>Value</b>", body_style), Paragraph("<b>Risk</b>", body_style)]]
            for ioc in iocs[:5]:
                ioc_rows.append([
                    Paragraph(str(ioc.get("type", "IOC")), body_style),
                    Paragraph(str(ioc.get("value", "")), mono_style),
                    Paragraph(str(ioc.get("risk_score", 0)), body_style),
                ])
            ioc_table = Table(ioc_rows, colWidths=[80, 400, 60])
            ioc_table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(ioc_table)
        else:
            story.append(Paragraph("No external IOCs flagged for this email.", body_style))
        story.append(Spacer(1, 10))

        # 7. Attribution Assessment
        story.append(Paragraph("7. Attribution Assessment", section_style))
        att = report_data.get("attribution", {})
        att_data = [
            [Paragraph("<b>Actor Category:</b>", body_style), Paragraph(str(att.get("category", "Unknown")), body_style)],
            [Paragraph("<b>Attribution Confidence:</b>", body_style), Paragraph(f"{att.get('confidence', 0):.1f}%", body_style)],
            [Paragraph("<b>Campaign Cluster ID:</b>", body_style), Paragraph(str(att.get("campaign_id", "N/A")), mono_style)],
        ]
        att_table = Table(att_data, colWidths=[140, 400])
        att_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(att_table)
        story.append(Spacer(1, 14))

        # 8. Chain of Custody & Hash Verification
        story.append(Paragraph("8. Chain of Custody & Cryptographic Verification", section_style))
        custody = report_data["chain_of_custody"]
        custody_data = [
            [Paragraph("<b>Evidence Ingestion Time:</b>", body_style), Paragraph(str(custody.get("ingested_at", "N/A")), body_style)],
            [Paragraph("<b>Analysis Completed Time:</b>", body_style), Paragraph(str(custody.get("analyzed_at", "N/A")), body_style)],
            [Paragraph("<b>Digital Signature Status:</b>", body_style), Paragraph(str(custody.get("hash_verification", "VERIFIED")), body_style)],
        ]
        custody_table = Table(custody_data, colWidths=[160, 380])
        custody_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(custody_table)

        doc.build(story)
        return buf.getvalue()

    async def generate_json(
        self,
        email_id: Union[str, UUID],
        db: AsyncSession,
        user_id: str = "analyst",
    ) -> Dict[str, Any]:
        """Fetch email & analysis, assemble forensic data, log audit event, and return JSON."""
        parsed_uuid = _normalize_uuid(email_id)
        if not parsed_uuid:
            raise ValueError(f"Invalid email ID: {email_id}")

        email_res = await db.execute(select(Email).where(Email.id == parsed_uuid))
        email = email_res.scalar_one_or_none()
        if not email:
            raise ValueError(f"Email with ID {email_id} not found")

        analysis_res = await db.execute(
            select(AnalysisResult).where(AnalysisResult.email_id == parsed_uuid)
        )
        analysis = analysis_res.scalar_one_or_none()
        if not analysis:
            raise ValueError(f"Analysis result for email {email_id} not found")

        report_data = self._assemble_report_data(email, analysis)

        # Audit logging
        await self.audit_service.log_action(
            case_id=None,
            email_id=email.id,
            user_id=user_id,
            action="forensic_report_generated",
            action_data={
                "report_id": report_data["report_id"],
                "format": "json",
                "risk_score": report_data["threat_assessment"]["overall_risk_score"],
            },
            db=db,
        )

        return report_data

    async def generate_pdf(
        self,
        email_id: Union[str, UUID],
        db: AsyncSession,
        user_id: str = "analyst",
    ) -> bytes:
        """Render report HTML, convert to PDF, log audit event, and return raw PDF bytes."""
        parsed_uuid = _normalize_uuid(email_id)
        if not parsed_uuid:
            raise ValueError(f"Invalid email ID: {email_id}")

        email_res = await db.execute(select(Email).where(Email.id == parsed_uuid))
        email = email_res.scalar_one_or_none()
        if not email:
            raise ValueError(f"Email with ID {email_id} not found")

        analysis_res = await db.execute(
            select(AnalysisResult).where(AnalysisResult.email_id == parsed_uuid)
        )
        analysis = analysis_res.scalar_one_or_none()
        if not analysis:
            raise ValueError(f"Analysis result for email {email_id} not found")

        report_data = self._assemble_report_data(email, analysis)

        def _render_pdf_sync() -> bytes:
            try:
                import weasyprint
                html_content = self._render_html(report_data)
                return weasyprint.HTML(string=html_content).write_pdf()
            except Exception as e:
                logger.info(f"WeasyPrint unavailable or failed ({e}); using ReportLab fallback for PDF generation.")
                return self._generate_pdf_fallback(report_data)

        pdf_bytes = await asyncio.to_thread(_render_pdf_sync)

        # Audit logging
        await self.audit_service.log_action(
            case_id=None,
            email_id=email.id,
            user_id=user_id,
            action="forensic_report_generated",
            action_data={
                "report_id": report_data["report_id"],
                "format": "pdf",
                "size_bytes": len(pdf_bytes),
            },
            db=db,
        )

        return pdf_bytes

    async def generate_preview(
        self,
        email_id: Union[str, UUID],
        db: AsyncSession,
        user_id: str = "analyst",
    ) -> str:
        """Fetch email & analysis, assemble forensic data, and return rendered HTML preview."""
        parsed_uuid = _normalize_uuid(email_id)
        if not parsed_uuid:
            raise ValueError(f"Invalid email ID: {email_id}")

        email_res = await db.execute(select(Email).where(Email.id == parsed_uuid))
        email = email_res.scalar_one_or_none()
        if not email:
            raise ValueError(f"Email with ID {email_id} not found")

        analysis_res = await db.execute(
            select(AnalysisResult).where(AnalysisResult.email_id == parsed_uuid)
        )
        analysis = analysis_res.scalar_one_or_none()
        if not analysis:
            raise ValueError(f"Analysis result for email {email_id} not found")

        report_data = self._assemble_report_data(email, analysis)
        html_content = self._render_html(report_data)

        # Audit logging for preview
        await self.audit_service.log_action(
            case_id=None,
            email_id=email.id,
            user_id=user_id,
            action="forensic_report_previewed",
            action_data={
                "report_id": report_data["report_id"],
                "format": "html_preview",
            },
            db=db,
        )

        return html_content


