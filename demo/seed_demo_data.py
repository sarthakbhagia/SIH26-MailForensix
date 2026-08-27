import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

# Add backend directory to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = BASE_DIR / "backend"
sys.path.insert(0, str(BACKEND_DIR))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from datetime import datetime, timezone
from sqlalchemy import select, delete
from app.database import AsyncSessionLocal, engine, Base
from app.models.email_case import Email, EmailStatus, Case, CaseEmail, CaseNote, CaseStatus, CaseSeverity
from app.models.analysis_result import AnalysisResult
from app.models.alert import Alert, AlertSeverity
from app.models.audit_log import AuditLog
from app.core.pipeline import AnalysisPipeline
from app.services.email_service import EmailService
from app.services.case_service import CaseService
from app.services.audit_service import AuditService
from app.core.reporting.report_generator import ReportGenerator
from app.schemas.case import CaseCreate, CaseNoteCreate
from app.core.utils.timezone import now_utc, format_ist

SAMPLE_DIR = BASE_DIR / "sample_emails"
REPORTS_DIR = BASE_DIR / "demo" / "reports"


async def reset_database():
    """Clean existing database tables to provide a pristine demo starting state."""
    print("[CLEANUP] Cleaning database tables for demo reset...")
    async with AsyncSessionLocal() as session:
        await session.execute(delete(CaseEmail))
        await session.execute(delete(CaseNote))
        await session.execute(delete(AuditLog))
        await session.execute(delete(Alert))
        await session.execute(delete(AnalysisResult))
        await session.execute(delete(Case))
        await session.execute(delete(Email))
        await session.commit()
    print("[CLEANUP] Database reset complete.")


async def seed_demo():
    parser = argparse.ArgumentParser(description="Seed realistic demo data for SIH Email Threat Intelligence System")
    parser.add_argument("--reset", action="store_true", help="Reset all tables before seeding")
    args = parser.parse_args()

    if args.reset:
        await reset_database()

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 80)
    print("[INIT] SIH DEMO DATA INITIALIZATION & PIPELINE SEEDING")
    print("=" * 80)

    # 1. Prepare sample email files
    sample_files = [
        ("sample_legit_newsletter.eml", "Engineering Weekly Digest (Legitimate)"),
        ("sample_phishing.eml", "PayPal Credential Harvester (High-Risk Phishing)"),
        ("sample_phishing_campaign_2.eml", "Fake Invoice Overdue Notice (Campaign Correlation)"),
        ("sample_bec_fraud.eml", "CEO Confidential Wire Request (BEC Fraud)"),
    ]

    email_service = EmailService()
    pipeline = AnalysisPipeline()
    case_service = CaseService()
    audit_service = AuditService()
    report_gen = ReportGenerator(audit_service=audit_service)

    ingested_emails = {}

    print("\n[STEP 1/6] Ingesting and Running Analysis Pipelines on Sample Emails...")
    async with AsyncSessionLocal() as session:
        for filename, description in sample_files:
            file_path = SAMPLE_DIR / filename
            if not file_path.exists():
                print(f"  [ERROR] Missing sample file: {file_path}")
                continue

            with open(file_path, "rb") as f:
                raw_bytes = f.read()

            # Ingest raw email (parsing, evidence hashing, preprocessing)
            email_record = await email_service.ingest_email(db=session, raw_bytes=raw_bytes)

            # Execute full AI/ML analysis pipeline
            analysis_record = await pipeline.run(
                email_id=str(email_record.id),
                db=session,
            )

            # Re-fetch email with parsed headers
            email_ref = (await session.execute(select(Email).where(Email.id == email_record.id))).scalar_one()
            ingested_emails[filename] = {
                "id": str(email_ref.id),
                "sender": email_ref.sender,
                "subject": email_ref.subject,
                "label": analysis_record.nlp_label if analysis_record else "Unknown",
                "risk_score": analysis_record.composite_risk_score if analysis_record else 0.0,
            }

            score = analysis_record.composite_risk_score if analysis_record else 0.0
            label = analysis_record.nlp_label if analysis_record else "Unknown"
            print(f"  [OK] Analyzed: {filename} -> Subject: '{email_ref.subject}' | NLP: {label} | Risk: {score:.1f}/100")

        # Populate realistic demo alerts for presentation feed
        phish1_uuid = ingested_emails.get("sample_phishing.eml", {}).get("id")
        phish2_uuid = ingested_emails.get("sample_phishing_campaign_2.eml", {}).get("id")
        if phish1_uuid:
            alert1 = Alert(
                email_id=phish1_uuid,
                message="High-Severity Phishing Attack - Tor Exit Node Relay and Homoglyph Landing Page",
                severity=AlertSeverity.high,
                risk_score=78.0,
                contributing_factors=["Tor Relay Hop 185.220.101.5", "Lookalike Domain paypa1-security-login.xyz", "SPF/DKIM Authentication Failures"],
                acknowledged=False,
                created_at=now_utc().replace(tzinfo=None),
            )
            session.add(alert1)
        if phish2_uuid:
            alert2 = Alert(
                email_id=phish2_uuid,
                message="Campaign Correlation - Impersonated PayPal Invoice and Overdue Notice",
                severity=AlertSeverity.high,
                risk_score=75.0,
                contributing_factors=["Shared Campaign Infrastructure", "Lookalike Domain", "SPF Failures"],
                acknowledged=False,
                created_at=now_utc().replace(tzinfo=None),
            )
            session.add(alert2)
        await session.commit()

        alerts_res = await session.execute(select(Alert).order_by(Alert.created_at.desc()))
        alerts = list(alerts_res.scalars().all())
        print(f"  [ALERTS] Total Active Alerts Generated: {len(alerts)}")
        for a in alerts:
            sev_str = a.severity.value if hasattr(a.severity, "value") else str(a.severity)
            print(f"    - [{sev_str.upper()}] {a.message} (Risk: {a.risk_score:.0f}, Created: {format_ist(a.created_at)})")

    print("\n[STEP 3/6] Creating Structured Investigation Cases...")
    case1_id = None
    case2_id = None
    async with AsyncSessionLocal() as session:
        # Case 1: Campaign Investigation (Linking Phishing Email 1 & Campaign Email 2)
        c1 = await case_service.create_case(
            session,
            CaseCreate(
                title="CASE-2026-001: Operation Aegis Spear - PayPal Credential Harvester Campaign",
                description="Coordinated spear-phishing campaign leveraging Tor exit node relays (185.220.101.5), lookalike domains (paypa1-security-alert.com), and credential harvesting landing pages.",
                severity="high",
                assigned_to="senior_analyst_raj",
            ),
        )
        case1_id = c1.id

        # Update case 1 status to investigating
        await case_service.update_case(session, case1_id, {"status": "investigating"})

        # Case 2: Executive Impersonation / BEC
        c2 = await case_service.create_case(
            session,
            CaseCreate(
                title="CASE-2026-002: Executive Impersonation Wire Fraud Attempt",
                description="CEO impersonation email attempting to solicit unauthorized confidential foreign wire transfers from finance controllers.",
                severity="medium",
                assigned_to="tier2_investigator_neha",
            ),
        )
        case2_id = c2.id

        print(f"  [CASE] Created Case 1: '{c1.title}' (ID: {case1_id})")
        print(f"  [CASE] Created Case 2: '{c2.title}' (ID: {case2_id})")

    print("\n[STEP 4/6] Linking Evidence Emails & Adding Forensic Notes...")
    async with AsyncSessionLocal() as session:
        # Link emails to Case 1
        phish1_id = ingested_emails.get("sample_phishing.eml", {}).get("id")
        phish2_id = ingested_emails.get("sample_phishing_campaign_2.eml", {}).get("id")
        bec_id = ingested_emails.get("sample_bec_fraud.eml", {}).get("id")

        if phish1_id:
            await case_service.add_email_to_case(session, case1_id, phish1_id)
        if phish2_id:
            await case_service.add_email_to_case(session, case1_id, phish2_id)

        if bec_id:
            await case_service.add_email_to_case(session, case2_id, bec_id)

        # Add analyst notes to Case 1
        await case_service.add_note(
            session,
            case1_id,
            CaseNoteCreate(
                content="Identified originating relay hop at IP 185.220.101.5 corresponding to known Tor exit node router. Homoglyph lookalike domain `paypa1-security-login.xyz` registered recently.",
                author="senior_analyst_raj",
            ),
        )
        await case_service.add_note(
            session,
            case1_id,
            CaseNoteCreate(
                content="Correlated with second inbound invoice lure sharing identical upstream MTA `mail.evil-relay.xyz`. Added firewall perimeter block rules for 185.220.101.5 and sinkholed domain.",
                author="senior_analyst_raj",
            ),
        )

        # Add analyst notes to Case 2
        await case_service.add_note(
            session,
            case2_id,
            CaseNoteCreate(
                content="Urgent financial wire solicitation detected. Display name spoofing 'Johnathan Smith (CEO)' originating from non-corporate Gmail address. Contacted controller to confirm wire cancellation.",
                author="tier2_investigator_neha",
            ),
        )

        print(f"  [LINK] Linked 2 evidence emails and added 2 forensic notes to Case 1.")
        print(f"  [LINK] Linked 1 evidence email and added 1 forensic note to Case 2.")

    print("\n[STEP 5/6] Generating Publication-Ready Forensic Reports...")
    async with AsyncSessionLocal() as session:
        if phish1_id:
            # Generate JSON forensic report
            json_report = await report_gen.generate_json(phish1_id, session, user_id="senior_analyst_raj")
            json_out_path = REPORTS_DIR / "sample_phishing_forensic_report.json"
            with open(json_out_path, "w", encoding="utf-8") as f:
                json.dump(json_report, f, indent=2)

            # Generate PDF forensic report
            pdf_bytes = await report_gen.generate_pdf(phish1_id, session, user_id="senior_analyst_raj")
            pdf_out_path = REPORTS_DIR / "sample_phishing_forensic_report.pdf"
            with open(pdf_out_path, "wb") as f:
                f.write(pdf_bytes)

            print(f"  [REPORT] Saved JSON Forensic Report: {json_out_path}")
            print(f"  [REPORT] Saved PDF Forensic Report: {pdf_out_path} ({len(pdf_bytes)} bytes)")

    print("\n[STEP 6/6] Cryptographic Audit Chain Verification...")
    async with AsyncSessionLocal() as session:
        audit_status = await audit_service.verify_chain(session)
        print(f"  [AUDIT] Cryptographic Audit Chain Verified: {audit_status['valid']}")
        print(f"  [AUDIT] Total Tamper-Evident Entries: {audit_status['entries_checked']}")
        print(f"  [AUDIT] Status: {audit_status['message']}")

    print("\n" + "=" * 80)
    print("[READY] DEMO ENVIRONMENT READY! All services initialized with realistic threat telemetry.")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(seed_demo())
