"""Live End-to-End Verification Script for Active ML Pipeline."""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4
import json

from app.config import settings
from app.database import Base, engine, AsyncSessionLocal
from app.models.email_case import Email, EmailStatus
from app.models.analysis_result import AnalysisResult
from app.core.pipeline import AnalysisPipeline
from app.core.ingestion.parser import EmailParser


async def run_live_proof():
    # 1. Initialize DB schema and pipeline
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    pipeline = AnalysisPipeline()
    print("=== 1. ML RUNTIME INITIALIZATION ===")
    print(f"NLPClassifier rule_based_only: {pipeline.nlp_classifier.rule_based_only}")
    print(f"DistilRoBERTa Model Loaded: {pipeline.nlp_classifier.transformer_model is not None}")
    print(f"LightGBM Tabular Model Loaded: {pipeline.nlp_classifier.tabular_classifier is not None}")
    print(f"Stacking Ensemble Model Loaded: {pipeline.nlp_classifier.ensemble_classifier is not None}")

    # 2. Ingest Sample Phishing Email via EmailService
    raw_eml = (
        b"From: Security Team <security@account-verification-service.com>\n"
        b"To: target@victim.org\n"
        b"Subject: CRITICAL: Your account will be closed within 24 hours\n"
        b"Date: Tue, 01 Sep 2026 12:00:00 +0000\n"
        b"Message-ID: <threat-test-01@mailforensix.com>\n"
        b"MIME-Version: 1.0\n"
        b"Content-Type: text/plain; charset=\"utf-8\"\n\n"
        b"Dear user,\n"
        b"Unauthorized login was detected on your account.\n"
        b"Click here immediately to verify your identity: http://secure-login.suspicious-domain.ru\n"
    )

    from app.services.email_service import EmailService
    email_service = EmailService()

    async with AsyncSessionLocal() as session:
        email = await email_service.ingest_email(session, raw_eml)
        email_id = email.id
        await session.commit()


        # 3. Execute AnalysisPipeline
        print("\n=== 2. EXECUTING LIVE ANALYSIS PIPELINE ===")
        analysis = await pipeline.run(email_id, session)
        await session.commit()

        print("\n=== 3. LIVE PIPELINE PERSISTENCE & RESULTS ===")
        print(f"Email ID: {analysis.email_id}")
        print(f"NLP Threat Verdict: {analysis.nlp_label}")
        print(f"Calibrated Model Confidence: {analysis.nlp_confidence}%")
        print(f"Confidence Method: {analysis.nlp_details.get('confidence_method')}")
        print(f"Is Calibrated: {analysis.nlp_details.get('confidence_calibrated')}")
        print(f"Probabilities Breakdown: {json.dumps(analysis.nlp_details.get('probabilities'), indent=2)}")
        print(f"Composite Threat Risk Score: {analysis.composite_risk_score} / 100.0")
        print(f"Risk Severity Tier: {analysis.risk_breakdown.get('severity')}")
        print(f"Recommended Action: {analysis.risk_breakdown.get('recommended_action')}")
        print(f"Graph Entities Created: {len(analysis.graph_data.get('nodes', []))}")


if __name__ == "__main__":
    asyncio.run(run_live_proof())
