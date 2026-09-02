import asyncio
import dataclasses
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.config import settings
from app.models.analysis_result import AnalysisResult
from app.models.email_case import Email, EmailStatus
from app.core.analysis.header_forensics import HeaderForensics
from app.core.analysis.geo_intel import GeoIntelligence
from app.core.analysis.nlp_classifier import NLPClassifier
from app.core.analysis.link_analyzer import LinkAnalyzer
from app.core.analysis.attachment_analyzer import AttachmentAnalyzer
from app.core.correlation.risk_scorer import RiskScorer, normalize_threat_label
from app.core.correlation.graph_engine import GraphEngine
from app.core.reporting.alert_engine import AlertEngine
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)


class AnalysisPipeline:
    def __init__(self):
        self.header_forensics = HeaderForensics()
        self.geo_intel = GeoIntelligence()
        self.nlp_classifier = NLPClassifier(
            model_path=settings.NLP_MODEL_PATH,
            ensemble_path=settings.ENSEMBLE_MODEL_PATH,
            tabular_path=settings.TABULAR_MODEL_PATH,
        )
        self.link_analyzer = LinkAnalyzer()
        self.attachment_analyzer = AttachmentAnalyzer()
        self.risk_scorer = RiskScorer()
        self.graph_engine = GraphEngine()
        self.alert_engine = AlertEngine()
        self.audit_service = AuditService()

    async def run(
        self,
        email_id: Union[str, UUID],
        db: AsyncSession,
    ) -> Optional[AnalysisResult]:
        parsed_uuid = email_id if isinstance(email_id, UUID) else UUID(str(email_id))
        result = await db.execute(select(Email).filter(Email.id == parsed_uuid))
        email = result.scalar_one_or_none()

        if not email:
            return None

        # Update status to "processing"
        email.status = EmailStatus.processing
        await db.commit()

        try:
            # Extract domain from sender for geo intel
            sender_str = str(email.sender or "")
            sender_domain = sender_str.split("@")[-1] if "@" in sender_str else ""

            # Run analysis modules IN PARALLEL using asyncio.gather()
            email_headers = email.headers or {}
            header_result, geo_result, nlp_result, link_result, attachment_result = await asyncio.gather(
                self.header_forensics.analyze(
                    email.raw_eml or b"", email_headers, sender_str,
                    email_headers.get("received_hops", [])
                ),
                self.geo_intel.analyze(
                    email_headers.get("received_hops", []), sender_domain,
                    email_headers=email_headers,
                ),
                asyncio.to_thread(
                    self.nlp_classifier.classify,
                    email.subject or "",
                    email.body_text or "",
                    sender_str,
                    email_headers,
                    urls=email.urls or [],
                    attachments=email.attachments or [],
                ),
                self.link_analyzer.analyze(email.urls or []),
                asyncio.to_thread(self.attachment_analyzer.analyze, email.attachments or []),
                return_exceptions=True,
            )

            # Handle errors from individual modules gracefully
            default_header = self._get_default_header()
            default_geo = self._get_default_geo()
            default_nlp = self._get_default_nlp()
            default_link = self._get_default_link()
            default_attachment = self._get_default_attachment()

            if isinstance(header_result, Exception):
                logger.warning(f"HeaderForensics error for email {email_id}: {header_result}")
                header_result = default_header
            if isinstance(geo_result, Exception):
                logger.warning(f"GeoIntelligence error for email {email_id}: {geo_result}")
                geo_result = default_geo
            if isinstance(nlp_result, Exception):
                logger.warning(f"NLPClassifier error for email {email_id}: {nlp_result}")
                nlp_result = default_nlp
            if isinstance(link_result, Exception):
                logger.warning(f"LinkAnalyzer error for email {email_id}: {link_result}")
                link_result = default_link
            if isinstance(attachment_result, Exception):
                logger.warning(f"AttachmentAnalyzer error for email {email_id}: {attachment_result}")
                attachment_result = default_attachment

            # Build IOC list from all modules
            iocs = self._collect_iocs(
                header_result, geo_result, link_result, attachment_result
            )

            # Compute multi-factor risk score using RiskScorer
            risk_composite = self.risk_scorer.compute(
                nlp_result, header_result, geo_result,
                link_result, attachment_result
            )

            # Determine attribution category
            attribution_category = self._determine_attribution(
                header_result, geo_result, nlp_result
            )

            # Prepare serializable dictionaries for storage and graph
            relay_hops_dict = [self._asdict(hop) for hop in getattr(header_result, "relay_path", [])]
            geo_data_dict = [self._asdict(geo) for geo in getattr(geo_result, "geo_locations", [])]
            domain_intel_dict = self._asdict(geo_result.domain_intel) if getattr(geo_result, "domain_intel", None) else {}

            # Calculate attribution evidence support score across evaluated domains
            attribution_evidence_score = self._compute_attribution_evidence_support(
                header_result, geo_result, nlp_result
            )

            # Build / update attribution graph entity for this email
            self.graph_engine.add_email(
                {"id": str(email.id), "sender": email.sender, "subject": email.subject},
                {
                    "relay_path": relay_hops_dict,
                    "geo_data": geo_data_dict,
                    "domain_intel": domain_intel_dict,
                    "composite_risk_score": risk_composite.overall_score,
                    "attribution_evidence_score": attribution_evidence_score,
                    "analyzed_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            graph_json = self.graph_engine.get_subgraph_for_email(str(email.id), hops=2)
            if isinstance(graph_json, dict):
                graph_json["attribution_evidence_score"] = attribution_evidence_score

            # Delete any existing AnalysisResult row before inserting new one to support clean re-analysis
            existing_res = await db.execute(select(AnalysisResult).filter(AnalysisResult.email_id == email.id))
            existing_analysis = existing_res.scalar_one_or_none()
            if existing_analysis:
                await db.delete(existing_analysis)
                await db.flush()

            # Build analysis result record
            analysis = AnalysisResult(
                email_id=email.id,
                nlp_label=nlp_result.label,
                nlp_confidence=nlp_result.confidence,
                nlp_details={
                    "probabilities": getattr(nlp_result, "probabilities", {}),
                    "urgency_score": getattr(nlp_result, "urgency_score", 0.0),
                    "bec_indicators": getattr(nlp_result, "bec_indicators", []),
                    "impersonation_signals": getattr(nlp_result, "impersonation_signals", []),
                    "confidence_calibrated": getattr(nlp_result, "confidence_calibrated", False),
                    "confidence_method": getattr(nlp_result, "confidence_method", "rule_heuristic"),
                    "evidence_score": getattr(nlp_result, "evidence_score", None),
                },
                auth_status={
                    "spf": getattr(getattr(header_result, "spf", None), "status", "none"),
                    "spf_status": getattr(getattr(header_result, "spf", None), "status", "none"),
                    "spf_domain": getattr(getattr(header_result, "spf", None), "domain", ""),
                    "spf_ip": getattr(getattr(header_result, "spf", None), "ip", ""),
                    "spf_record": getattr(getattr(header_result, "spf", None), "record", ""),
                    "spf_details": getattr(getattr(header_result, "spf", None), "details", ""),

                    "dkim": getattr(getattr(header_result, "dkim", None), "status", "none"),
                    "dkim_status": getattr(getattr(header_result, "dkim", None), "status", "none"),
                    "dkim_domain": getattr(getattr(header_result, "dkim", None), "domain", ""),
                    "dkim_selector": getattr(getattr(header_result, "dkim", None), "selector", ""),
                    "dkim_details": getattr(getattr(header_result, "dkim", None), "details", ""),

                    "dmarc": getattr(getattr(header_result, "dmarc", None), "status", "none"),
                    "dmarc_status": getattr(getattr(header_result, "dmarc", None), "status", "none"),
                    "dmarc_domain": getattr(getattr(header_result, "dmarc", None), "domain", ""),
                    "dmarc_policy": getattr(getattr(header_result, "dmarc", None), "policy", "none"),
                    "policy": getattr(getattr(header_result, "dmarc", None), "policy", "none"),
                    "alignment_spf": getattr(getattr(header_result, "dmarc", None), "alignment_spf", False),
                    "alignment_dkim": getattr(getattr(header_result, "dmarc", None), "alignment_dkim", False),
                    "dmarc_record": getattr(getattr(header_result, "dmarc", None), "record", ""),
                    "dmarc_details": getattr(getattr(header_result, "dmarc", None), "details", ""),

                    "auth_confidence_score": getattr(header_result, "auth_confidence_score", 50.0),
                },
                relay_path=relay_hops_dict,
                geo_data=geo_data_dict,
                ip_reputation={"score": getattr(geo_result, "ip_reputation_score", 50.0)},
                domain_intel=domain_intel_dict,
                iocs=[self._asdict(ioc) for ioc in iocs],
                composite_risk_score=risk_composite.overall_score,
                risk_breakdown={
                    "factors": [self._asdict(f) for f in risk_composite.factors],
                    "severity": risk_composite.severity,
                    "recommended_action": risk_composite.recommended_action,
                    "nlp": next((f.raw_score for f in risk_composite.factors if "NLP" in f.name), 0.0),
                    "auth": next((f.raw_score for f in risk_composite.factors if "Authentication" in f.name), 0.0),
                    "ip": next((f.raw_score for f in risk_composite.factors if "IP" in f.name), 0.0),
                    "link": next((f.raw_score for f in risk_composite.factors if "Link" in f.name), 0.0),
                    "attachment": next((f.raw_score for f in risk_composite.factors if "Attachment" in f.name), 0.0),
                },
                attribution_category=attribution_category,
                attribution_confidence=None,
                graph_data=graph_json,
                analyzed_at=datetime.now(timezone.utc).replace(tzinfo=None),
            )

            db.add(analysis)
            email.status = EmailStatus.analyzed
            await db.commit()
            await db.refresh(analysis)
        except Exception as exc:
            logger.error(f"Analysis pipeline failed for email {email_id}: {exc}", exc_info=True)
            try:
                email.status = EmailStatus.error
                await db.commit()
            except Exception as db_err:
                logger.error(f"Failed to record error status for email {email_id}: {db_err}")
            raise exc

        # Phase 4 Integration: Alerting & Tamper-Evident Audit Logging
        alert_created = False
        try:
            try:
                await self.alert_engine.connect()
                alert = await self.alert_engine.evaluate(
                    email_id=email.id,
                    risk_score=risk_composite.overall_score,
                    risk_breakdown=analysis.risk_breakdown,
                    iocs=iocs,
                    nlp_label=nlp_result.label,
                    db=db,
                )
                if alert:
                    alert_created = True
                    logger.info(
                        f"Alert triggered for email {email_id}: severity={alert.severity}, risk={alert.risk_score}"
                    )
            finally:
                await self.alert_engine.disconnect()
        except Exception as alert_err:
            logger.error(f"Alert evaluation error for email {email_id}: {alert_err}", exc_info=True)

        try:
            await self.audit_service.log_action(
                action="email_analysis_completed",
                action_data={
                    "email_id": str(email.id),
                    "risk_score": float(risk_composite.overall_score),
                    "nlp_label": str(nlp_result.label),
                    "alert_triggered": alert_created,
                },
                email_id=email.id,
                user_id="system_pipeline",
                db=db,
            )
        except Exception as audit_err:
            logger.error(f"Audit logging error for email {email_id}: {audit_err}", exc_info=True)

        # Dispatch async threat intel enrichment task via Celery (if broker reachable)
        try:
            from app.workers.tasks import enrich_threat_intel_task
            att_hashes = [att.sha256 for att in getattr(attachment_result, "results", []) if getattr(att, "sha256", None)]
            enrich_threat_intel_task.apply_async(
                args=[
                    str(email.id),
                    [hop.ip for hop in getattr(header_result, "relay_path", []) if getattr(hop, "ip", None) and not getattr(hop, "is_private", False)],
                    [sender_domain] if sender_domain else [],
                    email.urls or [],
                    att_hashes,
                ],
                expires=60,
                connect_timeout=0.1,
            )
        except Exception:
            logger.debug(f"Celery broker dispatch skipped for email {email_id}.")

        return analysis

    def _get_default_header(self):
        return type('H', (), {
            'spf': type('S', (), {'status': 'none'})(),
            'dkim': type('S', (), {'status': 'none'})(),
            'dmarc': type('S', (), {'status': 'none', 'policy': 'none'})(),
            'relay_path': [],
            'anomalies': [],
            'auth_confidence_score': 0.0,
        })()

    def _get_default_geo(self):
        return type('G', (), {
            'originating_ip': 'unknown',
            'geo_locations': [],
            'domain_intel': None,
            'infrastructure_flags': [],
            'location_confidence': 'medium',
            'ip_reputation_score': 50.0,
        })()

    def _get_default_nlp(self):
        return type('N', (), {
            'label': 'Legitimate',
            'confidence': 0.0,
            'probabilities': {},
            'urgency_score': 0.0,
            'bec_indicators': [],
            'impersonation_signals': [],
            'contributing_factors': [],
        })()

    def _get_default_link(self):
        return type('L', (), {'overall_link_risk': 0.0, 'urls_analyzed': 0, 'phishing_urls_found': 0})()

    def _get_default_attachment(self):
        return type('A', (), {'overall_attachment_risk': 0.0, 'total_attachments': 0, 'results': []})()

    def _asdict(self, obj: Any) -> Any:
        if dataclasses.is_dataclass(obj):
            return {k: self._asdict(v) for k, v in vars(obj).items()}
        if hasattr(obj, "__dict__"):
            return {k: self._asdict(v) for k, v in obj.__dict__.items() if not k.startswith("_")}
        if isinstance(obj, list):
            return [self._asdict(item) for item in obj]
        if isinstance(obj, dict):
            return {k: self._asdict(v) for k, v in obj.items()}
        return obj

    def _collect_iocs(
        self,
        header_result,
        geo_result,
        link_result,
        attachment_result,
    ) -> List[Any]:
        iocs = []

        # From link analyzer
        if link_result:
            for url_result in getattr(link_result, 'url_results', []):
                if getattr(url_result, 'risk_reasons', []):
                    for reason in url_result.risk_reasons:
                        if "lookalike" in reason:
                            iocs.append(type('I', (), {
                                'type': 'URL',
                                'value': getattr(url_result, 'original_url', ''),
                                'risk_score': getattr(url_result, 'risk_score', 0),
                                'reason': reason,
                                'source': 'Link Analyzer',
                            })())
                        elif "homoglyph" in reason:
                            iocs.append(type('I', (), {
                                'type': 'Domain',
                                'value': getattr(url_result, 'domain', ''),
                                'risk_score': getattr(url_result, 'risk_score', 0),
                                'reason': reason,
                                'source': 'Link Analyzer',
                            })())

        # From attachment analyzer
        if attachment_result:
            for att_result in getattr(attachment_result, 'results', []):
                if getattr(att_result, 'risk_reasons', []):
                    for reason in att_result.risk_reasons:
                        if "executable" in reason or "macro" in reason:
                            iocs.append(type('I', (), {
                                'type': 'Hash',
                                'value': getattr(att_result, 'sha256', ''),
                                'risk_score': getattr(att_result, 'risk_score', 0),
                                'reason': reason,
                                'source': 'Attachment Analyzer',
                            })())

        # From geo intel - TOR/VPN IPs
        if geo_result:
            for geo in getattr(geo_result, 'geo_locations', []):
                if getattr(geo, 'infrastructure_type', '') in ("known_vpn", "tor_exit_node"):
                    iocs.append(type('I', (), {
                        'type': 'IP',
                        'value': getattr(geo, 'ip', ''),
                        'risk_score': 90,
                        'reason': f"{geo.infrastructure_type}",
                        'source': 'Geo Intelligence',
                    })())

        return iocs

    def _compute_risk_score(
        self,
        nlp,
        header,
        geo,
        link,
        attachment,
    ) -> float:
        """Backward-compatible fallback risk calculation."""
        res = self.risk_scorer.compute(nlp, header, geo, link, attachment)
        return res.overall_score

    def _determine_attribution(
        self, header, geo, nlp
    ) -> str:
        spf_status = getattr(getattr(header, "spf", None), "status", "")
        dkim_status = getattr(getattr(header, "dkim", None), "status", "")
        raw_label = getattr(nlp, "label", "LEGITIMATE")
        canonical_label = normalize_threat_label(raw_label)
        impersonation_signals = getattr(nlp, "impersonation_signals", [])
        infra_flags = getattr(geo, "infrastructure_flags", []) or []
        anomalies = getattr(header, "anomalies", []) or []
        ip_rep = getattr(geo, "ip_reputation_score", 50)

        if spf_status == "pass" and dkim_status == "pass" and canonical_label != "LEGITIMATE":
            return "Compromised Account"
        if spf_status == "fail" and any(s.startswith("lookalike") for s in impersonation_signals):
            return "Spoofed Domain"
        if "tor_exit_node" in infra_flags or "known_vpn" in infra_flags:
            return "Anonymized Infrastructure"
        if any(getattr(a, "type", "") == "time_travel" for a in anomalies):
            return "Compromised Relay"
        if geo and ip_rep < 30:
            return "Direct Malicious Actor"
        return "Unknown"

    def _compute_attribution_evidence_support(
        self, header, geo, nlp
    ) -> float:
        """Compute heuristic evidence support score across evaluated analysis domains."""
        factors = 0
        total = 4
        # 1. Header authentication evaluated
        if getattr(header, "spf", None) or getattr(header, "dkim", None) or getattr(header, "dmarc", None):
            factors += 1
        # 2. Network/Geo routing evaluated
        if geo and (getattr(geo, "geo_locations", None) or getattr(geo, "domain_intel", None)):
            factors += 1
        # 3. NLP classifier produced evidence
        if getattr(nlp, "confidence", None) is not None or getattr(nlp, "evidence_score", None) is not None:
            factors += 1
        # 4. Definite attribution category identified
        category = self._determine_attribution(header, geo, nlp)
        if category and category != "Unknown":
            factors += 1
        return round((max(1, factors) / total) * 100.0, 1)

    def _compute_attribution_confidence(
        self, header, geo, nlp
    ) -> Optional[float]:
        """Backward-compatible method returning evidence support score for callers."""
        return self._compute_attribution_evidence_support(header, geo, nlp)