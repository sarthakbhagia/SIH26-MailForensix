import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.alert import Alert, AlertSeverity
from app.core.correlation.risk_scorer import normalize_threat_label

logger = logging.getLogger(__name__)


def _normalize_uuid(val: Optional[Union[str, UUID]]) -> Optional[UUID]:
    if val is None or val == "":
        return None
    if isinstance(val, UUID):
        return val
    try:
        return UUID(str(val))
    except (ValueError, TypeError, AttributeError):
        return None


@dataclass
class AlertConfig:
    high_threshold: float = 75.0
    critical_threshold: float = 90.0
    enabled: bool = True
    websocket_enabled: bool = True
    max_alerts_per_hour: int = 100


@dataclass
class AlertTrigger:
    email_id: str
    risk_score: float
    severity: str  # "high" | "critical"
    title: str
    message: str
    contributing_factors: List[str]
    recommended_action: str
    ioc_summary: List[Dict[str, Any]]


class AlertEngine:
    """Alert evaluation and publishing engine for high/critical threats."""

    ALERT_CHANNEL = "alerts:realtime"

    def __init__(
        self,
        redis_url: Optional[str] = None,
        config: Optional[AlertConfig] = None,
    ):
        high_t = float(os.getenv("ALERT_THRESHOLD_HIGH", str(getattr(settings, "ALERT_THRESHOLD_HIGH", 75))))
        crit_t = float(os.getenv("ALERT_THRESHOLD_CRITICAL", str(getattr(settings, "ALERT_THRESHOLD_CRITICAL", 90))))
        self.config = config or AlertConfig(
            high_threshold=high_t,
            critical_threshold=crit_t,
            enabled=True,
            websocket_enabled=True,
            max_alerts_per_hour=100,
        )
        self.redis_url = redis_url or getattr(settings, "REDIS_URL", "redis://localhost:6379/0")
        self._redis = None
        self._alert_count_key = "alert_engine:hourly_count"

    async def connect(self) -> None:
        """Initialize Redis connection for Pub/Sub notifications."""
        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(self.redis_url, decode_responses=True)
            await self._redis.ping()
            logger.debug(f"AlertEngine connected to Redis at {self.redis_url}")
        except Exception as e:
            logger.warning(
                f"Could not connect AlertEngine to Redis at {self.redis_url}: {e}. AlertEngine running without Redis push."
            )
            self._redis = None

    async def disconnect(self) -> None:
        """Disconnect Redis connection."""
        if self._redis:
            try:
                if hasattr(self._redis, "aclose"):
                    await self._redis.aclose()
                elif hasattr(self._redis, "close"):
                    await self._redis.close()
            except Exception as e:
                logger.warning(f"Error closing AlertEngine Redis connection: {e}")
            finally:
                self._redis = None

    def _build_title(self, nlp_label: str, severity: str, risk_score: float) -> str:
        """Build a concise, severity-coded alert title."""
        severity_emoji = "🔴" if severity == "critical" else "🟠"
        canonical = normalize_threat_label(nlp_label)
        titles = {
            "PHISHING": f"{severity_emoji} Phishing Email Detected (Risk: {risk_score:.0f})",
            "BEC_FRAUD": f"{severity_emoji} Business Email Compromise Attempt (Risk: {risk_score:.0f})",
            "IMPERSONATION": f"{severity_emoji} Impersonation Attack Detected (Risk: {risk_score:.0f})",
            "SUSPICIOUS": f"{severity_emoji} Suspicious Email Flagged (Risk: {risk_score:.0f})",
        }
        return titles.get(canonical, f"{severity_emoji} Threat Detected (Risk: {risk_score:.0f})")

    def _extract_top_factors(self, risk_breakdown: Dict[str, Any]) -> List[str]:
        """Extract top 3 risk factors formatted as readable strings."""
        factors = (risk_breakdown or {}).get("factors", [])
        sorted_factors = sorted(
            factors,
            key=lambda f: f.get("raw_score", 0) if isinstance(f, dict) else getattr(f, "raw_score", 0),
            reverse=True,
        )
        result = []
        for f in sorted_factors[:3]:
            if isinstance(f, dict):
                name = f.get("name", "Unknown Factor")
                raw = f.get("raw_score", 0.0)
                sev = f.get("severity", "medium")
                result.append(f"{name}: {raw:.0f}/100 ({sev})")
            else:
                name = getattr(f, "name", "Unknown Factor")
                raw = getattr(f, "raw_score", 0.0)
                sev = getattr(f, "severity", "medium")
                result.append(f"{name}: {raw:.0f}/100 ({sev})")
        return result

    def _build_message(self, nlp_label: str, risk_breakdown: Dict[str, Any]) -> str:
        """Build detailed human-readable alert message."""
        top_factors = self._extract_top_factors(risk_breakdown)
        action = (risk_breakdown or {}).get("recommended_action", "Review")
        lines = [f"Classification: {nlp_label or 'Unknown'}"]
        for f in top_factors:
            lines.append(f"• {f}")
        lines.append(f"\nAction: {action}")
        return "\n".join(lines)

    async def _check_rate_limit(self) -> bool:
        """Check if we are under the hourly alert rate limit."""
        if not self._redis:
            return True
        try:
            count = await self._redis.get(self._alert_count_key)
            return int(count or 0) < self.config.max_alerts_per_hour
        except Exception as e:
            logger.warning(f"Error checking rate limit in Redis: {e}")
            return True

    async def _increment_rate_limit(self) -> None:
        """Increment hourly alert counter with 3600s TTL."""
        if not self._redis:
            return
        try:
            pipe = self._redis.pipeline()
            pipe.incr(self._alert_count_key)
            pipe.expire(self._alert_count_key, 3600)
            await pipe.execute()
        except Exception as e:
            logger.warning(f"Error incrementing rate limit in Redis: {e}")

    async def _publish_alert(self, alert: Alert) -> None:
        """Publish alert payload to Redis Pub/Sub for WebSocket push."""
        if not self._redis or not self.config.websocket_enabled:
            return
        try:
            sev_str = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
            created_str = alert.created_at.isoformat() if hasattr(alert.created_at, "isoformat") else str(alert.created_at)
            payload = {
                "id": str(alert.id),
                "email_id": str(alert.email_id) if alert.email_id else "",
                "severity": sev_str,
                "message": alert.message,
                "risk_score": alert.risk_score,
                "contributing_factors": alert.contributing_factors,
                "acknowledged": alert.acknowledged,
                "created_at": created_str,
            }
            await self._redis.publish(self.ALERT_CHANNEL, json.dumps(payload))
            logger.info(f"Published alert {alert.id} to {self.ALERT_CHANNEL}")
        except Exception as e:
            logger.warning(f"Failed to publish alert to Redis {self.ALERT_CHANNEL}: {e}")

    async def evaluate(
        self,
        email_id: Union[str, UUID],
        risk_score: float,
        risk_breakdown: Dict[str, Any],
        iocs: List[Any],
        nlp_label: str,
        db: AsyncSession,
    ) -> Optional[Alert]:
        """
        Evaluate analysis results and create alert if thresholds are exceeded.
        """
        if not self.config.enabled:
            return None

        # 1. Determine severity
        if risk_score >= self.config.critical_threshold:
            severity = "critical"
        elif risk_score >= self.config.high_threshold:
            severity = "high"
        else:
            return None  # Below threshold

        # 2. Rate limit check
        if not await self._check_rate_limit():
            logger.warning(
                f"Alert rate limit ({self.config.max_alerts_per_hour}/hr) reached; suppressing alert for email {email_id}"
            )
            return None

        # 3. Extract top 5 IOCs by risk
        sorted_iocs = []
        for ioc in (iocs or []):
            if isinstance(ioc, dict):
                sorted_iocs.append(ioc)
            elif hasattr(ioc, "__dict__"):
                sorted_iocs.append({k: v for k, v in ioc.__dict__.items() if not k.startswith("_")})
        top_iocs = sorted(sorted_iocs, key=lambda x: x.get("risk_score", 0), reverse=True)[:5]

        # 4. Extract contributing factors & action
        top_factors = self._extract_top_factors(risk_breakdown)
        rec_action = (risk_breakdown or {}).get("recommended_action", "Review")

        # 5. Build title & message
        title = self._build_title(nlp_label, severity, risk_score)
        message = self._build_message(nlp_label, risk_breakdown)

        # 6. Build trigger object
        trigger = AlertTrigger(
            email_id=str(email_id),
            risk_score=risk_score,
            severity=severity,
            title=title,
            message=message,
            contributing_factors=top_factors,
            recommended_action=rec_action,
            ioc_summary=top_iocs,
        )

        # 7. Persist Alert
        parsed_email_uuid = _normalize_uuid(email_id)
        severity_enum = (
            AlertSeverity[severity]
            if severity in AlertSeverity.__members__
            else getattr(AlertSeverity, severity, AlertSeverity.high)
        )

        alert = Alert(
            email_id=parsed_email_uuid,
            severity=severity_enum,
            message=trigger.message,
            risk_score=risk_score,
            contributing_factors={
                "title": trigger.title,
                "factors": trigger.contributing_factors,
                "recommended_action": trigger.recommended_action,
                "ioc_summary": trigger.ioc_summary,
            },
            acknowledged=False,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )

        db.add(alert)
        await db.commit()
        await db.refresh(alert)

        # 8. Publish to Redis for WebSocket push
        if self.config.websocket_enabled:
            await self._publish_alert(alert)

        # 9. Increment rate limit counter
        await self._increment_rate_limit()

        return alert

