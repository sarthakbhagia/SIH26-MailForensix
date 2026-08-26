import asyncio
import json
import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.alert import Alert, AlertSeverity
from app.schemas.alert import AlertAcknowledgeResponse, AlertListResponse, AlertResponse, AlertStatsResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/stats", response_model=AlertStatsResponse)
async def get_alert_stats(db: AsyncSession = Depends(get_db)):
    """Return summary statistics of alerts: total, unacknowledged, and critical."""
    total_query = select(func.count(Alert.id))
    total = (await db.execute(total_query)).scalar() or 0

    unack_query = select(func.count(Alert.id)).where(Alert.acknowledged == False)  # noqa: E712
    unacknowledged = (await db.execute(unack_query)).scalar() or 0

    crit_query = select(func.count(Alert.id)).where(
        or_(Alert.severity == AlertSeverity.critical, Alert.severity == "critical")
    )
    critical = (await db.execute(crit_query)).scalar() or 0

    return AlertStatsResponse(total=total, unacknowledged=unacknowledged, critical=critical)


@router.get("/", response_model=AlertListResponse)
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=500),
    limit: Optional[int] = Query(None, ge=1, le=500),
    offset: Optional[int] = Query(None, ge=0),
    severity: Optional[str] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """List paginated alerts ordered newest first with optional severity and acknowledged filters."""
    calc_limit = limit if limit is not None else page_size
    calc_offset = offset if offset is not None else (page - 1) * page_size

    query = select(Alert)
    count_query = select(func.count(Alert.id))

    if severity:
        # Match enum by value or string
        query = query.where(Alert.severity == severity)
        count_query = count_query.where(Alert.severity == severity)

    if acknowledged is not None:
        query = query.where(Alert.acknowledged == acknowledged)
        count_query = count_query.where(Alert.acknowledged == acknowledged)

    total_res = await db.execute(count_query)
    total = total_res.scalar() or 0

    query = query.order_by(desc(Alert.created_at), desc(Alert.id)).offset(calc_offset).limit(calc_limit)
    result = await db.execute(query)
    items = list(result.scalars().all())

    return AlertListResponse(items=items, total=total)


@router.put("/{alert_id}/acknowledge", response_model=AlertAcknowledgeResponse)
@router.post("/{alert_id}/acknowledge", response_model=AlertAcknowledgeResponse)
async def acknowledge_alert(alert_id: UUID, db: AsyncSession = Depends(get_db)):
    """Mark an alert as acknowledged. Returns 404 if the alert does not exist."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.acknowledged = True
    await db.commit()
    await db.refresh(alert)
    return AlertAcknowledgeResponse(status="acknowledged", alert_id=alert.id, acknowledged=True)


@router.websocket("/ws")
async def websocket_alerts(websocket: WebSocket):
    """
    WebSocket endpoint streaming real-time threat alerts from Redis Pub/Sub channel 'alerts:realtime'.
    Supports heartbeat ping/pong and graceful disconnect cleanup.
    """
    await websocket.accept()
    pubsub = None
    redis_conn = None

    try:
        import redis.asyncio as aioredis

        redis_conn = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        pubsub = redis_conn.pubsub()
        await pubsub.subscribe("alerts:realtime")
        logger.debug("WebSocket client connected and subscribed to alerts:realtime")

        async def forward_redis_messages():
            try:
                async for message in pubsub.listen():
                    if message and message.get("type") == "message":
                        data = message.get("data")
                        if data:
                            await websocket.send_text(data)
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.debug(f"Redis listener ended: {e}")

        async def handle_client_heartbeats():
            try:
                while True:
                    text = await websocket.receive_text()
                    if text in ("ping", '{"type":"ping"}', '{"type": "ping"}'):
                        await websocket.send_text(json.dumps({"type": "pong"}))
            except WebSocketDisconnect:
                pass
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.debug(f"WebSocket receiver ended: {e}")

        forward_task = asyncio.create_task(forward_redis_messages())
        receive_task = asyncio.create_task(handle_client_heartbeats())

        done, pending = await asyncio.wait(
            [forward_task, receive_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()

    except WebSocketDisconnect:
        logger.debug("WebSocket client disconnected normally")
    except Exception as e:
        logger.warning(f"WebSocket alert connection error: {e}")
    finally:
        if pubsub:
            try:
                await pubsub.unsubscribe("alerts:realtime")
                await pubsub.close()
            except Exception:
                pass
        if redis_conn:
            try:
                await redis_conn.close()
            except Exception:
                pass

