from celery import Celery
from app.config import settings

celery_app = Celery(
    "email_threat_intel",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,          # 5 min hard timeout
    task_soft_time_limit=240,     # 4 min soft timeout
    worker_prefetch_multiplier=1, # Control worker concurrency
    worker_max_tasks_per_child=50, # Periodic worker recycling
    broker_connection_timeout=0.2, # Fast fail if Redis broker is offline
    broker_connection_retry=False,
    broker_connection_max_retries=0,
    beat_schedule={
        "refresh-phishtank-hourly": {
            "task": "refresh_phishtank_db",
            "schedule": 3600.0,
        },
        "refresh-tor-nodes-daily": {
            "task": "refresh_tor_exit_nodes",
            "schedule": 86400.0,
        },
    },
)
