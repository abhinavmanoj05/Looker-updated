from celery import Celery

from config.database import settings

celery_engine = Celery(
    "intel_tasks",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

celery_engine.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True
)

# Automatically register sub-module workers
celery_engine.autodiscover_tasks(["services.osint_worker", "services.ml_engine"])
