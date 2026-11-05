from celery import Celery

from app.config import settings

celery_app = Celery("concierge", broker=settings.redis_url, include=["app.workers.tasks"])
celery_app.conf.update(
    task_acks_late=True,                 # ack only after the task finishes
    task_reject_on_worker_lost=True,     # a killed worker puts the message back
    worker_prefetch_multiplier=1,        # no hoarding: fair dispatch across workers
    broker_transport_options={"visibility_timeout": 3600},
    task_default_queue="intent",
    task_ignore_result=True,             # state lives in Postgres, not in a result backend
    broker_connection_retry_on_startup=True,
)
app = celery_app  # `celery -A app.workers.celery_app worker` finds this
