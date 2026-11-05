"""Scheduler process: fire due jobs, relay the outbox, reconcile. Safe to run several replicas
(every query uses FOR UPDATE SKIP LOCKED or a conditional UPDATE)."""
import logging
import signal
import time

from app.config import settings
from app.services import workflow_engine as wfe
from app.workers.celery_app import celery_app

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("scheduler")
_running = True


def publish(topic: str, payload: dict) -> None:
    payload = dict(payload)
    queue = payload.pop("queue", "intent")
    celery_app.send_task(topic, kwargs=payload, queue=queue)


def tick() -> dict:
    fired = wfe.fire_due_jobs()
    relayed = wfe.relay_outbox(publish)
    return {"fired": fired, "relayed": relayed}


def main() -> None:
    def stop(*_):
        global _running
        _running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    last_reconcile = 0.0
    log.info("scheduler started, interval=%ss", settings.scheduler_interval_seconds)
    while _running:
        try:
            stats = tick()
            if time.monotonic() - last_reconcile > 30:
                stats |= wfe.reconcile()
                wfe.relay_outbox(publish)
                last_reconcile = time.monotonic()
            if any(stats.values()):
                log.info("tick %s", stats)
        except Exception:
            log.exception("scheduler tick failed")
        time.sleep(settings.scheduler_interval_seconds)


if __name__ == "__main__":
    main()
