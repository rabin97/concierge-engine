"""Channel router. UNIQUE(step_id, channel) makes a retried step skip channels already sent."""
import logging
import time
import uuid
from uuid import UUID

import redis

from app.config import settings
from app.db import q, tx
from app.services.notifications.providers import ProviderError, email_provider, whatsapp_provider
from app.services.notifications.templates import TEMPLATES

log = logging.getLogger(__name__)
_redis = redis.Redis.from_url(settings.redis_url)
LIMITS = {"WHATSAPP": settings.whatsapp_max_per_second, "EMAIL": settings.email_max_per_second}


def take_token(channel: str, max_wait_s: float = 5.0) -> None:
    """Fixed-window rate limit per channel per second, shared by all workers through Redis."""
    deadline = time.monotonic() + max_wait_s
    while True:
        key = f"rl:{channel}:{int(time.time())}"
        n = _redis.incr(key)
        if n == 1:
            _redis.expire(key, 2)
        if n <= LIMITS[channel]:
            return
        if time.monotonic() > deadline:
            raise ProviderError(f"{channel} rate limit wait exceeded")
        time.sleep(0.05)


def _claim(step_id: UUID, channel: str, template: str) -> UUID | None:
    with tx() as conn:
        row = q(conn, """INSERT INTO notifications (id, step_id, channel, template, status)
                         VALUES (:id, :s, :c, :t, 'QUEUED')
                         ON CONFLICT (step_id, channel) DO UPDATE SET updated_at=now()
                           WHERE notifications.status IN ('QUEUED', 'FAILED')
                         RETURNING id""",
                id=uuid.uuid4(), s=step_id, c=channel, t=template).first()
    return row[0] if row else None  # None = already SENT/DELIVERED: skip


def _mark(notification_id: UUID, status: str, provider_id: str | None = None, error: str | None = None) -> None:
    with tx() as conn:
        q(conn, """UPDATE notifications SET status=:s, provider_msg_id=COALESCE(:p, provider_msg_id),
                   error=:e, updated_at=now() WHERE id=:id""", id=notification_id, s=status, p=provider_id, e=error)


def _suppressed(channel: str, address: str) -> bool:
    with tx() as conn:
        return q(conn, "SELECT 1 FROM suppression_list WHERE channel=:c AND address=:a",
                 c=channel, a=address).first() is not None


def send(step_id: UUID, user: dict, channels: list[str], template: str, ctx: dict) -> dict:
    """Returns {channel: status}. Raises ProviderError only if every channel failed (so the step retries)."""
    tpl = TEMPLATES[template]
    results: dict[str, str] = {}
    targets = list(channels)
    if "WHATSAPP" in targets and "EMAIL" not in targets and user.get("email"):
        targets.append("EMAIL_FALLBACK")

    for ch in targets:
        if ch == "EMAIL_FALLBACK":
            if results.get("WHATSAPP") != "FAILED":
                continue
            ch = "EMAIL"
        address = user["phone_e164"] if ch == "WHATSAPP" else user["email"]
        if not address or _suppressed(ch, address):
            results[ch] = "SKIPPED"
            continue
        nid = _claim(step_id, ch, template)
        if nid is None:
            results[ch] = "ALREADY_SENT"
            continue
        try:
            take_token(ch)
            provider = whatsapp_provider() if ch == "WHATSAPP" else email_provider()
            msg_id = provider.send(address, tpl, ctx)
            _mark(nid, "SENT", provider_id=msg_id)
            results[ch] = "SENT"
        except ProviderError as e:
            log.warning("send failed step=%s channel=%s: %s", step_id, ch, e)
            _mark(nid, "FAILED", error=str(e)[:500])
            results[ch] = "FAILED"

    if results and all(v == "FAILED" for v in results.values()):
        raise ProviderError(f"all channels failed: {results}")
    return results
