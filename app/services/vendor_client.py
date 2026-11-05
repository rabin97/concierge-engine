"""Vendor adapter. One class per real vendor; all share this contract.

Outbound calls carry Idempotency-Key = our step_id, so a timeout followed by a retry never books twice.
We also pass client_reference = step_id, which the vendor echoes in webhooks (no lookup race).
"""
import hashlib
import hmac

import httpx

from app.config import settings


class TransientVendorError(Exception):
    """Timeouts, 429 and 5xx: safe to retry with the same idempotency key."""


class PermanentVendorError(Exception):
    """4xx validation errors: retrying won't help."""


class VendorClient:
    name = "mockclean"

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = base_url or settings.vendor_base_url

    def _post(self, path: str, json: dict, idempotency_key: str) -> dict:
        try:
            r = httpx.post(f"{self.base_url}{path}", json=json, timeout=10.0,
                           headers={"Idempotency-Key": idempotency_key})
        except httpx.HTTPError as e:
            raise TransientVendorError(str(e)) from e
        if r.status_code == 429 or r.status_code >= 500:
            raise TransientVendorError(f"vendor {r.status_code}")
        if r.status_code >= 400:
            raise PermanentVendorError(f"vendor {r.status_code}: {r.text[:200]}")
        return r.json()

    def create_booking(self, step_id: str, params: dict) -> dict:
        body = {
            "client_reference": step_id,
            "service_code": params["service_code"],
            "window_start": params["window"]["start"],
            "window_end": params["window"]["end"],
            "address_id": params["address_id"],
            "requirements": [k for k, v in params.get("constraints", {}).items() if v],
        }
        return self._post("/v1/bookings", body, idempotency_key=step_id)

    def cancel_booking(self, vendor_ref: str) -> dict:
        return self._post(f"/v1/bookings/{vendor_ref}/cancel", {}, idempotency_key=f"cancel:{vendor_ref}")


def sign(secret: str, timestamp: str, body: bytes) -> str:
    return hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()


def verify_signature(secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(secret, timestamp, body), signature or "")
