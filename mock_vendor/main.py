"""A deliberately badly-behaved cleaning vendor, to prove the engine's idempotency.

- Honours Idempotency-Key (same key -> same booking)
- Optionally fails the first N calls with 503 (MOCK_FAIL_FIRST_N) to exercise retries
- After booking, sends CONFIRMED three times (duplicates), then ASSIGNED,
  then a stale CONFIRMED with a new event id (out of order)
"""
import json
import os
import threading
import time
import uuid

import httpx
from fastapi import FastAPI, Header, HTTPException

from app.services.vendor_client import sign

SECRET = os.getenv("VENDOR_WEBHOOK_SECRET", "dev-vendor-secret")
WEBHOOK_URL = os.getenv("VENDOR_WEBHOOK_URL", "http://localhost:8000/v1/webhooks/vendors/mockclean")
FAIL_FIRST_N = int(os.getenv("MOCK_FAIL_FIRST_N", "0"))

app = FastAPI(title="Mock cleaning vendor")
bookings: dict[str, dict] = {}
by_key: dict[str, str] = {}
calls = {"n": 0}
lock = threading.Lock()


def _send(event: dict) -> None:
    body = json.dumps(event).encode()
    ts = str(int(time.time()))
    try:
        r = httpx.post(WEBHOOK_URL, content=body, timeout=5.0, headers={
            "Content-Type": "application/json", "X-Vendor-Timestamp": ts,
            "X-Vendor-Signature": sign(SECRET, ts, body)})
        print(f"[vendor] webhook {event['status']} {event['event_id'][:8]} -> {r.status_code} {r.text}")
    except httpx.HTTPError as e:
        print(f"[vendor] webhook failed: {e}")


def _lifecycle(ref: str, client_reference: str) -> None:
    time.sleep(2)
    confirmed = {"event_id": str(uuid.uuid4()), "booking_ref": ref, "client_reference": client_reference,
                 "status": "CONFIRMED"}
    for _ in range(3):  # same event delivered three times
        _send(confirmed)
    time.sleep(1)
    _send({"event_id": str(uuid.uuid4()), "booking_ref": ref, "client_reference": client_reference,
           "status": "ASSIGNED", "professional": "Asha R."})
    time.sleep(1)
    _send({"event_id": str(uuid.uuid4()), "booking_ref": ref, "client_reference": client_reference,
           "status": "CONFIRMED"})  # late, out-of-order: must be ignored


@app.post("/v1/bookings")
def create_booking(body: dict, idempotency_key: str = Header(...)):
    with lock:
        calls["n"] += 1
        if calls["n"] <= FAIL_FIRST_N:
            raise HTTPException(503, "vendor temporarily unavailable")
        if idempotency_key in by_key:
            return bookings[by_key[idempotency_key]]
        ref = f"BK-{uuid.uuid4().hex[:8].upper()}"
        booking = {"booking_ref": ref, "status": "REQUESTED", **body}
        bookings[ref] = booking
        by_key[idempotency_key] = ref
    threading.Thread(target=_lifecycle, args=(ref, body["client_reference"]), daemon=True).start()
    return booking


@app.post("/v1/bookings/{ref}/cancel")
def cancel_booking(ref: str, idempotency_key: str = Header(...)):
    b = bookings.get(ref)
    if b is None:
        raise HTTPException(404, "no such booking")
    b["status"] = "CANCELLED"
    threading.Thread(target=_send, args=({"event_id": str(uuid.uuid4()), "booking_ref": ref,
                                          "client_reference": b["client_reference"], "status": "CANCELLED"},),
                     daemon=True).start()
    return b


@app.get("/v1/bookings")
def list_bookings():
    return list(bookings.values())
