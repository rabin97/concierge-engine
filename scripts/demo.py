"""End-to-end demo against a running stack (API on :8000, worker, scheduler, mock vendor).

    python scripts/demo.py

Shows: preference retrieval, plan JSON, confirmation, vendor booking, duplicate + out-of-order
webhooks being absorbed, WhatsApp/email notifications, and the reminder firing (fast-forwarded).
"""
import json
import sys
import time
import uuid

import httpx

API = "http://localhost:8000"
USER = "11111111-1111-1111-1111-111111111111"
H = {"X-User-Id": USER}
PROMPT = "Schedule a deep cleaning service for Saturday morning and remind me on Friday night"


def wait_for(wf_id: str, cond, timeout=30, label=""):
    deadline = time.time() + timeout
    while time.time() < deadline:
        view = httpx.get(f"{API}/v1/workflows/{wf_id}", headers=H).json()
        if cond(view):
            return view
        time.sleep(0.5)
    print(f"timed out waiting for {label}; last status={view['status']}")
    print(json.dumps(view, indent=2, default=str))
    sys.exit(1)


def main():
    print("1) Save a preference (embedded into pgvector)")
    print("  ", httpx.put(f"{API}/v1/users/me/preferences", headers=H,
                          json={"category": "HEALTH", "text": "I am allergic to harsh chemicals"}).json())

    key = str(uuid.uuid4())
    print(f"\n2) Submit prompt: {PROMPT!r}")
    r1 = httpx.post(f"{API}/v1/intents", headers=H | {"Idempotency-Key": key}, json={"prompt": PROMPT})
    r2 = httpx.post(f"{API}/v1/intents", headers=H | {"Idempotency-Key": key}, json={"prompt": PROMPT})
    wf_id = r1.json()["workflow_id"]
    print(f"   first call {r1.status_code}, retry with same key {r2.status_code} -> same id: "
          f"{r2.json()['workflow_id'] == wf_id}")

    view = wait_for(wf_id, lambda v: v["status"] in ("AWAITING_CONFIRMATION", "NEEDS_INPUT"), label="plan")
    if view["status"] == "NEEDS_INPUT":
        print("   needs input:", view["question"])
        sys.exit(1)
    print("\n3) Validated plan:")
    print("  ", view["summary"])
    print(json.dumps(view["plan"], indent=2))

    print("\n4) Confirm (twice, to show it's idempotent)")
    print("  ", httpx.post(f"{API}/v1/workflows/{wf_id}/confirm", headers=H).json(),
          httpx.post(f"{API}/v1/workflows/{wf_id}/confirm", headers=H).json())

    view = wait_for(wf_id, lambda v: any(e["type"] == "VENDOR_EVENT_STALE" for e in v["events"]),
                    timeout=40, label="vendor lifecycle")
    print("\n5) After vendor sent CONFIRMED x3, ASSIGNED, then a stale CONFIRMED:")
    print("   booking:", view["booking"])
    for s in view["steps"]:
        print(f"   step {s['step_key']:<16} {s['status']:<10} attempts={s['attempt']}")
    print("   notifications:", [(n["step_key"], n["channel"], n["status"]) for n in view["notifications"]])

    print("\n6) Fast-forward the Friday-night reminder (local demo only)")
    sys.path.insert(0, ".")
    from app.db import q, tx

    with tx() as conn:
        q(conn, """UPDATE scheduled_jobs j SET due_at = now() FROM workflow_steps s
                   WHERE j.step_id = s.id AND s.workflow_id = :w AND j.state = 'WAITING'""", w=wf_id)
    view = wait_for(wf_id, lambda v: v["status"] in ("COMPLETED", "FAILED"), timeout=20, label="completion")
    print(f"   workflow {view['status']}")
    print("   notifications:", [(n["step_key"], n["channel"], n["status"]) for n in view["notifications"]])
    print("\n7) Event log:")
    for e in view["events"]:
        print(f"   {e['at'][11:19]}  {e['type']:<24} {json.dumps(e['data']) if e['data'] else ''}")


if __name__ == "__main__":
    main()
