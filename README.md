# AI Household Concierge Engine

Backend that turns *"Schedule a deep cleaning service for Saturday morning and remind me on Friday night"*
into a validated task tree, books a vendor, absorbs duplicate/out-of-order vendor webhooks, and notifies
the customer on WhatsApp and email — with Postgres as the source of truth.

Runs fully offline by default (fake LLM, console notifications, mock vendor). Flip env vars to use
Amazon Bedrock, Amazon SES and the WhatsApp Cloud API.

## Quick start (Docker)

```bash
cp .env.example .env
docker compose up --build -d      # postgres+pgvector, redis, api, worker, scheduler, mock-vendor
pip install -e ".[dev]"           # for the demo script and tests on your machine
python scripts/demo.py            # end-to-end walkthrough
pytest -q                         # unit tests
```

API docs: http://localhost:8000/docs

## Quick start (no Docker)

Needs Python 3.12+, PostgreSQL 16 with the `pgvector` extension, and Redis 7.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
createuser -s concierge -P   # password: concierge
createdb -O concierge concierge
make migrate
# four terminals:
make api        # FastAPI on :8000
make worker     # Celery worker on queues intent, booking, notify, webhook
make scheduler  # due jobs + outbox relay + reconciler
make vendor     # mock vendor on :9000
python scripts/demo.py
```

## Try it by hand

```bash
U="X-User-Id: 11111111-1111-1111-1111-111111111111"   # seeded demo user

curl -X PUT localhost:8000/v1/users/me/preferences -H "$U" -H 'Content-Type: application/json' \
  -d '{"category":"HEALTH","text":"I am allergic to harsh chemicals"}'

curl -X POST localhost:8000/v1/intents -H "$U" -H "Idempotency-Key: $(uuidgen)" \
  -H 'Content-Type: application/json' \
  -d '{"prompt":"Schedule a deep cleaning service for Saturday morning and remind me on Friday night"}'

curl localhost:8000/v1/workflows/<id> -H "$U"            # status AWAITING_CONFIRMATION + plan
curl -X POST localhost:8000/v1/workflows/<id>/confirm -H "$U"
curl -X POST localhost:8000/v1/workflows/<id>/cancel  -H "$U"
```

Set `MOCK_FAIL_FIRST_N=2` on the mock vendor to watch the booking step retry with backoff.

## How a request flows

1. `POST /v1/intents` — guard masks PII, inserts `workflows` (`PLANNING`) keyed on `(user_id, Idempotency-Key)`
   and an `outbox` row in the same transaction. Returns 202.
2. Scheduler relays the outbox row to Celery → `plan_workflow` on the `intent` queue.
3. Pipeline (`app/agents/pipeline.py`): intent agent (LLM, schema-forced) → repair loop → pgvector preferences
   → time resolver (code, not LLM) → planner → business-rule validator → `AWAITING_CONFIRMATION` or `NEEDS_INPUT`.
4. `POST /confirm` materialises `workflow_steps`; `advance()` queues `book_1`.
5. `booking` worker calls the vendor with `Idempotency-Key = step_id`; step waits in `WAITING_EXTERNAL`.
6. Vendor webhook → HMAC check → `webhook_inbox` (unique key drops duplicates) → `process_webhook` applies a
   forward-only status change → step `SUCCEEDED` → `advance()` queues the notification and schedules the reminder.
7. Scheduler fires `scheduled_jobs` when due → `notify` worker sends WhatsApp (email fallback).
8. Reconciler re-queues expired leases, stuck `QUEUED` steps and unprocessed webhooks. A lost Redis message
   can delay a workflow, never lose it.

## File map

| Path | What it does |
| --- | --- |
| `migrations/001_init.sql` | Schema. The `UNIQUE` constraints are the idempotency guarantees |
| `migrations/002_seed.sql` | Demo user + address |
| `app/config.py` | All settings from env vars |
| `app/db.py` | Engine + `tx()` transaction helper; plain SQL |
| `app/schemas/task_tree.py` | Pydantic `TaskTree`: discriminated step params, tz-aware times, DAG/cycle check |
| `app/schemas/intent.py` | What the LLM may return: intents + raw slots, never timestamps |
| `app/agents/guard.py` | PII masking, injection heuristics |
| `app/agents/llm.py` | `FakeLLM` (offline rules) and `BedrockLLM` (Converse API, forced tool call) |
| `app/agents/time_resolver.py` | "saturday" + MORNING → 2026-11-07 09:00–12:00 IST |
| `app/agents/planner.py` | Compiles intents into a `TaskTree`; business-rule validator |
| `app/agents/pipeline.py` | Runs the agents in order, repair loop, writes the plan |
| `app/services/workflow_engine.py` | State machine: claim, advance, retry, cancel, scheduler, outbox relay, reconciler |
| `app/services/webhooks.py` | Inbox dedupe + forward-only vendor status transitions |
| `app/services/vendor_client.py` | Vendor adapter with idempotency keys, transient vs permanent errors, HMAC |
| `app/services/preferences.py` | Preferences in pgvector; per-user exact cosine search |
| `app/services/embeddings.py` | Titan V2 embeddings, or a hashing embedder offline |
| `app/services/notifications/` | Templates, WhatsApp/SES/console providers, router with dedupe, Redis rate limit, fallback |
| `app/workers/celery_app.py` | Celery config: `acks_late`, prefetch 1, reject on worker loss |
| `app/workers/tasks.py` | Thin tasks: `plan_workflow`, `run_step`, `process_webhook`, `cancel_vendor_booking` |
| `app/workers/handlers.py` | What each step type does |
| `app/workers/scheduler.py` | Loop: fire due jobs, relay outbox, reconcile every 30 s |
| `app/api/routes.py` | REST endpoints + vendor/WhatsApp webhooks |
| `mock_vendor/main.py` | Vendor that sends duplicate and out-of-order webhooks on purpose |
| `scripts/demo.py` | End-to-end walkthrough |
| `tests/` | Schema, time, planner, guard and signature tests |

## Going live on AWS (ap-south-1)

| Local | AWS | Env change |
| --- | --- | --- |
| Postgres container | RDS PostgreSQL 16 Multi-AZ (pgvector is supported on RDS) | `DATABASE_URL` |
| Redis container | ElastiCache Redis, Multi-AZ, encryption in transit | `REDIS_URL` (use `rediss://`) |
| `FakeLLM` | Bedrock Converse | `LLM_PROVIDER=bedrock`, `BEDROCK_MODEL_ID=<enabled model>` |
| Hashing embeddings | Bedrock Titan Text Embeddings V2 (512 dims) | `EMBEDDINGS_PROVIDER=bedrock` |
| Console email | SES (verified domain, SPF/DKIM/DMARC, out of sandbox) | `EMAIL_PROVIDER=ses`, `SES_FROM_ADDRESS` |
| Console WhatsApp | WhatsApp Cloud API, approved utility templates | `WHATSAPP_PROVIDER=meta`, token, phone number id |
| `docker compose` | ECS Fargate: one service each for api, worker per queue, scheduler | task definitions + Secrets Manager |

The same image runs every role; only the command differs (see `docker-compose.yml`).

WhatsApp templates must exist in Meta Business Manager under **Utility** with the names and variable order in
`app/services/notifications/templates.py`. The Bedrock tool schema comes from `IntentExtraction.model_json_schema()`;
if your chosen model rejects `$defs`/`$ref`, inline the schema before sending.

## What to build next

- [ ] JWT/OIDC auth (replace the `X-User-Id` header in `app/api/deps.py`)
- [ ] Alembic migrations instead of raw SQL files
- [ ] Verify `X-Hub-Signature-256` on the WhatsApp webhook; SES bounce/complaint via SNS → `suppression_list`
- [ ] OpenTelemetry tracing with `workflow_id` on every span; Flower for Celery
- [ ] Integration tests with testcontainers (Postgres + Redis) covering duplicate webhooks and worker crashes
- [ ] Locust load test at 25 prompts/s; LLM eval set of ~200 labelled prompts
- [ ] Terraform for VPC, RDS, ElastiCache, ECS, ALB/WAF
