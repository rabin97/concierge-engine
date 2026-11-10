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

1. `POST /v1/intents` — the guard screens the prompt. An injection/jailbreak gets a 400 with a friendly message
   and no workflow. Otherwise PII is masked (`<PHONE_1>`, `<ADDRESS_1>`), and the masked text goes into
   `workflows` (`PLANNING`) keyed on `(user_id, Idempotency-Key)` with an `outbox` row in the same transaction.
   Returns 202. Answers (`/answer`) and preferences are screened the same way.
2. Scheduler relays the outbox row to Celery → `plan_workflow` on the `intent` queue.
3. Pipeline (`app/agents/pipeline.py`): intent agent (LLM, schema-forced, canary in the system prompt) → output
   guard (canary / prompt leak) → repair loop → pgvector preferences → time resolver (code, not LLM) → planner →
   business-rule validator → action guard (step allowlist, per-user booking limits, forced confirmation)
   → `AWAITING_CONFIRMATION` or `NEEDS_INPUT`.
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
| `app/agents/guard/` | Input/output guard (see [Guard](#guard)); `service.py` is how the app calls it |
| `app/api/routes.py` | REST endpoints + vendor/WhatsApp webhooks |
| `mock_vendor/main.py` | Vendor that sends duplicate and out-of-order webhooks on purpose |
| `scripts/demo.py` | End-to-end walkthrough |
| `tests/` | Schema, time, planner, signature and guard-integration tests; `tests/guard/` unit-tests the guard |
| `eval/` | Guard red-team / benign / holdout sets, mutation fuzzers, CI regression gate |

## Guard

`app/agents/guard/` screens everything that crosses a trust boundary. It has no ML dependencies. By default it is
fully offline: rules, a heuristic classifier and regex/checksum PII detection run in about 1 ms. Two optional layers
call gpt-oss on Bedrock through its OpenAI-compatible endpoint (`openai` SDK, Responses API), using a Bedrock API key
in `AWS_BEARER_TOKEN_BEDROCK`:

- `GUARD_CLASSIFIER=llm` replaces the heuristic classifier with the model, on every message (~1 s, one call each).
- `GUARD_LLM_JUDGE=true` asks the model only about borderline prompts (risk 0.30–0.80).

Both use `GUARD_LLM_MODEL` (default `openai.gpt-oss-120b`). Their timeouts come from `GUARD_LLM_TIMEOUT_MS`. If the
model times out or errors, the classifier flags the message (it still goes through) and the judge is ignored; after 5
failures in a row the circuit breaker stops calling it for 30 s.

```
user text (prompt, answer, preference) ─► normalize ─► PII mask ─► tier 0: hidden content · rules · multi-turn
                                                                   tier 1: heuristic or gpt-oss classifier
                                                                   tier 2: gpt-oss judge (borderline only, opt-in)
                                       ─► risk ─► allow / allow_with_redaction / flag / block (400)
intent LLM output ─► OutputGuard (canary · system-prompt leak) ─► planner
TaskTree ─► ActionGuard (step allowlist · forced confirmation · per-user hour/day limits from Postgres) ─► execution
```

| Piece | Where | What it does |
|---|---|---|
| Normalization | `normalize.py` | NFKC; strips zero-width, bidi and tag chars (decodes tag-char smuggling); homoglyph skeleton; decodes base64, URL, HTML entities, leetspeak, spaced letters; script/language detection (Hindi, Bengali, Hinglish) |
| PII | `pii/` | Aadhaar (Verhoeff), PAN, UPI, cards (Luhn), IFSC, vehicle numbers, passport, phone, email, PIN code with context checks against prices and order IDs; heuristic names/addresses; reversible `<PHONE_1>` tokens; per-field policy (`mask` / `drop` / `allow`) |
| Pipeline | `pipeline.py`, `config.py`, `checks/` | Tiers run cheapest first, parallel within a tier; per-check timeout, circuit breaker, fail-open/closed; noisy-OR risk; verdict cache; shadow mode for checks and single rules; per-tenant overrides; hot reload that keeps the last good config |
| Rules | `config/patterns.yaml` | 17 versioned rules: override, role-play, DAN, delimiters, prompt extraction, secrets, impersonation, Hindi/Hinglish/Bengali, business abuse |
| Output + actions | `output_guard.py` | Canary tokens, prompt-leak n-gram overlap, foreign-PII redaction; `ActionGuard.review_plan()` for the `TaskTree` |
| Observability | `observability.py` | JSON decision logs (HMAC-hashed user/IP, redacted prompt, rule IDs, config version); metrics at `GET /internal/guard/metrics`; optional hash-chained audit trail and review queue |
| App wiring | `service.py` | `screen_user_text()`, `screen_llm_output()`, `review_plan()`; one pipeline per process |

Tune thresholds, PII policies, action limits and messages in `app/agents/guard/config/default.yaml`; bump `version` on
each change (every decision logs it). `make eval` runs the regression gate CI uses:

| Set | Result |
|---|---|
| Red-team (45) / benign (50), tuned on | precision 1.00, recall 1.00, FPR 0.00 |
| 533 mutated attacks | 99% caught |
| **Holdout paraphrases (20 + 20), never tuned on** | **recall 0.35, FPR 0.00** |

The holdout number is the honest one: rules catch known phrasing and encoding tricks but not paraphrases. That gap
is what the LLM judge is for. Don't add patterns to fix holdout misses; move them into `redteam.jsonl` and write a
fresh holdout.

Per-process state to move to Redis when running several API replicas: the multi-turn session history and the verdict
cache. Not built yet: self-harm routing (the `ESCALATE` verdict exists), off-topic scope classifier, strike system /
token budgets, and screening of vendor text with `check_untrusted()` (no vendor text reaches the LLM today).

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
