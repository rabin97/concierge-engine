-- Concierge Engine schema. Uniqueness constraints are what enforce idempotency.
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
  id            uuid PRIMARY KEY,
  name          text NOT NULL,
  phone_e164    text UNIQUE,
  email         citext UNIQUE,
  timezone      text NOT NULL DEFAULT 'Asia/Kolkata',
  wa_opt_in_at  timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE addresses (
  id        uuid PRIMARY KEY,
  user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  line1     text NOT NULL,
  city      text NOT NULL,
  pincode   text NOT NULL,
  is_default boolean NOT NULL DEFAULT false
);

CREATE TABLE user_preferences (
  id          uuid PRIMARY KEY,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  category    text NOT NULL,                 -- HEALTH, SCHEDULE, PRODUCT, CHANNEL
  text        text NOT NULL,                 -- 'allergic to harsh chemicals'
  structured  jsonb NOT NULL DEFAULT '{}',   -- {"eco_products": true}
  embedding   vector(512) NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now()
);
-- Per-user exact search over ~10 rows: a btree on user_id is enough, no ANN index needed.
CREATE INDEX ON user_preferences (user_id);

CREATE TABLE workflows (
  id                uuid PRIMARY KEY,
  user_id           uuid NOT NULL REFERENCES users(id),
  client_request_id text NOT NULL,            -- Idempotency-Key header
  prompt_redacted   text NOT NULL,
  plan              jsonb,                    -- validated TaskTree
  plan_hash         text,
  prompt_version    text,
  status            text NOT NULL,            -- PLANNING, NEEDS_INPUT, AWAITING_CONFIRMATION, RUNNING, COMPLETED, FAILED, CANCELLED
  question          text,
  summary           text,
  version           int NOT NULL DEFAULT 0,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, client_request_id)
);

CREATE TABLE workflow_steps (
  id           uuid PRIMARY KEY,
  workflow_id  uuid NOT NULL REFERENCES workflows(id),
  step_key     text NOT NULL,
  type         text NOT NULL,
  params       jsonb NOT NULL,
  depends_on   text[] NOT NULL DEFAULT '{}',
  run_condition text NOT NULL DEFAULT 'ON_SUCCESS',
  status       text NOT NULL,                -- PENDING, SCHEDULED, QUEUED, RUNNING, WAITING_EXTERNAL, SUCCEEDED, RETRYING, FAILED, SKIPPED, CANCELLED
  attempt      int NOT NULL DEFAULT 0,
  lease_until  timestamptz,
  last_error   text,
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workflow_id, step_key)
);
CREATE INDEX ON workflow_steps (status, lease_until);

CREATE TABLE scheduled_jobs (
  id       bigserial PRIMARY KEY,
  step_id  uuid NOT NULL UNIQUE REFERENCES workflow_steps(id),
  due_at   timestamptz NOT NULL,
  state    text NOT NULL DEFAULT 'WAITING'   -- WAITING, FIRED, CANCELLED
);
CREATE INDEX ON scheduled_jobs (due_at) WHERE state = 'WAITING';

CREATE TABLE vendor_bookings (
  id          uuid PRIMARY KEY,
  step_id     uuid NOT NULL UNIQUE REFERENCES workflow_steps(id),
  vendor      text NOT NULL,
  vendor_ref  text,
  status      text NOT NULL,
  status_rank int NOT NULL,
  version     int NOT NULL DEFAULT 0,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (vendor, vendor_ref)
);

CREATE TABLE webhook_inbox (
  id               bigserial PRIMARY KEY,
  idempotency_key  text NOT NULL UNIQUE,
  source           text NOT NULL,             -- vendor name, 'whatsapp', 'ses'
  event_type       text NOT NULL,
  payload          jsonb NOT NULL,
  state            text NOT NULL DEFAULT 'RECEIVED', -- RECEIVED, PROCESSED, IGNORED_STALE, FAILED
  received_at      timestamptz NOT NULL DEFAULT now(),
  processed_at     timestamptz
);
CREATE INDEX ON webhook_inbox (received_at) WHERE state = 'RECEIVED';

CREATE TABLE outbox (
  id          bigserial PRIMARY KEY,
  topic       text NOT NULL,                  -- celery task name
  payload     jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  sent_at     timestamptz
);
CREATE INDEX ON outbox (id) WHERE sent_at IS NULL;

CREATE TABLE notifications (
  id               uuid PRIMARY KEY,
  step_id          uuid NOT NULL REFERENCES workflow_steps(id),
  channel          text NOT NULL,             -- WHATSAPP, EMAIL
  template         text NOT NULL,
  provider_msg_id  text UNIQUE,
  status           text NOT NULL,             -- QUEUED, SENT, DELIVERED, READ, FAILED, BOUNCED
  error            text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (step_id, channel)
);

CREATE TABLE workflow_events (
  id           bigserial PRIMARY KEY,
  workflow_id  uuid NOT NULL,
  type         text NOT NULL,
  data         jsonb NOT NULL DEFAULT '{}',
  at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON workflow_events (workflow_id, at);
-- Production: PARTITION BY RANGE (at) with monthly partitions, archive to S3 after 90 days.

CREATE TABLE suppression_list (
  channel text NOT NULL,
  address text NOT NULL,
  reason  text NOT NULL,
  PRIMARY KEY (channel, address)
);
