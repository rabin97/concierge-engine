.PHONY: up down logs demo test eval lint migrate api worker scheduler vendor

up:            ## start everything in Docker
	cp -n .env.example .env || true
	docker compose up --build -d

down:
	docker compose down -v

logs:
	docker compose logs -f api worker scheduler mock-vendor

demo:          ## run the end-to-end demo against the running stack
	python scripts/demo.py

test:
	pytest -q

eval:          ## guard red-team/benign eval with regression gate
	python eval/run_eval.py

lint:
	ruff check .

# --- run without Docker (needs local Postgres 16 + pgvector and Redis) ---
migrate:
	for f in migrations/*.sql; do psql "postgresql://concierge:concierge@localhost:5432/concierge" -v ON_ERROR_STOP=1 -f $$f; done

api:
	uvicorn app.api.main:app --reload --port 8000

worker:
	celery -A app.workers.celery_app worker -Q intent,booking,notify,webhook -l info -c 4

scheduler:
	python -m app.workers.scheduler

vendor:
	uvicorn mock_vendor.main:app --port 9000
