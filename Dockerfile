FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

COPY pyproject.toml ./
COPY app ./app
COPY mock_vendor ./mock_vendor
RUN pip install --no-cache-dir .

# Default command is the API; docker-compose overrides it for worker/scheduler/mock vendor
CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
