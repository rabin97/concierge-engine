from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All configuration comes from env vars (or .env). On AWS, inject via ECS task definition + Secrets Manager."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "local"
    database_url: str = "postgresql+psycopg://concierge:concierge@localhost:5432/concierge"
    redis_url: str = "redis://localhost:6379/0"
    default_timezone: str = "Asia/Kolkata"
    aws_region: str = "ap-south-1"

    llm_provider: str = "fake"  # fake | bedrock
    bedrock_model_id: str = ""
    embeddings_provider: str = "fake"  # fake | bedrock
    bedrock_embed_model_id: str = "amazon.titan-embed-text-v2:0"
    embedding_dim: int = 512
    prompt_version: str = "intent-v1"

    email_provider: str = "console"  # console | ses
    ses_from_address: str = "no-reply@example.com"
    ses_configuration_set: str = ""
    whatsapp_provider: str = "console"  # console | meta
    whatsapp_token: str = ""
    whatsapp_phone_number_id: str = ""
    whatsapp_api_version: str = "v21.0"
    whatsapp_verify_token: str = "dev-verify-token"
    whatsapp_app_secret: str = ""
    whatsapp_max_per_second: int = 50
    email_max_per_second: int = 14

    vendor_base_url: str = "http://localhost:9000"
    vendor_webhook_secret: str = "dev-vendor-secret"
    vendor_webhook_tolerance_seconds: int = 300

    scheduler_interval_seconds: float = 1.0
    step_lease_seconds: int = 300
    max_step_attempts: int = 5
    booking_lead_time_minutes: int = 120

    # guard (app/agents/guard): screens user text, checks LLM output, limits planned actions
    guard_config_path: str = ""  # empty = app/agents/guard/config/default.yaml
    guard_hmac_key: str = ""  # hashes user IDs and IPs in guard logs; set from Secrets Manager
    # guard LLM: gpt-oss on Bedrock through its OpenAI-compatible endpoint (openai SDK, Responses API)
    guard_classifier: str = "heuristic"  # heuristic (offline, ~0.1 ms) | llm (one LLM call per message)
    guard_llm_judge: bool = False  # ask the LLM about borderline prompts only
    guard_llm_model: str = "openai.gpt-oss-120b"
    guard_llm_base_url: str = ""  # empty = https://bedrock-mantle.{aws_region}.api.aws/v1
    guard_llm_api_key: str = ""  # empty = AWS_BEARER_TOKEN_BEDROCK (a Bedrock API key)
    guard_llm_timeout_ms: int = 5000
    aws_bearer_token_bedrock: str = ""  # Bedrock API key; boto3 reads it from the env too
    guard_review_queue_path: str = ""  # JSONL of flagged prompts for human review
    guard_audit_path: str = ""  # hash-chained JSONL audit trail of guard decisions


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
