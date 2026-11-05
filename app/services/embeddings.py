"""Embeddings: Bedrock Titan V2 in prod, a hashing embedder offline (keyword overlap, but same API)."""
import hashlib
import json
import math
import re

from app.config import settings

STOP = {"a", "an", "the", "to", "of", "and", "my", "me", "i", "am", "is", "for", "on", "in", "please", "with"}


def _fake_embed(text: str, dim: int) -> list[float]:
    vec = [0.0] * dim
    words = [w for w in re.findall(r"[a-z]+", text.lower()) if w not in STOP]
    for w in words:
        for token in (w, w[:5]):  # crude stemming: "chemicals" ~ "chemi"
            h = int(hashlib.md5(token.encode()).hexdigest(), 16)
            vec[h % dim] += 1.0 if (h >> 8) % 2 else -1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def embed(text: str) -> list[float]:
    if settings.embeddings_provider == "bedrock":
        import boto3

        client = boto3.client("bedrock-runtime", region_name=settings.aws_region)
        body = {"inputText": text, "dimensions": settings.embedding_dim, "normalize": True}
        resp = client.invoke_model(modelId=settings.bedrock_embed_model_id, body=json.dumps(body))
        return json.loads(resp["body"].read())["embedding"]
    return _fake_embed(text, settings.embedding_dim)
