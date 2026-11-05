"""User preferences with semantic retrieval (pgvector). The context agent calls retrieve()."""
import json
import re
import uuid
from uuid import UUID

from app.db import jdump, q, tx, vec_literal
from app.services.embeddings import embed

# Offline fallback for turning a free-text preference into flags the planner can apply.
FLAG_RULES = [
    (r"chemical|allerg|eco|organic|non[- ]toxic", "eco_products"),
    (r"\bpet|dog|cat\b", "pet_safe"),
    (r"asthma|dust", "low_dust"),
]


def derive_structured(text: str) -> dict:
    t = text.lower()
    return {flag: True for pat, flag in FLAG_RULES if re.search(pat, t)}


def upsert_preference(user_id: UUID, category: str, text: str, structured: dict | None) -> dict:
    structured = structured if structured is not None else derive_structured(text)
    pref_id = uuid.uuid4()
    with tx() as conn:
        q(
            conn,
            """INSERT INTO user_preferences (id, user_id, category, text, structured, embedding)
               VALUES (:id, :uid, :cat, :text, CAST(:st AS jsonb), CAST(:emb AS vector))""",
            id=pref_id, uid=user_id, cat=category, text=text, st=jdump(structured), emb=vec_literal(embed(text)),
        )
    return {"id": str(pref_id), "category": category, "text": text, "structured": structured}


def list_preferences(user_id: UUID) -> list[dict]:
    with tx() as conn:
        rows = q(
            conn,
            "SELECT id, category, text, structured FROM user_preferences WHERE user_id=:uid ORDER BY updated_at",
            uid=user_id,
        ).mappings().all()
    return [dict(r) | {"id": str(r["id"])} for r in rows]


def retrieve(user_id: UUID, query_text: str, k: int = 5) -> list[dict]:
    """Exact cosine search over one user's rows. HEALTH prefs are always included (safety-relevant)."""
    with tx() as conn:
        rows = q(
            conn,
            """SELECT text, category, structured, 1 - (embedding <=> CAST(:q AS vector)) AS score
               FROM user_preferences WHERE user_id = :uid
               ORDER BY (category = 'HEALTH') DESC, embedding <=> CAST(:q AS vector)
               LIMIT :k""",
            uid=user_id, q=vec_literal(embed(query_text)), k=k,
        ).mappings().all()
    out = []
    for r in rows:
        st = r["structured"] if isinstance(r["structured"], dict) else json.loads(r["structured"])
        out.append({"text": r["text"], "category": r["category"], "structured": st, "score": float(r["score"])})
    return out
