from uuid import UUID

from fastapi import Header, HTTPException

from app.db import q, tx


def current_user(x_user_id: UUID = Header(..., description="Local dev auth. Replace with JWT/OIDC in prod.")) -> dict:
    with tx() as conn:
        user = q(conn, "SELECT id, name, timezone FROM users WHERE id=:id", id=x_user_id).mappings().first()
    if user is None:
        raise HTTPException(status_code=401, detail="unknown user")
    return dict(user)
