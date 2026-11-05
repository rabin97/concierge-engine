"""Database access. Plain SQL through SQLAlchemy Core so the idempotency SQL is visible, not hidden in an ORM."""
import json
from contextlib import contextmanager
from typing import Any, Iterator

from sqlalchemy import Connection, create_engine, text

from app.config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True, pool_size=5, max_overflow=10)


@contextmanager
def tx() -> Iterator[Connection]:
    """One transaction. Commits on success, rolls back on exception."""
    with engine.begin() as conn:
        yield conn


def q(conn: Connection, sql: str, **params: Any):
    return conn.execute(text(sql), params)


def jdump(value: Any) -> str:
    return json.dumps(value, default=str)


def vec_literal(values: list[float]) -> str:
    """pgvector accepts '[0.1,0.2,...]' cast to ::vector."""
    return "[" + ",".join(f"{v:.6f}" for v in values) + "]"
