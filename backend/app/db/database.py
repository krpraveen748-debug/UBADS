"""Database engine/session setup for local SQLite and production PostgreSQL."""

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import declarative_base, sessionmaker

from app.core.config import settings


def _resolve_database_url(value: str) -> URL:
    url = make_url(value)
    if url.drivername in {"postgres", "postgresql"}:
        url = url.set(drivername="postgresql+psycopg")
    elif url.drivername == "sqlite" and url.database not in (None, "", ":memory:"):
        path = Path(url.database)
        if not path.is_absolute():
            path = Path(__file__).resolve().parents[3] / path
        url = url.set(database=str(path.resolve()))
    return url


database_url = _resolve_database_url(settings.database_url)
if database_url.get_backend_name() == "sqlite":
    connect_args = {"check_same_thread": False, "timeout": 30}
    engine_options = {
        "connect_args": connect_args,
        "pool_pre_ping": True,
    }
else:
    connect_args = {"connect_timeout": settings.database_connect_timeout_seconds}
    engine_options = {
        "connect_args": connect_args,
        "pool_pre_ping": True,
        "pool_size": settings.database_pool_size,
        "max_overflow": settings.database_max_overflow,
        "pool_timeout": settings.database_pool_timeout_seconds,
        "pool_recycle": settings.database_pool_recycle_seconds,
    }

engine = create_engine(database_url, **engine_options)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
