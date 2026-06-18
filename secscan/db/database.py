import os
from typing import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from db.orm_models import Base

_DB_PATH = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.db")
)
DATABASE_URL = f"sqlite:///{_DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    # SQLite requires this flag when the same connection is used across threads
    # (the default check rejects it). Flask's threaded request handling needs it.
    connect_args={"check_same_thread": False},
    echo=False,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    """Yield a DB session, closing it in a finally block.

    Designed for use as a Flask request-scoped dependency:
        with contextlib.closing(next(get_db())) as db: ...
    or injected by a framework that supports generator dependencies.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables and apply any pending inline column migrations."""
    Base.metadata.create_all(engine)
    _run_migrations()


def _run_migrations() -> None:
    """Idempotent inline migrations for schema changes that create_all() can't apply
    to pre-existing tables (SQLite does not support ALTER COLUMN or DROP COLUMN)."""
    with engine.connect() as conn:
        existing_clients = {col["name"] for col in inspect(engine).get_columns("clients")}
        if "user_id" not in existing_clients:
            conn.execute(text("ALTER TABLE clients ADD COLUMN user_id INTEGER REFERENCES users(id)"))
            conn.commit()

        existing_targets = {col["name"] for col in inspect(engine).get_columns("targets")}
        if "verification_token" not in existing_targets:
            # Use SQLite's randomblob to backfill tokens for any pre-existing rows.
            conn.execute(text("ALTER TABLE targets ADD COLUMN verification_token TEXT NOT NULL DEFAULT ''"))
            conn.execute(text("UPDATE targets SET verification_token = lower(hex(randomblob(16))) WHERE verification_token = ''"))
            conn.commit()
        if "verified" not in existing_targets:
            conn.execute(text("ALTER TABLE targets ADD COLUMN verified INTEGER NOT NULL DEFAULT 0"))
            conn.commit()
        if "verification_method" not in existing_targets:
            conn.execute(text("ALTER TABLE targets ADD COLUMN verification_method TEXT"))
            conn.commit()
        if "verified_at" not in existing_targets:
            conn.execute(text("ALTER TABLE targets ADD COLUMN verified_at DATETIME"))
            conn.commit()
