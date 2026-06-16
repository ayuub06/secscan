import os
from typing import Generator

from sqlalchemy import create_engine
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
    """Create all tables defined in orm_models. Call explicitly — not on import."""
    Base.metadata.create_all(engine)
