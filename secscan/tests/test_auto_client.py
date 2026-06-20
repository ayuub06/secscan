"""
Test: auto-Client creation on first OAuth login; no duplicate on re-login.

Calls the DB logic directly (no Flask/OAuth) using an in-memory SQLite database
so the real app.db is never touched.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.orm_models import Base, Client
from db.user_model import User


def _simulate_oauth_login(db, google_id: str, email: str, name: str) -> User:
    """Mirrors the find-or-create logic in google_callback()."""
    user = db.query(User).filter_by(google_id=google_id).first()
    is_new = user is None
    if is_new:
        user = User(google_id=google_id, email=email, name=name)
        db.add(user)
        db.flush()  # populate user.id before creating the linked Client
    else:
        user.email = email
        user.name = name
    db.commit()
    db.refresh(user)

    if not db.query(Client).filter_by(user_id=user.id).first():
        client_name = (user.name or "").strip() or user.email
        db.add(Client(name=client_name, contact_email=user.email, user_id=user.id))
        db.commit()

    return user


def test_auto_client_creation():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    # ── First login: brand-new user ───────────────────────────────────────────
    db = Session()
    try:
        user = _simulate_oauth_login(db, "g_alice_001", "alice@example.com", "Alice")
        clients = db.query(Client).filter_by(user_id=user.id).all()
        assert len(clients) == 1, f"Expected 1 client after first login, got {len(clients)}"
        assert clients[0].name == "Alice"
        assert clients[0].contact_email == "alice@example.com"
        assert clients[0].user_id == user.id
        print("OK First login (new user): exactly 1 Client created")
    finally:
        db.close()

    # ── Second login: same google_id, returning user ──────────────────────────
    db = Session()
    try:
        user = _simulate_oauth_login(db, "g_alice_001", "alice@example.com", "Alice")
        clients = db.query(Client).filter_by(user_id=user.id).all()
        assert len(clients) == 1, f"Expected 1 client after second login, got {len(clients)}"
        print("OK Second login (returning user): still exactly 1 Client — no duplicate")
    finally:
        db.close()

    # ── Edge case: user with no name falls back to email ─────────────────────
    db = Session()
    try:
        user = _simulate_oauth_login(db, "g_bob_002", "bob@example.com", "")
        clients = db.query(Client).filter_by(user_id=user.id).all()
        assert len(clients) == 1
        assert clients[0].name == "bob@example.com", f"Expected email fallback, got {clients[0].name!r}"
        print("OK No-name user: Client name falls back to email")
    finally:
        db.close()

    # ── Default role is "customer" ────────────────────────────────────────────
    db = Session()
    try:
        user = db.query(User).filter_by(google_id="g_alice_001").first()
        assert user.role == "customer", f"Expected role='customer', got {user.role!r}"
        print("OK New user gets role='customer' by default")
    finally:
        db.close()

    print("\nAll tests passed.")


if __name__ == "__main__":
    test_auto_client_creation()
