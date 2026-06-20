"""
Tests for admin_required decorator and /api/admin/* endpoints.

Uses an in-memory SQLite DB and Flask's test client with a manually-crafted
session so the real app.db and Google OAuth are never touched.
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.orm_models import Base, Client, ScanRun, Target
from db.user_model import User


# ── Fixture helpers ───────────────────────────────────────────────────────────

def _make_app(db_url: str):
    """Return a Flask test client wired to an in-memory DB."""
    import web.app as app_module

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    # Patch the module-level SessionLocal so all endpoints use our test DB.
    original_session_local = app_module.SessionLocal
    app_module.SessionLocal = Session

    app = app_module.app
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret"
    app.secret_key = "test-secret"

    client = app.test_client()
    return client, Session, engine, app_module, original_session_local


def _seed(session_factory):
    """Seed two users (one admin, one customer), clients, targets, scan runs."""
    db = session_factory()
    try:
        admin = User(google_id="g_admin", email="admin@example.com", name="Admin", role="admin")
        customer = User(google_id="g_cust", email="cust@example.com", name="Customer", role="customer")
        db.add_all([admin, customer])
        db.flush()

        c1 = Client(name="Admin Corp", contact_email="admin@example.com", user_id=admin.id)
        c2 = Client(name="Cust Biz", contact_email="cust@example.com", user_id=customer.id)
        db.add_all([c1, c2])
        db.flush()

        t1 = Target(client_id=c1.id, scope="example.com", authorized_by="admin@example.com",
                    verified=True, verification_token="tok1")
        t2 = Target(client_id=c2.id, scope="other.com", authorized_by="cust@example.com",
                    verified=False, verification_token="tok2")
        db.add_all([t1, t2])
        db.flush()

        summary = {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 1}
        result_blob = json.dumps({
            "scan_id": "s1", "target_scope": ["example.com"], "authorized_by": "admin@example.com",
            "started_at": "2026-01-01T00:00:00", "completed_at": "2026-01-01T00:01:00",
            "checks_run": ["port_scan"], "findings": [], "summary": summary,
        })
        sr1 = ScanRun(target_id=t1.id, scan_id="s1", status="completed", result_json=result_blob)
        sr2 = ScanRun(target_id=t1.id, scan_id="s2", status="failed")
        sr3 = ScanRun(target_id=t2.id, scan_id="s3", status="pending")
        db.add_all([sr1, sr2, sr3])
        db.commit()
        db.refresh(admin)
        db.refresh(customer)
        return admin.id, customer.id
    finally:
        db.close()


def _session_with_user(client, app, user_id: int):
    """Inject user_id into the Flask session cookie."""
    with app.session_transaction() as sess:
        sess["user_id"] = user_id


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_admin_required_unauthenticated():
    client, Session, engine, app_module, orig = _make_app("sqlite:///:memory:")
    _seed(Session)
    try:
        for path in [
            "/api/admin/users",
            "/api/admin/clients",
            "/api/admin/targets",
            "/api/admin/scans",
            "/api/admin/stats",
        ]:
            r = client.get(path)
            assert r.status_code == 401, f"{path}: expected 401, got {r.status_code}"
            assert r.get_json()["error"] == "Authentication required"
        print("OK  unauthenticated -> 401 on all /api/admin/* routes")
    finally:
        app_module.SessionLocal = orig
        engine.dispose()


def test_admin_required_customer_gets_403():
    client, Session, engine, app_module, orig = _make_app("sqlite:///:memory:")
    admin_id, customer_id = _seed(Session)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = customer_id

        for path in [
            "/api/admin/users",
            "/api/admin/clients",
            "/api/admin/targets",
            "/api/admin/scans",
            "/api/admin/stats",
        ]:
            r = client.get(path)
            assert r.status_code == 403, f"{path}: expected 403 for customer, got {r.status_code}"
            assert r.get_json()["error"] == "Admin access required"
        print("OK  customer -> 403 on all /api/admin/* routes")
    finally:
        app_module.SessionLocal = orig
        engine.dispose()


def test_admin_list_users():
    client, Session, engine, app_module, orig = _make_app("sqlite:///:memory:")
    admin_id, customer_id = _seed(Session)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = admin_id

        r = client.get("/api/admin/users")
        assert r.status_code == 200
        data = r.get_json()
        assert isinstance(data, list)
        assert len(data) == 2

        admin_row = next(u for u in data if u["email"] == "admin@example.com")
        assert admin_row["role"] == "admin"
        assert admin_row["client_count"] == 1

        cust_row = next(u for u in data if u["email"] == "cust@example.com")
        assert cust_row["role"] == "customer"
        assert cust_row["client_count"] == 1
        print("OK  GET /api/admin/users returns all users with client counts")
    finally:
        app_module.SessionLocal = orig
        engine.dispose()


def test_admin_list_clients():
    client, Session, engine, app_module, orig = _make_app("sqlite:///:memory:")
    admin_id, _ = _seed(Session)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = admin_id

        r = client.get("/api/admin/clients")
        assert r.status_code == 200
        data = r.get_json()
        assert len(data) == 2

        c1 = next(c for c in data if c["name"] == "Admin Corp")
        assert c1["owner_email"] == "admin@example.com"
        assert c1["target_count"] == 1
        print("OK  GET /api/admin/clients returns all clients with owner email and target count")
    finally:
        app_module.SessionLocal = orig
        engine.dispose()


def test_admin_list_targets():
    client, Session, engine, app_module, orig = _make_app("sqlite:///:memory:")
    admin_id, _ = _seed(Session)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = admin_id

        r = client.get("/api/admin/targets")
        assert r.status_code == 200
        data = r.get_json()
        assert len(data) == 2

        t1 = next(t for t in data if t["scope"] == "example.com")
        assert t1["verified"] is True
        assert t1["client_name"] == "Admin Corp"
        assert t1["owner_email"] == "admin@example.com"
        assert t1["scan_count"] == 2  # sr1 + sr2

        t2 = next(t for t in data if t["scope"] == "other.com")
        assert t2["verified"] is False
        assert t2["scan_count"] == 1  # sr3
        print("OK  GET /api/admin/targets returns all targets with client/owner/scan_count")
    finally:
        app_module.SessionLocal = orig
        engine.dispose()


def test_admin_list_scans_pagination():
    client, Session, engine, app_module, orig = _make_app("sqlite:///:memory:")
    admin_id, _ = _seed(Session)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = admin_id

        r = client.get("/api/admin/scans")
        assert r.status_code == 200
        body = r.get_json()
        assert body["total"] == 3
        assert body["page"] == 1
        assert body["per_page"] == 50
        scans = body["scans"]
        assert len(scans) == 3
        # Sorted newest-first (descending id)
        assert scans[0]["id"] > scans[-1]["id"]

        # First page of 1
        r2 = client.get("/api/admin/scans?page=1&per_page=1")
        body2 = r2.get_json()
        assert len(body2["scans"]) == 1
        assert body2["total"] == 3

        # Page 2 of 1 per page
        r3 = client.get("/api/admin/scans?page=2&per_page=1")
        body3 = r3.get_json()
        assert len(body3["scans"]) == 1
        assert body3["scans"][0]["id"] != body2["scans"][0]["id"]

        print("OK  GET /api/admin/scans returns paginated scans sorted newest-first")
    finally:
        app_module.SessionLocal = orig
        engine.dispose()


def test_admin_stats():
    client, Session, engine, app_module, orig = _make_app("sqlite:///:memory:")
    admin_id, _ = _seed(Session)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = admin_id

        r = client.get("/api/admin/stats")
        assert r.status_code == 200
        data = r.get_json()

        assert data["total_users"] == 2
        assert data["total_clients"] == 2
        assert data["total_targets"] == 2
        assert data["total_verified_targets"] == 1
        assert data["total_scans"] == 3

        assert data["scans_by_status"]["completed"] == 1
        assert data["scans_by_status"]["failed"] == 1
        assert data["scans_by_status"]["pending"] == 1
        assert data["scans_by_status"]["running"] == 0

        sev = data["findings_by_severity"]
        assert sev["critical"] == 1
        assert sev["high"] == 2
        assert sev["info"] == 1
        assert sev["medium"] == 0
        assert sev["low"] == 0
        print("OK  GET /api/admin/stats returns correct aggregate numbers")
    finally:
        app_module.SessionLocal = orig
        engine.dispose()


def test_admin_set_user_role():
    client, Session, engine, app_module, orig = _make_app("sqlite:///:memory:")
    admin_id, customer_id = _seed(Session)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = admin_id

        # Promote customer to admin
        r = client.post(
            f"/api/admin/users/{customer_id}/role",
            json={"role": "admin"},
            content_type="application/json",
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["role"] == "admin"
        assert body["email"] == "cust@example.com"

        # Demote back to customer
        r2 = client.post(
            f"/api/admin/users/{customer_id}/role",
            json={"role": "customer"},
            content_type="application/json",
        )
        assert r2.status_code == 200
        assert r2.get_json()["role"] == "customer"

        # Invalid role value -> 400
        r3 = client.post(
            f"/api/admin/users/{customer_id}/role",
            json={"role": "superuser"},
            content_type="application/json",
        )
        assert r3.status_code == 400
        assert "role must be" in r3.get_json()["error"]

        # Non-existent user -> 404
        r4 = client.post(
            "/api/admin/users/99999/role",
            json={"role": "admin"},
            content_type="application/json",
        )
        assert r4.status_code == 404

        print("OK  POST /api/admin/users/<id>/role promotes/demotes correctly, validates role value")
    finally:
        app_module.SessionLocal = orig
        engine.dispose()


def test_customer_cannot_set_role():
    client, Session, engine, app_module, orig = _make_app("sqlite:///:memory:")
    admin_id, customer_id = _seed(Session)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = customer_id

        r = client.post(
            f"/api/admin/users/{admin_id}/role",
            json={"role": "customer"},
            content_type="application/json",
        )
        assert r.status_code == 403
        print("OK  customer cannot call POST /api/admin/users/<id>/role")
    finally:
        app_module.SessionLocal = orig
        engine.dispose()


if __name__ == "__main__":
    test_admin_required_unauthenticated()
    test_admin_required_customer_gets_403()
    test_admin_list_users()
    test_admin_list_clients()
    test_admin_list_targets()
    test_admin_list_scans_pagination()
    test_admin_stats()
    test_admin_set_user_role()
    test_customer_cannot_set_role()
    print("\nAll admin endpoint tests passed.")
