"""
Tests for rate limiting and audit logging.

All tests use an in-memory SQLite DB (StaticPool for thread-safety) and the
Flask test client.  The real app.db is never touched.
"""
import json
import sys
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db.orm_models import AuditLog, Base, Client, ScanRun, Target
from db.user_model import User


# ─────────────────────────────────────────────────────────────────────────────
# Shared fixture helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, autoflush=False, autocommit=False)


def _make_app(Session):
    import web.app as app_module
    import db.audit as audit_module
    import scheduler as sched_module

    orig_app_sl = app_module.SessionLocal
    orig_audit_sl = audit_module.SessionLocal
    orig_sched_sl = sched_module.SessionLocal
    app_module.SessionLocal = Session
    audit_module.SessionLocal = Session
    sched_module.SessionLocal = Session

    flask_app = app_module.app
    flask_app.config["TESTING"] = True
    flask_app.secret_key = "test-secret"

    return flask_app.test_client(), app_module, audit_module, sched_module, (
        orig_app_sl, orig_audit_sl, orig_sched_sl
    )


def _restore(app_module, audit_module, sched_module, originals):
    app_module.SessionLocal = originals[0]
    audit_module.SessionLocal = originals[1]
    sched_module.SessionLocal = originals[2]
    # Reset rate-limit counters so tests don't bleed into each other.
    # The limiter is a module-level singleton; fresh DBs restart user IDs at 1,
    # so counters from one test would poison the next test's same integer user_id.
    try:
        app_module.limiter._storage.reset()
    except Exception:
        pass


def _seed(Session, role="customer", verified=True):
    db = Session()
    try:
        user = User(
            google_id=str(uuid.uuid4()),
            email=f"user-{uuid.uuid4().hex[:6]}@example.com",
            name="Tester",
            role=role,
        )
        db.add(user); db.flush()
        client = Client(name="Co", contact_email=user.email, user_id=user.id)
        db.add(client); db.flush()
        target = Target(
            client_id=client.id,
            scope="example.com",
            authorized_by="test-ref",
            verified=verified,
            verification_token="test-tok",
            skip_cve=True,
        )
        db.add(target); db.flush()
        db.commit()
        return user.id, client.id, target.id
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiting tests
# ─────────────────────────────────────────────────────────────────────────────

def test_scan_trigger_rate_limit_5_per_hour():
    """
    POST /api/targets/<id>/scan is limited to 5 per user per hour.
    Calls 1-5 must NOT return 429. Call 6 must return 429 with correct JSON.
    execute_scan is mocked to avoid background threads touching the DB.
    """
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, originals = _make_app(Session)
    user_id, _, target_id = _seed(Session, verified=True)

    try:
        with http.session_transaction() as sess:
            sess["user_id"] = user_id

        with patch("web.app.execute_scan"):
            for i in range(1, 6):
                r = http.post(f"/api/targets/{target_id}/scan")
                assert r.status_code != 429, (
                    f"Request {i} was unexpectedly rate-limited (got 429). "
                    f"Response: {r.get_json()}"
                )
            # 6th request must be rate-limited
            r6 = http.post(f"/api/targets/{target_id}/scan")

        assert r6.status_code == 429, f"Expected 429 on 6th call, got {r6.status_code}"
        body = r6.get_json()
        assert body["error"] == "Rate limit exceeded. Please try again later."
        assert "retry_after_seconds" in body
        assert isinstance(body["retry_after_seconds"], int)
        assert body["retry_after_seconds"] >= 0

        print("OK  rate limit: scan trigger allows 5/hour, blocks 6th with correct JSON 429")
    finally:
        _restore(app_module, audit_module, sched_module, originals)
        engine.dispose()


def test_health_not_rate_limited():
    """GET /api/health is exempt from rate limiting — should always return 200."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, originals = _make_app(Session)

    try:
        for _ in range(10):
            r = http.get("/api/health")
            assert r.status_code == 200, f"Health check returned {r.status_code}"
        print("OK  GET /api/health is exempt from rate limiting")
    finally:
        _restore(app_module, audit_module, sched_module, originals)
        engine.dispose()


def test_rate_limit_json_format():
    """429 response must match the rest of the API's error format."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, originals = _make_app(Session)
    user_id, _, target_id = _seed(Session, verified=True)

    try:
        with http.session_transaction() as sess:
            sess["user_id"] = user_id

        with patch("web.app.execute_scan"):
            for _ in range(5):
                http.post(f"/api/targets/{target_id}/scan")
            r = http.post(f"/api/targets/{target_id}/scan")

        assert r.status_code == 429
        body = r.get_json()
        assert set(body.keys()) == {"error", "retry_after_seconds"}, (
            f"Unexpected keys in 429 body: {body.keys()}"
        )
        assert body["error"] == "Rate limit exceeded. Please try again later."
        print("OK  429 response has exactly {'error', 'retry_after_seconds'} keys")
    finally:
        _restore(app_module, audit_module, sched_module, originals)
        engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# Audit logging tests
# ─────────────────────────────────────────────────────────────────────────────

def _audit_rows(Session, action=None):
    db = Session()
    try:
        q = db.query(AuditLog)
        if action:
            q = q.filter(AuditLog.action == action)
        return q.order_by(AuditLog.id).all()
    finally:
        db.close()


def test_audit_client_created():
    """POST /api/clients writes a 'client_created' AuditLog row."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, originals = _make_app(Session)
    user_id, _, _ = _seed(Session)

    try:
        with http.session_transaction() as sess:
            sess["user_id"] = user_id

        r = http.post("/api/clients", json={"name": "Audit Test Co"}, content_type="application/json")
        assert r.status_code == 201, r.get_json()

        rows = _audit_rows(Session, "client_created")
        assert len(rows) == 1
        assert rows[0].user_id == user_id
        assert rows[0].resource_type == "client"
        assert rows[0].resource_id == r.get_json()["id"]
        print("OK  audit: client_created row written with correct user_id and resource_id")
    finally:
        _restore(app_module, audit_module, sched_module, originals)
        engine.dispose()


def test_audit_client_deleted():
    """DELETE /api/clients/<id> writes a 'client_deleted' AuditLog row with the name."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, originals = _make_app(Session)
    user_id, client_id, _ = _seed(Session)

    try:
        with http.session_transaction() as sess:
            sess["user_id"] = user_id

        r = http.delete(f"/api/clients/{client_id}")
        assert r.status_code == 200, r.get_json()

        rows = _audit_rows(Session, "client_deleted")
        assert len(rows) == 1
        assert rows[0].resource_id == client_id
        details = json.loads(rows[0].details)
        assert "name" in details
        print(f"OK  audit: client_deleted row with name={details['name']!r}")
    finally:
        _restore(app_module, audit_module, sched_module, originals)
        engine.dispose()


def test_audit_target_created():
    """POST /api/targets writes a 'target_created' AuditLog row with scope in details."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, originals = _make_app(Session)
    user_id, client_id, _ = _seed(Session)

    try:
        with http.session_transaction() as sess:
            sess["user_id"] = user_id

        r = http.post("/api/targets", json={
            "client_id": client_id,
            "scope": "audit-test.com",
            "authorized_by": "test-ref",
        }, content_type="application/json")
        assert r.status_code == 201, r.get_json()

        rows = _audit_rows(Session, "target_created")
        assert len(rows) == 1
        assert rows[0].resource_type == "target"
        details = json.loads(rows[0].details)
        assert details["scope"] == "audit-test.com"
        print("OK  audit: target_created row with scope in details")
    finally:
        _restore(app_module, audit_module, sched_module, originals)
        engine.dispose()


def test_audit_verification_attempted_logged_for_both_success_and_failure():
    """POST /api/targets/<id>/verify writes 'verification_attempted' for both outcomes."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, originals = _make_app(Session)
    user_id, _, target_id = _seed(Session, verified=False)

    try:
        with http.session_transaction() as sess:
            sess["user_id"] = user_id

        # Patch DNS/file checks to return False (failed verification)
        with patch("web.app.check_dns_verification", return_value=False):
            r = http.post(f"/api/targets/{target_id}/verify",
                          json={"method": "dns"}, content_type="application/json")
        assert r.status_code == 200
        assert r.get_json()["verified"] is False

        rows = _audit_rows(Session, "verification_attempted")
        assert len(rows) == 1
        assert json.loads(rows[0].details)["result"] == "failed"

        # Now simulate success
        with patch("web.app.check_dns_verification", return_value=True):
            r2 = http.post(f"/api/targets/{target_id}/verify",
                           json={"method": "dns"}, content_type="application/json")
        assert r2.get_json()["verified"] is True

        rows2 = _audit_rows(Session, "verification_attempted")
        assert len(rows2) == 2
        results = {json.loads(row.details)["result"] for row in rows2}
        assert results == {"failed", "success"}
        print("OK  audit: verification_attempted logged for both failed and success outcomes")
    finally:
        _restore(app_module, audit_module, sched_module, originals)
        engine.dispose()


def test_audit_scan_triggered():
    """POST /api/targets/<id>/scan writes a 'scan_triggered' AuditLog row."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, originals = _make_app(Session)
    user_id, _, target_id = _seed(Session, verified=True)

    try:
        with http.session_transaction() as sess:
            sess["user_id"] = user_id

        with patch("web.app.execute_scan"):
            r = http.post(f"/api/targets/{target_id}/scan")
        assert r.status_code == 202, r.get_json()

        rows = _audit_rows(Session, "scan_triggered")
        assert len(rows) == 1
        assert rows[0].resource_type == "target"
        assert rows[0].resource_id == target_id
        assert rows[0].user_id == user_id
        print("OK  audit: scan_triggered row with correct target_id and user_id")
    finally:
        _restore(app_module, audit_module, sched_module, originals)
        engine.dispose()


def test_audit_rate_limit_exceeded():
    """Hitting the rate limit writes a 'rate_limit_exceeded' AuditLog row."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, originals = _make_app(Session)
    user_id, _, target_id = _seed(Session, verified=True)

    try:
        with http.session_transaction() as sess:
            sess["user_id"] = user_id

        with patch("web.app.execute_scan"):
            for _ in range(5):
                http.post(f"/api/targets/{target_id}/scan")
            r = http.post(f"/api/targets/{target_id}/scan")

        assert r.status_code == 429

        rows = _audit_rows(Session, "rate_limit_exceeded")
        assert len(rows) >= 1
        details = json.loads(rows[0].details)
        assert "endpoint" in details
        print(f"OK  audit: rate_limit_exceeded row with endpoint={details['endpoint']!r}")
    finally:
        _restore(app_module, audit_module, sched_module, originals)
        engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# Admin audit-log endpoint tests
# ─────────────────────────────────────────────────────────────────────────────

def test_admin_audit_log_returns_entries():
    """GET /api/admin/audit-log returns correct entries and supports filtering."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, originals = _make_app(Session)
    admin_id, client_id, target_id = _seed(Session, role="admin", verified=True)

    try:
        with http.session_transaction() as sess:
            sess["user_id"] = admin_id

        # Trigger a couple of auditable actions
        with patch("web.app.execute_scan"):
            http.post(f"/api/targets/{target_id}/scan")
            http.post(f"/api/targets/{target_id}/scan")

        http.post("/api/clients", json={"name": "Audit Co"}, content_type="application/json")

        r = http.get("/api/admin/audit-log")
        assert r.status_code == 200, r.get_json()
        body = r.get_json()
        assert body["total"] >= 3
        assert isinstance(body["entries"], list)

        # Filter by action
        r2 = http.get("/api/admin/audit-log?action=scan_triggered")
        body2 = r2.get_json()
        assert body2["total"] == 2
        for entry in body2["entries"]:
            assert entry["action"] == "scan_triggered"
            assert entry["user_id"] == admin_id

        # Filter by user_id
        r3 = http.get(f"/api/admin/audit-log?user_id={admin_id}")
        body3 = r3.get_json()
        assert body3["total"] >= 3

        print("OK  GET /api/admin/audit-log returns entries, supports ?action= and ?user_id= filters")
    finally:
        _restore(app_module, audit_module, sched_module, originals)
        engine.dispose()


def test_admin_audit_log_customer_gets_403():
    """Non-admin users must get 403 on GET /api/admin/audit-log."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, originals = _make_app(Session)
    user_id, _, _ = _seed(Session, role="customer")

    try:
        with http.session_transaction() as sess:
            sess["user_id"] = user_id

        r = http.get("/api/admin/audit-log")
        assert r.status_code == 403
        assert r.get_json()["error"] == "Admin access required"
        print("OK  GET /api/admin/audit-log returns 403 for non-admin users")
    finally:
        _restore(app_module, audit_module, sched_module, originals)
        engine.dispose()


def test_admin_audit_log_pagination():
    """Pagination params (page, per_page) work correctly on the audit-log endpoint."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, originals = _make_app(Session)
    admin_id, _, target_id = _seed(Session, role="admin", verified=True)

    try:
        with http.session_transaction() as sess:
            sess["user_id"] = admin_id

        # Create 7 audit entries
        from db.audit import log_audit_event
        orig_sl = audit_module.SessionLocal
        audit_module.SessionLocal = Session
        try:
            for i in range(7):
                log_audit_event(admin_id, "test_event", details={"i": i})
        finally:
            audit_module.SessionLocal = orig_sl

        r1 = http.get("/api/admin/audit-log?action=test_event&per_page=3&page=1")
        assert r1.status_code == 200
        b1 = r1.get_json()
        assert b1["total"] == 7
        assert len(b1["entries"]) == 3

        r2 = http.get("/api/admin/audit-log?action=test_event&per_page=3&page=3")
        b2 = r2.get_json()
        assert len(b2["entries"]) == 1  # last page has 1 entry (7 mod 3 = 1)

        # Newest-first ordering (id desc)
        all_ids = b1["entries"] + r2.get_json()["entries"]
        # ids should be descending across pages
        ids = [e["id"] for e in b1["entries"]]
        assert ids == sorted(ids, reverse=True)
        print("OK  /api/admin/audit-log pagination and ordering work correctly")
    finally:
        _restore(app_module, audit_module, sched_module, originals)
        engine.dispose()


def test_admin_audit_log_null_user_handled():
    """Audit entries with user_id=None (anonymous events) don't crash the endpoint."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, originals = _make_app(Session)
    admin_id, _, _ = _seed(Session, role="admin")

    try:
        # Write an anon audit entry (user_id=None)
        orig_sl = audit_module.SessionLocal
        audit_module.SessionLocal = Session
        try:
            from db.audit import log_audit_event
            log_audit_event(None, "anon_event", details={"note": "anonymous"})
        finally:
            audit_module.SessionLocal = orig_sl

        with http.session_transaction() as sess:
            sess["user_id"] = admin_id

        r = http.get("/api/admin/audit-log?action=anon_event")
        assert r.status_code == 200
        entries = r.get_json()["entries"]
        assert len(entries) == 1
        assert entries[0]["user_id"] is None
        assert entries[0]["user_email"] is None
        print("OK  audit-log endpoint handles null user_id gracefully")
    finally:
        _restore(app_module, audit_module, sched_module, originals)
        engine.dispose()


if __name__ == "__main__":
    test_scan_trigger_rate_limit_5_per_hour()
    test_health_not_rate_limited()
    test_rate_limit_json_format()
    test_audit_client_created()
    test_audit_client_deleted()
    test_audit_target_created()
    test_audit_verification_attempted_logged_for_both_success_and_failure()
    test_audit_scan_triggered()
    test_audit_rate_limit_exceeded()
    test_admin_audit_log_returns_entries()
    test_admin_audit_log_customer_gets_403()
    test_admin_audit_log_pagination()
    test_admin_audit_log_null_user_handled()
    print("\nAll rate-limit and audit tests passed.")
