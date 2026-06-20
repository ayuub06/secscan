"""
Tests for admin manual-verification override.

Covers:
  a. Non-admin calling POST /api/admin/targets/<id>/manual-verify -> 403
  b. Admin calling it without a reason -> 400
  c. Admin calling it with a valid reason -> target fields updated correctly
  d. Scanning unblocked after manual verification
  e. Audit log contains target_manually_verified with the full reason text
  f. GET /api/admin/targets/unverified excludes just-verified target
"""
import json
import sys
import os
import uuid
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db.orm_models import AuditLog, Base, Client, Target
from db.user_model import User


# ── Fixture helpers ───────────────────────────────────────────────────────────

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

    orig = (app_module.SessionLocal, audit_module.SessionLocal, sched_module.SessionLocal)
    app_module.SessionLocal = Session
    audit_module.SessionLocal = Session
    sched_module.SessionLocal = Session

    flask_app = app_module.app
    flask_app.config["TESTING"] = True
    flask_app.secret_key = "test-secret"

    return flask_app.test_client(), app_module, audit_module, sched_module, orig


def _restore(app_module, audit_module, sched_module, originals):
    app_module.SessionLocal = originals[0]
    audit_module.SessionLocal = originals[1]
    sched_module.SessionLocal = originals[2]
    try:
        app_module.limiter._storage.reset()
    except Exception:
        pass


def _seed(Session):
    """Seed admin + customer, each with a client and one unverified target. Returns ids."""
    db = Session()
    try:
        admin = User(google_id=str(uuid.uuid4()), email="admin@example.com",
                     name="Admin", role="admin")
        customer = User(google_id=str(uuid.uuid4()), email="cust@example.com",
                        name="Customer", role="customer")
        db.add_all([admin, customer])
        db.flush()

        admin_client = Client(name="Admin Corp", contact_email="admin@example.com",
                              user_id=admin.id)
        cust_client = Client(name="Cust Biz", contact_email="cust@example.com",
                             user_id=customer.id)
        db.add_all([admin_client, cust_client])
        db.flush()

        # Both targets start unverified so we can test the full verify->scan flow.
        t1 = Target(client_id=cust_client.id, scope="example.com",
                    authorized_by="cust@example.com", verified=False,
                    verification_token=uuid.uuid4().hex, skip_cve=True)
        t2 = Target(client_id=cust_client.id, scope="other.com",
                    authorized_by="cust@example.com", verified=False,
                    verification_token=uuid.uuid4().hex, skip_cve=True)
        db.add_all([t1, t2])
        db.commit()
        return admin.id, customer.id, t1.id, t2.id
    finally:
        db.close()


def _audit_rows(Session, action):
    db = Session()
    try:
        return (
            db.query(AuditLog)
            .filter(AuditLog.action == action)
            .order_by(AuditLog.id)
            .all()
        )
    finally:
        db.close()


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_a_non_admin_gets_403():
    """(a) A customer user must receive 403 on the manual-verify endpoint."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, orig = _make_app(Session)
    _, customer_id, t1_id, _ = _seed(Session)
    try:
        with http.session_transaction() as sess:
            sess["user_id"] = customer_id

        r = http.post(
            f"/api/admin/targets/{t1_id}/manual-verify",
            json={"reason": "Called client on phone"},
            content_type="application/json",
        )
        assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.get_json()}"
        assert r.get_json()["error"] == "Admin access required"
        print("OK  (a) non-admin customer -> 403 on POST /api/admin/targets/<id>/manual-verify")
    finally:
        _restore(app_module, audit_module, sched_module, orig)
        engine.dispose()


def test_b_missing_reason_gets_400():
    """(b) Admin calling without a reason (empty or absent) must get 400."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, orig = _make_app(Session)
    admin_id, _, t1_id, _ = _seed(Session)
    try:
        with http.session_transaction() as sess:
            sess["user_id"] = admin_id

        # No reason field
        r1 = http.post(
            f"/api/admin/targets/{t1_id}/manual-verify",
            json={},
            content_type="application/json",
        )
        assert r1.status_code == 400, f"Expected 400, got {r1.status_code}"
        assert "reason" in r1.get_json()["error"].lower()

        # Empty string reason
        r2 = http.post(
            f"/api/admin/targets/{t1_id}/manual-verify",
            json={"reason": "   "},
            content_type="application/json",
        )
        assert r2.status_code == 400, f"Expected 400 for whitespace-only reason, got {r2.status_code}"
        print("OK  (b) admin without reason (absent / blank) -> 400")
    finally:
        _restore(app_module, audit_module, sched_module, orig)
        engine.dispose()


def test_c_admin_with_reason_verifies_target():
    """(c) Admin supplying a reason sets verified, method, verified_by_admin_id, verified_at."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, orig = _make_app(Session)
    admin_id, _, t1_id, _ = _seed(Session)
    try:
        with http.session_transaction() as sess:
            sess["user_id"] = admin_id

        reason = "Confirmed ownership via phone call with client on 2026-06-20"
        r = http.post(
            f"/api/admin/targets/{t1_id}/manual-verify",
            json={"reason": reason},
            content_type="application/json",
        )
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.get_json()}"
        body = r.get_json()

        assert body["verified"] is True, "verified must be True"
        assert body["verification_method"] == "manual_admin", (
            f"verification_method must be 'manual_admin', got {body['verification_method']!r}"
        )
        assert body["verified_by_admin_id"] == admin_id, (
            f"verified_by_admin_id must be admin_id={admin_id}, got {body['verified_by_admin_id']}"
        )
        assert body["verified_at"] is not None, "verified_at must be set"
        assert "manual_verification_note" in body, (
            "Response must include manual_verification_note for admin-verified targets"
        )

        # Cross-check against the DB directly
        db = Session()
        try:
            t = db.get(Target, t1_id)
            assert t.verified is True
            assert t.verification_method == "manual_admin"
            assert t.verified_by_admin_id == admin_id
            assert t.verified_at is not None
        finally:
            db.close()

        print("OK  (c) admin with reason -> verified=True, method=manual_admin, "
              "verified_by_admin_id set, verified_at set")
    finally:
        _restore(app_module, audit_module, sched_module, orig)
        engine.dispose()


def test_d_scan_unblocked_after_manual_verify():
    """(d) POST /api/targets/<id>/scan succeeds after manual verification (was blocked before)."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, orig = _make_app(Session)
    admin_id, customer_id, t1_id, _ = _seed(Session)
    try:
        # Log in as customer — scan should be blocked (not verified yet)
        with http.session_transaction() as sess:
            sess["user_id"] = customer_id

        r_blocked = http.post(f"/api/targets/{t1_id}/scan")
        assert r_blocked.status_code == 403, (
            f"Expected 403 before verification, got {r_blocked.status_code}"
        )
        assert "not verified" in r_blocked.get_json()["error"].lower()

        # Admin manually verifies the target
        with http.session_transaction() as sess:
            sess["user_id"] = admin_id

        http.post(
            f"/api/admin/targets/{t1_id}/manual-verify",
            json={"reason": "Client sent registrar screenshot via email"},
            content_type="application/json",
        )

        # Now log back in as customer and scan — should succeed
        with http.session_transaction() as sess:
            sess["user_id"] = customer_id

        with patch("web.app.execute_scan"):
            r_ok = http.post(f"/api/targets/{t1_id}/scan")

        assert r_ok.status_code == 202, (
            f"Expected 202 after manual verification, got {r_ok.status_code}: {r_ok.get_json()}"
        )
        assert r_ok.get_json()["status"] == "pending"
        print("OK  (d) scan blocked before manual-verify, succeeds (202) after")
    finally:
        _restore(app_module, audit_module, sched_module, orig)
        engine.dispose()


def test_e_audit_log_contains_reason():
    """(e) Audit log must have a target_manually_verified entry with the full reason text."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, orig = _make_app(Session)
    admin_id, _, t1_id, _ = _seed(Session)
    try:
        with http.session_transaction() as sess:
            sess["user_id"] = admin_id

        reason_text = "Operator verified via contract reference #C-2026-042"
        http.post(
            f"/api/admin/targets/{t1_id}/manual-verify",
            json={"reason": reason_text},
            content_type="application/json",
        )

        rows = _audit_rows(Session, "target_manually_verified")
        assert len(rows) == 1, f"Expected 1 audit row, got {len(rows)}"

        row = rows[0]
        assert row.user_id == admin_id
        assert row.resource_type == "target"
        assert row.resource_id == t1_id

        details = json.loads(row.details)
        assert details["reason"] == reason_text, (
            f"Reason text not preserved in audit log. Got: {details['reason']!r}"
        )
        assert details["admin_id"] == admin_id
        assert "target_scope" in details

        print(f"OK  (e) audit log: target_manually_verified entry with reason={reason_text!r}")
    finally:
        _restore(app_module, audit_module, sched_module, orig)
        engine.dispose()


def test_f_unverified_worklist_excludes_verified():
    """(f) GET /api/admin/targets/unverified excludes manually-verified target."""
    engine, Session = _make_db()
    http, app_module, audit_module, sched_module, orig = _make_app(Session)
    admin_id, _, t1_id, t2_id = _seed(Session)
    try:
        with http.session_transaction() as sess:
            sess["user_id"] = admin_id

        # Before verification: both targets should appear in the worklist
        r_before = http.get("/api/admin/targets/unverified")
        assert r_before.status_code == 200, r_before.get_json()
        ids_before = {t["id"] for t in r_before.get_json()}
        assert t1_id in ids_before, "t1 should be in unverified list before manual-verify"
        assert t2_id in ids_before, "t2 should be in unverified list before manual-verify"

        # Manually verify t1
        http.post(
            f"/api/admin/targets/{t1_id}/manual-verify",
            json={"reason": "Confirmed by contract"},
            content_type="application/json",
        )

        # After verification: t1 must be gone, t2 must remain
        r_after = http.get("/api/admin/targets/unverified")
        assert r_after.status_code == 200
        ids_after = {t["id"] for t in r_after.get_json()}
        assert t1_id not in ids_after, "t1 must be excluded after manual verification"
        assert t2_id in ids_after, "t2 must still appear as unverified"

        # Response shape check
        remaining = next(t for t in r_after.get_json() if t["id"] == t2_id)
        for field in ("scope", "client_id", "client_name", "owner_email", "created_at"):
            assert field in remaining, f"Missing field '{field}' in unverified list entry"

        print("OK  (f) unverified worklist excludes t1 after manual-verify, retains t2; "
              "response includes client_name and owner_email")
    finally:
        _restore(app_module, audit_module, sched_module, orig)
        engine.dispose()


if __name__ == "__main__":
    test_a_non_admin_gets_403()
    test_b_missing_reason_gets_400()
    test_c_admin_with_reason_verifies_target()
    test_d_scan_unblocked_after_manual_verify()
    test_e_audit_log_contains_reason()
    test_f_unverified_worklist_excludes_verified()
    print("\nAll manual-verify tests passed.")
