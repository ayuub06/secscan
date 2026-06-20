"""
Tests for core/diff.py and the /api/targets/<id>/diff + /latest-diff endpoints.

All DB tests use an in-memory SQLite DB; the real app.db is never touched.
"""
import json
import sys
import os
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from core.diff import _finding_fingerprint, compare_scans
from db.orm_models import Base, Client, ScanRun, Target
from db.user_model import User


# ─────────────────────────────────────────────────────────────────────────────
# Fixture helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_finding(
    check_type: str,
    target: str,
    title: str,
    severity: int,
    port: int | None = None,
    evidence: str = "default evidence",
    scan_id: str | None = None,
) -> dict:
    """Return a finding dict matching Finding.to_dict() output."""
    return {
        "id":           str(uuid.uuid4()),
        "scan_id":      scan_id or str(uuid.uuid4()),
        "check_type":   check_type,
        "target":       target,
        "port":         port,
        "title":        title,
        "description":  f"Description for {title}",
        "severity":     severity,   # int: CRITICAL=5 HIGH=4 MEDIUM=3 LOW=2 INFO=1
        "cvss_score":   None,
        "cve_ids":      [],
        "evidence":     evidence,
        "remediation":  f"Remediation for {title}",
        "discovered_at": "2026-01-01T00:00:00+00:00",
    }


def _make_result(findings: list[dict], scan_id: str | None = None, completed_at: str | None = None) -> dict:
    """Return a minimal ScanResult.to_dict() dict wrapping the given findings."""
    sid = scan_id or str(uuid.uuid4())
    return {
        "scan_id":      sid,
        "target_scope": ["example.com"],
        "authorized_by": "test-ref",
        "started_at":   "2026-01-01T00:00:00+00:00",
        "completed_at": completed_at or "2026-01-01T00:01:00+00:00",
        "checks_run":   ["port_scan"],
        "findings":     findings,
        "summary":      {},
    }


# ─────────────────────────────────────────────────────────────────────────────
# a. _finding_fingerprint — same stable fields, different ephemeral fields
# ─────────────────────────────────────────────────────────────────────────────

def test_fingerprint_ignores_ephemeral_fields():
    """Same check_type/target/port/title -> same fingerprint, regardless of id/discovered_at/evidence."""
    f1 = _make_finding("open_port", "example.com", "Open Port 22/tcp", severity=4, port=22,
                        evidence="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
                        scan_id="scan-aaa")
    f2 = _make_finding("open_port", "example.com", "Open Port 22/tcp", severity=4, port=22,
                        evidence="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",  # different banner
                        scan_id="scan-bbb")
    # Force different id and discovered_at
    f2["id"] = str(uuid.uuid4())
    f2["discovered_at"] = "2026-06-01T12:34:56+00:00"

    fp1 = _finding_fingerprint(f1)
    fp2 = _finding_fingerprint(f2)

    assert fp1 == fp2, (
        f"Expected same fingerprint for identical check_type/target/port/title; "
        f"got {fp1!r} vs {fp2!r}"
    )
    print("OK  a. fingerprint ignores id, discovered_at, evidence — stable across runs")


# ─────────────────────────────────────────────────────────────────────────────
# b. _finding_fingerprint — different title -> different fingerprint
# ─────────────────────────────────────────────────────────────────────────────

def test_fingerprint_differs_on_title():
    """Different title -> different fingerprint (fingerprint is not too loose)."""
    f1 = _make_finding("open_port", "example.com", "Open Port 22/tcp",  severity=4, port=22)
    f2 = _make_finding("open_port", "example.com", "Open Port 443/tcp", severity=4, port=443)

    fp1 = _finding_fingerprint(f1)
    fp2 = _finding_fingerprint(f2)

    assert fp1 != fp2, "Expected different fingerprints for different titles"
    print("OK  b. fingerprint differs when title (or port) changes")


# ─────────────────────────────────────────────────────────────────────────────
# c. compare_scans — clean old (0 findings) -> all new findings land in NEW
# ─────────────────────────────────────────────────────────────────────────────

def test_clean_baseline_all_new():
    """Old scan with 0 findings + new scan with 3 findings -> all 3 land in new_findings."""
    old = _make_result([])
    new_findings = [
        _make_finding("open_port",     "h.com", "Open Port 22/tcp",    severity=4, port=22),
        _make_finding("missing_header","h.com", "Missing X-Frame",     severity=2),
        _make_finding("dns_misconfig", "h.com", "SPF Record Missing",  severity=3),
    ]
    new = _make_result(new_findings)

    diff = compare_scans(old, new)

    assert diff["summary"]["new_count"]        == 3
    assert diff["summary"]["resolved_count"]   == 0
    assert diff["summary"]["persistent_count"] == 0
    assert diff["summary"]["escalated_count"]  == 0
    assert len(diff["new_findings"])        == 3
    assert len(diff["resolved_findings"])   == 0
    assert len(diff["persistent_findings"]) == 0
    assert len(diff["escalated_findings"])  == 0
    print("OK  c. clean baseline (0 old findings) -> all 3 new_findings, nothing else")


def test_empty_new_all_resolved():
    """Old scan with 3 findings + new scan with 0 findings -> all 3 land in resolved_findings."""
    old_findings = [
        _make_finding("open_port",     "h.com", "Open Port 22/tcp",  severity=4, port=22),
        _make_finding("missing_header","h.com", "Missing X-Frame",   severity=2),
        _make_finding("dns_misconfig", "h.com", "SPF Record Missing",severity=3),
    ]
    old = _make_result(old_findings)
    new = _make_result([])

    diff = compare_scans(old, new)

    assert diff["summary"]["new_count"]        == 0
    assert diff["summary"]["resolved_count"]   == 3
    assert diff["summary"]["persistent_count"] == 0
    assert diff["summary"]["escalated_count"]  == 0
    assert len(diff["resolved_findings"]) == 3
    print("OK  c. everything fixed (0 new findings) -> all 3 resolved_findings, nothing else")


# ─────────────────────────────────────────────────────────────────────────────
# d. compare_scans — finding in both at same severity -> persistent
# ─────────────────────────────────────────────────────────────────────────────

def test_persistent_same_severity():
    """Finding present in both scans with unchanged severity lands in persistent_findings only."""
    shared = _make_finding("open_port", "h.com", "Open Port 22/tcp", severity=4, port=22)
    old = _make_result([shared])
    # New scan: same logical finding, fresh UUID/timestamp/evidence
    shared_new = _make_finding("open_port", "h.com", "Open Port 22/tcp", severity=4, port=22,
                                evidence="slightly different banner")
    new = _make_result([shared_new])

    diff = compare_scans(old, new)

    assert diff["summary"]["persistent_count"] == 1
    assert diff["summary"]["new_count"]        == 0
    assert diff["summary"]["escalated_count"]  == 0
    assert len(diff["persistent_findings"]) == 1
    assert len(diff["escalated_findings"])  == 0
    print("OK  d. same severity persistent finding lands in persistent_findings, not new/escalated")


def test_persistent_deescalated():
    """Finding with severity DECREASED (e.g. HIGH -> MEDIUM) counts as persistent, not its own category."""
    old_f = _make_finding("open_port", "h.com", "Open Port 22/tcp", severity=4, port=22)  # HIGH
    new_f = _make_finding("open_port", "h.com", "Open Port 22/tcp", severity=3, port=22)  # MEDIUM
    diff = compare_scans(_make_result([old_f]), _make_result([new_f]))

    assert diff["summary"]["persistent_count"] == 1
    assert diff["summary"]["escalated_count"]  == 0
    print("OK  d. de-escalated finding (severity decreased) counts as persistent, not escalated")


# ─────────────────────────────────────────────────────────────────────────────
# e. compare_scans — finding in both with severity INCREASED -> escalated only
# ─────────────────────────────────────────────────────────────────────────────

def test_escalated_finding():
    """Finding in both scans with severity increased lands in escalated_findings, NOT persistent."""
    old_f = _make_finding("open_port", "h.com", "Open Port 22/tcp", severity=3, port=22)  # MEDIUM
    new_f = _make_finding("open_port", "h.com", "Open Port 22/tcp", severity=5, port=22)  # CRITICAL

    diff = compare_scans(_make_result([old_f]), _make_result([new_f]))

    assert diff["summary"]["escalated_count"]  == 1, f"Expected 1 escalated, got {diff['summary']}"
    assert diff["summary"]["persistent_count"] == 0, "Escalated finding must NOT appear in persistent"
    assert diff["summary"]["new_count"]        == 0

    esc = diff["escalated_findings"][0]
    assert esc["old_severity"] == 3
    assert esc["new_severity"] == 5
    assert esc["finding"]["title"] == "Open Port 22/tcp"

    # Confirm it is NOT also in persistent_findings
    assert len(diff["persistent_findings"]) == 0
    print("OK  e. escalated finding (MEDIUM->CRITICAL) in escalated_findings only, absent from persistent")


# ─────────────────────────────────────────────────────────────────────────────
# f. compare_scans — finding in old only -> resolved
# ─────────────────────────────────────────────────────────────────────────────

def test_resolved_finding():
    """Finding present in old but missing from new lands in resolved_findings."""
    old_only = _make_finding("open_port", "h.com", "Open Port 3306/tcp", severity=4, port=3306)
    shared   = _make_finding("open_port", "h.com", "Open Port 22/tcp",   severity=2, port=22)

    old = _make_result([old_only, shared])
    new = _make_result([
        _make_finding("open_port", "h.com", "Open Port 22/tcp", severity=2, port=22)  # shared persists
    ])

    diff = compare_scans(old, new)

    assert diff["summary"]["resolved_count"]   == 1
    assert diff["summary"]["persistent_count"] == 1
    assert diff["summary"]["new_count"]        == 0
    resolved_titles = [f["title"] for f in diff["resolved_findings"]]
    assert "Open Port 3306/tcp" in resolved_titles
    assert "Open Port 22/tcp"  not in resolved_titles
    print("OK  f. finding in old but absent from new lands in resolved_findings")


# ─────────────────────────────────────────────────────────────────────────────
# g. Integration test — Flask test client, real DB, all four categories
# ─────────────────────────────────────────────────────────────────────────────

def _make_app_with_db():
    import web.app as app_module

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    orig_sl = app_module.SessionLocal
    app_module.SessionLocal = Session

    app = app_module.app
    app.config["TESTING"] = True
    app.secret_key = "test-secret"

    return app.test_client(), Session, engine, app_module, orig_sl


def test_diff_endpoint_all_four_categories():
    """
    Integration test: seed two ScanRuns covering all four diff categories,
    call GET /api/targets/<id>/diff, verify counts and category membership.

    old scan findings:
        A — open_port / port 22 / severity MEDIUM(3)   -> PERSISTENT (same in new)
        B — open_port / port 80 / severity HIGH(4)     -> ESCALATED  (CRITICAL in new)
        C — dns_misconfig / severity INFO(1)            -> RESOLVED   (absent in new)

    new scan findings:
        A — open_port / port 22 / severity MEDIUM(3)   -> PERSISTENT
        B — open_port / port 80 / severity CRITICAL(5) -> ESCALATED
        D — missing_header / severity LOW(2)            -> NEW
    """
    http, Session, engine, app_module, orig_sl = _make_app_with_db()

    try:
        # ── Seed DB ───────────────────────────────────────────────────────────
        db = Session()
        try:
            user = User(google_id="gu1", email="u@e.com", name="U", role="customer")
            db.add(user); db.flush()
            client = Client(name="C", contact_email="u@e.com", user_id=user.id)
            db.add(client); db.flush()
            target = Target(
                client_id=client.id, scope="t.com",
                authorized_by="ref", verified=True, verification_token="tok",
            )
            db.add(target); db.flush()

            old_sid = str(uuid.uuid4())
            new_sid = str(uuid.uuid4())

            finding_A_old = _make_finding("open_port",     "t.com", "Open Port 22/tcp",   3, port=22,  scan_id=old_sid)
            finding_B_old = _make_finding("open_port",     "t.com", "Open Port 80/tcp",   4, port=80,  scan_id=old_sid)
            finding_C_old = _make_finding("dns_misconfig", "t.com", "SPF Record Missing", 1,           scan_id=old_sid)

            finding_A_new = _make_finding("open_port",      "t.com", "Open Port 22/tcp",   3, port=22, scan_id=new_sid)
            finding_B_new = _make_finding("open_port",      "t.com", "Open Port 80/tcp",   5, port=80, scan_id=new_sid)  # escalated
            finding_D_new = _make_finding("missing_header", "t.com", "Missing X-Frame-Options", 2,     scan_id=new_sid)

            old_result = _make_result([finding_A_old, finding_B_old, finding_C_old],
                                      scan_id=old_sid, completed_at="2026-01-01T00:01:00+00:00")
            new_result = _make_result([finding_A_new, finding_B_new, finding_D_new],
                                      scan_id=new_sid, completed_at="2026-01-02T00:01:00+00:00")

            old_run = ScanRun(
                target_id=target.id, scan_id=old_sid, status="completed",
                result_json=json.dumps(old_result),
                completed_at=datetime(2026, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
            )
            new_run = ScanRun(
                target_id=target.id, scan_id=new_sid, status="completed",
                result_json=json.dumps(new_result),
                completed_at=datetime(2026, 1, 2, 0, 1, 0, tzinfo=timezone.utc),
            )
            db.add_all([old_run, new_run])
            db.commit()
            db.refresh(old_run); db.refresh(new_run)
            tid = target.id
            uid = user.id
            old_id = old_run.id
            new_id = new_run.id
        finally:
            db.close()

        # ── Call /diff endpoint ───────────────────────────────────────────────
        with http.session_transaction() as sess:
            sess["user_id"] = uid

        resp = http.get(f"/api/targets/{tid}/diff?old_scan_id={old_id}&new_scan_id={new_id}")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.get_json()}"
        diff = resp.get_json()

        # ── Verify counts ─────────────────────────────────────────────────────
        summary = diff["summary"]
        assert summary["new_count"]        == 1, f"new_count: {summary}"
        assert summary["resolved_count"]   == 1, f"resolved_count: {summary}"
        assert summary["persistent_count"] == 1, f"persistent_count: {summary}"
        assert summary["escalated_count"]  == 1, f"escalated_count: {summary}"
        assert summary["old_scan_id"]      == old_sid
        assert summary["new_scan_id"]      == new_sid

        # ── Verify category membership ────────────────────────────────────────
        new_titles        = {f["title"] for f in diff["new_findings"]}
        resolved_titles   = {f["title"] for f in diff["resolved_findings"]}
        persistent_titles = {f["title"] for f in diff["persistent_findings"]}
        escalated_titles  = {e["finding"]["title"] for e in diff["escalated_findings"]}

        assert "Missing X-Frame-Options" in new_titles,        f"D missing from new: {new_titles}"
        assert "SPF Record Missing"       in resolved_titles,  f"C missing from resolved: {resolved_titles}"
        assert "Open Port 22/tcp"         in persistent_titles,f"A missing from persistent: {persistent_titles}"
        assert "Open Port 80/tcp"         in escalated_titles, f"B missing from escalated: {escalated_titles}"

        # B must NOT appear in persistent
        assert "Open Port 80/tcp" not in persistent_titles, "Escalated finding B leaked into persistent"

        # ── Verify escalated severity values ──────────────────────────────────
        esc_b = diff["escalated_findings"][0]
        assert esc_b["old_severity"] == 4, f"Expected old_severity=4 (HIGH), got {esc_b['old_severity']}"
        assert esc_b["new_severity"] == 5, f"Expected new_severity=5 (CRITICAL), got {esc_b['new_severity']}"

        print("OK  g. integration: /diff returns correct counts and category membership for all 4 categories")

        # ── Also test /latest-diff ────────────────────────────────────────────
        resp2 = http.get(f"/api/targets/{tid}/latest-diff")
        assert resp2.status_code == 200, resp2.get_json()
        diff2 = resp2.get_json()
        # latest-diff should produce the same result (only 2 completed scans exist)
        assert diff2["summary"]["new_count"]        == 1
        assert diff2["summary"]["resolved_count"]   == 1
        assert diff2["summary"]["persistent_count"] == 1
        assert diff2["summary"]["escalated_count"]  == 1
        print("OK  g. /latest-diff automatically selects the two most recent completed scans")

    finally:
        app_module.SessionLocal = orig_sl
        engine.dispose()


def test_latest_diff_insufficient_scans():
    """latest-diff with fewer than 2 completed scans returns an informative message, not an error."""
    http, Session, engine, app_module, orig_sl = _make_app_with_db()
    try:
        db = Session()
        try:
            user = User(google_id="gu2", email="u2@e.com", name="U2", role="customer")
            db.add(user); db.flush()
            client = Client(name="C2", contact_email="u2@e.com", user_id=user.id)
            db.add(client); db.flush()
            target = Target(
                client_id=client.id, scope="t2.com",
                authorized_by="ref2", verified=True, verification_token="tok2",
            )
            db.add(target); db.flush()
            # Only one completed scan
            run = ScanRun(
                target_id=target.id, scan_id=str(uuid.uuid4()), status="completed",
                result_json=json.dumps(_make_result([])),
            )
            db.add(run); db.commit()
            tid = target.id; uid = user.id; cid = client.id
        finally:
            db.close()

        with http.session_transaction() as sess:
            sess["user_id"] = uid

        resp = http.get(f"/api/targets/{tid}/latest-diff")
        assert resp.status_code == 200
        body = resp.get_json()
        assert "message" in body, f"Expected 'message' key, got {body}"
        assert "1" in body["message"], f"Count not in message: {body['message']}"
        print("OK  g. /latest-diff with 1 completed scan returns informative message")

        # Zero scans case
        db = Session()
        try:
            target2 = Target(
                client_id=cid, scope="t3.com",
                authorized_by="ref3", verified=True, verification_token="tok3",
            )
            db.add(target2); db.commit(); db.refresh(target2)
            tid2 = target2.id
        finally:
            db.close()

        resp3 = http.get(f"/api/targets/{tid2}/latest-diff")
        assert resp3.status_code == 200
        body3 = resp3.get_json()
        assert "message" in body3
        assert "0" in body3["message"]
        print("OK  g. /latest-diff with 0 completed scans returns informative message")

    finally:
        app_module.SessionLocal = orig_sl
        engine.dispose()


def test_diff_endpoint_not_completed():
    """diff endpoint returns 400 when either scan is not yet completed."""
    http, Session, engine, app_module, orig_sl = _make_app_with_db()
    try:
        db = Session()
        try:
            user = User(google_id="gu3", email="u3@e.com", name="U3", role="customer")
            db.add(user); db.flush()
            client = Client(name="C3", contact_email="u3@e.com", user_id=user.id)
            db.add(client); db.flush()
            target = Target(
                client_id=client.id, scope="t4.com",
                authorized_by="ref4", verified=True, verification_token="tok4",
            )
            db.add(target); db.flush()

            completed = ScanRun(target_id=target.id, scan_id=str(uuid.uuid4()),
                                status="completed", result_json=json.dumps(_make_result([])))
            pending   = ScanRun(target_id=target.id, scan_id=str(uuid.uuid4()),
                                status="running")
            db.add_all([completed, pending]); db.commit()
            db.refresh(completed); db.refresh(pending)
            tid = target.id; uid = user.id
            cid = completed.id; pid = pending.id
        finally:
            db.close()

        with http.session_transaction() as sess:
            sess["user_id"] = uid

        resp = http.get(f"/api/targets/{tid}/diff?old_scan_id={cid}&new_scan_id={pid}")
        assert resp.status_code == 400
        assert "completed" in resp.get_json()["error"].lower()
        print("OK  g. /diff with non-completed scan returns 400")

    finally:
        app_module.SessionLocal = orig_sl
        engine.dispose()


def test_diff_endpoint_wrong_target():
    """diff endpoint returns 400 if a scan_run belongs to a different target."""
    http, Session, engine, app_module, orig_sl = _make_app_with_db()
    try:
        db = Session()
        try:
            user = User(google_id="gu4", email="u4@e.com", name="U4", role="customer")
            db.add(user); db.flush()
            client = Client(name="C4", contact_email="u4@e.com", user_id=user.id)
            db.add(client); db.flush()
            t1 = Target(client_id=client.id, scope="t5.com", authorized_by="r",
                        verified=True, verification_token="tk5")
            t2 = Target(client_id=client.id, scope="t6.com", authorized_by="r",
                        verified=True, verification_token="tk6")
            db.add_all([t1, t2]); db.flush()

            r1 = ScanRun(target_id=t1.id, scan_id=str(uuid.uuid4()),
                         status="completed", result_json=json.dumps(_make_result([])))
            r2 = ScanRun(target_id=t2.id, scan_id=str(uuid.uuid4()),
                         status="completed", result_json=json.dumps(_make_result([])))
            db.add_all([r1, r2]); db.commit()
            db.refresh(r1); db.refresh(r2)
            uid = user.id; tid1 = t1.id; r1id = r1.id; r2id = r2.id
        finally:
            db.close()

        with http.session_transaction() as sess:
            sess["user_id"] = uid

        # r2 belongs to t2, not t1 — should 400
        resp = http.get(f"/api/targets/{tid1}/diff?old_scan_id={r1id}&new_scan_id={r2id}")
        assert resp.status_code == 400
        assert "does not belong" in resp.get_json()["error"]
        print("OK  g. /diff with mismatched target returns 400")

    finally:
        app_module.SessionLocal = orig_sl
        engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_fingerprint_ignores_ephemeral_fields()
    test_fingerprint_differs_on_title()
    test_clean_baseline_all_new()
    test_empty_new_all_resolved()
    test_persistent_same_severity()
    test_persistent_deescalated()
    test_escalated_finding()
    test_resolved_finding()
    test_diff_endpoint_all_four_categories()
    test_latest_diff_insufficient_scans()
    test_diff_endpoint_not_completed()
    test_diff_endpoint_wrong_target()
    print("\nAll diff tests passed.")
