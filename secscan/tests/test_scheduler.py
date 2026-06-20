"""
Tests for scheduler.py and the PATCH /api/targets/<id>/schedule endpoint.

Strategy:
  - In-memory SQLite DB; Flask test client with patched SessionLocal.
  - execute_scan is monkey-patched to a no-op so we don't hit the network.
  - APScheduler is used for real (BackgroundScheduler) so sync_schedules()
    and job creation/removal are tested against the live scheduler.
"""
import sys
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db.orm_models import Base, Client, ScanRun, Target
from db.user_model import User


# ── Test helpers ──────────────────────────────────────────────────────────────

def _make_app(db_url: str = "sqlite:///:memory:"):
    import web.app as app_module
    import scheduler as sched_module

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    original_app_sl = app_module.SessionLocal
    original_sched_sl = sched_module.SessionLocal
    app_module.SessionLocal = Session
    sched_module.SessionLocal = Session

    app = app_module.app
    app.config["TESTING"] = True
    app.secret_key = "test-secret"

    return app.test_client(), Session, engine, app_module, sched_module, (
        original_app_sl, original_sched_sl
    )


def _restore(app_module, sched_module, originals):
    app_module.SessionLocal = originals[0]
    sched_module.SessionLocal = originals[1]


def _seed(Session):
    db = Session()
    try:
        user = User(google_id="g_u1", email="user@example.com", name="User", role="customer")
        db.add(user)
        db.flush()
        client = Client(name="MyCo", contact_email="user@example.com", user_id=user.id)
        db.add(client)
        db.flush()
        target = Target(
            client_id=client.id,
            scope="example.com",
            authorized_by="user@example.com",
            verified=True,
            verification_token="tok",
        )
        db.add(target)
        db.commit()
        db.refresh(user)
        db.refresh(target)
        return user.id, target.id
    finally:
        db.close()


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_patch_schedule_valid_cron():
    client, Session, engine, app_module, sched_module, originals = _make_app()
    user_id, target_id = _seed(Session)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = user_id

        r = client.patch(
            f"/api/targets/{target_id}/schedule",
            json={"schedule_cron": "0 3 * * *"},
            content_type="application/json",
        )
        assert r.status_code == 200, r.get_json()
        body = r.get_json()
        assert body["schedule_cron"] == "0 3 * * *"
        print("OK  PATCH with valid cron -> 200, schedule_cron set")
    finally:
        _restore(app_module, sched_module, originals)
        engine.dispose()


def test_patch_schedule_invalid_cron():
    client, Session, engine, app_module, sched_module, originals = _make_app()
    user_id, target_id = _seed(Session)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = user_id

        r = client.patch(
            f"/api/targets/{target_id}/schedule",
            json={"schedule_cron": "not a cron"},
            content_type="application/json",
        )
        assert r.status_code == 400
        assert "Invalid cron expression" in r.get_json()["error"]
        print("OK  PATCH with invalid cron -> 400 before DB write")
    finally:
        _restore(app_module, sched_module, originals)
        engine.dispose()


def test_patch_schedule_clear():
    client, Session, engine, app_module, sched_module, originals = _make_app()
    user_id, target_id = _seed(Session)
    try:
        with client.session_transaction() as sess:
            sess["user_id"] = user_id

        # Set then clear
        client.patch(
            f"/api/targets/{target_id}/schedule",
            json={"schedule_cron": "0 4 * * *"},
            content_type="application/json",
        )
        r = client.patch(
            f"/api/targets/{target_id}/schedule",
            json={"schedule_cron": None},
            content_type="application/json",
        )
        assert r.status_code == 200
        assert r.get_json()["schedule_cron"] is None
        print("OK  PATCH with null schedule_cron -> clears the schedule")
    finally:
        _restore(app_module, sched_module, originals)
        engine.dispose()


def test_patch_schedule_forbidden():
    client, Session, engine, app_module, sched_module, originals = _make_app()
    user_id, target_id = _seed(Session)

    db = Session()
    try:
        other = User(google_id="g_other", email="other@example.com", name="Other", role="customer")
        db.add(other)
        db.commit()
        other_id = other.id
    finally:
        db.close()

    try:
        with client.session_transaction() as sess:
            sess["user_id"] = other_id

        r = client.patch(
            f"/api/targets/{target_id}/schedule",
            json={"schedule_cron": "0 1 * * *"},
            content_type="application/json",
        )
        assert r.status_code == 403
        print("OK  PATCH from non-owner -> 403")
    finally:
        _restore(app_module, sched_module, originals)
        engine.dispose()


def test_sync_schedules_creates_and_removes_jobs():
    import scheduler as sched_module
    from apscheduler.schedulers.background import BackgroundScheduler

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    original_sl = sched_module.SessionLocal
    sched_module.SessionLocal = Session

    # Use a fresh BackgroundScheduler for this test so jobs don't leak between tests.
    original_sched = sched_module.scheduler
    test_scheduler = BackgroundScheduler()
    test_scheduler.start()
    sched_module.scheduler = test_scheduler

    try:
        db = Session()
        try:
            u = User(google_id="gu", email="u@e.com", name="U", role="customer")
            db.add(u)
            db.flush()
            c = Client(name="C", contact_email="u@e.com", user_id=u.id)
            db.add(c)
            db.flush()
            t = Target(client_id=c.id, scope="s.com", authorized_by="u@e.com",
                       verified=True, verification_token="t1",
                       schedule_cron="30 6 * * *")
            db.add(t)
            db.commit()
            db.refresh(t)
            target_id = t.id
        finally:
            db.close()

        sched_module.sync_schedules()
        job_ids = [j.id for j in test_scheduler.get_jobs()]
        assert f"target-{target_id}" in job_ids, f"Job not found; got {job_ids}"
        print(f"OK  sync_schedules() created job target-{target_id}")

        # Clear the schedule and re-sync -> job should be removed
        db = Session()
        try:
            t = db.get(Target, target_id)
            t.schedule_cron = None
            db.commit()
        finally:
            db.close()

        sched_module.sync_schedules()
        job_ids = [j.id for j in test_scheduler.get_jobs()]
        assert f"target-{target_id}" not in job_ids, f"Stale job still present: {job_ids}"
        print("OK  sync_schedules() removed stale job after schedule cleared")

    finally:
        test_scheduler.shutdown(wait=False)
        sched_module.scheduler = original_sched
        sched_module.SessionLocal = original_sl
        engine.dispose()


def test_run_scheduled_scan_skips_unverified():
    import scheduler as sched_module

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    original_sl = sched_module.SessionLocal
    sched_module.SessionLocal = Session

    db = Session()
    try:
        u = User(google_id="gu2", email="u2@e.com", name="U2", role="customer")
        db.add(u)
        db.flush()
        c = Client(name="C2", contact_email="u2@e.com", user_id=u.id)
        db.add(c)
        db.flush()
        t = Target(client_id=c.id, scope="unverified.com", authorized_by="u2@e.com",
                   verified=False, verification_token="t2")
        db.add(t)
        db.commit()
        db.refresh(t)
        target_id = t.id
    finally:
        db.close()

    try:
        executed = []
        with patch("scheduler.execute_scan", side_effect=lambda rid: executed.append(rid)):
            sched_module.run_scheduled_scan(target_id)

        assert executed == [], f"execute_scan should not have been called; got {executed}"
        scan_count = Session().query(ScanRun).count()
        assert scan_count == 0, f"No ScanRun should exist; got {scan_count}"
        print("OK  run_scheduled_scan skips unverified target without error")
    finally:
        sched_module.SessionLocal = original_sl
        engine.dispose()


def test_run_scheduled_scan_fires_for_verified():
    import scheduler as sched_module

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    original_sl = sched_module.SessionLocal
    sched_module.SessionLocal = Session

    db = Session()
    try:
        u = User(google_id="gu3", email="u3@e.com", name="U3", role="customer")
        db.add(u)
        db.flush()
        c = Client(name="C3", contact_email="u3@e.com", user_id=u.id)
        db.add(c)
        db.flush()
        t = Target(client_id=c.id, scope="verified.com", authorized_by="u3@e.com",
                   verified=True, verification_token="t3",
                   schedule_cron="0 1 * * *")
        db.add(t)
        db.commit()
        db.refresh(t)
        target_id = t.id
    finally:
        db.close()

    try:
        executed = []
        with patch("scheduler.execute_scan", side_effect=lambda rid: executed.append(rid)):
            sched_module.run_scheduled_scan(target_id)

        assert len(executed) == 1, f"execute_scan should have been called once; got {executed}"
        db = Session()
        try:
            runs = db.query(ScanRun).all()
            assert len(runs) == 1
            assert runs[0].status == "pending"
            assert runs[0].target_id == target_id
        finally:
            db.close()
        print("OK  run_scheduled_scan creates ScanRun and calls execute_scan for verified target")
    finally:
        sched_module.SessionLocal = original_sl
        engine.dispose()


def test_scheduler_fires_job_automatically():
    """
    Integration test: start the real scheduler with a very short interval trigger
    (IntervalTrigger, seconds=3) on run_scheduled_scan, confirm a ScanRun appears
    within 10 seconds without any manual call.

    Uses StaticPool so APScheduler's background threads share the same in-memory
    SQLite connection (sqlite:///:memory: normally gives each thread its own empty DB).
    """
    import scheduler as sched_module
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    original_sl = sched_module.SessionLocal
    sched_module.SessionLocal = Session

    original_sched = sched_module.scheduler
    test_scheduler = BackgroundScheduler()
    test_scheduler.start()
    sched_module.scheduler = test_scheduler

    db = Session()
    try:
        u = User(google_id="gu4", email="u4@e.com", name="U4", role="customer")
        db.add(u)
        db.flush()
        c = Client(name="C4", contact_email="u4@e.com", user_id=u.id)
        db.add(c)
        db.flush()
        t = Target(client_id=c.id, scope="auto.com", authorized_by="u4@e.com",
                   verified=True, verification_token="t4",
                   schedule_cron="* * * * *")
        db.add(t)
        db.commit()
        db.refresh(t)
        target_id = t.id
    finally:
        db.close()

    try:
        with patch("scheduler.execute_scan") as mock_exec:
            # Fire every 3 seconds (interval trigger, not cron — so we don't wait a full minute)
            test_scheduler.add_job(
                sched_module.run_scheduled_scan,
                trigger=IntervalTrigger(seconds=3),
                id="test-fire",
                args=[target_id],
            )

            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if mock_exec.called:
                    break
                time.sleep(0.25)

            assert mock_exec.called, "execute_scan was never called by the scheduler within 10s"
            called_run_id = mock_exec.call_args[0][0]

            db = Session()
            try:
                run = db.get(ScanRun, called_run_id)
                assert run is not None
                assert run.target_id == target_id
                assert run.status == "pending"
            finally:
                db.close()

        print("OK  Scheduler fires run_scheduled_scan automatically, ScanRun created in DB")
    finally:
        test_scheduler.shutdown(wait=False)
        sched_module.scheduler = original_sched
        sched_module.SessionLocal = original_sl
        engine.dispose()


if __name__ == "__main__":
    test_patch_schedule_valid_cron()
    test_patch_schedule_invalid_cron()
    test_patch_schedule_clear()
    test_patch_schedule_forbidden()
    test_sync_schedules_creates_and_removes_jobs()
    test_run_scheduled_scan_skips_unverified()
    test_run_scheduled_scan_fires_for_verified()
    test_scheduler_fires_job_automatically()
    print("\nAll scheduler tests passed.")
