"""
Live end-to-end scheduler integration test.

Creates a verified localhost target in the real DB, PATCHes its schedule to
fire at the next minute boundary via the Flask test client, then waits for
the APScheduler to fire the job automatically and shows the resulting ScanRun.

Run from the project root:
    .venv/Scripts/python.exe secscan/tests/live_scheduler_test.py
"""
import os
import sys
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv
_env = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
)
load_dotenv(_env, encoding="utf-16")

# ── Compute cron (fires ~2 minutes from now) ──────────────────────────────────
now = datetime.now()
nxt = now + timedelta(minutes=2)
CRON = f"{nxt.minute} {nxt.hour} {nxt.day} {nxt.month} *"
print(f"Current time : {now.strftime('%H:%M:%S')}")
print(f"Scheduler fires at : {nxt.strftime('%H:%M')}  (cron: '{CRON}')")
print()

# ── Seed test data in the real DB ─────────────────────────────────────────────
# Import app AFTER dotenv is loaded; this also starts APScheduler (app.debug=False)
from db.database import SessionLocal, init_db
from db.orm_models import Client, ScanRun, Target
from db.user_model import User
import scheduler as sched_module

init_db()

db = SessionLocal()
try:
    user = db.query(User).first()
    if user is None:
        user = User(google_id="g_live_test", email="livetest@example.com",
                    name="Live Test", role="customer")
        db.add(user)
        db.flush()

    client = db.query(Client).filter_by(user_id=user.id).first()
    if client is None:
        client = Client(name="Live Test Co", contact_email=user.email, user_id=user.id)
        db.add(client)
        db.flush()

    # skip_cve=True so the scan completes faster
    target = Target(
        client_id=client.id,
        scope="localhost",
        authorized_by="live-scheduler-test-ref",
        verified=True,
        verification_token="live-sched-test-token",
        skip_cve=True,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    TARGET_ID = target.id
    USER_ID = user.id
    print(f"Seeded: user_id={USER_ID}  target_id={TARGET_ID}  scope='localhost'")
finally:
    db.close()

# ── PATCH the schedule via Flask test client ──────────────────────────────────
from web.app import app as flask_app

flask_app.config["TESTING"] = True
with flask_app.test_client() as http:
    with http.session_transaction() as sess:
        sess["user_id"] = USER_ID
    resp = http.patch(
        f"/api/targets/{TARGET_ID}/schedule",
        json={"schedule_cron": CRON},
        content_type="application/json",
    )

print(f"\nPATCH /api/targets/{TARGET_ID}/schedule  ->  {resp.status_code}")
body = resp.get_json()
print(f"Response schedule_cron: {body.get('schedule_cron')!r}")
assert resp.status_code == 200, f"PATCH failed: {body}"

# ── Show scheduler job registration ──────────────────────────────────────────
print(f"\nScheduler running: {sched_module.scheduler.running}")
print("Registered jobs:")
for j in sched_module.scheduler.get_jobs():
    print(f"  {j.id:30s}  next={j.next_run_time}")

# ── Wait for the cron to fire ─────────────────────────────────────────────────
print(f"\nWaiting for automatic scan at {nxt.strftime('%H:%M')} ...\n")
scan_appeared_at: str | None = None
deadline = time.monotonic() + 200  # 3-min+ ceiling

while time.monotonic() < deadline:
    db = SessionLocal()
    try:
        runs = db.query(ScanRun).filter_by(target_id=TARGET_ID).all()
    finally:
        db.close()

    if runs and scan_appeared_at is None:
        scan_appeared_at = datetime.now().strftime("%H:%M:%S")
        print(f"\n[{scan_appeared_at}] ScanRun appeared in DB automatically!")

    if runs and any(r.status in ("completed", "failed") for r in runs):
        break

    remaining = int(deadline - time.monotonic())
    ts = datetime.now().strftime("%H:%M:%S")
    status = runs[0].status if runs else "not yet created"
    print(f"  [{ts}]  status={status}  waiting... ({remaining}s remaining)", flush=True)
    time.sleep(10)

print()

# ── Final report ──────────────────────────────────────────────────────────────
db = SessionLocal()
try:
    runs = db.query(ScanRun).filter_by(target_id=TARGET_ID).order_by(ScanRun.id).all()
finally:
    db.close()

print("=" * 60)
if not runs:
    print("FAIL: No ScanRun was created. The scheduler did not fire.")
else:
    for run in runs:
        print(f"ScanRun #{run.id}")
        print(f"  status      : {run.status}")
        print(f"  started_at  : {run.started_at}")
        print(f"  completed_at: {run.completed_at}")
        if run.error_message:
            print(f"  error       : {run.error_message}")
    print()
    if any(r.status == "completed" for r in runs):
        print("PASS: Scheduled scan completed automatically without any manual trigger.")
    elif any(r.status in ("running", "pending") for r in runs):
        print("PASS (in progress): Scheduler fired, scan is still running.")
    elif any(r.status == "failed" for r in runs):
        print("PASS (scheduler fired): Scan attempted on localhost — failure is expected")
        print("  if no services are listening. The key result is the ScanRun was created")
        print("  automatically by APScheduler at the scheduled cron time.")
print("=" * 60)

# ── Cleanup ───────────────────────────────────────────────────────────────────
db = SessionLocal()
try:
    for run in db.query(ScanRun).filter_by(target_id=TARGET_ID).all():
        db.delete(run)
    db.query(Target).filter_by(id=TARGET_ID).delete()
    db.commit()
    print(f"\nCleaned up test target #{TARGET_ID} and its scan runs.")
finally:
    db.close()

if sched_module.scheduler.running:
    sched_module.scheduler.shutdown(wait=False)
