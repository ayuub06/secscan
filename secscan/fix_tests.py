"""
Targeted tests for the 4 specific bug fixes.
"""
import json, sys, os, time, threading, logging
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
_env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
load_dotenv(dotenv_path=_env_path, encoding="utf-16")

logging.basicConfig(level=logging.WARNING)  # suppress scheduler noise in output

from web.app import app
from db.database import SessionLocal, init_db
from db.orm_models import Client, Target, ScanRun
from db.user_model import User
from checks.dns_check import run as dns_run
from core.scan_runner import execute_scan

init_db()

RESULTS = []

def ok(name, evidence=""):
    RESULTS.append(("PASS", name, evidence))
    print(f"  \033[92mPASS\033[0m {name}")
    if evidence:
        print(f"       {evidence[:250]}")

def fail(name, evidence=""):
    RESULTS.append(("FAIL", name, evidence))
    print(f"  \033[91mFAIL\033[0m {name}")
    if evidence:
        print(f"       {evidence[:250]}")

# ─────────────────────────────────────────────────────────────────────────────
# FIX 1 — Client isolation
# ─────────────────────────────────────────────────────────────────────────────
print("\n=== FIX 1: Client list isolation + @login_required ===")

db = SessionLocal()
try:
    u1 = db.get(User, 1)
    u2 = db.get(User, 2)
    # Ensure user1 has at least one client, user2 has at least one client
    c1 = db.query(Client).filter_by(user_id=1).first()
    c2 = db.query(Client).filter_by(user_id=2).first()
    c1_id = c1.id if c1 else None
    c2_id = c2.id if c2 else None
finally:
    db.close()

with app.test_client() as c:
    # 1a: Unauthenticated → 401
    r = c.get("/api/clients")
    b = r.get_json()
    if r.status_code == 401:
        ok("Unauthenticated GET /api/clients → 401", f"body={b}")
    else:
        fail("Unauthenticated GET /api/clients → 401", f"got status={r.status_code} body={b}")

    # 1b: User 2 sees only their own clients
    with c.session_transaction() as sess:
        sess["user_id"] = 2
    r = c.get("/api/clients")
    clients = r.get_json()
    if r.status_code == 200 and isinstance(clients, list):
        user_ids_seen = {cl["user_id"] for cl in clients}
        if user_ids_seen <= {2} and 1 not in user_ids_seen:
            ok("User 2 sees only their own clients",
               f"returned {len(clients)} client(s), user_ids={sorted(user_ids_seen)}")
        else:
            fail("User 2 sees only their own clients",
                 f"returned user_ids={sorted(user_ids_seen)} (admin's clients leaked)")
    else:
        fail("User 2 GET /api/clients returned non-200", f"status={r.status_code} body={clients}")

    # 1c: User 1 (admin) sees only their own clients (not user 2's)
    with c.session_transaction() as sess:
        sess["user_id"] = 1
    r = c.get("/api/clients")
    clients = r.get_json()
    if r.status_code == 200 and isinstance(clients, list):
        user_ids_seen = {cl["user_id"] for cl in clients}
        if user_ids_seen <= {1} and 2 not in user_ids_seen:
            ok("User 1 sees only their own clients",
               f"returned {len(clients)} client(s), user_ids={sorted(user_ids_seen)}")
        else:
            fail("User 1 sees only their own clients",
                 f"returned user_ids={sorted(user_ids_seen)} (user2's client leaked)")
    else:
        fail("User 1 GET /api/clients returned non-200", f"status={r.status_code}")

# ─────────────────────────────────────────────────────────────────────────────
# FIX 2 — Scheduler DB corruption
# ─────────────────────────────────────────────────────────────────────────────
print("\n=== FIX 2: Scheduler DB corruption ===")

db = SessionLocal()
try:
    bad = db.query(Target).filter(Target.schedule_cron == '').count()
    if bad == 0:
        ok("No empty-string schedule_cron rows remain in DB", f"remaining={bad}")
    else:
        fail("Empty-string schedule_cron rows still exist", f"count={bad}")

    # Test that create_target with schedule_cron="" stores NULL not ""
    # (test via direct Target creation without API to isolate the normalization)
finally:
    db.close()

with app.test_client() as c:
    with c.session_transaction() as sess:
        sess["user_id"] = 1
    r = c.post("/api/targets", json={
        "client_id": 1,
        "scope": "cron-empty-test.example.com",
        "authorized_by": "Audit",
        "schedule_cron": "",   # empty string — must become NULL
    })
    b = r.get_json()
    target_id = b.get("id")
    if r.status_code == 201 and b.get("schedule_cron") is None:
        ok("POST /api/targets with schedule_cron='' stores NULL", f"schedule_cron={b.get('schedule_cron')!r}")
    else:
        fail("POST /api/targets with schedule_cron='' stored non-null", f"status={r.status_code} schedule_cron={b.get('schedule_cron')!r}")

    # Clean up
    if target_id:
        db = SessionLocal()
        try:
            t = db.get(Target, target_id)
            if t: db.delete(t); db.commit()
        finally:
            db.close()

# Verify scheduler sync doesn't throw ValueError anymore
print("  Checking scheduler sync with fixed data...")
from scheduler import sync_schedules, scheduler
import io, logging as _logging

log_capture = io.StringIO()
handler = _logging.StreamHandler(log_capture)
handler.setLevel(_logging.ERROR)
_logging.getLogger("scheduler").addHandler(handler)

sync_schedules()

_logging.getLogger("scheduler").removeHandler(handler)
captured = log_capture.getvalue()
if "ValueError" not in captured and "Wrong number of fields" not in captured:
    ok("sync_schedules() runs without ValueError after DB fix", "no errors in scheduler log")
else:
    fail("sync_schedules() still emits errors", captured[:200])

# ─────────────────────────────────────────────────────────────────────────────
# FIX 3 — DNS check: unresolvable domain
# ─────────────────────────────────────────────────────────────────────────────
print("\n=== FIX 3: DNS check for unresolvable domain ===")

INVALID_DOMAIN = "this-domain-definitely-does-not-exist-xyz123abc.invalid"
findings = dns_run([INVALID_DOMAIN], scan_id="fix3-test")
titles = [f.title for f in findings]
severities = [f.severity.name for f in findings]

if len(findings) == 1 and findings[0].title == "Domain does not resolve":
    ok("Unresolvable domain → exactly 1 'Domain does not resolve' finding",
       f"title={findings[0].title!r} severity={findings[0].severity.name} evidence={findings[0].evidence!r}")
else:
    fail("Unresolvable domain → wrong findings",
         f"count={len(findings)} titles={titles} severities={severities}")

# Confirm it's INFO severity, not MEDIUM
if findings and findings[0].severity.name == "INFO":
    ok("Finding severity is INFO (not MEDIUM/HIGH)", f"severity={findings[0].severity.name}")
else:
    fail("Finding severity is not INFO", f"severities={severities}")

# Confirm a real domain still runs normally
REAL_DOMAIN = "gestion-examens-frontend.vercel.app"
real_findings = dns_run([REAL_DOMAIN], scan_id="fix3-real-test")
real_titles = [f.title for f in real_findings]
domain_not_resolve_in_real = any(f.title == "Domain does not resolve" for f in real_findings)
if not domain_not_resolve_in_real and len(real_findings) > 0:
    ok("Real domain still runs normal SPF/DMARC/DKIM sub-checks",
       f"findings={real_titles}")
else:
    fail("Real domain produced unexpected results",
         f"count={len(real_findings)} titles={real_titles}")

# ─────────────────────────────────────────────────────────────────────────────
# FIX 4 — StaleDataError on delete-during-scan
# ─────────────────────────────────────────────────────────────────────────────
print("\n=== FIX 4: StaleDataError race condition ===")

# Create a fresh target, trigger a scan, then immediately delete the client
db = SessionLocal()
try:
    rc_client = Client(name="RaceCondTest", contact_email="rc@test.com", user_id=1)
    db.add(rc_client)
    db.commit()
    db.refresh(rc_client)
    rc_client_id = rc_client.id

    rc_target = Target(
        client_id=rc_client_id,
        scope="race-condition-test.example.com",
        authorized_by="Audit Script",
        verified=True,
        verification_method="manual_admin",
    )
    db.add(rc_target)
    db.commit()
    db.refresh(rc_target)
    rc_target_id = rc_target.id

    import uuid as _uuid
    rc_run = ScanRun(
        target_id=rc_target_id,
        scan_id=str(_uuid.uuid4()),
        status="pending",
    )
    db.add(rc_run)
    db.commit()
    db.refresh(rc_run)
    rc_run_id = rc_run.id
finally:
    db.close()

# Capture WARNING log from scan_runner
import io as _io
log_capture2 = _io.StringIO()
handler2 = _logging.StreamHandler(log_capture2)
handler2.setLevel(_logging.WARNING)
_logging.getLogger("core.scan_runner").addHandler(handler2)

# Start the scan in a thread
scan_thread = threading.Thread(target=execute_scan, args=(rc_run_id,), daemon=True)
scan_thread.start()

# Wait a tiny bit then delete the client (cascade-deletes target + scan_runs)
time.sleep(0.3)
db = SessionLocal()
try:
    rc_cl = db.get(Client, rc_client_id)
    if rc_cl:
        db.delete(rc_cl)
        db.commit()
        print(f"  Deleted client {rc_client_id} (cascade → target {rc_target_id} + scan_run {rc_run_id})")
finally:
    db.close()

# Wait for the thread to finish
scan_thread.join(timeout=30)

_logging.getLogger("core.scan_runner").removeHandler(handler2)
captured2 = log_capture2.getvalue()

# Check for clean warning, not StaleDataError exception
stale_error_logged = "StaleDataError" in captured2
warned_cleanly = "target was deleted" in captured2.lower() or "deleted" in captured2.lower()
no_unhandled_exception = "Traceback" not in captured2

print(f"  Captured scan_runner log:\n    {captured2.strip()[:400]}")

if not stale_error_logged and warned_cleanly and no_unhandled_exception:
    ok("Delete-during-scan: clean warning logged, no StaleDataError propagated",
       f"warned_cleanly={warned_cleanly} stale_error_logged={stale_error_logged}")
elif not stale_error_logged and no_unhandled_exception:
    # Scan may have started before the delete hit — either path is acceptable
    ok("Delete-during-scan: no StaleDataError exception propagated",
       f"scan_thread_alive={scan_thread.is_alive()} log={captured2.strip()[:200]}")
else:
    fail("Delete-during-scan: StaleDataError still propagated or thread crashed",
         f"log={captured2.strip()[:400]}")

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("FIX VERIFICATION SUMMARY")
print("="*60)
for status, name, _ in RESULTS:
    tag = "\033[92mPASS\033[0m" if status == "PASS" else "\033[91mFAIL\033[0m"
    print(f"  {tag}  {name}")
passes = sum(1 for s, _, _ in RESULTS if s == "PASS")
fails  = sum(1 for s, _, _ in RESULTS if s == "FAIL")
print(f"\n  {passes} PASS  {fails} FAIL")
print("="*60)
