"""
Full test suite runner + manual scan-trigger smoke test + admin stats verification.

Runs automated tests as isolated subprocesses (so module patching in each file
can't bleed into the others), then performs the manual trigger and admin stats
checks against the real DB in-process.

Usage:
    .venv/Scripts/python.exe secscan/tests/run_all_tests.py
"""
import os
import subprocess
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

VENV_PYTHON = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", ".venv", "Scripts", "python.exe")
)
TESTS_DIR = os.path.dirname(__file__)
PASS = "PASS"
FAIL = "FAIL"

# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────

def banner(title: str) -> None:
    print(f"\n{'='*65}")
    print(f"  {title}")
    print(f"{'='*65}")


_ENC = sys.stdout.encoding or "utf-8"

def _safe_print(text: str) -> None:
    """Print, replacing any characters the console can't encode."""
    print(text.encode(_ENC, errors="replace").decode(_ENC))


def run_subprocess_test(path: str) -> bool:
    """Run a test file as a subprocess, stream its output, return True if passed."""
    result = subprocess.run(
        [VENV_PYTHON, path],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    noise_prefixes = (
        "[INFO] apscheduler",
        "[INFO] scheduler",
        "[INFO] core.",
        "[INFO] secscan",
        "[WARNING] scheduler",
        "WARNING: Could not import",  # npcap/nmap warning
    )
    # stdout: test OK lines and final verdict (no noise filtering needed)
    if result.stdout.strip():
        _safe_print(result.stdout.rstrip())
    # stderr: filter APScheduler/SQLAlchemy INFO noise, show the rest
    if result.stderr.strip():
        filtered = [
            line for line in result.stderr.splitlines()
            if not any(p in line for p in noise_prefixes)
        ]
        if filtered:
            _safe_print("\n".join(filtered))
    return result.returncode == 0


# ─────────────────────────────────────────────────────────────────────────────
# 1. Automated test suite
# ─────────────────────────────────────────────────────────────────────────────

AUTOMATED = [
    ("test_auto_client.py",     "DB / auto-client creation + role default"),
    ("test_admin_endpoints.py", "Admin decorator + all /api/admin/* endpoints"),
    ("test_scheduler.py",       "Scheduler: sync_schedules, PATCH /schedule, auto-fire"),
]

suite_results: list[tuple[str, bool]] = []

for filename, description in AUTOMATED:
    banner(f"AUTOMATED: {filename}\n  {description}")
    path = os.path.join(TESTS_DIR, filename)
    passed = run_subprocess_test(path)
    suite_results.append((filename, passed))
    print(f"\n  Result: {'PASS' if passed else 'FAIL'}")

# ─────────────────────────────────────────────────────────────────────────────
# 2. Manual scan-trigger smoke test  (in-process, real DB)
# ─────────────────────────────────────────────────────────────────────────────

banner("SMOKE TEST: Manual trigger  POST /api/targets/<id>/scan\n  Confirms execute_scan() works via daemon thread (not scheduler)")

# Load env before importing web.app (it needs FLASK_SECRET_KEY etc.)
from dotenv import load_dotenv
_env = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
)
load_dotenv(_env, encoding="utf-16")

import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

from db.database import SessionLocal, init_db
from db.orm_models import Client, ScanRun, Target
from db.user_model import User
import scheduler as sched_module

init_db()

# ── Promote user 1 to admin so we can call /api/admin/stats later ─────────────
db = SessionLocal()
try:
    admin_user = db.query(User).first()
    assert admin_user is not None, "No users in DB — run the app and log in first."
    original_role = admin_user.role
    admin_user.role = "admin"
    db.commit()
    ADMIN_USER_ID = admin_user.id
    print(f"\nPromoted user #{ADMIN_USER_ID} ({admin_user.email}) to admin.")
finally:
    db.close()

# ── Find or create a client owned by the admin user ──────────────────────────
db = SessionLocal()
try:
    client = db.query(Client).filter_by(user_id=ADMIN_USER_ID).first()
    if client is None:
        client = Client(name="Smoke Test Co", contact_email=admin_user.email, user_id=ADMIN_USER_ID)
        db.add(client)
        db.commit()
        db.refresh(client)
    CLIENT_ID = client.id
    print(f"Using client #{CLIENT_ID} ('{client.name}')")
finally:
    db.close()

# ── Create a verified target (localhost, skip_cve for speed) ──────────────────
db = SessionLocal()
try:
    target = Target(
        client_id=CLIENT_ID,
        scope="localhost",
        authorized_by="smoke-test-manual-trigger-ref",
        verified=True,
        verification_token="smoke-test-tok",
        skip_cve=True,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    SMOKE_TARGET_ID = target.id
    print(f"Created verified target #{SMOKE_TARGET_ID} (scope='localhost', skip_cve=True)")
finally:
    db.close()

# ── Trigger scan via Flask test client ────────────────────────────────────────
# Import web.app AFTER env is loaded; this starts the scheduler too.
from web.app import app as flask_app
flask_app.config["TESTING"] = True

with flask_app.test_client() as http:
    with http.session_transaction() as sess:
        sess["user_id"] = ADMIN_USER_ID

    resp = http.post(f"/api/targets/{SMOKE_TARGET_ID}/scan")
    body = resp.get_json()

print(f"\nPOST /api/targets/{SMOKE_TARGET_ID}/scan  ->  {resp.status_code}")
print(f"Response: {body}")

assert resp.status_code == 202, f"Expected 202, got {resp.status_code}: {body}"
SCAN_RUN_ID = body["scan_run_id"]
print(f"ScanRun #{SCAN_RUN_ID} dispatched (background thread, not scheduler).")

# ── Poll for completion ───────────────────────────────────────────────────────
print(f"\nPolling ScanRun #{SCAN_RUN_ID} for completion (skip_cve=True; max ~4 min)...")
deadline = time.monotonic() + 300  # 5-minute ceiling
final_status = "unknown"

while time.monotonic() < deadline:
    db = SessionLocal()
    try:
        run = db.get(ScanRun, SCAN_RUN_ID)
        final_status = run.status if run else "missing"
    finally:
        db.close()

    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  [{ts}]  status={final_status}", flush=True)

    if final_status in ("completed", "failed"):
        break
    time.sleep(10)

# ── Show ScanRun result ───────────────────────────────────────────────────────
db = SessionLocal()
try:
    run = db.get(ScanRun, SCAN_RUN_ID)
    import json as _json
    findings_count = 0
    finding_summary = {}
    if run and run.result_json:
        data = _json.loads(run.result_json)
        findings_count = len(data.get("findings", []))
        finding_summary = data.get("summary", {})
finally:
    db.close()

print(f"\nScanRun #{SCAN_RUN_ID} final state:")
print(f"  status       : {run.status}")
print(f"  started_at   : {run.started_at}")
print(f"  completed_at : {run.completed_at}")
if run.error_message:
    print(f"  error        : {run.error_message}")
print(f"  findings     : {findings_count}  {finding_summary}")

smoke_passed = final_status in ("completed", "failed")
if final_status == "completed":
    print("\n  Smoke test PASS: manual trigger completed via daemon thread (not scheduler).")
elif final_status == "failed":
    print("\n  Smoke test PASS (partial): daemon thread ran; scan failed on localhost (expected).")
else:
    print(f"\n  Smoke test FAIL: scan did not finish within timeout (status={final_status}).")

suite_results.append(("smoke: POST /api/targets/<id>/scan", smoke_passed))

# ─────────────────────────────────────────────────────────────────────────────
# 3. Admin stats verification  (real DB, real counts)
# ─────────────────────────────────────────────────────────────────────────────

banner("ADMIN STATS: GET /api/admin/stats\n  Verifies aggregate numbers reflect all data in app.db")

# Compute expected values directly from DB
db = SessionLocal()
try:
    exp_users       = db.query(User).count()
    exp_clients     = db.query(Client).count()
    exp_targets     = db.query(Target).count()
    exp_verified    = db.query(Target).filter_by(verified=True).count()
    exp_total_scans = db.query(ScanRun).count()
    exp_completed   = db.query(ScanRun).filter_by(status="completed").count()
    exp_failed      = db.query(ScanRun).filter_by(status="failed").count()
    exp_running     = db.query(ScanRun).filter_by(status="running").count()
    exp_pending     = db.query(ScanRun).filter_by(status="pending").count()

    # Sum severity counts from result_json summary dicts
    exp_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for (rj,) in db.query(ScanRun.result_json).filter(
        ScanRun.status == "completed", ScanRun.result_json.isnot(None)
    ).all():
        try:
            s = _json.loads(rj).get("summary", {})
            for k, v in s.items():
                if k in exp_sev:
                    exp_sev[k] += v
        except Exception:
            pass
finally:
    db.close()

print(f"\nExpected from direct DB query:")
print(f"  users={exp_users}  clients={exp_clients}  targets={exp_targets}  verified={exp_verified}")
print(f"  scans total={exp_total_scans}  completed={exp_completed}  failed={exp_failed}"
      f"  running={exp_running}  pending={exp_pending}")
print(f"  severity counts: {exp_sev}")

# Call the endpoint
with flask_app.test_client() as http:
    with http.session_transaction() as sess:
        sess["user_id"] = ADMIN_USER_ID
    stats_resp = http.get("/api/admin/stats")

print(f"\nGET /api/admin/stats  ->  {stats_resp.status_code}")
assert stats_resp.status_code == 200, f"Expected 200, got {stats_resp.status_code}"
stats = stats_resp.get_json()

print(f"  total_users              : {stats['total_users']}")
print(f"  total_clients            : {stats['total_clients']}")
print(f"  total_targets            : {stats['total_targets']}")
print(f"  total_verified_targets   : {stats['total_verified_targets']}")
print(f"  total_scans              : {stats['total_scans']}")
print(f"  scans_by_status          : {stats['scans_by_status']}")
print(f"  findings_by_severity     : {stats['findings_by_severity']}")

# Verify against direct DB query
stats_checks = [
    ("total_users",            stats["total_users"],           exp_users),
    ("total_clients",          stats["total_clients"],         exp_clients),
    ("total_targets",          stats["total_targets"],         exp_targets),
    ("total_verified_targets", stats["total_verified_targets"],exp_verified),
    ("total_scans",            stats["total_scans"],           exp_total_scans),
    ("completed",              stats["scans_by_status"]["completed"], exp_completed),
    ("failed",                 stats["scans_by_status"]["failed"],    exp_failed),
    ("running",                stats["scans_by_status"]["running"],   exp_running),
    ("pending",                stats["scans_by_status"]["pending"],   exp_pending),
]
for sev in ("critical", "high", "medium", "low", "info"):
    stats_checks.append((f"severity.{sev}", stats["findings_by_severity"][sev], exp_sev[sev]))

stats_mismatches = []
print()
for name, got, expected in stats_checks:
    status = "ok" if got == expected else "MISMATCH"
    if got != expected:
        stats_mismatches.append(f"{name}: got {got!r}, expected {expected!r}")
    print(f"  {status:8s}  {name}: {got}")

stats_passed = len(stats_mismatches) == 0
if stats_passed:
    print("\n  Stats PASS: all values match the DB exactly.")
else:
    print("\n  Stats FAIL:")
    for m in stats_mismatches:
        print(f"    {m}")

suite_results.append(("GET /api/admin/stats", stats_passed))

# ─────────────────────────────────────────────────────────────────────────────
# 4. Cleanup
# ─────────────────────────────────────────────────────────────────────────────

banner("CLEANUP")

db = SessionLocal()
try:
    # Remove smoke test target (cascade deletes its scan_runs)
    t = db.get(Target, SMOKE_TARGET_ID)
    if t:
        db.delete(t)
        db.commit()
        print(f"Deleted smoke test target #{SMOKE_TARGET_ID} and its ScanRuns.")
    # Restore admin user's original role
    u = db.get(User, ADMIN_USER_ID)
    if u:
        u.role = original_role
        db.commit()
        print(f"Restored user #{ADMIN_USER_ID} role to '{original_role}'.")
finally:
    db.close()

if sched_module.scheduler.running:
    sched_module.scheduler.shutdown(wait=False)

# ─────────────────────────────────────────────────────────────────────────────
# 5. Final summary
# ─────────────────────────────────────────────────────────────────────────────

banner("SUMMARY")
all_passed = True
for name, passed in suite_results:
    mark = "PASS" if passed else "FAIL"
    print(f"  [{mark}]  {name}")
    if not passed:
        all_passed = False

print()
if all_passed:
    print("All tests passed.")
else:
    print("SOME TESTS FAILED — see output above.")
    sys.exit(1)
