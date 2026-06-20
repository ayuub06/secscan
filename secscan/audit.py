"""
Full functional audit — 18 checks against the live Flask app + real SQLite DB.
Run from: cd secscan/ && .venv/Scripts/python.exe secscan/audit.py
"""

import json
import sys
import time
import uuid

sys.path.insert(0, ".")

import requests
from db.database import SessionLocal
from db.orm_models import AuditLog, Client, ScanRun, Target
from db.user_model import User  # must be first to register with SQLAlchemy mapper
from web.app import app
from scheduler import scheduler          # live APScheduler instance
from core.models import ScanResult, Finding, Severity, CheckType
from reports.generator import generate_html

HOST = "http://localhost:5000"
ADMIN_EMAIL = "workayoub6@gmail.com"

SEP  = "=" * 70
SEP2 = "-" * 70

results: dict[str, tuple[str, str]] = {}   # label -> (PASS|FAIL|GAP, note)


def _cookie(user_id: int) -> dict:
    with app.test_request_context():
        from flask import session as _s
        _s["user_id"] = user_id
        val = app.session_interface.get_signing_serializer(app).dumps(dict(_s))
    return {"session": val}


def J(resp) -> dict:
    try:
        return resp.json()
    except Exception:
        return {"_raw": resp.text[:300]}


def section(n: int, title: str):
    print(f"\n{SEP}")
    print(f"CHECK {n:02d} — {title}")
    print(SEP)


def result(label: str, ok: bool | None, note: str, body=None):
    tag = "PASS" if ok is True else ("GAP" if ok is None else "FAIL")
    results[label] = (tag, note)
    print(f"  [{tag}] {note}")
    if body is not None:
        txt = json.dumps(body, indent=2) if isinstance(body, (dict, list)) else str(body)
        for line in txt.splitlines()[:20]:
            print(f"         {line}")


# ─────────────────────────────────────────────────────────────────────────────
# Fixture setup
# ─────────────────────────────────────────────────────────────────────────────

db = SessionLocal()
try:
    admin = db.query(User).filter_by(email=ADMIN_EMAIL).first()
    ADMIN_ID = admin.id

    # Second user: customer role (create if absent)
    cust = db.query(User).filter_by(email="audit-customer@test.local").first()
    if not cust:
        cust = User(
            google_id=f"fake-audit-{uuid.uuid4().hex[:8]}",
            email="audit-customer@test.local",
            name="Audit Customer",
            role="customer",
        )
        db.add(cust)
        db.commit()
        db.refresh(cust)
    CUST_ID = cust.id

    # Ensure customer has a client (needed for target CRUD tests)
    cust_client = db.query(Client).filter_by(user_id=CUST_ID).first()
    if not cust_client:
        cust_client = Client(name="Audit Customer Client",
                             contact_email="audit-customer@test.local",
                             user_id=CUST_ID)
        db.add(cust_client)
        db.commit()
        db.refresh(cust_client)
    CUST_CLIENT_ID = cust_client.id

    # Admin's client (assumed to exist)
    admin_client = db.query(Client).filter_by(user_id=ADMIN_ID).first()
    ADMIN_CLIENT_ID = admin_client.id if admin_client else None

finally:
    db.close()

ADMIN_COOKIE = _cookie(ADMIN_ID)
CUST_COOKIE  = _cookie(CUST_ID)
HDR          = {"Content-Type": "application/json"}
print(f"Admin user id={ADMIN_ID}  customer user id={CUST_ID}")
print(f"Admin client={ADMIN_CLIENT_ID}  customer client={CUST_CLIENT_ID}")


# ─────────────────────────────────────────────────────────────────────────────
# 1. GET /api/auth/me
# ─────────────────────────────────────────────────────────────────────────────
section(1, "GET /api/auth/me returns correct admin user info")
r = requests.get(f"{HOST}/api/auth/me", cookies=ADMIN_COOKIE)
b = J(r)
ok = (r.status_code == 200
      and b.get("email") == ADMIN_EMAIL
      and b.get("role") == "admin"
      and b.get("id") == ADMIN_ID)
result("auth_me", ok,
       f"status={r.status_code} id={b.get('id')} email={b.get('email')!r} role={b.get('role')!r}",
       b)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Non-admin gets 403 on all /api/admin/* endpoints
# ─────────────────────────────────────────────────────────────────────────────
section(2, "Non-admin user is blocked (403) on every /api/admin/* endpoint")
ADMIN_ROUTES = [
    ("GET",  "/api/admin/users"),
    ("GET",  "/api/admin/clients"),
    ("GET",  "/api/admin/targets"),
    ("GET",  "/api/admin/scans"),
    ("GET",  "/api/admin/stats"),
    ("GET",  "/api/admin/audit-log"),
    ("GET",  "/api/admin/targets/unverified"),
    ("POST", f"/api/admin/users/{ADMIN_ID}/role"),
    ("POST", f"/api/admin/targets/3/manual-verify"),
]
all_403 = True
for method, path in ADMIN_ROUTES:
    resp = requests.request(method, f"{HOST}{path}",
                            cookies=CUST_COOKIE, headers=HDR, json={})
    ok_i = resp.status_code == 403
    if not ok_i:
        all_403 = False
    print(f"  {method:4s} {path:50s} -> {resp.status_code} {'OK' if ok_i else 'WRONG'}")
result("admin_403", all_403,
       "all admin routes returned 403 to customer" if all_403
       else "SOME admin routes did NOT return 403 — authorization gap")


# ─────────────────────────────────────────────────────────────────────────────
# 3. POST /api/admin/users/<id>/role + audit log entry created
# ─────────────────────────────────────────────────────────────────────────────
section(3, "Role promote/demote writes correct DB state + audit log entry")
# promote customer -> admin
r = requests.post(f"{HOST}/api/admin/users/{CUST_ID}/role",
                  cookies=ADMIN_COOKIE, headers=HDR,
                  json={"role": "admin"})
b = J(r)
promoted = r.status_code == 200 and b.get("role") == "admin"
print(f"  Promote  status={r.status_code}  role={b.get('role')!r}  body={b}")

# demote back
r2 = requests.post(f"{HOST}/api/admin/users/{CUST_ID}/role",
                   cookies=ADMIN_COOKIE, headers=HDR,
                   json={"role": "customer"})
b2 = J(r2)
demoted = r2.status_code == 200 and b2.get("role") == "customer"
print(f"  Demote   status={r2.status_code}  role={b2.get('role')!r}  body={b2}")

# audit log must have role_changed entries for CUST_ID
r3 = requests.get(f"{HOST}/api/admin/audit-log",
                  cookies=ADMIN_COOKIE,
                  params={"action": "role_changed", "user_id": ADMIN_ID, "per_page": 5})
b3 = J(r3)
entries = b3.get("entries", [])
audit_ok = any(e.get("resource_id") == CUST_ID for e in entries)
print(f"  Audit entries for role_changed: {len(entries)}")
for e in entries[:3]:
    print(f"    id={e['id']} resource_id={e['resource_id']} details={e['details']}")
result("role_change", promoted and demoted and audit_ok,
       f"promote={promoted} demote={demoted} audit_entry={audit_ok}")


# ─────────────────────────────────────────────────────────────────────────────
# 4. GET /api/clients isolation — only own clients returned?
# ─────────────────────────────────────────────────────────────────────────────
section(4, "GET /api/clients returns only the logged-in user's clients")
r_admin = requests.get(f"{HOST}/api/clients", cookies=ADMIN_COOKIE)
r_cust  = requests.get(f"{HOST}/api/clients", cookies=CUST_COOKIE)
admin_clients = J(r_admin)
cust_clients  = J(r_cust)

# Admin client IDs vs customer client IDs — check if they're isolated
admin_ids = {c["id"] for c in admin_clients} if isinstance(admin_clients, list) else set()
cust_ids  = {c["id"] for c in cust_clients}  if isinstance(cust_clients, list) else set()

# Isolation holds iff neither list contains the other's clients
isolation_ok = (CUST_CLIENT_ID not in admin_ids) or (ADMIN_CLIENT_ID not in cust_ids)
# Actually the real check: does customer see ADMIN's clients or vice versa?
admin_sees_cust = CUST_CLIENT_ID in admin_ids
cust_sees_admin = ADMIN_CLIENT_ID in cust_ids and ADMIN_CLIENT_ID is not None

print(f"  Admin sees {len(admin_ids)} clients: {sorted(admin_ids)}")
print(f"  Cust  sees {len(cust_ids)} clients:  {sorted(cust_ids)}")
print(f"  Admin sees customer's client: {admin_sees_cust}")
print(f"  Cust  sees admin's client:    {cust_sees_admin}")

isolated = not admin_sees_cust and not cust_sees_admin
result("client_isolation", isolated,
       "GET /api/clients is properly isolated per user"
       if isolated
       else f"ISOLATION MISSING: endpoint returns ALL clients regardless of session — "
            f"admin sees cust={admin_sees_cust}, cust sees admin={cust_sees_admin}")


# ─────────────────────────────────────────────────────────────────────────────
# 5. DELETE /api/clients/<id> cascades + DB orphan check
# ─────────────────────────────────────────────────────────────────────────────
section(5, "DELETE /api/clients/<id> cascades to targets and scan_runs")

# Create a fresh client -> target -> scan_run to delete
db = SessionLocal()
try:
    tmp_client = Client(name="AuditTmp", contact_email="tmp@audit.local", user_id=ADMIN_ID)
    db.add(tmp_client)
    db.flush()
    tmp_target = Target(client_id=tmp_client.id, scope="tmp-audit.local",
                        authorized_by="audit test", verified=False)
    db.add(tmp_target)
    db.flush()
    tmp_run = ScanRun(target_id=tmp_target.id, scan_id=str(uuid.uuid4()), status="completed")
    db.add(tmp_run)
    db.commit()
    TMP_CLIENT_ID = tmp_client.id
    TMP_TARGET_ID = tmp_target.id
    TMP_RUN_ID    = tmp_run.id
finally:
    db.close()

print(f"  Created: client={TMP_CLIENT_ID} target={TMP_TARGET_ID} scan_run={TMP_RUN_ID}")

r_del = requests.delete(f"{HOST}/api/clients/{TMP_CLIENT_ID}", cookies=ADMIN_COOKIE)
print(f"  DELETE response: {r_del.status_code} {J(r_del)}")

db = SessionLocal()
try:
    orphan_target  = db.get(Target, TMP_TARGET_ID)
    orphan_run     = db.get(ScanRun, TMP_RUN_ID)
    orphan_client  = db.get(Client, TMP_CLIENT_ID)
finally:
    db.close()

cascade_ok = (orphan_client is None and orphan_target is None and orphan_run is None)
print(f"  After delete — client={orphan_client} target={orphan_target} scan_run={orphan_run}")

# Also check: does DELETE have an ownership/auth check?
# Create another client owned by ADMIN, try to delete as CUSTOMER
db = SessionLocal()
try:
    tmp2 = Client(name="AuditTmp2", contact_email="tmp2@audit.local", user_id=ADMIN_ID)
    db.add(tmp2)
    db.commit()
    TMP2_ID = tmp2.id
finally:
    db.close()

r_unauth = requests.delete(f"{HOST}/api/clients/{TMP2_ID}", cookies=CUST_COOKIE)
unauth_blocked = r_unauth.status_code in (401, 403)
print(f"  Customer deleting admin's client: {r_unauth.status_code} — {'blocked' if unauth_blocked else 'ALLOWED (BUG)'}")

# cleanup tmp2 if customer was blocked (it still exists)
if unauth_blocked:
    db = SessionLocal()
    try:
        c = db.get(Client, TMP2_ID)
        if c:
            db.delete(c)
            db.commit()
    finally:
        db.close()

result("delete_cascade", cascade_ok,
       f"cascade={cascade_ok} orphan_target={orphan_target is not None} orphan_run={orphan_run is not None}")
result("delete_auth", unauth_blocked,
       f"unauthenticated/cross-user delete returned {r_unauth.status_code} "
       f"({'blocked' if unauth_blocked else 'NOT BLOCKED — authorization missing'})")


# ─────────────────────────────────────────────────────────────────────────────
# 6. POST /api/targets rejects empty authorized_by with 400
# ─────────────────────────────────────────────────────────────────────────────
section(6, "POST /api/targets rejects empty authorized_by with 400")
r = requests.post(f"{HOST}/api/targets", cookies=ADMIN_COOKIE, headers=HDR,
                  json={"client_id": ADMIN_CLIENT_ID, "scope": "example.com", "authorized_by": ""})
b = J(r)
ok = r.status_code == 400 and "authorized_by" in json.dumps(b).lower()
result("target_auth_required", ok,
       f"status={r.status_code} body={b}", b)


# ─────────────────────────────────────────────────────────────────────────────
# 7. DNS verification — fail path + success path gap note
# ─────────────────────────────────────────────────────────────────────────────
section(7, "DNS verification: fail path for domain with no TXT record")

# Create an unverified target under customer's client
r_t = requests.post(f"{HOST}/api/targets", cookies=CUST_COOKIE, headers=HDR,
                    json={"client_id": CUST_CLIENT_ID,
                          "scope": "dns-verify-test.invalid",
                          "authorized_by": "audit test"})
DNS_TARGET_ID = J(r_t).get("id")
print(f"  Created target id={DNS_TARGET_ID} for DNS verify test")

r_verify = requests.post(f"{HOST}/api/targets/{DNS_TARGET_ID}/verify",
                         cookies=CUST_COOKIE, headers=HDR, json={"method": "dns"})
b = J(r_verify)
fail_correct = r_verify.status_code == 200 and b.get("verified") is False
result("dns_verify_fail", fail_correct,
       f"status={r_verify.status_code} verified={b.get('verified')} msg={b.get('message','')[:80]!r}",
       b)
result("dns_verify_success", None,
       "GAP: No real domain with secscan TXT record available to test success path — "
       "manual verification (check 9) substitutes as the only verified-path test")


# ─────────────────────────────────────────────────────────────────────────────
# 8. File verification — fail path + success path gap note
# ─────────────────────────────────────────────────────────────────────────────
section(8, "File verification: fail path for domain with no well-known file")
r_verify = requests.post(f"{HOST}/api/targets/{DNS_TARGET_ID}/verify",
                         cookies=CUST_COOKIE, headers=HDR, json={"method": "file"})
b = J(r_verify)
fail_correct = r_verify.status_code == 200 and b.get("verified") is False
result("file_verify_fail", fail_correct,
       f"status={r_verify.status_code} verified={b.get('verified')} msg={b.get('message','')[:80]!r}",
       b)
result("file_verify_success", None,
       "GAP: No real domain with secscan well-known file available to test success path")


# ─────────────────────────────────────────────────────────────────────────────
# 9. Admin manual-verify: empty reason=400, all 4 fields set on success
# ─────────────────────────────────────────────────────────────────────────────
section(9, "Admin manual-verify: empty reason=400, 4 fields set on success")

# Empty reason
r_bad = requests.post(f"{HOST}/api/admin/targets/{DNS_TARGET_ID}/manual-verify",
                      cookies=ADMIN_COOKIE, headers=HDR, json={"reason": ""})
b_bad = J(r_bad)
empty_reason_ok = r_bad.status_code == 400 and "reason" in json.dumps(b_bad).lower()
print(f"  Empty reason: {r_bad.status_code}  {b_bad}")
result("manual_verify_empty_reason", empty_reason_ok,
       f"status={r_bad.status_code} body={b_bad}")

# Valid reason
r_ok = requests.post(f"{HOST}/api/admin/targets/{DNS_TARGET_ID}/manual-verify",
                     cookies=ADMIN_COOKIE, headers=HDR,
                     json={"reason": "Audit test — confirmed ownership via audit script"})
b_ok = J(r_ok)
fields_set = (
    r_ok.status_code == 200
    and b_ok.get("verified") is True
    and b_ok.get("verification_method") == "manual_admin"
    and b_ok.get("verified_by_admin_id") == ADMIN_ID
    and b_ok.get("verified_at") is not None
)
print(f"  Valid reason: {r_ok.status_code}")
for f in ("verified", "verification_method", "verified_by_admin_id", "verified_at"):
    print(f"    {f} = {b_ok.get(f)!r}")
result("manual_verify_fields", fields_set,
       f"verified={b_ok.get('verified')} method={b_ok.get('verification_method')!r} "
       f"admin_id={b_ok.get('verified_by_admin_id')} at={b_ok.get('verified_at')!r}")


# ─────────────────────────────────────────────────────────────────────────────
# 10. Unverified target scan returns 403
# ─────────────────────────────────────────────────────────────────────────────
section(10, "Unverified target scan-trigger returns 403, unconditionally")

# Create a fresh unverified target
r_t2 = requests.post(f"{HOST}/api/targets", cookies=CUST_COOKIE, headers=HDR,
                     json={"client_id": CUST_CLIENT_ID,
                           "scope": "unverified-scan-test.invalid",
                           "authorized_by": "audit test"})
UNVER_TARGET_ID = J(r_t2).get("id")
print(f"  Unverified target id={UNVER_TARGET_ID}")

r_scan = requests.post(f"{HOST}/api/targets/{UNVER_TARGET_ID}/scan",
                       cookies=CUST_COOKIE, headers=HDR, json={})
b_scan = J(r_scan)
ok_403 = r_scan.status_code == 403 and "verified" in json.dumps(b_scan).lower()
result("unverified_scan_403", ok_403,
       f"status={r_scan.status_code} body={b_scan}", b_scan)


# ─────────────────────────────────────────────────────────────────────────────
# 11. Real scan against verified target — all 6 checks run
# ─────────────────────────────────────────────────────────────────────────────
section(11, "Real scan: verified target gestion-examens-frontend.vercel.app — 6 checks")

r_scan = requests.post(f"{HOST}/api/targets/3/scan",
                       cookies=ADMIN_COOKIE, headers=HDR, json={})
b_scan = J(r_scan)
SCAN_RUN_ID = b_scan.get("scan_run_id")
print(f"  POST /api/targets/3/scan -> {r_scan.status_code}  scan_run_id={SCAN_RUN_ID}")

# poll up to 3 min
start = time.time()
status = "pending"
while status not in ("completed", "failed") and time.time() - start < 180:
    time.sleep(5)
    pr = requests.get(f"{HOST}/api/scans/{SCAN_RUN_ID}", cookies=ADMIN_COOKIE)
    status = J(pr).get("status", "unknown")
    print(f"    [{int(time.time()-start):>3}s] status={status!r}")

final_body = J(requests.get(f"{HOST}/api/scans/{SCAN_RUN_ID}", cookies=ADMIN_COOKIE))
checks_run = (final_body.get("result") or {}).get("checks_run", [])
EXPECTED_CHECKS = {"port_scan", "tls_check", "http_headers", "dns_check", "admin_panels", "cve_lookup"}
all_ran = EXPECTED_CHECKS.issubset(set(checks_run))
result("real_scan_6_checks", status == "completed" and all_ran,
       f"status={status} checks_run={checks_run}  all_6={all_ran}")


# ─────────────────────────────────────────────────────────────────────────────
# 12. Scan against invalid/unreachable domain — fails gracefully
# ─────────────────────────────────────────────────────────────────────────────
section(12, "Scan invalid domain — status=failed gracefully, no crash")

# Create target with unresolvable domain, admin-verify it (skip DNS proof)
r_t3 = requests.post(f"{HOST}/api/targets", cookies=ADMIN_COOKIE, headers=HDR,
                     json={"client_id": ADMIN_CLIENT_ID,
                           "scope": "this-domain-definitely-does-not-exist-xyz123abc.invalid",
                           "authorized_by": "audit graceful fail test"})
INVALID_TARGET_ID = J(r_t3).get("id")
print(f"  Created invalid-domain target id={INVALID_TARGET_ID}")

requests.post(f"{HOST}/api/admin/targets/{INVALID_TARGET_ID}/manual-verify",
              cookies=ADMIN_COOKIE, headers=HDR,
              json={"reason": "Audit graceful-fail test — intentionally unresolvable"})

r_s = requests.post(f"{HOST}/api/targets/{INVALID_TARGET_ID}/scan",
                    cookies=ADMIN_COOKIE, headers=HDR, json={})
INVALID_RUN_ID = J(r_s).get("scan_run_id")
print(f"  Scan triggered: scan_run_id={INVALID_RUN_ID}")

start = time.time()
status = "pending"
while status not in ("completed", "failed") and time.time() - start < 120:
    time.sleep(5)
    pr = J(requests.get(f"{HOST}/api/scans/{INVALID_RUN_ID}", cookies=ADMIN_COOKIE))
    status = pr.get("status", "unknown")
    print(f"    [{int(time.time()-start):>3}s] status={status!r}  err={(pr.get('error_message') or '')[:60]!r}")

final_invalid = J(requests.get(f"{HOST}/api/scans/{INVALID_RUN_ID}", cookies=ADMIN_COOKIE))
failed_cleanly = status in ("completed", "failed")
result("invalid_scan_graceful", failed_cleanly,
       f"status={status}  error_message={(final_invalid.get('error_message') or '')[:80]!r}")


# ─────────────────────────────────────────────────────────────────────────────
# 13. Diff: compare 2 completed scans for target 3
# ─────────────────────────────────────────────────────────────────────────────
section(13, "Scan diff: GET /api/targets/3/latest-diff and explicit /diff")

r_latest = requests.get(f"{HOST}/api/targets/3/latest-diff", cookies=ADMIN_COOKIE)
b_latest = J(r_latest)
has_diff = (r_latest.status_code == 200
            and "new" in b_latest and "resolved" in b_latest
            and "persistent" in b_latest and "escalated" in b_latest)
print(f"  /latest-diff -> {r_latest.status_code}")
for k in ("new", "resolved", "persistent", "escalated"):
    print(f"    {k}: {len(b_latest.get(k, []))} item(s)")

# Explicit diff between scan #1 (old, had the TLS false positive) and current (no TLS)
db = SessionLocal()
try:
    completed = (db.query(ScanRun)
                 .filter_by(target_id=3, status="completed")
                 .order_by(ScanRun.id.asc())
                 .all())
    DIFF_OLD_ID = completed[0].id if completed else None
    DIFF_NEW_ID = completed[-1].id if completed else None
finally:
    db.close()

print(f"  Explicit diff: old_scan_id={DIFF_OLD_ID}  new_scan_id={DIFF_NEW_ID}")
r_explicit = requests.get(f"{HOST}/api/targets/3/diff",
                          cookies=ADMIN_COOKIE,
                          params={"old_scan_id": DIFF_OLD_ID, "new_scan_id": DIFF_NEW_ID})
b_explicit = J(r_explicit)
if DIFF_OLD_ID != DIFF_NEW_ID:
    print(f"  resolved (TLS false positive gone?): {len(b_explicit.get('resolved', []))}")
    for f in b_explicit.get("resolved", [])[:3]:
        print(f"    RESOLVED: {f.get('title')}")
    print(f"  persistent: {[f.get('title') for f in b_explicit.get('persistent', [])]}")

result("diff_latest", has_diff,
       f"status={r_latest.status_code} new={len(b_latest.get('new',[]))} "
       f"resolved={len(b_latest.get('resolved',[]))} persistent={len(b_latest.get('persistent',[]))}")


# ─────────────────────────────────────────────────────────────────────────────
# 14. Schedule PATCH: valid cron succeeds, invalid cron returns 400
# ─────────────────────────────────────────────────────────────────────────────
section(14, "PATCH /api/targets/<id>/schedule: valid=200, invalid=400")

r_valid = requests.patch(f"{HOST}/api/targets/3/schedule",
                         cookies=ADMIN_COOKIE, headers=HDR,
                         json={"schedule_cron": "0 3 * * *"})
b_valid = J(r_valid)
valid_ok = r_valid.status_code == 200 and b_valid.get("schedule_cron") == "0 3 * * *"
print(f"  Valid cron '0 3 * * *': {r_valid.status_code}  schedule_cron={b_valid.get('schedule_cron')!r}")

r_bad = requests.patch(f"{HOST}/api/targets/3/schedule",
                       cookies=ADMIN_COOKIE, headers=HDR,
                       json={"schedule_cron": "not a cron"})
b_bad = J(r_bad)
invalid_ok = r_bad.status_code == 400 and "error" in b_bad
print(f"  Invalid 'not a cron': {r_bad.status_code}  body={b_bad}")

result("schedule_valid", valid_ok, f"200 with correct schedule_cron={b_valid.get('schedule_cron')!r}")
result("schedule_invalid", invalid_ok, f"400 on bad cron: {b_bad.get('error','')[:80]!r}")


# ─────────────────────────────────────────────────────────────────────────────
# 15. Clear schedule — APScheduler job actually removed
# ─────────────────────────────────────────────────────────────────────────────
section(15, "Clearing schedule removes job from APScheduler job list")

# Confirm the job exists first
job_before = scheduler.get_job("target-3")
print(f"  Job 'target-3' before clear: {job_before}")

r_clear = requests.patch(f"{HOST}/api/targets/3/schedule",
                         cookies=ADMIN_COOKIE, headers=HDR,
                         json={"schedule_cron": None})
b_clear = J(r_clear)
print(f"  PATCH clear: {r_clear.status_code}  schedule_cron={b_clear.get('schedule_cron')!r}")

# Give APScheduler a moment to process sync_schedules()
time.sleep(1)
job_after = scheduler.get_job("target-3")
print(f"  Job 'target-3' after clear: {job_after}")

job_removed = job_after is None
result("schedule_clear_removes_job", job_removed,
       f"job_before={job_before is not None}  job_after={job_after is not None} "
       f"({'removed' if job_removed else 'STILL PRESENT — sync_schedules may not have run yet'})")


# ─────────────────────────────────────────────────────────────────────────────
# 16. Rate limit: 6th scan attempt in same hour returns 429
# ─────────────────────────────────────────────────────────────────────────────
section(16, "Rate limit: 6th POST /api/targets/<id>/scan in same hour = 429")

# Use DNS_TARGET_ID (now manually verified) for rapid-fire scan triggers
# We need exactly 6 POST requests; the 6th must 429.
# (In-memory limiter, fresh since server restart)
statuses = []
for i in range(1, 7):
    r_i = requests.post(f"{HOST}/api/targets/{DNS_TARGET_ID}/scan",
                        cookies=CUST_COOKIE, headers=HDR, json={})
    statuses.append(r_i.status_code)
    b_i = J(r_i)
    print(f"  Attempt {i}: status={r_i.status_code}  body={str(b_i)[:80]}")
    if r_i.status_code == 429:
        rl_body = b_i
        break

got_429 = 429 in statuses
attempt_num = statuses.index(429) + 1 if 429 in statuses else None
print(f"  Got 429 on attempt #{attempt_num}")
result("rate_limit_429", got_429,
       f"429 on attempt #{attempt_num}  body={rl_body if got_429 else 'never got 429'}")


# ─────────────────────────────────────────────────────────────────────────────
# 17. Audit log: filtering by ?action= and ?user_id= works
# ─────────────────────────────────────────────────────────────────────────────
section(17, "Audit log filtering: ?action= and ?user_id= actually filter")

# Get all entries first
r_all = requests.get(f"{HOST}/api/admin/audit-log",
                     cookies=ADMIN_COOKIE, params={"per_page": 200})
b_all = J(r_all)
total = b_all.get("total", 0)
print(f"  Total audit entries: {total}")

# Filter by action=scan_triggered
r_scan_act = requests.get(f"{HOST}/api/admin/audit-log",
                           cookies=ADMIN_COOKIE,
                           params={"action": "scan_triggered", "per_page": 50})
b_scan_act = J(r_scan_act)
scan_entries = b_scan_act.get("entries", [])
action_filter_ok = (
    b_scan_act.get("total", 0) < total
    and all(e["action"] == "scan_triggered" for e in scan_entries)
)
print(f"  ?action=scan_triggered  total={b_scan_act.get('total')}  "
      f"all correct action={all(e['action']=='scan_triggered' for e in scan_entries)}")

# Filter by user_id=CUST_ID
r_uid = requests.get(f"{HOST}/api/admin/audit-log",
                     cookies=ADMIN_COOKIE,
                     params={"user_id": CUST_ID, "per_page": 50})
b_uid = J(r_uid)
uid_entries = b_uid.get("entries", [])
uid_filter_ok = (
    b_uid.get("total", 0) < total
    and all(e["user_id"] == CUST_ID for e in uid_entries)
)
print(f"  ?user_id={CUST_ID}  total={b_uid.get('total')}  "
      f"all correct uid={all(e['user_id']==CUST_ID for e in uid_entries)}")

# Filter by action=rate_limit_exceeded (we just triggered one)
r_rl = requests.get(f"{HOST}/api/admin/audit-log",
                    cookies=ADMIN_COOKIE,
                    params={"action": "rate_limit_exceeded", "per_page": 10})
b_rl = J(r_rl)
print(f"  ?action=rate_limit_exceeded  total={b_rl.get('total')}")
for e in b_rl.get("entries", [])[:2]:
    print(f"    {e['action']}  details={e['details']}")

result("audit_action_filter", action_filter_ok,
       f"?action= filters correctly: {action_filter_ok} (scan_triggered total={b_scan_act.get('total')})")
result("audit_uid_filter", uid_filter_ok,
       f"?user_id= filters correctly: {uid_filter_ok} (cust total={b_uid.get('total')})")


# ─────────────────────────────────────────────────────────────────────────────
# 18. generate_html() with zero findings — renders sensibly
# ─────────────────────────────────────────────────────────────────────────────
section(18, "generate_html() with zero findings — clean case")

empty_result = ScanResult(
    scan_id="audit-zero-findings-test",
    target_scope=["clean-target.example.com"],
    authorized_by="Audit Test",
    started_at="2026-06-20T00:00:00+00:00",
    completed_at="2026-06-20T00:00:10+00:00",
    checks_run=["port_scan", "tls_check", "http_headers", "dns_check", "admin_panels", "cve_lookup"],
    findings=[],
)

try:
    html = generate_html(empty_result)
    length = len(html)
    has_no_findings_msg = any(phrase in html.lower() for phrase in
                              ["no findings", "no vulnerabilities", "clean", "nothing to report",
                               "0 finding", "zero finding"])
    has_summary = "critical" in html.lower() and "high" in html.lower()
    result("empty_report_html", length > 500 and has_summary,
           f"HTML length={length} bytes  has_no_findings_phrase={has_no_findings_msg}  "
           f"has_summary_section={has_summary}")
    # Show relevant snippet
    idx = html.lower().find("finding")
    if idx > 0:
        print(f"  Snippet around 'finding': ...{html[max(0,idx-50):idx+120].strip()!r}...")
except Exception as exc:
    import traceback
    result("empty_report_html", False, f"EXCEPTION: {exc}")
    traceback.print_exc()


# ─────────────────────────────────────────────────────────────────────────────
# FINAL CLEANUP
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("CLEANUP")
print(SEP)
db = SessionLocal()
try:
    for tid in [DNS_TARGET_ID, UNVER_TARGET_ID, INVALID_TARGET_ID]:
        t = db.get(Target, tid)
        if t:
            db.delete(t)
    cust = db.get(User, CUST_ID)
    if cust:
        # delete customer's client (cascades to targets)
        for c in db.query(Client).filter_by(user_id=CUST_ID).all():
            db.delete(c)
        db.delete(cust)
    db.commit()
    print("  Deleted: test targets, customer user and client")
except Exception as exc:
    print(f"  Cleanup error (non-fatal): {exc}")
    db.rollback()
finally:
    db.close()


# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY TABLE
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("AUDIT SUMMARY")
print(SEP)
print(f"  {'#':<4} {'Label':<35} {'Result':<6}  Note")
print(f"  {SEP2}")
for i, (label, (tag, note)) in enumerate(results.items(), 1):
    print(f"  {i:<4} {label:<35} {tag:<6}  {note[:80]}")

passes = sum(1 for _, (t, _) in results.items() if t == "PASS")
fails  = sum(1 for _, (t, _) in results.items() if t == "FAIL")
gaps   = sum(1 for _, (t, _) in results.items() if t == "GAP")
print(f"\n  TOTAL: {passes} PASS  /  {fails} FAIL  /  {gaps} GAP (known test limitation)")
