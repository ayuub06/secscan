"""
Trigger a fresh scan on target 3, poll to completion, print all findings.
Confirms the false-positive CRITICAL "No modern TLS support" is gone.
"""

import json
import sys
import time

sys.path.insert(0, ".")

import requests
from db.database import SessionLocal
from db.user_model import User
from web.app import app

HOST = "http://localhost:5000"
ADMIN_EMAIL = "workayoub6@gmail.com"

# ── Mint session cookie ───────────────────────────────────────────────────────
db = SessionLocal()
try:
    user = db.query(User).filter_by(email=ADMIN_EMAIL).first()
    user_id = user.id
finally:
    db.close()

with app.test_request_context():
    from flask import session as _s
    _s["user_id"] = user_id
    cookie = app.session_interface.get_signing_serializer(app).dumps(dict(_s))

cookies = {"session": cookie}
SEP = "=" * 60

# ── Trigger scan ──────────────────────────────────────────────────────────────
print(SEP)
print("POST /api/targets/3/scan")
r = requests.post(f"{HOST}/api/targets/3/scan", cookies=cookies,
                  headers={"Content-Type": "application/json"}, json={}, timeout=15)
print(f"  Status : {r.status_code}")
body = r.json()
print(f"  Body   : {json.dumps(body)}")
assert r.status_code == 202, f"Expected 202, got {r.status_code}: {body}"

scan_run_id = body["scan_run_id"]
print(f"\nPolling scan_run_id={scan_run_id} ...")
print(SEP)

# ── Poll ──────────────────────────────────────────────────────────────────────
attempt = 0
while True:
    attempt += 1
    pr = requests.get(f"{HOST}/api/scans/{scan_run_id}", cookies=cookies, timeout=15)
    pb = pr.json()
    status = pb.get("status", "unknown")
    print(f"  [{attempt:>3}] status={status!r}")
    if status in ("completed", "failed"):
        break
    time.sleep(5)

print()
print(SEP)
print(f"FINAL STATUS: {status.upper()}")
print(SEP)

# ── Findings ──────────────────────────────────────────────────────────────────
result   = pb.get("result") or {}
findings = result.get("findings") or []
summary  = result.get("summary") or {}
checks   = result.get("checks_run") or []

print(f"\nChecks run : {', '.join(checks)}")
print(f"Summary    : {json.dumps(summary)}")
print(f"Findings   : {len(findings)} total")
print()

SEV_LABEL = {1: "INFO", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}

tls_findings = []
sorted_f = sorted(findings, key=lambda f: -(f.get("severity") or 0))

print(SEP)
print("ALL FINDINGS (sorted highest → lowest severity)")
print(SEP)

if not sorted_f:
    print("  (none)")
else:
    for i, f in enumerate(sorted_f, 1):
        sev_int = f.get("severity") or 0
        sev_str = SEV_LABEL.get(sev_int, str(sev_int))
        check   = f.get("check_type", "")
        title   = f.get("title", "Untitled")
        print(f"\n  [{i}] [{sev_str}] {title}")
        print(f"       check_type  : {check}")
        print(f"       target      : {f.get('target', '-')}")
        if f.get("port"):
            print(f"       port        : {f['port']}")
        print(f"       evidence    : {f.get('evidence', '-')}")
        print(f"       remediation : {f.get('remediation', '-')}")
        if check == "weak_tls" or "tls" in title.lower():
            tls_findings.append(f)

# ── TLS verdict ───────────────────────────────────────────────────────────────
print()
print(SEP)
print("TLS CHECK VERDICT")
print(SEP)
critical_tls = [f for f in tls_findings if (f.get("severity") or 0) == 5
                and "no modern tls" in f.get("title", "").lower()]

if critical_tls:
    print(f"  FAIL — false-positive CRITICAL still present: {critical_tls[0]['title']!r}")
elif tls_findings:
    print(f"  PASS — no false-positive CRITICAL.  TLS findings present ({len(tls_findings)}):")
    for f in tls_findings:
        sev_str = SEV_LABEL.get(f.get("severity") or 0, "?")
        print(f"    [{sev_str}] {f.get('title')}")
else:
    print("  PASS — no TLS findings at all (inconclusive scan suppressed correctly).")

print()
print(SEP)
print("Scan metadata")
print(SEP)
for k in ("id", "target_id", "status", "started_at", "completed_at"):
    print(f"  {k:15s} = {pb.get(k)!r}")
