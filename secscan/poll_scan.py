"""
Poll GET /api/scans/1 every 5 seconds until status is completed or failed,
then print the full result with all findings.
"""

import json
import sys
import time

sys.path.insert(0, ".")

import requests

from db.database import SessionLocal
from db.user_model import User
from web.app import app

ADMIN_EMAIL = "workayoub6@gmail.com"
SCAN_URL = "http://localhost:5000/api/scans/1"
POLL_INTERVAL = 5

# Mint session cookie for admin user
db = SessionLocal()
try:
    user = db.query(User).filter_by(email=ADMIN_EMAIL).first()
    user_id = user.id
finally:
    db.close()

with app.test_request_context():
    from flask import session as flask_session
    flask_session["user_id"] = user_id
    cookie_value = app.session_interface.get_signing_serializer(app).dumps(
        dict(flask_session)
    )

cookies = {"session": cookie_value}

print(f"Polling {SCAN_URL} every {POLL_INTERVAL}s  (user_id={user_id})")
print("=" * 60)

attempt = 0
while True:
    attempt += 1
    resp = requests.get(SCAN_URL, cookies=cookies, timeout=15)
    body = resp.json() if resp.content else {}
    status = body.get("status", "unknown")
    started = body.get("started_at", "-")
    print(f"[{attempt:>3}] status={status!r}  started_at={started}")

    if status in ("completed", "failed"):
        break

    time.sleep(POLL_INTERVAL)

print()
print("=" * 60)
print(f"FINAL STATUS: {status.upper()}")
print("=" * 60)
print()

# Full raw response
print("Full JSON response:")
print(json.dumps(body, indent=2))
print()

# Findings are nested under result{}
findings = (body.get("result") or {}).get("findings") or body.get("findings") or []
print("=" * 60)
print(f"FINDINGS  ({len(findings)} total)")
print("=" * 60)

SEV_LABEL = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}

if not findings:
    print("  (none)")
else:
    # Sort highest severity (5) first
    findings_sorted = sorted(
        findings,
        key=lambda f: -(f.get("severity") or 0),
    )
    for i, f in enumerate(findings_sorted, 1):
        sev_int = f.get("severity") or 0
        sev_str = SEV_LABEL.get(sev_int, str(sev_int)).upper()
        print(f"\n  [{i}] {f.get('title', 'Untitled')}")
        print(f"       Severity    : {sev_str} (raw={sev_int})")
        print(f"       Check type  : {f.get('check_type', '-')}")
        print(f"       Target      : {f.get('target', '-')}")
        port = f.get("port")
        if port:
            print(f"       Port        : {port}")
        evidence = f.get("evidence") or f.get("details") or "-"
        print(f"       Evidence    : {evidence}")
        remediation = f.get("remediation") or f.get("recommendation") or "-"
        print(f"       Remediation : {remediation}")

print()
print("=" * 60)

# Scan metadata
print("Scan metadata:")
for key in ("id", "target_id", "status", "started_at", "finished_at", "triggered_by"):
    print(f"  {key:15s} = {body.get(key)!r}")
