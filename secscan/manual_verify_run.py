"""
One-shot script: manually verify target 3 via the admin override endpoint.

Steps:
  1. Confirm Flask is reachable (GET /api/health).
  2. Ensure workayoub6@gmail.com has role="admin" in the DB.
  3. Mint a signed Flask session cookie for that user.
  4. POST /api/admin/targets/3/manual-verify with a reason.
  5. GET /api/targets/3 — confirm verified=true, method, admin_id, timestamp.
  6. POST /api/targets/3/scan — should now return 202 instead of 403.
"""

import json
import sys

sys.path.insert(0, ".")

# ── Step 1: Health check ──────────────────────────────────────────────────────
import requests

health = requests.get("http://localhost:5000/api/health", timeout=10)
print("=" * 60)
print("STEP 1 — Health check")
print(f"  Status : {health.status_code}")
print(f"  Body   : {health.text.strip()}")
assert health.status_code == 200, "Flask server is not up!"

# ── Step 2: Ensure admin role ─────────────────────────────────────────────────
from db.database import SessionLocal
from db.user_model import User

ADMIN_EMAIL = "workayoub6@gmail.com"

db = SessionLocal()
try:
    user = db.query(User).filter_by(email=ADMIN_EMAIL).first()
    if user is None:
        print(f"\nFATAL: no user with email {ADMIN_EMAIL!r} found in DB")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("STEP 2 — Admin role check")
    print(f"  User  : id={user.id}  email={user.email!r}  role={user.role!r}")

    if user.role != "admin":
        print(f"  [UPDATE] role is {user.role!r}, updating to 'admin' ...")
        user.role = "admin"
        db.commit()
        db.refresh(user)
        print(f"  [OK] committed.  new role={user.role!r}")
    else:
        print("  [OK] already admin, no change needed")

    user_id = user.id
finally:
    db.close()

# ── Step 3: Mint a session cookie ─────────────────────────────────────────────
from web.app import app

print("\n" + "=" * 60)
print("STEP 3 — Generating signed session cookie")

with app.test_request_context():
    from flask import session as flask_session
    flask_session["user_id"] = user_id
    cookie_value = app.session_interface.get_signing_serializer(app).dumps(
        dict(flask_session)
    )

print(f"  user_id in session : {user_id}")
print(f"  cookie (first 60)  : {cookie_value[:60]}…")

cookies = {"session": cookie_value}
headers = {"Content-Type": "application/json"}

# ── Step 4: POST manual-verify ────────────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 4 — POST /api/admin/targets/3/manual-verify")

resp1 = requests.post(
    "http://localhost:5000/api/admin/targets/3/manual-verify",
    headers=headers,
    cookies=cookies,
    json={"reason": "Own Vercel deployment, verified via dashboard access"},
    timeout=15,
)

print(f"  Status : {resp1.status_code}")
body1 = resp1.json() if resp1.content else {}
print(f"  Body   :\n{json.dumps(body1, indent=4)}")

# ── Step 5: GET target/3 — confirm verified fields ────────────────────────────
print("\n" + "=" * 60)
print("STEP 5 — GET /api/targets/3  (confirm verified status)")

resp2 = requests.get(
    "http://localhost:5000/api/targets/3",
    cookies=cookies,
    timeout=10,
)

print(f"  Status : {resp2.status_code}")
body2 = resp2.json() if resp2.content else {}
print(f"  Body   :\n{json.dumps(body2, indent=4)}")

# Highlight the verification fields specifically
t = body2.get("target", body2)
for field in ("verified", "verification_method", "verified_by_admin_id", "verified_at"):
    print(f"    {field:30s} = {t.get(field)!r}")

# ── Step 6: POST /api/targets/3/scan — should now be 202 ─────────────────────
print("\n" + "=" * 60)
print("STEP 6 — POST /api/targets/3/scan  (should be 202, not 403)")

resp3 = requests.post(
    "http://localhost:5000/api/targets/3/scan",
    headers=headers,
    cookies=cookies,
    json={},
    timeout=15,
)

print(f"  Status : {resp3.status_code}")
body3 = resp3.json() if resp3.content else {}
print(f"  Body   :\n{json.dumps(body3, indent=4)}")

if resp3.status_code == 202:
    print("\n  SUCCESS — manual-verify unblocked scanning (202 received)")
elif resp3.status_code == 403:
    print("\n  FAIL — still getting 403, verification did not propagate")
else:
    print(f"\n  Unexpected status {resp3.status_code}")

print("\n" + "=" * 60)
print("Done.")
