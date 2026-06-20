"""
secscan Flask API — HTTP interface to the scan engine.

Run from the secscan/ package directory so that relative imports
(checks, core, db) resolve correctly:

    cd secscan/
    python web/app.py

Or via the venv:
    .venv/Scripts/python.exe secscan/web/app.py   (from project root)
"""

import functools
import json
import logging
import os
import sys
import threading
import time as _time
import uuid
from datetime import datetime, timezone

from apscheduler.triggers.cron import CronTrigger
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import func as sa_func

# Add secscan/ package root to sys.path so sibling packages (checks, core, db)
# resolve correctly regardless of where this script is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load .env before anything reads os.environ.
# The .env is at the project root (two levels above the secscan/ package dir).
from dotenv import load_dotenv

_env_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    ".env",
)
# The .env file is UTF-16-LE encoded (Windows default for some editors).
load_dotenv(dotenv_path=_env_path, encoding="utf-16")

from authlib.integrations.flask_client import OAuth
from flask import Flask, jsonify, redirect, request, session
from flask_cors import CORS

from core.diff import compare_scans
from core.scan_runner import execute_scan
from core.verification import check_dns_verification, check_file_verification
from db.audit import log_audit_event
from db.database import SessionLocal, init_db
from db.orm_models import AuditLog, Client, ScanRun, Target
from db.user_model import User  # must be imported before init_db() so Base.metadata knows about users table
from scheduler import start_scheduler, sync_schedules

# ── App setup ────────────────────────────────────────────────────────────────

app = Flask(__name__)
# supports_credentials=True is required so browsers send the session cookie
# with cross-origin requests from the React frontend (localhost:5173).
CORS(app, supports_credentials=True, origins=["http://localhost:5173"])
app.secret_key = os.environ["FLASK_SECRET_KEY"]
# Without these, Flask defaults to SameSite=None (or browser-dependent) and
# Secure=True in some configurations. On http://localhost (no TLS), Secure=True
# silently drops the cookie, and SameSite=Strict blocks it on the cross-site
# redirect back from Google. Lax + non-Secure is the correct posture for local
# HTTP development.
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("secscan.web")

# User model is already imported above, so Base.metadata includes the users table.
# AuditLog is a NEW table; create_all() handles it automatically (no ALTER TABLE needed).
init_db()
# In Werkzeug's reloader the outer watcher sets WERKZEUG_RUN_MAIN=true in the
# child before exec'ing it.  Start the scheduler only in the child (or in
# production where the reloader is not used and app.debug is False).
if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
    start_scheduler()

# ── Rate limiting ─────────────────────────────────────────────────────────────


def _limiter_key() -> str:
    """Use the logged-in user's id as the rate-limit key; fall back to IP for
    unauthenticated requests (health check, OAuth redirect)."""
    user_id = session.get("user_id")
    return f"user:{user_id}" if user_id else get_remote_address()


def _ratelimit_on_breach(request_limit) -> "Response":  # type: ignore[name-defined]
    """Return a JSON 429 response and write an audit log entry."""
    retry_after = max(0, request_limit.reset_at - int(_time.time()))
    log_audit_event(
        user_id=session.get("user_id"),
        action="rate_limit_exceeded",
        details={"endpoint": request.path},
        ip_address=request.remote_addr,
    )
    resp = jsonify({
        "error": "Rate limit exceeded. Please try again later.",
        "retry_after_seconds": retry_after,
    })
    resp.status_code = 429
    return resp


# In-memory storage is appropriate for a single-process deployment.
# For multi-process production (e.g. multiple gunicorn workers), switch to:
#   storage_uri="redis://localhost:6379/0"
limiter = Limiter(
    key_func=_limiter_key,
    app=app,
    default_limits=["200 per hour"],
    storage_uri="memory://",
    on_breach=_ratelimit_on_breach,
)

# ── OAuth ────────────────────────────────────────────────────────────────────

oauth = OAuth(app)
oauth.register(
    name="google",
    client_id=os.environ["GOOGLE_CLIENT_ID"],
    client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# ── Auth helpers ──────────────────────────────────────────────────────────────

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"error": "Authentication required"}), 401
        db = SessionLocal()
        try:
            user = db.get(User, user_id)
            is_admin = user is not None and user.role == "admin"
        finally:
            db.close()
        if not is_admin:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


# ── Helpers ──────────────────────────────────────────────────────────────────

def _fmt_dt(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt is not None else None


def _client_dict(client: Client) -> dict:
    return {
        "id": client.id,
        "name": client.name,
        "contact_email": client.contact_email,
        "user_id": client.user_id,
        "created_at": _fmt_dt(client.created_at),
    }


def _target_dict(target: Target) -> dict:
    return {
        "id": target.id,
        "client_id": target.client_id,
        "scope": target.scope,
        "authorized_by": target.authorized_by,
        "schedule_cron": target.schedule_cron,
        "skip_cve": target.skip_cve,
        "verification_token": target.verification_token,
        "verified": target.verified,
        "verification_method": target.verification_method,
        "verified_at": _fmt_dt(target.verified_at),
        "created_at": _fmt_dt(target.created_at),
    }


def _scan_run_summary(run: ScanRun) -> dict:
    """Compact representation used in list views — no result_json."""
    return {
        "id": run.id,
        "scan_id": run.scan_id,
        "status": run.status,
        "started_at": _fmt_dt(run.started_at),
        "completed_at": _fmt_dt(run.completed_at),
    }


# _run_scan_background has been replaced by core.scan_runner.execute_scan,
# which is called directly from trigger_scan's daemon thread and from the
# APScheduler jobs in scheduler.py.


# ── Health ───────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
@limiter.exempt
def health():
    return jsonify({"status": "ok"}), 200


# ── Auth endpoints ────────────────────────────────────────────────────────────

@app.route("/api/auth/google/login", methods=["GET"])
def google_login():
    redirect_uri = os.environ["OAUTH_REDIRECT_URI"]
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/api/auth/google/callback", methods=["GET"])
def google_callback():
    try:
        token = oauth.google.authorize_access_token(leeway=300)
        user_info = token.get("userinfo") or {}
        google_id = user_info.get("sub")
        email = user_info.get("email")
        name = user_info.get("name")

        if not google_id or not email:
            return jsonify({"error": "Google did not return required user info"}), 400

        db = SessionLocal()
        try:
            user = db.query(User).filter_by(google_id=google_id).first()
            is_new = user is None
            if is_new:
                user = User(google_id=google_id, email=email, name=name)
                db.add(user)
                db.flush()  # populate user.id before creating the linked Client
            else:
                user.email = email
                user.name = name
            db.commit()
            db.refresh(user)

            # Auto-create a Client for new users. For returning users, create one
            # only if they have none (handles accounts that pre-date this feature).
            if not db.query(Client).filter_by(user_id=user.id).first():
                client_name = (user.name or "").strip() or user.email
                db.add(Client(name=client_name, contact_email=user.email, user_id=user.id))
                db.commit()

            session["user_id"] = user.id
        finally:
            db.close()

        log_audit_event(
            user_id=session["user_id"],
            action="login_success",
            details={"email": email, "is_new_user": is_new},
            ip_address=request.remote_addr,
        )
        logger.info("OAuth callback: session user_id set to %s, redirecting to dashboard", session.get("user_id"))
        return redirect("http://localhost:5173/dashboard")

    except Exception as exc:
        logger.exception("OAuth callback failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/auth/me", methods=["GET"])
def auth_me():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    try:
        db = SessionLocal()
        try:
            user = db.get(User, user_id)
            if user is None:
                session.clear()
                return jsonify({"error": "User not found"}), 401
            result = {"id": user.id, "email": user.email, "name": user.name, "role": user.role}
        finally:
            db.close()

        return jsonify(result), 200

    except Exception as exc:
        logger.exception("Error in /api/auth/me")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "logged out"}), 200


# ── Client endpoints ─────────────────────────────────────────────────────────

@app.route("/api/clients", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def create_client():
    try:
        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name is required"}), 400

        db = SessionLocal()
        try:
            client = Client(
                name=name,
                contact_email=data.get("contact_email"),
                user_id=session["user_id"],
            )
            db.add(client)
            db.commit()
            db.refresh(client)
            result = _client_dict(client)
            client_id = client.id
            log_audit_event(
                user_id=session["user_id"],
                action="client_created",
                resource_type="client",
                resource_id=client_id,
                ip_address=request.remote_addr,
            )
        finally:
            db.close()

        return jsonify(result), 201

    except Exception as exc:
        logger.exception("Error creating client")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/clients", methods=["GET"])
def list_clients():
    try:
        db = SessionLocal()
        try:
            clients = db.query(Client).all()
            result = [_client_dict(c) for c in clients]
        finally:
            db.close()

        return jsonify(result), 200

    except Exception as exc:
        logger.exception("Error listing clients")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/clients/<int:client_id>", methods=["GET"])
def get_client(client_id):
    try:
        db = SessionLocal()
        try:
            client = db.get(Client, client_id)
            if client is None:
                return jsonify({"error": "Client not found"}), 404
            result = {
                **_client_dict(client),
                "targets": [
                    {
                        "id": t.id,
                        "scope": t.scope,
                        "authorized_by": t.authorized_by,
                        "schedule_cron": t.schedule_cron,
                        "skip_cve": t.skip_cve,
                    }
                    for t in client.targets
                ],
            }
        finally:
            db.close()

        return jsonify(result), 200

    except Exception as exc:
        logger.exception("Error fetching client %d", client_id)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/clients/<int:client_id>", methods=["DELETE"])
def delete_client(client_id):
    try:
        db = SessionLocal()
        try:
            client = db.get(Client, client_id)
            if client is None:
                return jsonify({"error": "Client not found"}), 404
            client_name = client.name  # capture BEFORE deletion
            db.delete(client)
            db.commit()
            log_audit_event(
                user_id=session.get("user_id"),
                action="client_deleted",
                resource_id=client_id,
                details={"name": client_name},
                ip_address=request.remote_addr,
            )
        finally:
            db.close()

        return jsonify({"deleted": client_id}), 200

    except Exception as exc:
        logger.exception("Error deleting client %d", client_id)
        return jsonify({"error": str(exc)}), 500


# ── Target endpoints ─────────────────────────────────────────────────────────

@app.route("/api/targets", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def create_target():
    try:
        data = request.get_json(silent=True) or {}
        client_id = data.get("client_id")
        scope = (data.get("scope") or "").strip()
        authorized_by = (data.get("authorized_by") or "").strip()

        if not client_id:
            return jsonify({"error": "client_id is required"}), 400
        if not scope:
            return jsonify({"error": "scope is required"}), 400
        if not authorized_by:
            return jsonify({"error": "authorized_by is required and must be non-empty"}), 400

        db = SessionLocal()
        try:
            client = db.get(Client, client_id)
            if client is None:
                return jsonify({"error": f"Client {client_id} not found"}), 404

            target = Target(
                client_id=client_id,
                scope=scope,
                authorized_by=authorized_by,
                schedule_cron=data.get("schedule_cron"),
                skip_cve=bool(data.get("skip_cve", False)),
            )
            db.add(target)
            db.commit()
            db.refresh(target)
            result = _target_dict(target)
            log_audit_event(
                user_id=session["user_id"],
                action="target_created",
                resource_type="target",
                resource_id=target.id,
                details={"scope": target.scope},
                ip_address=request.remote_addr,
            )
        finally:
            db.close()

        return jsonify(result), 201

    except Exception as exc:
        logger.exception("Error creating target")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/targets/<int:target_id>", methods=["GET"])
def get_target(target_id):
    try:
        db = SessionLocal()
        try:
            target = db.get(Target, target_id)
            if target is None:
                return jsonify({"error": "Target not found"}), 404
            result = {
                **_target_dict(target),
                "scan_runs": [_scan_run_summary(r) for r in target.scan_runs],
            }
        finally:
            db.close()

        return jsonify(result), 200

    except Exception as exc:
        logger.exception("Error fetching target %d", target_id)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/targets/<int:target_id>", methods=["DELETE"])
def delete_target(target_id):
    try:
        db = SessionLocal()
        try:
            target = db.get(Target, target_id)
            if target is None:
                return jsonify({"error": "Target not found"}), 404
            db.delete(target)
            db.commit()
        finally:
            db.close()

        return jsonify({"deleted": target_id}), 200

    except Exception as exc:
        logger.exception("Error deleting target %d", target_id)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/targets/<int:target_id>/verification-info", methods=["GET"])
@login_required
def get_verification_info(target_id):
    try:
        db = SessionLocal()
        try:
            target = db.get(Target, target_id)
            if target is None:
                return jsonify({"error": "Target not found"}), 404
            if target.client.user_id != session["user_id"]:
                return jsonify({"error": "Forbidden"}), 403
            token = target.verification_token
            domain = target.scope.split(",")[0].strip()
            result = {
                "target_id": target.id,
                "verified": target.verified,
                "verification_token": token,
                "dns_instructions": {
                    "record_type": "TXT",
                    "name": f"_secscan-verify.{domain}",
                    "value": f"secscan-verify-{token}",
                    "note": "Add this TXT record to your DNS zone, then POST to /verify with {\"method\": \"dns\"}",
                },
                "file_instructions": {
                    "path": "/.well-known/secscan-verify.txt",
                    "content": f"secscan-verify-{token}",
                    "note": f"Upload a file at https://{domain}/.well-known/secscan-verify.txt containing exactly the content above, then POST to /verify with {{\"method\": \"file\"}}",
                },
            }
        finally:
            db.close()
        return jsonify(result), 200
    except Exception as exc:
        logger.exception("Error fetching verification info for target %d", target_id)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/targets/<int:target_id>/verify", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def verify_target(target_id):
    try:
        data = request.get_json(silent=True) or {}
        method = data.get("method")

        db = SessionLocal()
        verified = False
        try:
            target = db.get(Target, target_id)
            if target is None:
                return jsonify({"error": "Target not found"}), 404
            if target.client.user_id != session["user_id"]:
                return jsonify({"error": "Forbidden"}), 403
            if method not in ("dns", "file"):
                return jsonify({"error": "method must be 'dns' or 'file'"}), 400

            domain = target.scope.split(",")[0].strip()
            token = target.verification_token

            if method == "dns":
                verified = check_dns_verification(domain, token)
            else:
                verified = check_file_verification(domain, token)

            if verified:
                target.verified = True
                target.verification_method = method
                target.verified_at = datetime.now(timezone.utc)
                db.commit()

            # Log every attempt (success or failure) — the result is in details.
            log_audit_event(
                user_id=session["user_id"],
                action="verification_attempted",
                resource_type="target",
                resource_id=target_id,
                details={"method": method, "result": "success" if verified else "failed"},
                ip_address=request.remote_addr,
            )
        finally:
            db.close()

        if verified:
            return jsonify({"verified": True, "method": method}), 200
        return jsonify({
            "verified": False,
            "message": "Verification check failed, please ensure the DNS record or file is correctly set up and try again.",
        }), 200
    except Exception as exc:
        logger.exception("Error verifying target %d", target_id)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/targets/<int:target_id>/scan", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def trigger_scan(target_id):
    try:
        db = SessionLocal()
        try:
            target = db.get(Target, target_id)
            if target is None:
                return jsonify({"error": "Target not found"}), 404

            # CRITICAL ENFORCEMENT POINT: this check is what actually prevents scanning
            # unverified/unowned targets — login + the verification endpoints exist to
            # support this one gate. Do not move or remove it.
            if not target.verified:
                return jsonify({
                    "error": "Target is not verified. Complete domain ownership verification before scanning.",
                    "verification_token": target.verification_token,
                }), 403

            scan_run = ScanRun(
                target_id=target.id,
                scan_id=str(uuid.uuid4()),
                status="pending",
            )
            db.add(scan_run)
            db.commit()
            db.refresh(scan_run)
            run_id = scan_run.id

            log_audit_event(
                user_id=session["user_id"],
                action="scan_triggered",
                resource_type="target",
                resource_id=target_id,
                ip_address=request.remote_addr,
            )
        finally:
            db.close()

        thread = threading.Thread(target=execute_scan, args=(run_id,), daemon=True)
        thread.start()
        logger.info("Scan run %d dispatched for target %d", run_id, target_id)

        return jsonify({"scan_run_id": run_id, "status": "pending"}), 202

    except Exception as exc:
        logger.exception("Error triggering scan for target %d", target_id)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/targets/<int:target_id>/schedule", methods=["PATCH"])
@login_required
def update_target_schedule(target_id):
    try:
        data = request.get_json(silent=True) or {}
        raw = data.get("schedule_cron")
        schedule_cron: str | None = raw.strip() if isinstance(raw, str) else None

        if schedule_cron:
            try:
                CronTrigger.from_crontab(schedule_cron)
            except Exception as exc:
                return jsonify({"error": f"Invalid cron expression: {exc}"}), 400

        db = SessionLocal()
        try:
            target = db.get(Target, target_id)
            if target is None:
                return jsonify({"error": "Target not found"}), 404
            if target.client.user_id != session["user_id"]:
                return jsonify({"error": "Forbidden"}), 403
            target.schedule_cron = schedule_cron or None
            db.commit()
            result = _target_dict(target)
        finally:
            db.close()

        sync_schedules()
        return jsonify(result), 200

    except Exception as exc:
        logger.exception("Error updating schedule for target %d", target_id)
        return jsonify({"error": str(exc)}), 500


# ── Scan run detail ──────────────────────────────────────────────────────────

@app.route("/api/scans/<int:scan_run_id>", methods=["GET"])
def get_scan_run(scan_run_id):
    try:
        db = SessionLocal()
        try:
            run = db.get(ScanRun, scan_run_id)
            if run is None:
                return jsonify({"error": "ScanRun not found"}), 404

            result: dict = {
                "id": run.id,
                "target_id": run.target_id,
                "scan_id": run.scan_id,
                "status": run.status,
                "started_at": _fmt_dt(run.started_at),
                "completed_at": _fmt_dt(run.completed_at),
                "error_message": run.error_message,
            }
            if run.status == "completed" and run.result_json:
                result["result"] = json.loads(run.result_json)
        finally:
            db.close()

        return jsonify(result), 200

    except Exception as exc:
        logger.exception("Error fetching scan run %d", scan_run_id)
        return jsonify({"error": str(exc)}), 500


# ── Scan diff endpoints ──────────────────────────────────────────────────────

@app.route("/api/targets/<int:target_id>/diff", methods=["GET"])
@login_required
def scan_diff(target_id):
    try:
        old_id = request.args.get("old_scan_id", type=int)
        new_id = request.args.get("new_scan_id", type=int)
        if old_id is None or new_id is None:
            return jsonify({"error": "old_scan_id and new_scan_id query params are required"}), 400

        db = SessionLocal()
        try:
            target = db.get(Target, target_id)
            if target is None:
                return jsonify({"error": "Target not found"}), 404
            if target.client.user_id != session["user_id"]:
                return jsonify({"error": "Forbidden"}), 403

            old_run = db.get(ScanRun, old_id)
            new_run = db.get(ScanRun, new_id)

            for run, run_id in ((old_run, old_id), (new_run, new_id)):
                if run is None:
                    return jsonify({"error": f"ScanRun {run_id} not found"}), 404
                if run.target_id != target_id:
                    return jsonify({"error": f"ScanRun {run_id} does not belong to target {target_id}"}), 400
                if run.status != "completed":
                    return jsonify({"error": "Both scans must be completed to compare"}), 400

            old_result = json.loads(old_run.result_json)
            new_result = json.loads(new_run.result_json)
        finally:
            db.close()

        return jsonify(compare_scans(old_result, new_result)), 200

    except Exception as exc:
        logger.exception("Error diffing scans for target %d", target_id)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/targets/<int:target_id>/latest-diff", methods=["GET"])
@login_required
def latest_diff(target_id):
    try:
        db = SessionLocal()
        try:
            target = db.get(Target, target_id)
            if target is None:
                return jsonify({"error": "Target not found"}), 404
            if target.client.user_id != session["user_id"]:
                return jsonify({"error": "Forbidden"}), 403

            completed_runs = (
                db.query(ScanRun)
                .filter_by(target_id=target_id, status="completed")
                .order_by(ScanRun.completed_at.desc())
                .limit(2)
                .all()
            )

            if len(completed_runs) < 2:
                return jsonify({
                    "message": (
                        f"Need at least 2 completed scans to show a diff. "
                        f"Currently have: {len(completed_runs)}"
                    )
                }), 200

            # completed_runs[0] is newer (desc order), [1] is older — compare older -> newer.
            old_result = json.loads(completed_runs[1].result_json)
            new_result = json.loads(completed_runs[0].result_json)
        finally:
            db.close()

        return jsonify(compare_scans(old_result, new_result)), 200

    except Exception as exc:
        logger.exception("Error computing latest diff for target %d", target_id)
        return jsonify({"error": str(exc)}), 500


# ── Admin endpoints ──────────────────────────────────────────────────────────

@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_list_users():
    try:
        db = SessionLocal()
        try:
            users = db.query(User).order_by(User.id).all()
            result = [
                {
                    "id": u.id,
                    "email": u.email,
                    "name": u.name,
                    "role": u.role,
                    "created_at": _fmt_dt(u.created_at),
                    "client_count": len(u.clients),
                }
                for u in users
            ]
        finally:
            db.close()
        return jsonify(result), 200
    except Exception as exc:
        logger.exception("Error in admin_list_users")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/admin/clients", methods=["GET"])
@admin_required
def admin_list_clients():
    try:
        db = SessionLocal()
        try:
            clients = db.query(Client).order_by(Client.id).all()
            result = [
                {
                    "id": c.id,
                    "name": c.name,
                    "contact_email": c.contact_email,
                    "user_id": c.user_id,
                    "owner_email": c.user.email if c.user else None,
                    "target_count": len(c.targets),
                    "created_at": _fmt_dt(c.created_at),
                }
                for c in clients
            ]
        finally:
            db.close()
        return jsonify(result), 200
    except Exception as exc:
        logger.exception("Error in admin_list_clients")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/admin/targets", methods=["GET"])
@admin_required
def admin_list_targets():
    try:
        db = SessionLocal()
        try:
            targets = db.query(Target).order_by(Target.id).all()
            result = [
                {
                    "id": t.id,
                    "scope": t.scope,
                    "verified": t.verified,
                    "client_id": t.client_id,
                    "client_name": t.client.name,
                    "owner_email": t.client.user.email if t.client.user else None,
                    "scan_count": len(t.scan_runs),
                    "created_at": _fmt_dt(t.created_at),
                }
                for t in targets
            ]
        finally:
            db.close()
        return jsonify(result), 200
    except Exception as exc:
        logger.exception("Error in admin_list_targets")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/admin/scans", methods=["GET"])
@admin_required
def admin_list_scans():
    try:
        try:
            page = max(1, int(request.args.get("page", 1)))
            per_page = min(200, max(1, int(request.args.get("per_page", 50))))
        except (ValueError, TypeError):
            return jsonify({"error": "page and per_page must be integers"}), 400

        db = SessionLocal()
        try:
            total = db.query(ScanRun).count()
            runs = (
                db.query(ScanRun)
                .order_by(ScanRun.id.desc())
                .offset((page - 1) * per_page)
                .limit(per_page)
                .all()
            )
            result = []
            for r in runs:
                target = r.target
                client = target.client
                result.append({
                    "id": r.id,
                    "scan_id": r.scan_id,
                    "status": r.status,
                    "started_at": _fmt_dt(r.started_at),
                    "completed_at": _fmt_dt(r.completed_at),
                    "target_id": r.target_id,
                    "target_scope": target.scope,
                    "client_id": client.id,
                    "client_name": client.name,
                    "owner_email": client.user.email if client.user else None,
                })
        finally:
            db.close()
        return jsonify({"page": page, "per_page": per_page, "total": total, "scans": result}), 200
    except Exception as exc:
        logger.exception("Error in admin_list_scans")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def admin_stats():
    try:
        db = SessionLocal()
        try:
            total_users = db.query(sa_func.count(User.id)).scalar()
            total_clients = db.query(sa_func.count(Client.id)).scalar()
            total_targets = db.query(sa_func.count(Target.id)).scalar()
            total_verified_targets = (
                db.query(sa_func.count(Target.id)).filter(Target.verified == True).scalar()
            )
            total_scans = db.query(sa_func.count(ScanRun.id)).scalar()

            scans_by_status = {"completed": 0, "failed": 0, "running": 0, "pending": 0}
            for status, count in (
                db.query(ScanRun.status, sa_func.count(ScanRun.id))
                .group_by(ScanRun.status)
                .all()
            ):
                if status in scans_by_status:
                    scans_by_status[status] = count

            # Sum severity counts from each completed scan's stored summary dict.
            # NOTE: This is O(n_completed_scans) and loads all result_json blobs into
            # memory. If this becomes a bottleneck, add a denormalized findings table
            # (or cache summary counts on ScanRun) to avoid full-scan JSON parsing on
            # every admin request.
            findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for (result_json,) in (
                db.query(ScanRun.result_json)
                .filter(ScanRun.status == "completed", ScanRun.result_json.isnot(None))
                .all()
            ):
                try:
                    summary = json.loads(result_json).get("summary", {})
                    for sev, cnt in summary.items():
                        if sev in findings_by_severity:
                            findings_by_severity[sev] += cnt
                except (json.JSONDecodeError, TypeError, AttributeError):
                    pass
        finally:
            db.close()

        return jsonify({
            "total_users": total_users,
            "total_clients": total_clients,
            "total_targets": total_targets,
            "total_verified_targets": total_verified_targets,
            "total_scans": total_scans,
            "scans_by_status": scans_by_status,
            "findings_by_severity": findings_by_severity,
        }), 200
    except Exception as exc:
        logger.exception("Error in admin_stats")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/admin/users/<int:target_user_id>/role", methods=["POST"])
@admin_required
def admin_set_user_role(target_user_id):
    try:
        data = request.get_json(silent=True) or {}
        role = data.get("role")
        if role not in ("admin", "customer"):
            return jsonify({"error": "role must be 'admin' or 'customer'"}), 400

        db = SessionLocal()
        try:
            user = db.get(User, target_user_id)
            if user is None:
                return jsonify({"error": "User not found"}), 404
            old_role = user.role
            user.role = role
            db.commit()
            result = {"id": user.id, "email": user.email, "role": user.role}
            log_audit_event(
                user_id=session["user_id"],
                action="role_changed",
                resource_type="user",
                resource_id=target_user_id,
                details={
                    "old_role": old_role,
                    "new_role": role,
                    "changed_by_user_id": session["user_id"],
                },
                ip_address=request.remote_addr,
            )
        finally:
            db.close()
        return jsonify(result), 200
    except Exception as exc:
        logger.exception("Error in admin_set_user_role")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/admin/audit-log", methods=["GET"])
@admin_required
def admin_audit_log():
    try:
        try:
            page = max(1, int(request.args.get("page", 1)))
            per_page = min(200, max(1, int(request.args.get("per_page", 50))))
        except (ValueError, TypeError):
            return jsonify({"error": "page and per_page must be integers"}), 400

        filter_user_id = request.args.get("user_id", type=int)
        filter_action = request.args.get("action")

        db = SessionLocal()
        try:
            q = db.query(AuditLog).order_by(AuditLog.id.desc())
            if filter_user_id is not None:
                q = q.filter(AuditLog.user_id == filter_user_id)
            if filter_action:
                q = q.filter(AuditLog.action == filter_action)

            total = q.count()
            entries = q.offset((page - 1) * per_page).limit(per_page).all()

            result = []
            for e in entries:
                user_email = None
                if e.user_id is not None:
                    u = db.get(User, e.user_id)
                    user_email = u.email if u else None
                result.append({
                    "id": e.id,
                    "user_id": e.user_id,
                    "user_email": user_email,
                    "action": e.action,
                    "resource_type": e.resource_type,
                    "resource_id": e.resource_id,
                    "details": json.loads(e.details) if e.details else None,
                    "ip_address": e.ip_address,
                    "created_at": _fmt_dt(e.created_at),
                })
        finally:
            db.close()

        return jsonify({"page": page, "per_page": per_page, "total": total, "entries": result}), 200
    except Exception as exc:
        logger.exception("Error in admin_audit_log")
        return jsonify({"error": str(exc)}), 500


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # load_dotenv=False: we already called load_dotenv() above with the correct
    # encoding — prevent Flask from re-trying with its default UTF-8 encoding.
    app.run(debug=True, port=5000, load_dotenv=False)
