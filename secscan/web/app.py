"""
secscan Flask API — HTTP interface to the scan engine.

Run from the secscan/ package directory so that relative imports
(checks, core, db) resolve correctly:

    cd secscan/
    python web/app.py

Or via the venv:
    .venv/Scripts/python.exe secscan/web/app.py   (from project root)
"""

import json
import logging
import os
import sys
import threading
import uuid
from datetime import datetime, timezone

# Add secscan/ package root to sys.path so sibling packages (checks, core, db)
# resolve correctly regardless of where this script is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, request
from flask_cors import CORS

from checks import admin_panels, cve_lookup, dns_check, http_headers, port_scan, tls_check
from core.orchestrator import ScanOrchestrator
from core.target import UnauthorizedScanError
from db.database import SessionLocal, init_db
from db.orm_models import Client, ScanRun, Target

# ── App setup ────────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("secscan.web")

init_db()

# ── Helpers ──────────────────────────────────────────────────────────────────

def _fmt_dt(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt is not None else None


def _client_dict(client: Client) -> dict:
    return {
        "id": client.id,
        "name": client.name,
        "contact_email": client.contact_email,
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


# ── Background scan worker ───────────────────────────────────────────────────

def _run_scan_background(
    scan_run_id: int,
    target_scope: list[str],
    authorized_by: str,
    skip_cve: bool,
) -> None:
    """Executes in a daemon thread — owns its own DB session."""
    db = SessionLocal()
    try:
        scan_run = db.get(ScanRun, scan_run_id)
        scan_run.status = "running"
        scan_run.started_at = datetime.now(timezone.utc)
        db.commit()

        orchestrator = ScanOrchestrator(
            target_scope=target_scope,
            authorized_by=authorized_by,
        )
        orchestrator.register_check("port_scan",    port_scan.run)
        orchestrator.register_check("tls_check",    tls_check.run)
        orchestrator.register_check("http_headers", http_headers.run)
        orchestrator.register_check("dns_check",    dns_check.run)
        orchestrator.register_check("admin_panels", admin_panels.run)
        if not skip_cve:
            orchestrator.register_check("cve_lookup", cve_lookup.run, needs_findings=True)

        scan_result = orchestrator.run()

        scan_run.status = "completed"
        scan_run.completed_at = datetime.now(timezone.utc)
        scan_run.result_json = json.dumps(scan_result.to_dict())
        db.commit()
        logger.info("Scan run %d completed — %d finding(s)", scan_run_id, len(scan_result.findings))

    except Exception as exc:
        logger.exception("Scan run %d failed: %s", scan_run_id, exc)
        try:
            db.rollback()
            scan_run = db.get(ScanRun, scan_run_id)
            if scan_run is not None:
                scan_run.status = "failed"
                scan_run.error_message = str(exc)
                scan_run.completed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            logger.exception("Failed to persist failed status for scan run %d", scan_run_id)
    finally:
        db.close()


# ── Health ───────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# ── Client endpoints ─────────────────────────────────────────────────────────

@app.route("/api/clients", methods=["POST"])
def create_client():
    try:
        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name is required"}), 400

        db = SessionLocal()
        try:
            client = Client(name=name, contact_email=data.get("contact_email"))
            db.add(client)
            db.commit()
            db.refresh(client)
            result = _client_dict(client)
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
            db.delete(client)
            db.commit()
        finally:
            db.close()

        return jsonify({"deleted": client_id}), 200

    except Exception as exc:
        logger.exception("Error deleting client %d", client_id)
        return jsonify({"error": str(exc)}), 500


# ── Target endpoints ─────────────────────────────────────────────────────────

@app.route("/api/targets", methods=["POST"])
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


@app.route("/api/targets/<int:target_id>/scan", methods=["POST"])
def trigger_scan(target_id):
    try:
        db = SessionLocal()
        try:
            target = db.get(Target, target_id)
            if target is None:
                return jsonify({"error": "Target not found"}), 404

            scan_run = ScanRun(
                target_id=target.id,
                scan_id=str(uuid.uuid4()),
                status="pending",
            )
            db.add(scan_run)
            db.commit()
            db.refresh(scan_run)

            run_id = scan_run.id
            scope_list = [s.strip() for s in target.scope.split(",")]
            authorized_by = target.authorized_by
            skip_cve = target.skip_cve
        finally:
            db.close()

        thread = threading.Thread(
            target=_run_scan_background,
            args=(run_id, scope_list, authorized_by, skip_cve),
            daemon=True,
        )
        thread.start()
        logger.info("Scan run %d dispatched for target %d scope=%s", run_id, target_id, scope_list)

        return jsonify({"scan_run_id": run_id, "status": "pending"}), 202

    except Exception as exc:
        logger.exception("Error triggering scan for target %d", target_id)
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


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, port=5000)
