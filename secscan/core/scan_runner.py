"""
Shared scan execution logic.

Used by both the web API (manual trigger via a daemon thread) and the
APScheduler background jobs (scheduled runs).  Neither caller should
duplicate this code.
"""

import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm.exc import ObjectDeletedError, StaleDataError

# Both are raised when an ORM row disappears while we hold a reference to it:
# - StaleDataError: UPDATE matched 0 rows (row deleted by another process/session)
# - ObjectDeletedError: SQLAlchemy can't reload expired attributes because the row is gone
_DeletedDuringScan = (StaleDataError, ObjectDeletedError)

from checks import admin_panels, cve_lookup, dns_check, http_headers, port_scan, tls_check
from core.orchestrator import ScanOrchestrator
from db.database import SessionLocal
from db.orm_models import ScanRun

logger = logging.getLogger(__name__)


def execute_scan(scan_run_id: int) -> None:
    """Run a pending ScanRun to completion.

    Opens its own DB session so it is safe to call from any thread.
    On failure the ScanRun is marked 'failed' with the error message stored.
    """
    db = SessionLocal()
    try:
        scan_run = db.get(ScanRun, scan_run_id)
        if scan_run is None:
            logger.error("execute_scan: ScanRun %d not found", scan_run_id)
            return

        target = scan_run.target
        scope_list = [s.strip() for s in target.scope.split(",")]
        authorized_by = target.authorized_by
        skip_cve = target.skip_cve

        scan_run.status = "running"
        scan_run.started_at = datetime.now(timezone.utc)
        try:
            db.commit()
        except _DeletedDuringScan:
            logger.warning(
                "Scan run %d: target was deleted before scan could start — aborting.",
                scan_run_id,
            )
            return

        orchestrator = ScanOrchestrator(
            target_scope=scope_list,
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

        try:
            scan_run.status = "completed"
            scan_run.completed_at = datetime.now(timezone.utc)
            scan_run.result_json = json.dumps(scan_result.to_dict())
            db.commit()
            logger.info(
                "Scan run %d completed — %d finding(s)", scan_run_id, len(scan_result.findings)
            )
        except _DeletedDuringScan:
            logger.warning(
                "Scan run %d: target was deleted while scan was running — "
                "results discarded cleanly (scan completed but could not be saved).",
                scan_run_id,
            )

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
            logger.exception(
                "Failed to persist failed status for scan run %d", scan_run_id
            )
    finally:
        db.close()
