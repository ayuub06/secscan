"""
APScheduler integration for secscan — background scan scheduling.

Lifecycle:
  start_scheduler()  — call once at app startup after init_db().
  sync_schedules()   — re-syncs DB target schedules to APScheduler jobs;
                       called once on startup and then every 5 minutes so
                       schedule edits take effect without a restart.

Job IDs follow the pattern "target-<id>" so sync_schedules() is idempotent:
replace_existing=True ensures re-running it updates rather than duplicates jobs.
"""

import logging
import uuid

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from core.scan_runner import execute_scan
from db.database import SessionLocal
from db.orm_models import ScanRun, Target

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()


def run_scheduled_scan(target_id: int) -> None:
    """APScheduler job entry point for a single scheduled target.

    Silently skips if the target no longer exists or is not verified —
    there is no user watching a scheduled run, so we log a warning rather
    than raising.  Creates a ScanRun record, then delegates to execute_scan().
    """
    db = SessionLocal()
    run_id: int | None = None
    target_scope: str | None = None
    try:
        target = db.get(Target, target_id)
        if target is None:
            logger.warning("Scheduled scan skipped: target %d no longer exists", target_id)
            return
        if not target.verified:
            logger.warning(
                "Scheduled scan skipped: target %d (%s) is not verified",
                target_id, target.scope,
            )
            return

        target_scope = target.scope
        scan_run = ScanRun(
            target_id=target_id,
            scan_id=str(uuid.uuid4()),
            status="pending",
        )
        db.add(scan_run)
        db.commit()
        db.refresh(scan_run)
        run_id = scan_run.id
    except Exception:
        logger.exception("Failed to create ScanRun for scheduled target %d", target_id)
        return
    finally:
        db.close()

    logger.info(
        "Scheduled scan fired for target %d (scope=%r), scan_run_id=%d",
        target_id, target_scope, run_id,
    )
    execute_scan(run_id)


def sync_schedules() -> None:
    """Sync target cron schedules from the DB into APScheduler.

    Idempotent: adds new jobs, replaces changed jobs, removes jobs for targets
    whose schedule_cron was cleared.  Safe to call from any thread.
    """
    db = SessionLocal()
    try:
        targets = (
            db.query(Target)
            .filter(Target.schedule_cron.isnot(None))
            .all()
        )
        active_job_ids: set[str] = set()
        for target in targets:
            job_id = f"target-{target.id}"
            try:
                scheduler.add_job(
                    run_scheduled_scan,
                    trigger=CronTrigger.from_crontab(target.schedule_cron),
                    id=job_id,
                    args=[target.id],
                    replace_existing=True,
                )
                active_job_ids.add(job_id)
                logger.info(
                    "Synced job %s: cron=%r scope=%r", job_id, target.schedule_cron, target.scope
                )
            except Exception:
                logger.exception(
                    "Failed to schedule target %d (cron=%r)", target.id, target.schedule_cron
                )
    finally:
        db.close()

    for job in scheduler.get_jobs():
        if job.id.startswith("target-") and job.id not in active_job_ids:
            scheduler.remove_job(job.id)
            logger.info("Removed stale scheduled job %s", job.id)


def start_scheduler() -> None:
    """Start APScheduler. Call once at app startup, after init_db()."""
    sync_schedules()
    scheduler.add_job(
        sync_schedules, "interval", minutes=5, id="sync_schedules", replace_existing=True
    )
    if not scheduler.running:
        scheduler.start()
    logger.info("APScheduler started — %d job(s) loaded", len(scheduler.get_jobs()))
