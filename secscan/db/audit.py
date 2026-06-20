"""
Audit logging helper.

log_audit_event() is the single call site for all security-relevant
events.  It opens its own DB session so that:
  - Audit writes are never rolled back if the calling endpoint fails.
  - Audit failures never roll back the caller's main transaction.
  - Callers don't need to keep their own session open until after logging.
"""

import json
import logging

from db.database import SessionLocal
from db.orm_models import AuditLog

logger = logging.getLogger(__name__)


def log_audit_event(
    user_id: int | None,
    action: str,
    resource_type: str | None = None,
    resource_id: int | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """Insert one AuditLog row.  Never raises — all exceptions are swallowed and logged.

    Args:
        user_id:       The secscan User.id performing the action, or None for
                       anonymous/pre-login events.
        action:        Short snake_case label (e.g. "scan_triggered", "role_changed").
        resource_type: The type of object being acted on ("target", "client", …).
        resource_id:   The integer PK of that object, if applicable.
        details:       Arbitrary dict with action-specific context; stored as JSON.
        ip_address:    request.remote_addr from the caller.
    """
    db = SessionLocal()
    try:
        entry = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=json.dumps(details) if details is not None else None,
            ip_address=ip_address,
        )
        db.add(entry)
        db.commit()
    except Exception:
        logger.exception("audit: failed to write entry action=%r user_id=%s", action, user_id)
        try:
            db.rollback()
        except Exception:
            pass
    finally:
        db.close()
