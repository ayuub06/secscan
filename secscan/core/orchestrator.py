"""
Central scan orchestrator for secscan.

Contract:
  - Two supported check function signatures:

    Standard checks (the common case):
        run(target_scope: list[str], scan_id: str) -> list[Finding]

    Findings-dependent checks (post-processors like cve_lookup):
        run(target_scope: list[str], scan_id: str,
            existing_findings: list[Finding]) -> list[Finding]
    Register these with needs_findings=True.  They receive all findings
    accumulated SO FAR in registration order, so dependent checks MUST be
    registered AFTER the checks they depend on.

  - Check modules MUST NOT raise uncaught exceptions that kill the whole scan.
    The orchestrator wraps every check in try/except and continues on failure,
    logging the full traceback so no finding data is silently lost.
  - Authorization is enforced exactly once, at the very start of run(), before
    any check function is invoked. An UnauthorizedScanError aborts immediately
    and propagates to the caller — no checks run, no ScanResult is produced.
  - Construction of ScanOrchestrator is intentionally side-effect-free: no I/O,
    no validation, no network access. All of that happens in run().
"""

import logging
import time
import traceback
from datetime import datetime, timezone
from typing import Callable

from core.models import CheckType, Finding, ScanResult, Severity
from core.target import UnauthorizedScanError, enforce_authorization

logger = logging.getLogger(__name__)

# Duplicated intentionally from core.models to avoid a circular import.
# core.models must not depend on orchestrator, and extracting a shared
# utils module just for one line would be premature.
def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanOrchestrator:
    """Central runner for a secscan scan session.

    Construction is side-effect-free — stores arguments only.
    All validation and I/O happens in run().
    """

    def __init__(self, target_scope: list[str], authorized_by: str) -> None:
        self.target_scope = target_scope
        self.authorized_by = authorized_by
        # Registry entries: name -> {"fn": Callable, "needs_findings": bool}
        self._checks: dict[str, dict] = {}

    def register_check(
        self,
        name: str,
        check_fn: Callable,
        needs_findings: bool = False,
    ) -> None:
        """Register a check callable under a unique name.

        Args:
            name:           Unique identifier for this check (e.g. "port_scan").
            check_fn:       The callable to invoke.  See module docstring for the
                            two supported signatures.
            needs_findings: If True, the check receives accumulated findings so far
                            as existing_findings=... keyword argument.  Register
                            findings-dependent checks AFTER their dependencies so
                            the dependency's output is already in the list.

        Raises:
            ValueError: if name is already registered (no silent overwrites).
        """
        if name in self._checks:
            raise ValueError(
                f"A check named {name!r} is already registered. "
                "Each check must have a unique name."
            )
        self._checks[name] = {"fn": check_fn, "needs_findings": needs_findings}

    def run(self) -> ScanResult:
        """Run all registered checks and return a completed ScanResult.

        Authorization is enforced first — UnauthorizedScanError propagates
        immediately, aborting before any check is invoked.

        Per-check exceptions are caught, logged with full traceback, and the
        scan continues with the remaining checks.

        Returns:
            ScanResult with all findings, checks_run list, and completed_at set.

        Raises:
            UnauthorizedScanError: if authorization is invalid (propagated from
                enforce_authorization, never caught here).
            ValueError: if target_scope contains an invalid entry (propagated
                from enforce_authorization -> parse_targets).
        """
        # ── Authorization gate ───────────────────────────────────────────────
        # UnauthorizedScanError and ValueError are intentionally NOT caught.
        # An authorization failure must hard-stop the scan.
        enforce_authorization(self.target_scope, self.authorized_by)

        # ── Result container ─────────────────────────────────────────────────
        scan_result = ScanResult(
            target_scope=self.target_scope,
            authorized_by=self.authorized_by,
        )

        # ── Execute checks ───────────────────────────────────────────────────
        for name, entry in self._checks.items():
            check_fn       = entry["fn"]
            needs_findings = entry["needs_findings"]

            logger.info("Running check: %s", name)
            t_start = time.monotonic()
            try:
                if needs_findings:
                    # Pass a snapshot of findings accumulated so far.
                    # The list object is shared (not copied), so the check sees
                    # exactly what the preceding checks produced.
                    findings = check_fn(
                        self.target_scope,
                        scan_result.scan_id,
                        existing_findings=scan_result.findings,
                    )
                else:
                    findings = check_fn(self.target_scope, scan_result.scan_id)

                elapsed = time.monotonic() - t_start
                scan_result.findings.extend(findings)
                scan_result.checks_run.append(name)
                logger.info(
                    "Check %r finished in %.3fs — %d finding(s) returned.",
                    name,
                    elapsed,
                    len(findings),
                )
            except Exception:
                elapsed = time.monotonic() - t_start
                # NOTE: CheckType has no CHECK_ERROR variant, so we do not
                # fabricate a Finding here — that would pollute severity counts
                # with a meaningless entry.  The failure is captured fully in
                # the log; checks_run is intentionally left without this name
                # so callers can detect the gap.
                logger.error(
                    "Check %r failed after %.3fs — scan continues:\n%s",
                    name,
                    elapsed,
                    traceback.format_exc(),
                )

        # ── Mark completion ──────────────────────────────────────────────────
        scan_result.completed_at = _utc_now()

        return scan_result
