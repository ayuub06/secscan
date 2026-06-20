"""
Reconstruct ScanResult for scan_run_id=4 from the DB's result_json
and write a polished HTML report to secscan/real_pilot_report.html.
"""
import json
import os
import sys

sys.path.insert(0, ".")

from db.database import SessionLocal
from db.orm_models import ScanRun
from db.user_model import User  # noqa: F401 — must be imported before ORM mapper resolves relationships
from core.models import CheckType, Finding, ScanResult, Severity
from reports.generator import generate_html

SCAN_RUN_ID = 4
OUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "secscan", "real_pilot_report.html",
)

# ── Fetch from DB ─────────────────────────────────────────────────────────────
db = SessionLocal()
try:
    run = db.query(ScanRun).filter_by(id=SCAN_RUN_ID).first()
    if run is None:
        print(f"ERROR: ScanRun id={SCAN_RUN_ID} not found in DB")
        sys.exit(1)
    print(f"Fetched ScanRun #{run.id}  status={run.status!r}  "
          f"scan_id={run.scan_id!r}")
    raw = json.loads(run.result_json)
finally:
    db.close()

# ── Rebuild Finding objects ───────────────────────────────────────────────────
# JSON stores: check_type as string value, severity as int value
_check_by_value = {ct.value: ct for ct in CheckType}
_sev_by_value   = {sv.value: sv for sv in Severity}

findings = []
for fd in raw.get("findings", []):
    findings.append(Finding(
        id           = fd["id"],
        scan_id      = fd["scan_id"],
        check_type   = _check_by_value[fd["check_type"]],
        target       = fd["target"],
        port         = fd.get("port"),
        title        = fd["title"],
        description  = fd["description"],
        severity     = _sev_by_value[fd["severity"]],
        cvss_score   = fd.get("cvss_score"),
        cve_ids      = fd.get("cve_ids") or [],
        evidence     = fd.get("evidence", ""),
        remediation  = fd["remediation"],
        discovered_at= fd.get("discovered_at", ""),
    ))

# ── Rebuild ScanResult ────────────────────────────────────────────────────────
scan_result = ScanResult(
    scan_id      = raw["scan_id"],
    target_scope = raw["target_scope"],
    authorized_by= raw["authorized_by"],
    started_at   = raw["started_at"],
    completed_at = raw.get("completed_at"),
    checks_run   = raw.get("checks_run", []),
    findings     = findings,
)

print(f"Reconstructed ScanResult: {len(findings)} finding(s), "
      f"summary={scan_result.summary()}")

# ── Generate HTML ─────────────────────────────────────────────────────────────
html = generate_html(scan_result)

os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
with open(OUT_PATH, "w", encoding="utf-8") as fh:
    fh.write(html)

size = os.path.getsize(OUT_PATH)
print(f"\nWritten to : {OUT_PATH}")
print(f"File size  : {size:,} bytes  ({size/1024:.1f} KB)")
