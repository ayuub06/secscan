"""
Post-processing check that enriches port_scan findings with NVD CVE data.

This module does NOT probe the network itself — it reads the findings already
produced by port_scan.py, extracts service/version information from their
evidence strings, and queries the public NVD CVE API to surface known
vulnerabilities for those specific versions.

Because of the non-standard signature (existing_findings parameter), this
check MUST be wired differently in the orchestrator compared to other checks.
See the NOTE in run() and the comment about orchestrator wiring below.
"""

import json
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

from core.models import CheckType, Finding, Severity

logger = logging.getLogger(__name__)

# ── NVD API ───────────────────────────────────────────────────────────────────

# Public NVD CVE API 2.0 — no key required for low-volume use.
# Rate limit without key: 5 requests per 30 seconds → sleep 6s between calls.
# NOTE: Register a free API key at https://nvd.nist.gov/developers/request-an-api-key
# and set NVD_API_KEY in the project's .env file (python-dotenv is already a
# dependency) to raise the limit to 50 requests/30 seconds in production.
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_RATE_LIMIT_SLEEP = 6   # seconds; keeps us safely under 5 req/30 s
_CACHE_TTL_DAYS = 7
_MAX_CVES_PER_SERVICE = 20  # cap per-service results to keep findings manageable

# ── SQLite cache ──────────────────────────────────────────────────────────────

_CACHE_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "data", "cve_cache.db")
)


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_CACHE_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            service_version TEXT PRIMARY KEY,
            cve_data        TEXT NOT NULL,
            cached_at       TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def _cache_get(key: str) -> Optional[list[dict]]:
    try:
        with _get_conn() as conn:
            row = conn.execute(
                "SELECT cve_data, cached_at FROM cve_cache WHERE service_version = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        cached_at = datetime.fromisoformat(row[1])
        if datetime.now(timezone.utc) - cached_at > timedelta(days=_CACHE_TTL_DAYS):
            logger.debug("cve_lookup: cache stale for %r — will re-query.", key)
            return None
        return json.loads(row[0])
    except Exception as exc:
        logger.debug("cve_lookup: cache read error: %s", exc)
        return None


def _cache_set(key: str, data: list[dict]) -> None:
    try:
        with _get_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cve_cache (service_version, cve_data, cached_at) "
                "VALUES (?, ?, ?)",
                (key, json.dumps(data), datetime.now(timezone.utc).isoformat()),
            )
    except Exception as exc:
        logger.debug("cve_lookup: cache write error: %s", exc)


# ── Evidence parsing ──────────────────────────────────────────────────────────

# port_scan.py builds evidence as:
#   " ".join(filter(None, [svc_name, svc_product, svc_version])).strip()
# Typical formats:
#   "ssh OpenSSH 7.4"       → product="OpenSSH"  version="7.4"
#   "mysql MySQL 5.5.62"    → product="MySQL"     version="5.5.62"
#   "http Apache httpd 2.4.41-debian" → product="httpd" version="2.4.41-debian"
#   "msrpc"                 → None  (no version, skip)
#   "port 135/tcp open"     → None  (fallback string, no product/version)
#
# Heuristic: find the rightmost word that looks like a version (starts with a
# digit and contains at least one dot) and treat the word immediately before it
# as the product name.  This is intentionally permissive — false positives are
# better than false negatives here (a bad NVD query just returns no results).
_VERSION_TOKEN_RE = re.compile(r"^(\d[\d.]*)(?:-[\w.]+)?$")


def _extract_service_version(evidence: str) -> Optional[tuple[str, str]]:
    tokens = evidence.split()
    for i in range(len(tokens) - 1, 0, -1):
        m = _VERSION_TOKEN_RE.match(tokens[i])
        if m:
            return tokens[i - 1], tokens[i]
    return None


# ── CVSS helpers ──────────────────────────────────────────────────────────────

def _cvss_score(metrics: dict) -> Optional[float]:
    # Prefer CVSS v3.1 → v3.0 → v2. v2 scores are not directly comparable to
    # v3 scores but serve as a last-resort fallback when only v2 data exists.
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            return float(entries[0]["cvssData"]["baseScore"])
    return None


def _severity_from_score(score: Optional[float]) -> Severity:
    if score is None:
        return Severity.MEDIUM  # unknown score → assume medium for triage
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


# ── NVD query ─────────────────────────────────────────────────────────────────

def _query_nvd(product: str, version: str) -> list[dict]:
    """Query NVD for CVEs matching product+version; cache results for 7 days.

    Returns a list of dicts: [{id, description, cvss_score}, ...]
    Returns [] on any network/parse failure (caller logs and moves on).
    """
    key = f"{product} {version}"

    cached = _cache_get(key)
    if cached is not None:
        logger.debug("cve_lookup: cache hit for %r (%d CVE(s)).", key, len(cached))
        return cached

    # Sleep BEFORE the request to honour the rate limit even in a burst of calls.
    logger.debug("cve_lookup: sleeping %ds before NVD request for %r.", _RATE_LIMIT_SLEEP, key)
    time.sleep(_RATE_LIMIT_SLEEP)

    try:
        resp = requests.get(
            NVD_API_URL,
            params={
                "keywordSearch":  key,
                "resultsPerPage": _MAX_CVES_PER_SERVICE,
            },
            timeout=20,
        )
        if resp.status_code == 429:
            logger.warning(
                "cve_lookup: NVD API rate-limited (429) for %r — skipping.", key
            )
            return []
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.warning("cve_lookup: NVD request failed for %r: %s", key, exc)
        return []

    results: list[dict] = []
    for vuln_wrapper in data.get("vulnerabilities", []):
        cve = vuln_wrapper.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        descriptions = cve.get("descriptions", [])
        en_desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )
        short_desc = en_desc[:200]

        score = _cvss_score(cve.get("metrics", {}))

        results.append({"id": cve_id, "description": short_desc, "cvss_score": score})

    logger.debug("cve_lookup: NVD returned %d CVE(s) for %r.", len(results), key)
    _cache_set(key, results)
    return results


# ── Main entry point ──────────────────────────────────────────────────────────

# NOTE: Because run() requires existing_findings, its signature breaks the
# standard check contract of `run(target_scope, scan_id) -> list[Finding]`.
# The orchestrator's current generic `check_fn(self.target_scope, scan_result.scan_id)`
# call will NOT work for this check as-is.  The wiring fix (passing existing
# findings through, or registering this check via a wrapper lambda) must be
# handled in cli.py / orchestrator setup.  Do not modify orchestrator.py until
# that step — see the cli.py implementation task.

def run(
    target_scope: list[str],
    scan_id: str = "",
    existing_findings: Optional[list[Finding]] = None,
) -> list[Finding]:
    """Enrich open-port findings with NVD CVE data.

    This check is a POST-PROCESSOR, not a network probe.  It must run AFTER
    port_scan in the orchestrator's registration order and requires access to
    port_scan's output via existing_findings.  target_scope is accepted for
    API compatibility but is unused — CVE lookup is driven entirely by what
    port_scan already found.

    Returns NEW Finding objects for each matched CVE; the original port_scan
    findings are left untouched.
    """
    if not existing_findings:
        logger.warning(
            "cve_lookup: existing_findings is empty — nothing to enrich. "
            "Ensure port_scan has run before cve_lookup."
        )
        return []

    new_findings: list[Finding] = []

    port_findings = [
        f for f in existing_findings
        if f.check_type == CheckType.OPEN_PORT and f.evidence
    ]
    logger.info("cve_lookup: enriching %d open-port finding(s).", len(port_findings))

    for finding in port_findings:
        parsed = _extract_service_version(finding.evidence)
        if parsed is None:
            logger.debug(
                "cve_lookup: could not extract product/version from evidence %r — skipping.",
                finding.evidence,
            )
            continue

        product, version = parsed
        logger.info("cve_lookup: querying NVD for %s %s ...", product, version)
        cves = _query_nvd(product, version)

        for cve in cves:
            cve_id    = cve["id"]
            score     = cve["cvss_score"]
            severity  = _severity_from_score(score)
            new_findings.append(Finding(
                scan_id=scan_id,
                check_type=CheckType.OUTDATED_SOFTWARE,
                target=finding.target,
                port=finding.port,
                title=f"Known vulnerability in {product} {version}: {cve_id}",
                description=cve["description"],
                severity=severity,
                cvss_score=score,
                cve_ids=[cve_id],
                evidence=(
                    f"Detected {product} {version} via port scan; "
                    "matched against NVD CVE database."
                ),
                remediation=(
                    f"Upgrade {product} beyond version {version} to a patched release; "
                    "consult vendor advisories for the specific safe version."
                ),
            ))

    logger.info("cve_lookup: generated %d CVE finding(s).", len(new_findings))
    return new_findings
