"""
Scan diff engine — compares two completed ScanResult dicts and classifies
findings as NEW, RESOLVED, PERSISTENT, or ESCALATED.
"""

import hashlib


def _finding_fingerprint(finding: dict) -> str:
    """Return a stable SHA-256 hex digest that identifies a finding across scan runs.

    Fields used to build the fingerprint: check_type, target, port, title.

    WHY these four and not others:

    INCLUDED:
    - check_type:  a categorically different check type is a different finding class
                   (e.g. "open_port" vs "missing_header" can never be the same issue).
    - target:      scans can cover multiple hosts; port-80 on host-A != port-80 on host-B.
    - port:        a service on port 22 is a different finding from the same check on port 443.
    - title:       a human-stable label written by the check module that names the specific
                   issue (e.g. "Open Port 22/tcp").  Two runs of the same check hitting the
                   same port on the same host produce the same title — this is its purpose.

    EXCLUDED:
    - id:            fresh UUID per finding per scan, purely ephemeral.
    - discovered_at: per-scan timestamp — always different even for the same underlying issue.
    - evidence:      free-text output (banner grabs, raw headers, nmap lines) that can vary
                     slightly between runs for the same issue — e.g. "Apache/2.4.41" vs
                     "Apache/2.4.52" — including it would cause the same finding to appear
                     as RESOLVED+NEW instead of PERSISTENT across a minor server upgrade.
    - description / remediation: written alongside title by the same check module; if title
                     matches these will too.  Redundant in the fingerprint, and a minor
                     wording edit in a check module update would falsely break continuity.
    - scan_id / cvss_score / cve_ids: per-scan or derived metadata, not stable identity fields.
    """
    raw = (
        f"{finding.get('check_type')}"
        f"|{finding.get('target')}"
        f"|{finding.get('port')}"
        f"|{finding.get('title')}"
    )
    return hashlib.sha256(raw.encode()).hexdigest()


def compare_scans(old_result: dict, new_result: dict) -> dict:
    """Compare two completed ScanResult dicts and classify every finding.

    Args:
        old_result: the earlier ScanResult.to_dict() output (baseline).
        new_result: the later ScanResult.to_dict() output (current).

    Returns:
        {
          "new_findings":        list of full finding dicts from new_result that
                                 were not present in old_result.
          "resolved_findings":   list of full finding dicts from old_result that
                                 are absent from new_result (i.e. fixed).
          "persistent_findings": list of full finding dicts from new_result that
                                 also appeared in old_result, with severity unchanged
                                 OR decreased (de-escalation is good news, not an alarm).
          "escalated_findings":  list of {"finding": <new dict>,
                                          "old_severity": int,
                                          "new_severity": int}
                                 for findings present in both scans whose severity
                                 *increased* in new_result (higher int = more severe).
          "summary":             counts + scan metadata for quick display.
        }

    Edge cases:
        - old_result has 0 findings: all new_result findings land in new_findings.
        - new_result has 0 findings: all old_result findings land in resolved_findings.
    """
    old_fps: dict[str, dict] = {
        _finding_fingerprint(f): f for f in old_result.get("findings", [])
    }
    new_fps: dict[str, dict] = {
        _finding_fingerprint(f): f for f in new_result.get("findings", [])
    }

    old_keys = set(old_fps)
    new_keys = set(new_fps)

    new_findings      = [new_fps[fp] for fp in (new_keys - old_keys)]
    resolved_findings = [old_fps[fp] for fp in (old_keys - new_keys)]

    persistent_findings: list[dict] = []
    escalated_findings: list[dict] = []

    for fp in old_keys & new_keys:
        old_f   = old_fps[fp]
        new_f   = new_fps[fp]
        old_sev = old_f.get("severity", 0)
        new_sev = new_f.get("severity", 0)
        if new_sev > old_sev:
            # Severity increased — flag for immediate attention.
            escalated_findings.append({
                "finding":      new_f,
                "old_severity": old_sev,
                "new_severity": new_sev,
            })
        else:
            # Same severity or de-escalated (still present, but improving or stable).
            persistent_findings.append(new_f)

    return {
        "new_findings":        new_findings,
        "resolved_findings":   resolved_findings,
        "persistent_findings": persistent_findings,
        "escalated_findings":  escalated_findings,
        "summary": {
            "new_count":        len(new_findings),
            "resolved_count":   len(resolved_findings),
            "persistent_count": len(persistent_findings),
            "escalated_count":  len(escalated_findings),
            "old_scan_id":      old_result.get("scan_id"),
            "new_scan_id":      new_result.get("scan_id"),
            "old_scan_date":    old_result.get("completed_at"),
            "new_scan_date":    new_result.get("completed_at"),
        },
    }
