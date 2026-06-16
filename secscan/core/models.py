from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Severity(Enum):
    # Integer values: higher = more severe, enabling natural sort by .value
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


class CheckType(Enum):
    OPEN_PORT = "open_port"
    WEAK_TLS = "weak_tls"
    EXPOSED_PANEL = "exposed_panel"
    OUTDATED_SOFTWARE = "outdated_software"
    DNS_MISCONFIG = "dns_misconfig"
    MISSING_HEADER = "missing_header"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    # --- mandatory fields (no defaults) ---
    scan_id: str
    check_type: CheckType
    target: str
    title: str
    description: str
    severity: Severity
    remediation: str
    # --- optional / auto-generated fields ---
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    port: Optional[int] = None
    cvss_score: Optional[float] = None
    cve_ids: list[str] = field(default_factory=list)
    evidence: str = ""
    discovered_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "check_type": self.check_type.value,
            "target": self.target,
            "port": self.port,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cve_ids": self.cve_ids,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "discovered_at": self.discovered_at,
        }


@dataclass
class ScanResult:
    # --- mandatory fields (no defaults) ---
    target_scope: list[str]
    authorized_by: str
    # --- auto-generated / optional fields ---
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = field(default_factory=_utc_now)
    completed_at: Optional[str] = None
    checks_run: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def summary(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity.name.lower()] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target_scope": self.target_scope,
            "authorized_by": self.authorized_by,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "checks_run": self.checks_run,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary(),
        }
