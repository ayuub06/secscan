import logging

import nmap

from core.models import CheckType, Finding, Severity

logger = logging.getLogger(__name__)

# port -> (service_name, severity, description)
RISKY_PORTS: dict[int, tuple[str, Severity, str]] = {
    21: (
        "FTP",
        Severity.HIGH,
        "FTP often transmits credentials in plaintext.",
    ),
    22: (
        "SSH",
        Severity.MEDIUM,
        "SSH exposed publicly is normal but should be monitored for "
        "brute-force attempts; flagging for awareness, not necessarily "
        "a misconfiguration.",
    ),
    23: (
        "Telnet",
        Severity.CRITICAL,
        "Telnet transmits all traffic including credentials unencrypted.",
    ),
    445: (
        "SMB",
        Severity.CRITICAL,
        "SMB exposed publicly has been the vector for major worms like WannaCry.",
    ),
    3306: (
        "MySQL",
        Severity.HIGH,
        "Database port exposed publicly allows direct connection attempts.",
    ),
    3389: (
        "RDP",
        Severity.HIGH,
        "Remote Desktop exposed publicly is a common ransomware entry point.",
    ),
    5432: (
        "PostgreSQL",
        Severity.HIGH,
        "Database port exposed publicly allows direct connection attempts.",
    ),
    6379: (
        "Redis",
        Severity.CRITICAL,
        "Redis has no authentication by default in many configs and allows "
        "full data access.",
    ),
    27017: (
        "MongoDB",
        Severity.CRITICAL,
        "MongoDB has historically been exposed with no auth, leading to mass "
        "data breaches.",
    ),
}

_REMEDIATION: dict[Severity, str] = {
    Severity.CRITICAL: (
        "Restrict access via firewall to known IPs or disable the service "
        "if not required publicly."
    ),
    Severity.HIGH: (
        "Restrict access via firewall to known IPs or disable the service "
        "if not required publicly."
    ),
    Severity.MEDIUM: (
        "Ensure strong authentication and monitor for brute-force attempts."
    ),
    Severity.LOW: "Review whether this service needs to be publicly accessible.",
    Severity.INFO: "Review whether this service needs to be publicly accessible.",
}


def run(target_scope: list[str], scan_id: str = "") -> list[Finding]:
    """Scan each target in target_scope for open ports and return Findings.

    Uses nmap TCP connect scan (-sT) with host-discovery disabled (-Pn) against
    the top 100 most common ports (--top-ports 100).

    -sT  : TCP connect scan — works without raw-socket privileges (no root needed).
    -Pn  : Skip ping/host-discovery; many hosts block ICMP and would appear
           "down" to nmap even when they are up and listening.
    --top-ports 100 : Limits to the 100 most commonly-seen ports to keep scan
           time reasonable for broad target scopes while still catching the most
           dangerous exposures.
    """
    # ── Guard: nmap binary must be on PATH ───────────────────────────────────
    try:
        scanner = nmap.PortScanner(nmap_search_path=(
            "nmap",
            r"C:\Program Files (x86)\Nmap\nmap.exe",
        ))
    except nmap.PortScannerError:
        logger.error(
            "nmap binary not found. Install Nmap from https://nmap.org and "
            "ensure it is on your system PATH, then retry."
        )
        return []

    findings: list[Finding] = []

    for target in target_scope:
        try:
            # Scan args explained in function docstring above
            scanner.scan(hosts=target, arguments="-sT -Pn --top-ports 100")
        except Exception:
            logger.warning(
                "port_scan: failed to scan target %r — skipping.", target
            )
            continue

        for host in scanner.all_hosts():
            if "tcp" not in scanner[host]:
                continue

            for port, port_data in scanner[host]["tcp"].items():
                if port_data.get("state") != "open":
                    continue

                # Build evidence string from nmap service fingerprint
                svc_name    = port_data.get("name", "")
                svc_product = port_data.get("product", "")
                svc_version = port_data.get("version", "")
                evidence_parts = filter(None, [svc_name, svc_product, svc_version])
                evidence = " ".join(evidence_parts).strip() or f"port {port}/tcp open"

                if port in RISKY_PORTS:
                    known_name, severity, description = RISKY_PORTS[port]
                    title = f"Open port {port} ({known_name})"
                else:
                    known_name = svc_name or "unknown"
                    severity   = Severity.INFO
                    description = "Open port detected, manual review recommended."
                    title = f"Open port {port} ({known_name})"

                findings.append(
                    Finding(
                        scan_id=scan_id,
                        check_type=CheckType.OPEN_PORT,
                        target=host,
                        port=port,
                        title=title,
                        description=description,
                        severity=severity,
                        evidence=evidence,
                        remediation=_REMEDIATION[severity],
                    )
                )

    return findings
