import logging
import re
from datetime import datetime, timezone

from sslyze import (
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    Scanner,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerScanStatusEnum,
)

from core.models import CheckType, Finding, Severity

logger = logging.getLogger(__name__)

# Days-remaining threshold at which an expiring cert becomes a Medium finding
_CERT_WARN_DAYS = 30

# Cipher name patterns that indicate a weak/null/export/anonymous suite
_WEAK_CIPHER_RE = re.compile(r"NULL|EXPORT|ANON|RC4", re.IGNORECASE)

# The four TLS version commands we care about, paired with human labels and
# the exact attribute name they map to on AllScanCommandsAttempts
_VERSION_CHECKS: list[tuple[str, str, bool]] = [
    # (human_label,  AllScanCommandsAttempts attr,  is_deprecated)
    ("TLS 1.0", "tls_1_0_cipher_suites", True),
    ("TLS 1.1", "tls_1_1_cipher_suites", True),
    ("TLS 1.2", "tls_1_2_cipher_suites", False),
    ("TLS 1.3", "tls_1_3_cipher_suites", False),
]

_SCAN_COMMANDS = {
    ScanCommand.CERTIFICATE_INFO,
    ScanCommand.TLS_1_0_CIPHER_SUITES,
    ScanCommand.TLS_1_1_CIPHER_SUITES,
    ScanCommand.TLS_1_2_CIPHER_SUITES,
    ScanCommand.TLS_1_3_CIPHER_SUITES,
}


def run(target_scope: list[str], scan_id: str = "") -> list[Finding]:
    """Analyse TLS configuration on port 443 for each target and return Findings."""
    findings: list[Finding] = []
    for target in target_scope:
        try:
            _scan_one(target, scan_id, findings)
        except Exception:
            logger.warning(
                "tls_check: unexpected error scanning %r — skipping.",
                target,
                exc_info=True,
            )
    return findings


def _scan_one(target: str, scan_id: str, findings: list[Finding]) -> None:
    loc = ServerNetworkLocation(hostname=target, port=443)
    request = ServerScanRequest(server_location=loc, scan_commands=_SCAN_COMMANDS)

    scanner = Scanner()
    scanner.queue_scans([request])

    for result in scanner.get_results():
        # No TLS service on port 443 — not necessarily a misconfiguration,
        # many hosts legitimately don't run HTTPS.  Log silently and stop.
        if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            logger.debug(
                "tls_check: no TLS service reachable at %r:443 — no findings generated.",
                target,
            )
            return

        if result.scan_result is None:
            return

        sr = result.scan_result

        # ── Protocol & cipher suite analysis ─────────────────────────────────
        modern_supported = False  # tracks whether TLS 1.2 or 1.3 accepted anything

        for version_label, attr, is_deprecated in _VERSION_CHECKS:
            attempt = getattr(sr, attr)
            if attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
                continue

            accepted = attempt.result.accepted_cipher_suites

            if not accepted:
                continue

            if not is_deprecated:
                modern_supported = True

            # a) Deprecated protocol in use
            if is_deprecated:
                findings.append(Finding(
                    scan_id=scan_id,
                    check_type=CheckType.WEAK_TLS,
                    target=target,
                    port=443,
                    title=f"Deprecated TLS protocol enabled ({version_label})",
                    description=(
                        f"{version_label} has known vulnerabilities (BEAST, POODLE-adjacent "
                        "issues) and has been disabled by all major browsers. Its presence "
                        "indicates an outdated server configuration."
                    ),
                    severity=Severity.HIGH,
                    evidence=(
                        f"{version_label} accepted with {len(accepted)} cipher suite(s); "
                        f"first: {accepted[0].cipher_suite.name}"
                    ),
                    remediation=(
                        "Disable TLS 1.0 and 1.1 in server configuration, "
                        "support only TLS 1.2+."
                    ),
                ))

            # f) Weak/null/export/anonymous/RC4 cipher suites
            for cs_accepted in accepted:
                cipher_name = cs_accepted.cipher_suite.name
                if _WEAK_CIPHER_RE.search(cipher_name):
                    findings.append(Finding(
                        scan_id=scan_id,
                        check_type=CheckType.WEAK_TLS,
                        target=target,
                        port=443,
                        title=f"Weak cipher suite accepted: {cipher_name}",
                        description=(
                            f"The server accepts the weak cipher suite {cipher_name!r} "
                            f"on {version_label}. These ciphers provide little or no "
                            "cryptographic protection."
                        ),
                        severity=Severity.HIGH,
                        evidence=f"{version_label} — cipher: {cipher_name}",
                        remediation=(
                            "Disable weak/null/export-grade ciphers in server TLS configuration."
                        ),
                    ))

        # b) No modern TLS at all (only old protocols supported — worse than a)
        if not modern_supported:
            findings.append(Finding(
                scan_id=scan_id,
                check_type=CheckType.WEAK_TLS,
                target=target,
                port=443,
                title="No modern TLS protocol support detected",
                description=(
                    "The server does not support TLS 1.2 or TLS 1.3. Modern clients "
                    "require at least TLS 1.2; this server may be inaccessible to "
                    "standards-compliant clients and is vulnerable to downgrade attacks."
                ),
                severity=Severity.CRITICAL,
                evidence="Neither TLS 1.2 nor TLS 1.3 accepted any cipher suites.",
                remediation=(
                    "Server urgently needs TLS 1.2/1.3 support enabled; current "
                    "configuration is incompatible with modern security standards."
                ),
            ))

        # ── Certificate analysis ──────────────────────────────────────────────
        cert_attempt = sr.certificate_info
        if cert_attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
            return

        deployments = cert_attempt.result.certificate_deployments
        if not deployments or not deployments[0].received_certificate_chain:
            return

        leaf = deployments[0].received_certificate_chain[0]
        now_utc = datetime.now(timezone.utc)

        # c/d) Certificate expiry
        not_after = leaf.not_valid_after_utc  # timezone-aware UTC datetime
        not_after_str = not_after.strftime("%Y-%m-%d %H:%M:%S UTC")

        if not_after < now_utc:
            # c) Already expired
            findings.append(Finding(
                scan_id=scan_id,
                check_type=CheckType.WEAK_TLS,
                target=target,
                port=443,
                title="TLS certificate expired",
                description=f"The TLS certificate expired on {not_after_str}.",
                severity=Severity.CRITICAL,
                evidence=f"notAfter={not_after_str}",
                remediation="Renew the TLS certificate immediately.",
            ))
        else:
            days_left = (not_after - now_utc).days
            if days_left <= _CERT_WARN_DAYS:
                # d) Expiring soon
                findings.append(Finding(
                    scan_id=scan_id,
                    check_type=CheckType.WEAK_TLS,
                    target=target,
                    port=443,
                    title="TLS certificate expiring soon",
                    description=(
                        f"The TLS certificate expires on {not_after_str} "
                        f"({days_left} day(s) remaining)."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"notAfter={not_after_str}, days_remaining={days_left}",
                    remediation=(
                        "Renew the TLS certificate before it expires to avoid service disruption."
                    ),
                ))

        # e) Self-signed certificate (issuer == subject)
        if leaf.issuer == leaf.subject:
            findings.append(Finding(
                scan_id=scan_id,
                check_type=CheckType.WEAK_TLS,
                target=target,
                port=443,
                title="Self-signed TLS certificate detected",
                description=(
                    "The certificate is self-signed (issuer equals subject). "
                    "This triggers browser security warnings and provides no "
                    "third-party trust validation."
                ),
                severity=Severity.MEDIUM,
                evidence=f"issuer={leaf.issuer.rfc4514_string()!r}",
                remediation=(
                    "Replace with a certificate from a trusted CA "
                    "(e.g. Let's Encrypt for free certificates)."
                ),
            ))
