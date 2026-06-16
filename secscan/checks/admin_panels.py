import json
import logging
import os

import requests
import urllib3

from core.models import CheckType, Finding, Severity

logger = logging.getLogger(__name__)

# ── Signature loading ─────────────────────────────────────────────────────────

_SIGNATURES_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "data", "signatures.json")
)

# Hardcoded fallback — used only if signatures.json is missing or empty ({}).
# Keep this in sync with signatures.json; it exists purely as a safety net so
# the check still runs even in a fresh clone before the data file is populated.
_DEFAULT_SIGNATURES: list[dict] = [
    {
        "name": "phpMyAdmin",
        "path": "/phpmyadmin/",
        "match_type": "content_contains",
        "match_value": "phpMyAdmin",
        "severity": "HIGH",
        "description": (
            "phpMyAdmin provides a web interface for direct database access and "
            "management; public exposure allows brute-force attacks and may lead "
            "to full database compromise."
        ),
        "remediation": (
            "Move phpMyAdmin behind a VPN or IP allowlist, or remove it entirely "
            "from internet-facing servers and use a local or tunnelled connection instead."
        ),
    },
    {
        "name": ".env file",
        "path": "/.env",
        "match_type": "status_code",
        "match_value": 200,
        "severity": "CRITICAL",
        "description": (
            "An exposed .env file typically contains plaintext application secrets: "
            "database credentials, API keys, encryption keys, and third-party service tokens."
        ),
        "remediation": (
            "Remove this file from the publicly served directory immediately and rotate "
            "every credential and key it contained, as they must be considered fully compromised."
        ),
    },
    {
        "name": ".git config",
        "path": "/.git/config",
        "match_type": "content_contains",
        "match_value": "[core]",
        "severity": "CRITICAL",
        "description": (
            "An exposed .git directory allows an attacker to reconstruct the full source "
            "code history, including secrets that were committed and later deleted."
        ),
        "remediation": (
            "Remove or block the .git directory from web-accessible paths immediately. "
            "Treat all previously committed secrets as compromised and rotate them."
        ),
    },
    {
        "name": "WordPress admin",
        "path": "/wp-admin/",
        "match_type": "status_code",
        "match_value": 302,
        "severity": "MEDIUM",
        "description": (
            "WordPress admin login endpoint is publicly reachable. This is a target for "
            "credential stuffing and brute-force attacks."
        ),
        "remediation": (
            "Add IP allowlisting, two-factor authentication, or a WAF rule limiting login "
            "attempts. Consider moving wp-login.php to a non-standard path."
        ),
    },
    {
        "name": "Jenkins",
        "path": "/jenkins/",
        "match_type": "content_contains",
        "match_value": "Jenkins",
        "severity": "HIGH",
        "description": (
            "Jenkins automation server is publicly accessible. Depending on version and "
            "configuration, this may allow unauthenticated job execution or remote code execution."
        ),
        "remediation": (
            "Place Jenkins behind a VPN or IP allowlist. Ensure authentication is enforced "
            "and the instance is on a current, patched version."
        ),
    },
    {
        "name": "Tomcat Manager",
        "path": "/manager/html",
        "match_type": "content_contains",
        "match_value": "Tomcat Web Application Manager",
        "severity": "HIGH",
        "description": (
            "The Tomcat manager interface is publicly accessible. It allows deployment of "
            "arbitrary WAR files, which can trivially achieve remote code execution."
        ),
        "remediation": (
            "Restrict the /manager path to localhost or an internal network only. "
            "Never expose Tomcat Manager to the internet."
        ),
    },
    {
        "name": "Generic admin panel",
        "path": "/admin/",
        "match_type": "status_code",
        "match_value": 200,
        "severity": "MEDIUM",
        "description": (
            "A generic admin interface was found publicly accessible. This may be an "
            "intentional public-facing login page or inadvertent exposure of an internal panel."
        ),
        "remediation": (
            "Restrict access via IP allowlist, VPN, or additional authentication. If the "
            "panel is not intended to be public, remove it from the internet-facing configuration."
        ),
    },
    {
        "name": "Apache server-status",
        "path": "/server-status",
        "match_type": "content_contains",
        "match_value": "Apache Server Status",
        "severity": "MEDIUM",
        "description": (
            "Apache mod_status exposes real-time server metrics including active requests, "
            "client IPs, and full request URIs, which aids attacker reconnaissance."
        ),
        "remediation": (
            "Disable mod_status or restrict access to trusted IPs only via "
            "'Require ip 127.0.0.1' in the Apache configuration."
        ),
    },
]

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
    "INFO":     Severity.INFO,
}

# Generic fallback remediation strings keyed by severity, used when a signature
# doesn't supply its own remediation field.
_DEFAULT_REMEDIATION: dict[Severity, str] = {
    Severity.CRITICAL: (
        "Remove this file or interface from the publicly served directory immediately "
        "and rotate any credentials or secrets it may have exposed."
    ),
    Severity.HIGH: (
        "Restrict access via IP allowlist or VPN. "
        "Disable the interface entirely if it is not required to be internet-facing."
    ),
    Severity.MEDIUM: (
        "Restrict access via IP allowlist, VPN, or authentication. "
        "Remove the file or interface if not needed in production."
    ),
    Severity.LOW: "Review whether this endpoint needs to be publicly accessible.",
    Severity.INFO: "Review whether this endpoint needs to be publicly accessible.",
}


def _load_signatures() -> list[dict]:
    """Load signatures from JSON file; fall back to hardcoded defaults if needed."""
    try:
        with open(_SIGNATURES_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        if not data:
            raise ValueError("signatures.json is empty")
        logger.debug(
            "admin_panels: loaded %d signature(s) from %s", len(data), _SIGNATURES_PATH
        )
        return data
    except FileNotFoundError:
        logger.warning(
            "admin_panels: %s not found — using hardcoded default signatures.",
            _SIGNATURES_PATH,
        )
    except Exception as exc:
        logger.warning(
            "admin_panels: could not load %s (%s) — using hardcoded default signatures.",
            _SIGNATURES_PATH,
            exc,
        )
    return _DEFAULT_SIGNATURES


# Loaded once at import time so the file isn't re-read on every scan call.
SIGNATURES: list[dict] = _load_signatures()


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _resolve_base(target: str) -> tuple[str, int, bool]:
    """Determine the working scheme for target.

    Returns (base_url, port, ssl_verify).  Probes the root path with a HEAD
    request to avoid downloading a full response just for scheme detection.

    Strategy (same as http_headers.py):
      1. HTTPS with cert verification.
      2. On SSLError: retry HTTPS with verify=False.
      3. On full connection error: fall back to HTTP.
    """
    https_url = f"https://{target}"
    http_url  = f"http://{target}"

    try:
        requests.head(https_url, timeout=10, verify=True, allow_redirects=False)
        return https_url, 443, True
    except requests.exceptions.SSLError:
        try:
            requests.head(https_url, timeout=10, verify=False, allow_redirects=False)
            return https_url, 443, False
        except requests.exceptions.RequestException:
            pass  # HTTPS completely broken; try plain HTTP
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        pass  # No HTTPS listener; try plain HTTP

    # Raises RequestException if HTTP is also unreachable
    requests.head(http_url, timeout=10, allow_redirects=False)
    return http_url, 80, True


# ── Main check ────────────────────────────────────────────────────────────────

def run(target_scope: list[str], scan_id: str = "") -> list[Finding]:
    """Probe each target for exposed admin panels and sensitive files."""
    # Suppress InsecureRequestWarning when verify=False is used
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    findings: list[Finding] = []

    for target in target_scope:
        try:
            base_url, port, ssl_verify = _resolve_base(target)
        except Exception:
            logger.debug(
                "admin_panels: could not reach %r on HTTPS or HTTP — skipping.",
                target,
                exc_info=True,
            )
            continue

        logger.info(
            "admin_panels: probing %s with %d signature(s).",
            base_url,
            len(SIGNATURES),
        )

        for sig in SIGNATURES:
            # NOTE: In a real multi-target scan, add a small delay here (e.g.
            # time.sleep(0.1)) to be considerate to the target server and
            # reduce the chance of triggering rate-limiting or WAF blocks.
            # Omitted here because our primary test target is localhost.
            try:
                _probe_signature(
                    sig, base_url, port, ssl_verify, target, scan_id, findings
                )
            except Exception:
                logger.debug(
                    "admin_panels: probe failed for %r at %r — continuing.",
                    sig.get("name"),
                    sig.get("path"),
                    exc_info=True,
                )

    return findings


def _probe_signature(
    sig: dict,
    base_url: str,
    port: int,
    ssl_verify: bool,
    target: str,
    scan_id: str,
    findings: list[Finding],
) -> None:
    path       = sig["path"]
    full_url   = f"{base_url}{path}"
    match_type = sig["match_type"]
    match_value = sig["match_value"]
    severity   = _SEVERITY_MAP.get(sig["severity"].upper(), Severity.MEDIUM)
    name       = sig["name"]

    resp = requests.get(
        full_url,
        timeout=10,
        verify=ssl_verify,
        allow_redirects=False,  # redirect to login != direct exposure
    )

    matched = False
    evidence_extra = ""

    if match_type == "status_code":
        matched = resp.status_code == match_value
    elif match_type == "content_contains":
        if resp.status_code == 200 and match_value.lower() in resp.text.lower():
            matched = True
            # Include a snippet of the matched content as supporting evidence
            idx = resp.text.lower().find(match_value.lower())
            snippet = resp.text[max(0, idx - 20) : idx + len(match_value) + 80].strip()
            evidence_extra = f" | snippet: {snippet[:100]!r}"

    if not matched:
        return

    description  = sig.get("description") or (
        f"A {name} interface or sensitive file was found publicly accessible, "
        "which significantly increases the attack surface."
    )
    remediation  = sig.get("remediation") or _DEFAULT_REMEDIATION[severity]

    findings.append(Finding(
        scan_id=scan_id,
        check_type=CheckType.EXPOSED_PANEL,
        target=target,
        port=port,
        title=f"Exposed {name} detected at {path}",
        description=description,
        severity=severity,
        evidence=f"GET {full_url} returned status {resp.status_code}{evidence_extra}",
        remediation=remediation,
    ))
    logger.info("admin_panels: MATCH — %s at %s", name, full_url)
