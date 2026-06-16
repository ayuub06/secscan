import logging
import re

import requests

from core.models import CheckType, Finding, Severity

logger = logging.getLogger(__name__)

# header_name -> (severity, description, remediation)
SECURITY_HEADERS: dict[str, tuple[Severity, str, str]] = {
    "Strict-Transport-Security": (
        Severity.MEDIUM,
        "HSTS header missing, allows protocol downgrade attacks forcing users onto unencrypted HTTP.",
        "Add Strict-Transport-Security header with a long max-age, "
        "e.g. 'max-age=31536000; includeSubDomains'.",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "Missing header allows browsers to MIME-sniff content, "
        "which can lead to XSS in some scenarios.",
        "Add 'X-Content-Type-Options: nosniff' header.",
    ),
    "X-Frame-Options": (
        Severity.MEDIUM,
        "Missing header allows the site to be embedded in iframes on other domains, "
        "enabling clickjacking attacks.",
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use "
        "Content-Security-Policy frame-ancestors directive instead.",
    ),
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "Missing CSP header leaves the site more vulnerable to XSS and data injection "
        "attacks since there's no restriction on script/resource sources.",
        "Implement a Content-Security-Policy header appropriate to the site's actual "
        "resource needs.",
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "Missing header may leak full URLs (potentially containing sensitive query params) "
        "to third-party sites via the Referer header.",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
    ),
}

# Detects version strings like "2.4.41", "1.18.0", "7.4.3" in header values
_VERSION_RE = re.compile(r"\d+\.\d+")

# Headers that commonly expose server software versions
_DISCLOSURE_HEADERS = ("Server", "X-Powered-By")


def _fetch(target: str) -> tuple[requests.Response, str, int, bool]:
    """Attempt to fetch the target's HTTP response.

    Returns (response, url_used, port, ssl_bypassed).

    Strategy:
      1. HTTPS with cert verification — the secure default.
      2. On SSLError only: retry the same HTTPS URL with verify=False so we can
         still inspect headers (cert issues are reported by tls_check.py separately).
      3. On a full connection error: fall back to plain HTTP.
    Raises requests.RequestException on total failure (both schemes unreachable).
    """
    url_https = f"https://{target}"

    try:
        resp = requests.get(url_https, timeout=10, verify=True, allow_redirects=True)
        return resp, url_https, 443, False
    except requests.exceptions.SSLError:
        # Bad or self-signed cert — retry without verification for header inspection only
        try:
            resp = requests.get(url_https, timeout=10, verify=False, allow_redirects=True)
            return resp, url_https, 443, True
        except requests.exceptions.RequestException:
            pass  # HTTPS completely broken; fall through to HTTP
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        pass  # No HTTPS listener; fall through to HTTP

    # Fall back to plain HTTP
    url_http = f"http://{target}"
    resp = requests.get(url_http, timeout=10, allow_redirects=True)
    return resp, url_http, 80, False


def run(target_scope: list[str], scan_id: str = "") -> list[Finding]:
    """Check HTTP response headers for missing security headers and version disclosure."""
    findings: list[Finding] = []

    for target in target_scope:
        try:
            response, url, port, ssl_bypassed = _fetch(target)
        except Exception:
            logger.debug(
                "http_headers: could not reach %r on HTTPS or HTTP — skipping.",
                target,
                exc_info=True,
            )
            continue

        bypass_note = (
            " (SSL cert validation bypassed for header inspection only; "
            "cert issues reported separately by tls_check)"
            if ssl_bypassed
            else ""
        )

        # ── Missing security headers ─────────────────────────────────────────
        for header_name, (severity, description, remediation) in SECURITY_HEADERS.items():
            # requests.Response.headers is a CaseInsensitiveDict, so this
            # comparison is already case-insensitive by design.
            if header_name not in response.headers:
                findings.append(Finding(
                    scan_id=scan_id,
                    check_type=CheckType.MISSING_HEADER,
                    target=target,
                    port=port,
                    title=f"Missing security header: {header_name}",
                    description=description,
                    severity=severity,
                    evidence=f"Checked {url}{bypass_note}, header not present in response.",
                    remediation=remediation,
                ))

        # ── Server version disclosure ─────────────────────────────────────────
        for header_name in _DISCLOSURE_HEADERS:
            header_value = response.headers.get(header_name, "")
            if header_value and _VERSION_RE.search(header_value):
                # NOTE: CheckType.MISSING_HEADER is reused here because the enum
                # has no dedicated VERSION_DISCLOSURE or INFORMATION_DISCLOSURE
                # variant yet.  This should be added in a future models.py update.
                findings.append(Finding(
                    scan_id=scan_id,
                    check_type=CheckType.MISSING_HEADER,
                    target=target,
                    port=port,
                    title=f"Server version disclosed in {header_name} header",
                    description=(
                        "Exposing exact software versions helps attackers identify "
                        "known CVEs for that specific version without needing to probe further."
                    ),
                    severity=Severity.LOW,
                    evidence=f"{header_name}: {header_value}",
                    remediation=(
                        "Configure the web server to suppress or generalize version "
                        "information in response headers."
                    ),
                ))

    return findings
