import ipaddress
import re
from typing import Optional


class UnauthorizedScanError(Exception):
    """Raised when authorization is missing or a target is outside declared scope."""


# Matches hostnames/domains: alphanumeric start and end, hyphens and dots allowed
# in the middle. Single-character labels are valid. No leading/trailing hyphen or dot.
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-.]*[a-zA-Z0-9])?$")


def parse_targets(raw_targets: list[str]) -> list[str]:
    """Validate every entry in raw_targets; raise ValueError on the first bad one.

    Each entry must be one of:
      - A single IP address  ("10.0.0.5")
      - A CIDR range         ("10.0.0.0/24")
      - A hostname/domain    ("example.com", "localhost")

    Returns the original list unchanged (this is a gate, not a normaliser).
    """
    for entry in raw_targets:
        # Try as IP / CIDR first
        try:
            ipaddress.ip_network(entry, strict=False)
            continue
        except ValueError:
            pass

        # Fall back to hostname validation
        if _HOSTNAME_RE.match(entry) and ("." in entry or entry == "localhost"):
            continue

        raise ValueError(
            f"Invalid target entry: {entry!r}. "
            "Expected an IP address, CIDR range, or valid hostname."
        )

    return raw_targets


def is_in_scope(target: str, target_scope: list[str]) -> bool:
    """Return True if target falls within any entry in target_scope.

    IP targets: matched against CIDR ranges and single IPs in scope.
    Hostname targets: exact string match only — no wildcard or subdomain expansion.
    """
    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        # Hostname target — exact match only
        return target in target_scope

    # IP target — check every scope entry that parses as a network
    for entry in target_scope:
        try:
            if target_ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            pass  # scope entry is a hostname; irrelevant for an IP target

    return False


def enforce_authorization(target_scope: list[str], authorized_by: str) -> None:
    """Gate function — MUST be called by the orchestrator before any check module runs.

    Validates that:
      1. ``authorized_by`` is non-empty (not None, not blank whitespace).
      2. ``target_scope`` contains at least one entry.
      3. Every entry in ``target_scope`` is a syntactically valid IP, CIDR, or hostname.

    ``authorized_by`` should reference a **real, signed authorization record** —
    for example, a pentest ticket ID, a signed contract reference, or a client
    email confirmation thread ID.  Do **not** treat any non-empty string as proof
    of authorization.  This function only validates *presence and format*; verifying
    the *legitimacy* of the authorization is the responsibility of the human
    running the tool.

    Raises:
        UnauthorizedScanError: if ``authorized_by`` is empty/whitespace or
            ``target_scope`` is empty.
        ValueError: if any entry in ``target_scope`` is not a valid target
            (propagated from ``parse_targets``).
    """
    if not authorized_by or not authorized_by.strip():
        raise UnauthorizedScanError(
            "authorized_by must be a non-empty authorization reference "
            "(ticket ID, contract ref, etc.). Refusing to scan."
        )

    if not target_scope:
        raise UnauthorizedScanError(
            "target_scope must contain at least one entry. Refusing to scan."
        )

    parse_targets(target_scope)  # ValueError propagates naturally on bad entries
