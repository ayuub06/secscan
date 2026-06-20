import ipaddress
import logging

import dns.exception
import dns.query
import dns.resolver
import dns.zone

from core.models import CheckType, Finding, Severity

logger = logging.getLogger(__name__)

# Common DKIM selectors to probe; many providers use these by default.
# If none match it doesn't prove DKIM is absent — just that the selector
# name is non-standard.  The finding is therefore INFO, not higher.
_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail")


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _txt_strings(domain: str) -> list[str]:
    """Return all TXT record strings for domain as a list of decoded strings.

    Multi-chunk TXT records (where a single rdata has multiple byte strings)
    are joined before returning, which is how SPF/DMARC parsers expect them.
    Raises dns.resolver exceptions on NXDOMAIN / NoAnswer / timeout.
    """
    answer = dns.resolver.resolve(domain, "TXT", lifetime=10)
    return [
        b"".join(rdata.strings).decode("utf-8", errors="replace")
        for rdata in answer
    ]


def _check_spf(domain: str, target: str, scan_id: str, findings: list[Finding]) -> None:
    try:
        records = _txt_strings(domain)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        records = []
    except Exception as exc:
        logger.debug("dns_check: SPF query failed for %r: %s", domain, exc)
        return

    has_spf = any(r.startswith("v=spf1") for r in records)
    if not has_spf:
        findings.append(Finding(
            scan_id=scan_id,
            check_type=CheckType.DNS_MISCONFIG,
            target=target,
            port=None,
            title="Missing SPF record",
            description=(
                "No SPF record found; without it, nothing prevents other servers "
                "from sending email that appears to come from this domain."
            ),
            severity=Severity.MEDIUM,
            evidence="No TXT record starting with v=spf1 found.",
            remediation=(
                "Add a TXT record starting with 'v=spf1' defining authorized mail "
                "servers, ending in '-all' or '~all'."
            ),
        ))


def _check_dmarc(domain: str, target: str, scan_id: str, findings: list[Finding]) -> None:
    dmarc_domain = f"_dmarc.{domain}"
    try:
        records = _txt_strings(dmarc_domain)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        records = []
    except Exception as exc:
        logger.debug("dns_check: DMARC query failed for %r: %s", dmarc_domain, exc)
        return

    dmarc_record = next((r for r in records if r.startswith("v=DMARC1")), None)

    if dmarc_record is None:
        findings.append(Finding(
            scan_id=scan_id,
            check_type=CheckType.DNS_MISCONFIG,
            target=target,
            port=None,
            title="Missing DMARC record",
            description=(
                "No DMARC record found; without it, there's no policy telling "
                "receiving mail servers what to do with emails that fail SPF/DKIM "
                "checks, making spoofed emails more likely to reach inboxes."
            ),
            severity=Severity.MEDIUM,
            evidence=f"No TXT record found at {dmarc_domain}.",
            remediation=(
                f"Add a TXT record at {dmarc_domain} starting with "
                "'v=DMARC1; p=quarantine;' or stricter, plus a 'rua=' reporting address."
            ),
        ))
    elif "p=none" in dmarc_record.lower():
        findings.append(Finding(
            scan_id=scan_id,
            check_type=CheckType.DNS_MISCONFIG,
            target=target,
            port=None,
            title="DMARC policy set to none (monitoring only)",
            description=(
                "DMARC record exists but takes no action on failing emails, "
                "providing visibility without protection."
            ),
            severity=Severity.LOW,
            evidence=dmarc_record,
            remediation=(
                "Consider strengthening policy to 'p=quarantine' or 'p=reject' "
                "once monitoring confirms legitimate mail flows are correctly authenticated."
            ),
        ))


def _check_dkim(domain: str, target: str, scan_id: str, findings: list[Finding]) -> None:
    for selector in _DKIM_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            records = _txt_strings(dkim_domain)
            if any("v=DKIM1" in r for r in records):
                logger.debug(
                    "dns_check: DKIM found at selector %r for %r — no finding.",
                    selector, domain,
                )
                return  # DKIM confirmed; nothing to report
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            continue  # this selector doesn't exist; try the next one
        except Exception as exc:
            logger.debug(
                "dns_check: DKIM query error for %r: %s", dkim_domain, exc
            )
            continue

    # None of the common selectors resolved — inconclusive, report as INFO
    findings.append(Finding(
        scan_id=scan_id,
        check_type=CheckType.DNS_MISCONFIG,
        target=target,
        port=None,
        title="No DKIM record found at common selectors (inconclusive)",
        description=(
            "Checked common DKIM selector names but found none; this does not "
            "confirm DKIM is absent, only that it isn't using a commonly-guessed "
            "selector name."
        ),
        severity=Severity.INFO,
        evidence=f"Checked selectors: {list(_DKIM_SELECTORS)}",
        remediation="Manually verify DKIM configuration with your email provider's documentation.",
    ))


def _check_zone_transfer(
    domain: str, target: str, scan_id: str, findings: list[Finding]
) -> None:
    try:
        ns_answer = dns.resolver.resolve(domain, "NS", lifetime=10)
        nameservers = [str(rdata.target).rstrip(".") for rdata in ns_answer]
    except Exception as exc:
        logger.debug("dns_check: NS lookup failed for %r: %s", domain, exc)
        return

    for ns in nameservers:
        try:
            # dns.query.xfr returns a generator of Message objects.
            # timeout  = per-read idle timeout in seconds
            # lifetime = total allowed time for the entire transfer
            xfr_gen = dns.query.xfr(ns, domain, timeout=5, lifetime=5)
            record_count = sum(
                len(rrset)
                for msg in xfr_gen
                for rrset in msg.answer
            )
            if record_count > 0:
                findings.append(Finding(
                    scan_id=scan_id,
                    check_type=CheckType.DNS_MISCONFIG,
                    target=target,
                    port=None,
                    title=f"Zone transfer (AXFR) allowed on nameserver {ns}",
                    description=(
                        "The nameserver allows unauthenticated zone transfers, exposing "
                        "the complete DNS record set including potentially internal "
                        "hostnames, infrastructure details, and subdomains not meant "
                        "to be public."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Successfully transferred {record_count} records from {ns}.",
                    remediation=(
                        "Restrict zone transfers to authorized secondary nameservers "
                        "only via ACL/TSIG configuration."
                    ),
                ))
            else:
                logger.debug(
                    "dns_check: AXFR to %r returned no records (likely blocked).", ns
                )
        except Exception as exc:
            # Expected outcome for correctly configured servers — AXFR refused/timeout
            logger.debug(
                "dns_check: AXFR to %r failed (this is normal/secure): %s", ns, exc
            )


def _domain_resolves(domain: str) -> bool:
    """Return True if the bare domain resolves to at least one A, AAAA, or NS record."""
    for rdtype in ("A", "AAAA", "NS"):
        try:
            dns.resolver.resolve(domain, rdtype, lifetime=10)
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception:
            continue
    return False


def run(target_scope: list[str], scan_id: str = "") -> list[Finding]:
    """Query DNS records for each domain target and return security findings."""
    findings: list[Finding] = []

    for target in target_scope:
        if _is_ip(target):
            logger.debug(
                "dns_check: skipping %r — DNS email-auth checks are not meaningful "
                "for raw IP addresses.",
                target,
            )
            continue

        try:
            if not _domain_resolves(target):
                logger.info(
                    "dns_check: %r does not resolve — skipping sub-checks, adding single INFO finding.",
                    target,
                )
                findings.append(Finding(
                    scan_id=scan_id,
                    check_type=CheckType.DNS_MISCONFIG,
                    target=target,
                    port=None,
                    title="Domain does not resolve",
                    description=(
                        "This domain could not be resolved via DNS — it may not exist, "
                        "be misspelled, or be temporarily unavailable. "
                        "No further DNS checks were performed."
                    ),
                    severity=Severity.INFO,
                    evidence=f"A, AAAA, and NS lookups all failed for {target!r}.",
                    remediation=(
                        "Verify the domain name is spelled correctly and that it is "
                        "registered and has at least one DNS record."
                    ),
                ))
                continue

            _check_spf(target, target, scan_id, findings)
            _check_dmarc(target, target, scan_id, findings)
            _check_dkim(target, target, scan_id, findings)
            _check_zone_transfer(target, target, scan_id, findings)
        except Exception:
            logger.warning(
                "dns_check: unexpected error processing %r — skipping.",
                target,
                exc_info=True,
            )

    return findings
