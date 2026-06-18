import logging
import re

import dns.resolver
import requests

logger = logging.getLogger(__name__)


def _bare_hostname(domain: str) -> str:
    """Return the bare hostname, stripping any protocol prefix, path, port, or query string."""
    domain = re.sub(r"^https?://", "", domain.strip())
    domain = domain.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    return domain.strip()


def check_dns_verification(domain: str, expected_token: str) -> bool:
    """Return True if _secscan-verify.<domain> has the expected TXT record value."""
    hostname = _bare_hostname(domain)
    lookup_name = f"_secscan-verify.{hostname}"
    expected_value = f"secscan-verify-{expected_token}"
    try:
        answers = dns.resolver.resolve(lookup_name, "TXT")
        for rdata in answers:
            for string in rdata.strings:
                if string.decode("utf-8") == expected_value:
                    return True
        return False
    except Exception as exc:
        logger.debug("DNS verification failed for %s: %s", lookup_name, exc)
        return False


def check_file_verification(domain: str, expected_token: str) -> bool:
    """Return True if /.well-known/secscan-verify.txt on the domain contains the expected value."""
    hostname = _bare_hostname(domain)
    path = "/.well-known/secscan-verify.txt"
    expected_value = f"secscan-verify-{expected_token}"
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}{path}"
        try:
            resp = requests.get(url, timeout=10, allow_redirects=True)
            if resp.status_code == 200 and resp.text.strip() == expected_value:
                return True
        except Exception as exc:
            logger.debug("File verification failed for %s: %s", url, exc)
    return False
