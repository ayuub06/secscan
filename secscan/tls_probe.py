"""
Investigate the TLS false-positive for gestion-examens-frontend.vercel.app.

Tests, in order:
  A. Python ssl — auto-negotiate (no version restriction, explicit SNI)
  B. Python ssl — TLS 1.2 only, explicit SNI
  C. Python ssl — TLS 1.3 only, explicit SNI
  D. requests HTTPS (urllib3 + SNI)
  E. sslyze direct call — exactly what tls_check.py does
  F. sslyze cipher-suite result detail (which commands completed vs errored)
"""

import json
import socket
import ssl
import sys

sys.path.insert(0, ".")

HOST = "gestion-examens-frontend.vercel.app"
PORT = 443

SEP = "=" * 60


def probe_ssl(label, min_ver=None, max_ver=None):
    ctx = ssl.create_default_context()
    if min_ver:
        ctx.minimum_version = min_ver
    if max_ver:
        ctx.maximum_version = max_ver
    try:
        with socket.create_connection((HOST, PORT), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=HOST) as s:
                cert = s.getpeercert()
                subj = dict(x[0] for x in cert.get("subject", []))
                san = [v for _, v in cert.get("subjectAltName", [])]
                print(f"  [{label}] OK")
                print(f"    version : {s.version()}")
                print(f"    cipher  : {s.cipher()}")
                print(f"    subject : {subj}")
                print(f"    SAN     : {san[:4]}{'...' if len(san)>4 else ''}")
                print(f"    notAfter: {cert.get('notAfter')}")
                return True
    except ssl.SSLError as e:
        print(f"  [{label}] SSL ERROR: {e.reason} — {e}")
        return False
    except Exception as e:
        print(f"  [{label}] ERROR: {type(e).__name__}: {e}")
        return False


print(SEP)
print("SECTION A — Python ssl, auto-negotiate (all versions, SNI=hostname)")
print(SEP)
probe_ssl("auto")

print()
print(SEP)
print("SECTION B — Python ssl, TLS 1.2 only, SNI=hostname")
print(SEP)
probe_ssl("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)

print()
print(SEP)
print("SECTION C — Python ssl, TLS 1.3 only, SNI=hostname")
print(SEP)
probe_ssl("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)

print()
print(SEP)
print("SECTION D — requests HTTPS (urllib3, SNI handled automatically)")
print(SEP)
try:
    import requests
    r = requests.get(f"https://{HOST}", timeout=10)
    print(f"  status  : {r.status_code}")
    print(f"  headers : server={r.headers.get('server','?')}  "
          f"x-powered-by={r.headers.get('x-powered-by','?')}")
    # urllib3 doesn't expose the negotiated TLS version directly via requests,
    # but a successful response proves TLS works.
    print("  TLS     : OK (successful HTTPS response)")
except Exception as e:
    print(f"  FAIL: {type(e).__name__}: {e}")

print()
print(SEP)
print("SECTION E — sslyze direct (mirrors exactly what tls_check.py does)")
print(SEP)
try:
    from sslyze import (
        ScanCommand,
        ScanCommandAttemptStatusEnum,
        Scanner,
        ServerNetworkLocation,
        ServerScanRequest,
        ServerScanStatusEnum,
    )

    loc = ServerNetworkLocation(hostname=HOST, port=PORT)
    print(f"  ServerNetworkLocation.hostname = {loc.hostname!r}")
    print(f"  ServerNetworkLocation.port     = {loc.port}")
    print(f"  ServerNetworkLocation.ip_address = {loc.ip_address!r}")

    scan_commands = {
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
    }
    request = ServerScanRequest(server_location=loc, scan_commands=scan_commands)
    scanner = Scanner()
    scanner.queue_scans([request])

    for result in scanner.get_results():
        print(f"\n  scan_status     : {result.scan_status}")
        if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            print("  => ERROR_NO_CONNECTIVITY — sslyze couldn't reach the server at all")
            if result.connectivity_error_trace:
                print(f"  connectivity_error_trace: {result.connectivity_error_trace}")
            break

        sr = result.scan_result
        if sr is None:
            print("  scan_result is None")
            break

        print()
        print(SEP)
        print("SECTION F — sslyze per-command results")
        print(SEP)

        for cmd_label, attr in [
            ("TLS 1.2", "tls_1_2_cipher_suites"),
            ("TLS 1.3", "tls_1_3_cipher_suites"),
            ("CERT",    "certificate_info"),
        ]:
            attempt = getattr(sr, attr)
            print(f"\n  [{cmd_label}]  status={attempt.status.name}")
            if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                if hasattr(attempt.result, "accepted_cipher_suites"):
                    accepted = attempt.result.accepted_cipher_suites
                    print(f"    accepted_cipher_suites : {len(accepted)}")
                    for cs in accepted[:5]:
                        print(f"      - {cs.cipher_suite.name}")
                    if len(accepted) > 5:
                        print(f"      ... and {len(accepted)-5} more")
                elif hasattr(attempt.result, "certificate_deployments"):
                    dep = attempt.result.certificate_deployments
                    if dep:
                        leaf = dep[0].received_certificate_chain[0]
                        print(f"    leaf subject : {leaf.subject.rfc4514_string()}")
                        print(f"    leaf notAfter: {leaf.not_valid_after_utc}")
                        print(f"    verified_chain_has_sha1: {dep[0].verified_chain_has_sha1_signature}")
            elif attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                print(f"    error_reason : {attempt.error_reason}")
                if attempt.error_trace:
                    # Print just the last 3 lines of the traceback
                    lines = str(attempt.error_trace).strip().splitlines()
                    for line in lines[-4:]:
                        print(f"    | {line}")

except Exception as e:
    import traceback
    print(f"  sslyze EXCEPTION: {type(e).__name__}: {e}")
    traceback.print_exc()
