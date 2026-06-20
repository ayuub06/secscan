"""
Deeper TLS investigation:
  G. Raw TCP — does port 443 accept connections at all?
  H. Known-good HTTPS control (example.com) — rule out local firewall
  I. sslyze with verbose per-command ERROR details — what status does each command return?
  J. Decode: was the CRITICAL finding caused by zero accepted suites on COMPLETED
     commands, or by all commands returning ERROR status?
"""

import json
import socket
import ssl
import sys

sys.path.insert(0, ".")

HOST = "gestion-examens-frontend.vercel.app"
PORT = 443
SEP = "=" * 60

# G. Raw TCP
print(SEP)
print("SECTION G — Raw TCP connection (no TLS) to port 443")
print(SEP)
try:
    sock = socket.create_connection((HOST, PORT), timeout=10)
    print(f"  TCP connect OK — remote addr: {sock.getpeername()}")
    # Send a minimal TLS Client Hello and see what comes back
    # Instead, just close cleanly
    sock.close()
except Exception as e:
    print(f"  TCP FAIL: {type(e).__name__}: {e}")

# H. Known-good control
print()
print(SEP)
print("SECTION H — Control: TLS to example.com (rules out local firewall)")
print(SEP)
try:
    ctx = ssl.create_default_context()
    with socket.create_connection(("example.com", 443), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname="example.com") as s:
            print(f"  example.com TLS OK: {s.version()} / {s.cipher()[0]}")
except Exception as e:
    print(f"  example.com FAIL — likely local firewall/proxy: {type(e).__name__}: {e}")

# I + J. sslyze verbose — capture per-command status
print()
print(SEP)
print("SECTION I — sslyze: per-command status (COMPLETED / ERROR / TIMEOUT)")
print(SEP)

from sslyze import (
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    Scanner,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerScanStatusEnum,
)

loc = ServerNetworkLocation(hostname=HOST, port=PORT)
scan_commands = {
    ScanCommand.TLS_1_0_CIPHER_SUITES,
    ScanCommand.TLS_1_1_CIPHER_SUITES,
    ScanCommand.TLS_1_2_CIPHER_SUITES,
    ScanCommand.TLS_1_3_CIPHER_SUITES,
    ScanCommand.CERTIFICATE_INFO,
}
request = ServerScanRequest(server_location=loc, scan_commands=scan_commands)
scanner = Scanner()
scanner.queue_scans([request])

for result in scanner.get_results():
    print(f"  scan_status: {result.scan_status.name}")
    if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
        print(f"  => No connectivity. Error: {result.connectivity_error_trace}")
        break

    sr = result.scan_result
    if sr is None:
        print("  scan_result is None")
        break

    attr_map = {
        "TLS 1.0": "tls_1_0_cipher_suites",
        "TLS 1.1": "tls_1_1_cipher_suites",
        "TLS 1.2": "tls_1_2_cipher_suites",
        "TLS 1.3": "tls_1_3_cipher_suites",
        "CERT":    "certificate_info",
    }

    modern_commands_completed = 0
    any_accepted = False

    for label, attr in attr_map.items():
        attempt = getattr(sr, attr)
        status = attempt.status.name

        if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            if hasattr(attempt.result, "accepted_cipher_suites"):
                n = len(attempt.result.accepted_cipher_suites)
                print(f"  [{label:8s}] {status}  accepted_cipher_suites={n}")
                if label in ("TLS 1.2", "TLS 1.3"):
                    modern_commands_completed += 1
                    if n > 0:
                        any_accepted = True
            else:
                print(f"  [{label:8s}] {status}  (cert info)")
        elif attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            err = attempt.error_reason or ""
            print(f"  [{label:8s}] ERROR  reason={err!r}")
            # Show tail of traceback
            if attempt.error_trace:
                lines = str(attempt.error_trace).strip().splitlines()
                for line in lines[-3:]:
                    print(f"              | {line.strip()}")
        else:
            print(f"  [{label:8s}] {status}")

    print()
    print(SEP)
    print("SECTION J — Root-cause diagnosis")
    print(SEP)
    print(f"  modern_commands_completed : {modern_commands_completed}  (of 2: TLS 1.2, TLS 1.3)")
    print(f"  any modern suite accepted : {any_accepted}")
    print()
    if modern_commands_completed == 0:
        print("  DIAGNOSIS: Both TLS 1.2 and TLS 1.3 commands returned ERROR (not COMPLETED).")
        print("  The server refused to enumerate cipher suites — likely bot-detection or rate-limiting.")
        print("  tls_check.py sees modern_supported=False (default) and fires the CRITICAL finding.")
        print("  => FALSE POSITIVE: the finding is triggered by scan errors, not proven lack of TLS.")
        print()
        print("  ROOT CAUSE in tls_check.py:")
        print("    'modern_supported' starts as False.")
        print("    The for-loop skips all commands that aren't COMPLETED.")
        print("    If TLS 1.2 + TLS 1.3 commands both ERROR, the loop body never sets modern_supported=True.")
        print("    The 'if not modern_supported' block fires unconditionally.")
        print()
        print("  FIX: guard the CRITICAL finding on 'modern_commands_completed > 0'.")
        print("    Only emit it if at least one modern cipher-suite command ran to completion")
        print("    and found zero accepted suites — not when the commands themselves errored out.")
    elif not any_accepted:
        print("  DIAGNOSIS: Modern commands completed but server accepted NO cipher suites.")
        print("  This is a genuine 'no TLS 1.2/1.3 support' condition (real finding).")
    else:
        print("  DIAGNOSIS: Server accepted modern cipher suites — no issue.")
