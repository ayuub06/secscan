"""
Call tls_check.run() directly in this process (uses the fixed code on disk)
against gestion-examens-frontend.vercel.app.  Does NOT go through Flask.
"""
import sys, json
sys.path.insert(0, ".")

import logging
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")

from checks.tls_check import run

TARGET = "gestion-examens-frontend.vercel.app"
SCAN_ID = "fix-verification"

print("=" * 60)
print(f"Calling tls_check.run([{TARGET!r}]) with fixed code")
print("=" * 60)

findings = run([TARGET], scan_id=SCAN_ID)

print()
print("=" * 60)
print(f"tls_check returned {len(findings)} finding(s)")
print("=" * 60)

SEV = {1:"INFO",2:"LOW",3:"MEDIUM",4:"HIGH",5:"CRITICAL"}
tls_critical = []

for i, f in enumerate(findings, 1):
    sev = SEV.get(f.severity, str(f.severity))
    print(f"\n  [{i}] [{sev}] {f.title}")
    print(f"       target   : {f.target}")
    print(f"       evidence : {f.evidence}")
    if "no modern tls" in f.title.lower() and f.severity == 5:
        tls_critical.append(f)

print()
print("=" * 60)
print("VERDICT")
print("=" * 60)
if tls_critical:
    print(f"  FAIL — false-positive CRITICAL still present")
else:
    print(f"  PASS — no false-positive 'No modern TLS support' CRITICAL")
    if findings:
        print(f"  Other tls_check findings: {[f.title for f in findings]}")
    else:
        print("  No TLS findings at all (inconclusive scan correctly suppressed)")
