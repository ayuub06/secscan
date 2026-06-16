"""
secscan — command-line entry point.

Usage:
    python cli.py --targets <target> [<target> ...] --authorized-by <ref>
                  [--output <path>] [--format html|json]
                  [--skip-cve] [--log-level DEBUG|INFO|WARNING|ERROR]

Example:
    python cli.py --targets 10.0.0.5 example.com --authorized-by "ticket-1234"
"""

import argparse
import json
import logging
import sys

from checks import admin_panels, cve_lookup, dns_check, http_headers, port_scan, tls_check
from core.orchestrator import ScanOrchestrator
from core.target import UnauthorizedScanError
from reports.generator import generate_html, generate_pdf


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secscan",
        description="Network security scanner — scans targets and generates findings reports.",
    )
    p.add_argument(
        "--targets",
        nargs="+",
        required=True,
        metavar="TARGET",
        help="One or more targets: IP addresses, CIDR ranges, or hostnames.",
    )
    p.add_argument(
        "--authorized-by",
        required=True,
        metavar="REF",
        help=(
            "Authorization reference (ticket ID, contract ref, client email confirmation). "
            "Must be a real authorization record — this field is logged and auditable."
        ),
    )
    p.add_argument(
        "--output",
        default="report.html",
        metavar="PATH",
        help="Output file path for the report (default: report.html).",
    )
    p.add_argument(
        "--format",
        choices=["html", "json", "pdf"],
        default="html",
        help="Report format (default: html).",
    )
    p.add_argument(
        "--skip-cve",
        action="store_true",
        default=False,
        help=(
            "Skip CVE lookup enrichment. Recommended for quick scans since "
            "NVD API rate-limiting adds ~6s per unique service/version found."
        ),
    )
    p.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging verbosity (default: INFO).",
    )
    return p


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    # ── Logging setup ────────────────────────────────────────────────────────
    # basicConfig belongs here in the entry point, NOT in orchestrator.py or
    # any check module, so library consumers can configure logging themselves.
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )
    logger = logging.getLogger("secscan.cli")

    logger.info("secscan starting — targets: %s", args.targets)
    logger.info("Authorized by: %s", args.authorized_by)

    # ── Build orchestrator and register checks ───────────────────────────────
    orchestrator = ScanOrchestrator(
        target_scope=args.targets,
        authorized_by=args.authorized_by,
    )

    # Registration order matters: cve_lookup depends on port_scan's output,
    # so port_scan must be registered (and run) first.
    orchestrator.register_check("port_scan",    port_scan.run)
    orchestrator.register_check("tls_check",    tls_check.run)
    orchestrator.register_check("http_headers", http_headers.run)
    orchestrator.register_check("dns_check",    dns_check.run)
    orchestrator.register_check("admin_panels", admin_panels.run)

    if not args.skip_cve:
        orchestrator.register_check(
            "cve_lookup",
            cve_lookup.run,
            needs_findings=True,   # post-processor: receives port_scan output
        )
    else:
        logger.info("CVE lookup skipped (--skip-cve).")

    # ── Run scan ─────────────────────────────────────────────────────────────
    try:
        scan_result = orchestrator.run()
    except UnauthorizedScanError as exc:
        # Expected user error — print a clean message, no raw traceback
        print(f"\n[ERROR] Authorization check failed: {exc}", file=sys.stderr)
        print(
            "Provide a valid --authorized-by reference and ensure --targets "
            "contains at least one valid entry.",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception:
        logger.exception("Scan failed with an unexpected error.")
        print(
            "\n[ERROR] Scan failed — check the log output above for details.",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Console summary ───────────────────────────────────────────────────────
    summary = scan_result.summary()
    total   = sum(summary.values())
    print("\n" + "=" * 60)
    print(f"  Scan complete — {total} finding(s) across {len(args.targets)} target(s)")
    print(f"  Checks run : {', '.join(scan_result.checks_run) or 'none'}")
    print(f"  Started    : {scan_result.started_at}")
    print(f"  Completed  : {scan_result.completed_at}")
    print()
    print("  Findings by severity:")
    for sev in ("critical", "high", "medium", "low", "info"):
        count = summary[sev]
        bar   = "*" * min(count, 40)
        print(f"    {sev.upper():<8}  {count:>4}  {bar}")
    print("=" * 60)

    # ── Write report ──────────────────────────────────────────────────────────
    output_path = args.output

    try:
        if args.format == "json":
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(scan_result.to_dict(), fh, indent=2, ensure_ascii=False)
        elif args.format == "html":
            html_content = generate_html(scan_result)
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(html_content)
        elif args.format == "pdf":
            generate_pdf(scan_result, output_path)
        print(f"\n  Report written to: {output_path}")
    except OSError as exc:
        logger.error("Failed to write report to %r: %s", output_path, exc)
        sys.exit(1)
    except Exception as exc:
        logger.error("Report generation failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
