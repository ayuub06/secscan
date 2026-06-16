import logging
import os
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

from core.models import ScanResult, Severity

logger = logging.getLogger(__name__)

_SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#65a30d",
    "INFO":     "#0891b2",
}

_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")


def _severity_sort_key(finding) -> int:
    return finding.severity.value


def generate_html(scan_result: ScanResult) -> str:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=True,
    )
    template = env.get_template("report.html.j2")

    findings_sorted = sorted(scan_result.findings, key=_severity_sort_key, reverse=True)
    generated_at = datetime.now(timezone.utc).isoformat()

    context = {
        "scan_result":     scan_result,
        "findings":        findings_sorted,
        "generated_at":    generated_at,
        "severity_colors": _SEVERITY_COLORS,
        "summary":         scan_result.summary(),
    }

    return template.render(**context)


def generate_pdf(scan_result: ScanResult, output_path: str) -> None:
    html_string = generate_html(scan_result)
    try:
        HTML(string=html_string).write_pdf(output_path)
    except Exception as exc:
        logger.error(
            "PDF generation failed: %s. "
            "If this is a GTK/Pango DLL error on Windows, ensure the sitecustomize.py "
            "fix is in place (os.add_dll_directory pointing at the GTK runtime bin/).",
            exc,
        )
        raise
