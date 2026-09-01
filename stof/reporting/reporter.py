"""Layer 13 — Reporting Engine: orchestrates every report format.

Called by the orchestrator at the end of a scan (per CLAUDE.md). Input:
`list[Finding]` + scan metadata; output: HTML, JSON, and Excel reports
in `data/reports/`, matching CLAUDE.md's documented CLI output:

    [REPORT] HTML  -> data/reports/scan_abc123.html
    [REPORT] JSON  -> data/reports/scan_abc123.json
    [REPORT] Excel -> data/reports/scan_abc123.xlsx
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from stof.core.logger import get_logger

from . import excel_report, html_report, json_report, walkthrough_report

if TYPE_CHECKING:
    from stof.findings.models import Finding

    from .walkthrough_models import FindingWalkthrough

_log = get_logger("reporting.reporter")

DEFAULT_REPORTS_DIR = Path("data/reports")


@dataclass
class ReportPaths:
    html: Path
    json: Path
    excel: Path
    walkthrough: Path | None = None


def generate_reports(
    findings: list["Finding"],
    scan_metadata: dict[str, Any],
    output_dir: str | Path = DEFAULT_REPORTS_DIR,
    recon_report: dict[str, Any] | None = None,
    walkthroughs: "list[FindingWalkthrough] | None" = None,
) -> ReportPaths:
    output_dir = Path(output_dir)
    scan_id = scan_metadata.get("scan_id", "scan")
    stem = f"scan_{scan_id}"

    json_path = json_report.write(findings, scan_metadata, output_dir / f"{stem}.json", recon_report=recon_report)
    html_path = html_report.write(findings, scan_metadata, output_dir / f"{stem}.html", recon_report=recon_report)
    excel_path = excel_report.write(findings, output_dir / f"{stem}.xlsx")

    _log.info(f"[REPORT] HTML  -> {html_path}")
    _log.info(f"[REPORT] JSON  -> {json_path}")
    _log.info(f"[REPORT] Excel -> {excel_path}")

    walkthrough_path: Path | None = None
    if walkthroughs:
        walkthrough_path = walkthrough_report.write(walkthroughs, scan_metadata, output_dir / f"{stem}_walkthrough.html")
        _log.info(f"[REPORT] Walkthrough -> {walkthrough_path}")

    return ReportPaths(html=html_path, json=json_path, excel=excel_path, walkthrough=walkthrough_path)
