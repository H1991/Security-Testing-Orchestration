"""Layer 13 — Jinja2 HTML report, with embedded screenshots (base64) per
CLAUDE.md's own line for this file.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, FileSystemLoader

from stof.core.logger import get_logger

from .json_report import SEVERITY_ORDER, build_summary

if TYPE_CHECKING:
    from stof.findings.models import Finding

_log = get_logger("reporting.html_report")

TEMPLATE_DIR = Path(__file__).parent / "templates"
TEMPLATE_NAME = "report.html.j2"


_IMAGE_LABELS = {
    "request_response.png": "Request / Response",
    "screenshot.png": "Browser Screenshot",
}


def _evidence_images(evidence_refs: list[str]) -> list[dict[str, str]]:
    """Every PNG in `evidence_refs`, not just the first -- a Finding
    can carry both a live browser screenshot (`screenshot.py`) and the
    styled request/response evidence image (`request_response_image.
    py`), and the report should show both, clearly labeled."""
    images: list[dict[str, str]] = []
    for ref in evidence_refs:
        path = Path(ref)
        if path.suffix.lower() != ".png" or not path.is_file():
            continue
        try:
            encoded = base64.b64encode(path.read_bytes()).decode("ascii")
        except OSError as exc:
            _log.warning(f"could not read evidence image '{ref}': {exc}")
            continue
        images.append({
            "label": _IMAGE_LABELS.get(path.name, path.stem.replace("_", " ").title()),
            "data_uri": f"data:image/png;base64,{encoded}",
        })
    return images


def _enrich(finding: "Finding") -> dict[str, Any]:
    data = finding.to_dict()
    data["evidence_images"] = _evidence_images(finding.evidence_refs)
    return data


_SEVERITY_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
_PRIORITY_SEVERITIES = ("Critical", "High")


def _split_by_priority(enriched_findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Splits into (Critical/High, everything else), each severity-
    sorted -- the report's whole point is that a reviewer opening it
    sees "what needs action" before "what's hygiene", not one flat list
    where a Critical BFLA finding and a missing-header Low sit in
    whatever order the scan's modules happened to run. See this
    project's own severity-vs-cvss_score audit (`Finding.
    __post_init__`) for why that distinction is worth structurally
    surfacing, not just correctly labeling."""
    priority = sorted(
        (f for f in enriched_findings if f["severity"] in _PRIORITY_SEVERITIES),
        key=lambda f: _SEVERITY_RANK.get(f["severity"], len(SEVERITY_ORDER)),
    )
    other = sorted(
        (f for f in enriched_findings if f["severity"] not in _PRIORITY_SEVERITIES),
        key=lambda f: _SEVERITY_RANK.get(f["severity"], len(SEVERITY_ORDER)),
    )
    return priority, other


def _summarize_recon(recon_report: dict[str, Any] | None) -> dict[str, Any] | None:
    """Condenses `ReconReport.to_dict()` (potentially dozens of
    per-page entries) into the handful of management-readable facts a
    report section actually needs -- distinct tech signatures rather
    than one row per page, counts rather than full per-page listings."""
    if recon_report is None:
        return None
    tech_stack = recon_report.get("tech_stack", [])
    distinct_tech = sorted({t for page in tech_stack for t in page.get("tech", [])})
    missing_headers = recon_report.get("missing_security_headers", {})
    return {
        "target": recon_report.get("target"),
        "scanned_at": recon_report.get("scanned_at"),
        "pages_analyzed": recon_report.get("pages_analyzed", 0),
        "distinct_tech": distinct_tech,
        "missing_headers_count": len(missing_headers),
        "missing_headers_sample": list(missing_headers.items())[:8],
        "exposed_paths": recon_report.get("exposed_paths", []),
        "error_disclosures": recon_report.get("error_disclosures", []),
        "secrets": recon_report.get("secrets", []),
        "parameters_count": len(recon_report.get("parameters", {})),
    }


def write(
    findings: list["Finding"],
    scan_metadata: dict[str, Any],
    output_path: str | Path,
    recon_report: dict[str, Any] | None = None,
    template_dir: str | Path = TEMPLATE_DIR,
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # `select_autoescape()` decides based on the template *filename's*
    # extension (e.g. ".html") -- this project's template is named
    # "report.html.j2", which doesn't match, silently disabling
    # autoescaping and opening a stored-XSS hole via finding data
    # (description/recommendation/request_raw are all attacker-
    # observable strings on a real target). Since this Environment only
    # ever renders one HTML template, force autoescaping on
    # unconditionally instead of relying on filename sniffing.
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template(TEMPLATE_NAME)

    priority_findings, other_findings = _split_by_priority([_enrich(f) for f in findings])
    html = template.render(
        scan_metadata=scan_metadata,
        generated_at=datetime.now(timezone.utc).isoformat(),
        summary=build_summary(findings),
        priority_findings=priority_findings,
        other_findings=other_findings,
        recon=_summarize_recon(recon_report),
        module_notes=scan_metadata.get("module_notes", []),
        skipped_techniques=scan_metadata.get("skipped_techniques", []),
        cleanup=scan_metadata.get("cleanup", []),
        baseline_diff=scan_metadata.get("baseline_diff"),
    )
    path.write_text(html, encoding="utf-8")
    _log.info(f"wrote HTML report ({len(findings)} finding(s)) -> {path}")
    return path
