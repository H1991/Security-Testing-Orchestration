"""Layer 13 — renders the Walkthrough Report: plain-English,
screenshot-backed reproduction guide, one card per FAIL finding. No raw
HTTP request/response text shown by default anywhere on the page --
that's the entire point of this report type (see the technical HTML/
JSON/Excel reports for that).
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, FileSystemLoader

from stof.core.logger import get_logger

from .json_report import SEVERITY_ORDER

if TYPE_CHECKING:
    from .walkthrough_models import FindingWalkthrough

_log = get_logger("reporting.walkthrough_report")

TEMPLATE_DIR = Path(__file__).parent / "templates"
TEMPLATE_NAME = "walkthrough_report.html.j2"

_SEVERITY_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}


def _encode_screenshot(path: "str | None") -> "str | None":
    """Same base64-embedding convention `html_report._evidence_images()`
    already uses -- reused here rather than reinvented, just applied to
    a single `WalkthroughStep.screenshot_path` instead of a list of
    evidence refs."""
    if not path:
        return None
    file_path = Path(path)
    if file_path.suffix.lower() != ".png" or not file_path.is_file():
        return None
    try:
        encoded = base64.b64encode(file_path.read_bytes()).decode("ascii")
    except OSError as exc:
        _log.warning(f"could not read walkthrough screenshot '{path}': {exc}")
        return None
    return f"data:image/png;base64,{encoded}"


def _enrich_step(step: Any) -> dict[str, Any]:
    return {
        "order": step.order,
        "caption": step.caption,
        "detail": step.detail,
        "screenshot_data_uri": _encode_screenshot(step.screenshot_path),
    }


def _enrich(walkthrough: "FindingWalkthrough") -> dict[str, Any]:
    return {
        "finding_id": walkthrough.finding_id,
        "tc_id": walkthrough.tc_id,
        "title": walkthrough.title,
        "severity": walkthrough.severity,
        "endpoint_url": walkthrough.endpoint_url,
        "steps": [_enrich_step(s) for s in walkthrough.steps],
        "impact_summary": walkthrough.impact_summary,
        "remediation": walkthrough.remediation,
        "build_error": walkthrough.build_error,
    }


def _ordered(walkthroughs: list["FindingWalkthrough"]) -> list["FindingWalkthrough"]:
    """Critical-first severity ordering -- `html_report.py`/`report.
    html.j2` render findings in whatever order the caller passed them
    (no severity sort of their own to match), so this report defines
    its own explicit Critical-first order per the plan, reusing
    `json_report.SEVERITY_ORDER` as the single source of truth for that
    ordering rather than a second hardcoded tuple."""
    return sorted(walkthroughs, key=lambda w: _SEVERITY_RANK.get(w.severity, len(SEVERITY_ORDER)))


def write(
    walkthroughs: list["FindingWalkthrough"],
    scan_metadata: dict[str, Any],
    output_path: "str | Path",
    template_dir: "str | Path" = TEMPLATE_DIR,
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Same autoescape-forced-on rationale as `html_report.write()`:
    # this template's own filename ("walkthrough_report.html.j2")
    # doesn't end in ".html" either, so `select_autoescape()`'s
    # filename-sniffing would silently disable escaping otherwise.
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template(TEMPLATE_NAME)

    html = template.render(
        scan_metadata=scan_metadata,
        generated_at=datetime.now(timezone.utc).isoformat(),
        walkthroughs=[_enrich(w) for w in _ordered(walkthroughs)],
    )
    path.write_text(html, encoding="utf-8")
    _log.info(f"wrote walkthrough report ({len(walkthroughs)} finding(s)) -> {path}")
    return path
