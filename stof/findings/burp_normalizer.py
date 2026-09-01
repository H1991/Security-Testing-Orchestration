"""Layer 11 — normalizes Burp Suite issue dicts (from Layer 3C's
`BurpController.run_active_scan()`) into this project's own `Finding`
schema (Layer 10), so Burp's Active Scan results flow through the
exact same findings store / reporting pipeline as stof's own modules --
distinguished only by `Finding.scanner_source == "burp"`, exactly as
CLAUDE.md's own `Finding` dataclass spec anticipates
(`scanner_source: str  # "stof" | "burp" (Phase 2)`).

Built at explicit user instruction, ahead of CLAUDE.md's documented
Phase 2 schedule (same precedent as Layer 8 and Layer 3C). Not
live-verified against a real Burp instance -- see `burp_controller.py`'s
module docstring for why, and treat the exact issue-dict field names
assumed here as best-effort until confirmed against a live scan.

Severity is mapped directly from Burp's own rating, never escalated --
Burp has no "Critical" tier (its ceiling is "High"), and inventing one
here would misrepresent Burp's own assessment. `cvss_score` is a
representative approximation per severity bucket (Burp issues don't
carry a numeric CVSS score at all), same convention this project's own
modules already use for illustrative scores.
"""
from __future__ import annotations

import base64
import binascii
import html
import re
from typing import Any

from stof.crawler.endpoint_store import Endpoint

from .models import Finding

_SEVERITY_MAP = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "information": "Info",
    "info": "Info",
}
_CVSS_BY_SEVERITY = {"High": 8.5, "Medium": 5.5, "Low": 3.0, "Info": 0.5}

_TAG_RE = re.compile(r"<[^>]+>")
_REQUEST_LINE_RE = re.compile(r"^([A-Z]+)\s+(\S+)\s+HTTP/")


def _map_severity(burp_severity: str) -> str:
    return _SEVERITY_MAP.get((burp_severity or "").strip().lower(), "Info")


def _strip_html(markup: str) -> str:
    """Burp's `description_html`/`remediation_html` are real HTML;
    Finding.description/recommendation are plain text rendered through
    Jinja2's autoescaping in the HTML report, so a good-enough tag
    strip (not a full sanitizer -- nothing here is re-rendered as HTML)
    is sufficient rather than pulling in an HTML parser dependency."""
    if not markup:
        return ""
    return html.unescape(_TAG_RE.sub("", markup)).strip()


def _decode_base64(value: str) -> str:
    try:
        return base64.b64decode(value).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return ""


def _decode_evidence(evidence: list[dict[str, Any]]) -> tuple[str, str]:
    """Returns (request_raw, response_raw), joining multiple evidence
    entries (Burp can attach more than one request/response pair to a
    single issue) with a separator. Missing/malformed evidence yields
    an honest placeholder rather than a blank field or a crash."""
    requests: list[str] = []
    responses: list[str] = []
    for item in evidence or []:
        pair = item.get("request_response")
        if not pair:
            continue
        if pair.get("request"):
            requests.append(_decode_base64(pair["request"]))
        if pair.get("response"):
            responses.append(_decode_base64(pair["response"]))

    request_raw = "\n\n---\n\n".join(r for r in requests if r) or "(no request evidence provided by Burp for this issue)"
    response_raw = "\n\n---\n\n".join(r for r in responses if r) or "(no response evidence provided by Burp for this issue)"
    return request_raw, response_raw


def _extract_method(request_raw: str) -> str:
    match = _REQUEST_LINE_RE.match(request_raw.lstrip())
    return match.group(1) if match else "GET"


def normalize_burp_issue(issue: dict[str, Any]) -> Finding:
    severity = _map_severity(issue.get("severity", ""))
    request_raw, response_raw = _decode_evidence(issue.get("evidence", []))
    url = issue.get("path") or issue.get("origin") or "unknown"

    return Finding(
        module_id="burp_active_scan",
        vuln_type=issue.get("name", "Burp Active Scan Finding"),
        severity=severity,
        cvss_score=_CVSS_BY_SEVERITY.get(severity, 0.5),
        endpoint=Endpoint(url=url, method=_extract_method(request_raw), endpoint_type="api", auth_required=True),
        user_role="n/a",
        request_raw=request_raw,
        response_raw=response_raw,
        description=_strip_html(issue.get("description_html", "")) or "No description provided by Burp.",
        recommendation=_strip_html(issue.get("remediation_html", "")) or "See Burp Suite's issue detail for remediation guidance.",
        scanner_source="burp",
    )


def normalize_burp_issues(issues: list[dict[str, Any]]) -> list[Finding]:
    return [normalize_burp_issue(issue) for issue in issues]
