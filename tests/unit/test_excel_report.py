"""Unit tests for Layer 13 — stof.reporting.excel_report."""
from datetime import datetime, timezone

from openpyxl import load_workbook

from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding
from stof.reporting.excel_report import write


def _finding(**overrides) -> Finding:
    endpoint = Endpoint(url="https://x/admin/admin.jsp", method="GET", endpoint_type="page", parameters=[])
    defaults = dict(
        module_id="idor_tests", vuln_type="Vertical Privilege Escalation", severity="Critical", cvss_score=8.8,
        endpoint=endpoint, user_role="normal", request_raw="GET x", response_raw="HTTP 200",
        description="desc", recommendation="rec", discovered_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_write_produces_a_readable_workbook_with_header_and_rows(tmp_path):
    findings = [_finding(finding_id="f1"), _finding(finding_id="f2", severity="High")]
    path = write(findings, tmp_path / "report.xlsx")

    wb = load_workbook(path)
    ws = wb.active

    assert ws.cell(row=1, column=1).value == "Finding ID"
    assert ws.cell(row=2, column=1).value == "f1"
    assert ws.cell(row=3, column=1).value == "f2"
    assert ws.cell(row=2, column=3).value == "Critical"


def test_write_with_no_findings_still_produces_header_only(tmp_path):
    path = write([], tmp_path / "empty.xlsx")

    wb = load_workbook(path)
    ws = wb.active
    assert ws.cell(row=1, column=1).value == "Finding ID"
    assert ws.cell(row=2, column=1).value is None


def test_write_creates_parent_directories(tmp_path):
    path = write([], tmp_path / "nested" / "dir" / "report.xlsx")
    assert path.is_file()


def test_write_includes_evidence_refs_joined(tmp_path):
    finding = _finding(evidence_refs=["a.png", "b.json"])
    path = write([finding], tmp_path / "report.xlsx")

    wb = load_workbook(path)
    ws = wb.active
    assert ws.cell(row=2, column=12).value == "a.png; b.json"


def test_write_includes_scanner_source_column(tmp_path):
    findings = [_finding(finding_id="f1", scanner_source="stof"), _finding(finding_id="f2", scanner_source="burp")]
    path = write(findings, tmp_path / "report.xlsx")

    wb = load_workbook(path)
    ws = wb.active
    assert ws.cell(row=1, column=8).value == "Source"
    assert ws.cell(row=2, column=8).value == "STOF"
    assert ws.cell(row=3, column=8).value == "Burp Suite Pro"


def test_severity_score_column_is_honestly_labeled_not_cvss(tmp_path):
    """Every cvss_score value across this project is a hardcoded
    illustrative constant, never computed from a real CVSS vector (see
    excel_report.py's own module-level comment). Labeling the column
    "CVSS Score" with no disclaimer would let a client mistake it for a
    real calculated score -- e.g. feeding it into an SLA. The column
    must be honestly named, and the disclaimer must be visible on the
    sheet itself, not just in a hover-only comment."""
    finding = _finding(finding_id="f1")
    path = write([finding], tmp_path / "report.xlsx")

    wb = load_workbook(path)
    ws = wb.active
    header_cell = ws.cell(row=1, column=4)
    assert header_cell.value == "Severity Score (Illustrative)"
    assert "CVSS" not in header_cell.value
    assert header_cell.comment is not None
    assert "not a calculated CVSS" in header_cell.comment.text

    # An always-visible footer note, not just the hover comment.
    found_note = any(
        row[0].value and "not a calculated CVSS" in str(row[0].value)
        for row in ws.iter_rows(min_row=2, max_col=1)
    )
    assert found_note, "expected an always-visible disclaimer row below the data"
