"""Layer 13 — openpyxl Excel report, standard VAPT column layout."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from openpyxl import Workbook
from openpyxl.comments import Comment
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from stof.core.logger import get_logger

if TYPE_CHECKING:
    from stof.findings.models import Finding

_log = get_logger("reporting.excel_report")

# Was "CVSS Score" with no vector behind it at all (every value was a
# hardcoded illustrative constant per finding type, none computed --
# see stof.findings.cvss for the fix). A bare score with no vector is
# indistinguishable from a real calculated one once it lands in a
# client's spreadsheet, and clients DO feed CVSS into SLAs ("Critical
# >= 9.0 = fix in 24h"). The adjacent CVSS v3.1 Vector column is now
# the actual, independently-recomputable metric string the score comes
# from -- empty only for the rare score CVSS's own discrete metric
# space can't reproduce with any real vector (never a fabricated one).
_COLUMNS = (
    "Finding ID", "Vulnerability", "Severity", "Severity Score (Illustrative)", "CVSS v3.1 Vector", "Endpoint", "Method",
    "User Role", "Source", "Description", "Recommendation", "Discovered At", "Evidence Files",
)
_SEVERITY_SCORE_COL = _COLUMNS.index("Severity Score (Illustrative)") + 1
_CVSS_VECTOR_COL = _COLUMNS.index("CVSS v3.1 Vector") + 1
_SEVERITY_SCORE_NOTE = (
    "The base score of the adjacent CVSS v3.1 Vector column, independently recomputable from it. "
    "Empty vector = no real CVSS v3.1 metric combination reproduces this exact score; "
    "use the Severity column as the authoritative rating in that case."
)

_SOURCE_LABELS = {"stof": "STOF", "burp": "Burp Suite Pro"}

_SEVERITY_FILL = {
    "Critical": "C00000",
    "High": "E97132",
    "Medium": "FFC000",
    "Low": "70AD47",
    "Info": "8EA9DB",
}


def write(findings: list["Finding"], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    wb = Workbook()
    ws = wb.active
    ws.title = "Findings"

    header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF")
    for col_idx, header in enumerate(_COLUMNS, start=1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(wrap_text=True, vertical="center")
        if col_idx == _SEVERITY_SCORE_COL:
            cell.comment = Comment(_SEVERITY_SCORE_NOTE, "STOF")

    for row_idx, finding in enumerate(findings, start=2):
        values = (
            finding.finding_id, finding.vuln_type, finding.severity, finding.cvss_score, finding.cvss_vector or "",
            finding.endpoint.url, finding.endpoint.method, finding.user_role,
            _SOURCE_LABELS.get(finding.scanner_source, finding.scanner_source),
            finding.description, finding.recommendation,
            finding.discovered_at.isoformat(), "; ".join(finding.evidence_refs),
        )
        for col_idx, value in enumerate(values, start=1):
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.alignment = Alignment(wrap_text=True, vertical="top")

        severity_color = _SEVERITY_FILL.get(finding.severity)
        if severity_color:
            severity_cell = ws.cell(row=row_idx, column=3)
            severity_cell.fill = PatternFill(start_color=severity_color, end_color=severity_color, fill_type="solid")
            severity_cell.font = Font(bold=True, color="FFFFFF")

    column_widths = (36, 40, 12, 10, 46, 40, 8, 12, 14, 60, 60, 22, 30)
    for col_idx, width in enumerate(column_widths, start=1):
        ws.column_dimensions[get_column_letter(col_idx)].width = width
    ws.freeze_panes = "A2"

    # Always visible on the sheet itself, not just on hover over one
    # column header -- a reader who never hovers the header still sees
    # this before/while reading the Severity Score column.
    note_row = len(findings) + 3
    ws.merge_cells(start_row=note_row, start_column=1, end_row=note_row, end_column=len(_COLUMNS))
    note_cell = ws.cell(row=note_row, column=1, value=f"* Severity Score: {_SEVERITY_SCORE_NOTE}")
    note_cell.font = Font(italic=True, color="626E7A", size=9)
    note_cell.alignment = Alignment(wrap_text=True, vertical="top")

    wb.save(path)
    _log.info(f"wrote Excel report ({len(findings)} finding(s)) -> {path}")
    return path
