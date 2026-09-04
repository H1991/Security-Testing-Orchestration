"""Unit tests for scripts/backfill_classification.py's pure logic.

Not part of the `stof` package (the script lives in scripts/,
deliberately outside it, matching scripts/benchmark.py's own
precedent), so this test imports it directly by path.
"""
import importlib.util
import sys
from pathlib import Path

_SCRIPT_PATH = Path(__file__).resolve().parent.parent.parent / "scripts" / "backfill_classification.py"
_spec = importlib.util.spec_from_file_location("stof_backfill_script", _SCRIPT_PATH)
backfill = importlib.util.module_from_spec(_spec)
sys.modules["stof_backfill_script"] = backfill
_spec.loader.exec_module(backfill)


def test_backfill_finding_stamps_missing_cwe_and_owasp():
    finding = {"module_id": "sqli_tests", "vuln_type": "SQL Injection (login bypass)", "description": ""}

    changed = backfill._backfill_finding(finding)

    assert changed is True
    assert finding["cwe"] == "CWE-89 - SQL Injection"
    assert finding["owasp_category"] == "A05:2025 - Injection"
    assert finding["technique_id"] is None


def test_backfill_finding_leaves_an_already_classified_finding_untouched():
    finding = {"module_id": "sqli_tests", "vuln_type": "X", "description": "", "cwe": "CWE-1 - Custom", "owasp_category": "A01:2021 - Custom"}

    changed = backfill._backfill_finding(finding)

    assert changed is False
    assert finding["cwe"] == "CWE-1 - Custom"
    assert finding["owasp_category"] == "A01:2021 - Custom"


def test_backfill_finding_force_recomputes_even_when_already_classified():
    """Regression for the real need this flag exists for: after a
    classification RULE change (e.g. adopting a new OWASP edition),
    findings stamped under the old rules have real, non-null values --
    the default "only fill in what's missing" check would otherwise
    leave them on outdated categories forever."""
    finding = {"module_id": "sqli_tests", "vuln_type": "SQL Injection", "description": "", "cwe": "CWE-1 - Stale", "owasp_category": "A03:2021 - Stale"}

    changed = backfill._backfill_finding(finding, force=True)

    assert changed is True
    assert finding["owasp_category"] == "A05:2025 - Injection"


def test_backfill_finding_treats_null_cwe_as_missing():
    """A finding with the KEY present but the VALUE null (e.g. written
    by a scan that ran before extract_findings() stamped it, but after
    the Finding model gained the field) must still be backfilled."""
    finding = {"module_id": "xss_tests", "vuln_type": "Reflected XSS", "description": "", "cwe": None, "owasp_category": None}

    changed = backfill._backfill_finding(finding)

    assert changed is True
    assert finding["cwe"] == "CWE-79 - Cross-Site Scripting"


def test_backfill_report_file_updates_findings_in_place(tmp_path):
    import json

    report_path = tmp_path / "scan_abc.json"
    report_path.write_text(json.dumps({
        "findings": [
            {"module_id": "sqli_tests", "vuln_type": "SQL Injection", "description": ""},
            {"module_id": "xss_tests", "vuln_type": "XSS", "description": ""},
        ]
    }))

    changed = backfill._backfill_report_file(report_path, dry_run=False)

    assert changed == 2
    doc = json.loads(report_path.read_text())
    assert doc["findings"][0]["cwe"] == "CWE-89 - SQL Injection"
    assert doc["findings"][1]["cwe"] == "CWE-79 - Cross-Site Scripting"


def test_backfill_report_file_dry_run_does_not_write(tmp_path):
    import json

    report_path = tmp_path / "scan_abc.json"
    original = {"findings": [{"module_id": "sqli_tests", "vuln_type": "SQL Injection", "description": ""}]}
    report_path.write_text(json.dumps(original))

    changed = backfill._backfill_report_file(report_path, dry_run=True)

    assert changed == 1
    assert json.loads(report_path.read_text()) == original


def test_backfill_bare_findings_file_updates_a_flat_list(tmp_path):
    import json

    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps([{"module_id": "ssrf_tests", "vuln_type": "SSRF", "description": ""}]))

    changed = backfill._backfill_bare_findings_file(findings_path, dry_run=False)

    assert changed == 1
    doc = json.loads(findings_path.read_text())
    assert doc[0]["owasp_category"] == "API7:2023 - Server Side Request Forgery (SSRF)"
