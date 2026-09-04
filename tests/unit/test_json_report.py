"""Unit tests for Layer 13 — stof.reporting.json_report."""
import json
from datetime import datetime, timezone

from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding
from stof.reporting.json_report import build_report, build_summary, write


def _finding(severity="Critical", **overrides) -> Finding:
    endpoint = Endpoint(url="https://x/bank/showAccount", method="GET", endpoint_type="api", parameters=["listAccounts"])
    defaults = dict(
        module_id="idor_tests", vuln_type="IDOR", severity=severity, cvss_score=8.1, endpoint=endpoint,
        user_role="admin", request_raw="GET x", response_raw="HTTP 200", description="d", recommendation="r",
        discovered_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# build_summary
# ---------------------------------------------------------------------------


def test_build_summary_counts_by_severity():
    findings = [_finding("Critical"), _finding("Critical"), _finding("High"), _finding("Low")]

    summary = build_summary(findings)

    assert summary["total_findings"] == 4
    assert summary["by_severity"] == {"Critical": 2, "High": 1, "Medium": 0, "Low": 1, "Info": 0}


def test_build_summary_empty_findings():
    summary = build_summary([])
    assert summary["total_findings"] == 0
    assert summary["by_severity"]["Critical"] == 0


def test_build_summary_counts_by_source():
    findings = [
        _finding(scanner_source="stof"),
        _finding(scanner_source="stof"),
        _finding(scanner_source="burp"),
    ]

    summary = build_summary(findings)

    assert summary["by_source"] == {"STOF": 2, "Burp Suite Pro": 1}


def test_build_summary_by_source_omits_scanners_with_no_findings():
    summary = build_summary([_finding(scanner_source="stof")])
    assert summary["by_source"] == {"STOF": 1}


# ---------------------------------------------------------------------------
# build_report / write
# ---------------------------------------------------------------------------


def test_build_report_includes_scan_metadata_and_findings():
    findings = [_finding()]
    metadata = {"scan_id": "abc123", "target": "https://x", "modules_run": ["idor_tests"]}

    report = build_report(findings, metadata)

    assert report["scan_id"] == "abc123"
    assert report["target"] == "https://x"
    assert report["modules_run"] == ["idor_tests"]
    assert len(report["findings"]) == 1
    assert report["summary"]["total_findings"] == 1


def test_build_report_includes_coverage_when_supplied():
    metadata = {"scan_id": "abc123", "target": "https://x", "coverage": {
        "endpoints_discovered": 25, "endpoints_tested": 18, "endpoints_verified_exploitable": 4,
    }}

    report = build_report([], metadata)

    assert report["coverage"] == {"endpoints_discovered": 25, "endpoints_tested": 18, "endpoints_verified_exploitable": 4}


def test_build_report_coverage_is_none_when_not_supplied():
    report = build_report([], {"scan_id": "abc123", "target": "https://x"})
    assert report["coverage"] is None


def test_write_produces_valid_json_file(tmp_path):
    findings = [_finding()]
    path = write(findings, {"scan_id": "abc123"}, tmp_path / "scan_abc123.json")

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["scan_id"] == "abc123"
    assert len(data["findings"]) == 1


def test_write_creates_parent_directories(tmp_path):
    path = write([], {}, tmp_path / "nested" / "dir" / "report.json")
    assert path.is_file()


def test_write_with_no_findings_still_produces_valid_report(tmp_path):
    path = write([], {"scan_id": "empty"}, tmp_path / "empty.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["findings"] == []
    assert data["summary"]["total_findings"] == 0


# ---------------------------------------------------------------------------
# recon_report / module_notes
# ---------------------------------------------------------------------------


def test_build_report_includes_recon_when_supplied():
    recon = {"target": "https://x", "pages_analyzed": 5, "tech_stack": []}

    report = build_report([], {}, recon_report=recon)

    assert report["recon"] == recon


def test_build_report_omits_recon_key_when_not_supplied():
    report = build_report([], {})
    assert "recon" not in report


def test_build_report_includes_module_notes_from_metadata():
    notes = [{"module": "jwt_tests", "finding_count": 0, "note": "Not applicable."}]

    report = build_report([], {"module_notes": notes})

    assert report["module_notes"] == notes


def test_write_persists_recon_report(tmp_path):
    recon = {"target": "https://x", "pages_analyzed": 3}
    path = write([], {"scan_id": "abc"}, tmp_path / "report.json", recon_report=recon)

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["recon"] == recon
