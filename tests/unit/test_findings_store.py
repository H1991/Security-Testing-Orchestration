"""Unit tests for Layer 10 — stof.findings.store."""
from datetime import datetime, timezone

from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding
from stof.findings.store import FindingDB, load, write_findings


def _finding(**overrides) -> Finding:
    endpoint = Endpoint(url="https://x/admin/admin.jsp", method="GET", endpoint_type="page", parameters=[])
    defaults = dict(
        module_id="idor_tests",
        vuln_type="Vertical Privilege Escalation / Broken Function Level Authorization",
        severity="Critical",
        cvss_score=8.8,
        endpoint=endpoint,
        user_role="normal",
        request_raw="GET https://x/admin/admin.jsp",
        response_raw="HTTP 200, 27863 bytes",
        description="desc",
        recommendation="rec",
        discovered_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# JSON write/load
# ---------------------------------------------------------------------------


def test_write_and_load_round_trips(tmp_path):
    findings = [_finding(finding_id="f1"), _finding(finding_id="f2", user_role="admin")]
    path = write_findings(findings, path=tmp_path / "findings.json")

    loaded = load(path)

    assert len(loaded) == 2
    assert {f.finding_id for f in loaded} == {"f1", "f2"}


def test_load_missing_file_returns_empty_list(tmp_path):
    assert load(tmp_path / "does_not_exist.json") == []


# ---------------------------------------------------------------------------
# SQLite mirror
# ---------------------------------------------------------------------------


def test_finding_db_save_and_load_scan_round_trips(tmp_path):
    db = FindingDB(db_path=tmp_path / "stof.db")
    findings = [_finding(finding_id="f1"), _finding(finding_id="f2")]

    db.save("scan-1", findings)
    loaded = db.load_scan("scan-1")

    assert {f.finding_id for f in loaded} == {"f1", "f2"}


def test_finding_db_isolates_by_scan_id(tmp_path):
    db = FindingDB(db_path=tmp_path / "stof.db")
    db.save("scan-1", [_finding(finding_id="f1")])
    db.save("scan-2", [_finding(finding_id="f2")])

    assert [f.finding_id for f in db.load_scan("scan-1")] == ["f1"]
    assert [f.finding_id for f in db.load_scan("scan-2")] == ["f2"]


def test_finding_db_list_scan_ids(tmp_path):
    db = FindingDB(db_path=tmp_path / "stof.db")
    db.save("scan-1", [_finding()])
    db.save("scan-2", [_finding()])

    assert db.list_scan_ids() == ["scan-1", "scan-2"]


def test_finding_db_load_scan_missing_returns_empty(tmp_path):
    db = FindingDB(db_path=tmp_path / "stof.db")

    assert db.load_scan("nope") == []
