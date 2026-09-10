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
        severity="High",
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


def test_finding_db_round_trips_technique_id_cwe_and_owasp(tmp_path):
    db = FindingDB(db_path=tmp_path / "stof.db")
    finding = _finding(finding_id="f1", technique_id="TC-053.1", cwe="CWE-639 - ...", owasp_category="A01:2021 - ...")

    db.save("scan-1", [finding])
    loaded = db.load_scan("scan-1")[0]

    assert loaded.technique_id == "TC-053.1"
    assert loaded.cwe == "CWE-639 - ..."
    assert loaded.owasp_category == "A01:2021 - ..."


def test_finding_db_handles_a_finding_with_no_technique_id_or_classification(tmp_path):
    """A Finding built before this session's plumbing existed (or any
    caller that never ran it through extract_findings()) has these
    fields as None -- must round-trip cleanly, not error."""
    db = FindingDB(db_path=tmp_path / "stof.db")
    finding = _finding(finding_id="f1")

    db.save("scan-1", [finding])
    loaded = db.load_scan("scan-1")[0]

    assert loaded.technique_id is None
    assert loaded.cwe is None
    assert loaded.owasp_category is None


def test_finding_db_round_trips_fingerprint(tmp_path):
    db = FindingDB(db_path=tmp_path / "stof.db")
    finding = _finding(finding_id="f1", fingerprint="abc123def4567890")

    db.save("scan-1", [finding])
    loaded = db.load_scan("scan-1")[0]

    assert loaded.fingerprint == "abc123def4567890"


def test_finding_db_migrates_a_table_created_before_these_columns_existed(tmp_path):
    """Regression: `CREATE TABLE IF NOT EXISTS` is a no-op against an
    already-created table, so a pre-existing data/stof.db from before
    this change needs an explicit ALTER TABLE migration, not just an
    updated CREATE TABLE statement that only new databases would ever see."""
    import sqlite3

    db_path = tmp_path / "stof.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL, finding_id TEXT NOT NULL, module_id TEXT NOT NULL,
                vuln_type TEXT NOT NULL, severity TEXT NOT NULL, cvss_score REAL NOT NULL,
                endpoint TEXT NOT NULL, user_role TEXT NOT NULL, request_raw TEXT NOT NULL,
                response_raw TEXT NOT NULL, evidence_refs TEXT NOT NULL, description TEXT NOT NULL,
                recommendation TEXT NOT NULL, discovered_at TEXT NOT NULL, scanner_source TEXT NOT NULL
            )
            """
        )

    db = FindingDB(db_path=db_path)  # triggers _init_db()'s migration path
    db.save("scan-1", [_finding(finding_id="f1", technique_id="TC-001.1")])
    loaded = db.load_scan("scan-1")[0]

    assert loaded.technique_id == "TC-001.1"


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
