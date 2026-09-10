"""Unit tests for the failed-scan visibility fix in stof/ui/server.py.

Regression context: a scan that failed never wrote a report.json (only
the success path does), so `error_tail` -- already captured and
broadcast via the `process_exited` event -- was lost the moment this
server process restarted: `GET /api/scans/{id}` just 404'd, identical
to a scan_id that never existed, with no way to find out why a scan
died. `_write_failure_record()` persists it; `_glob_scan_json()` is the
shared disk-recovery mechanics `list_scans()` uses for both reports and
failure records.
"""
from stof.ui.server import ScanRecord, _glob_scan_json, _write_failure_record


def test_write_failure_record_creates_readable_json(tmp_path, monkeypatch):
    from stof.ui import server
    monkeypatch.setattr(server, "LOGS_DIR", tmp_path)

    record = ScanRecord("abc12345", "https://x.test", ["auth_tests"])
    record.exit_code = 1
    record.finished_at = "2026-09-08T10:00:00+00:00"
    _write_failure_record(record, error_tail="Traceback...\nError: boom", message="scan process exited with code 1")

    path = tmp_path / "scan_abc12345.failure.json"
    assert path.is_file()
    import json
    data = json.loads(path.read_text())
    assert data["scan_id"] == "abc12345"
    assert data["target"] == "https://x.test"
    assert data["modules"] == ["auth_tests"]
    assert data["exit_code"] == 1
    assert data["error_tail"] == "Traceback...\nError: boom"
    assert data["message"] == "scan process exited with code 1"


def test_write_failure_record_handles_empty_error_tail(tmp_path, monkeypatch):
    from stof.ui import server
    monkeypatch.setattr(server, "LOGS_DIR", tmp_path)

    record = ScanRecord("def67890", "https://x.test", [])
    _write_failure_record(record, error_tail="", message="failed to launch scan process: [Errno 2] No such file")

    import json
    data = json.loads((tmp_path / "scan_def67890.failure.json").read_text())
    assert data["error_tail"] == ""
    assert "No such file" in data["message"]


def test_glob_scan_json_finds_matching_files(tmp_path):
    (tmp_path / "scan_aaaa1111.json").write_text('{"target": "https://a.test"}')
    (tmp_path / "scan_bbbb2222.json").write_text('{"target": "https://b.test"}')
    (tmp_path / "not_a_scan_file.json").write_text("{}")

    found = _glob_scan_json(tmp_path, "scan_*.json", r"scan_([0-9a-f]+)\.json$", set())

    ids = {scan_id for scan_id, _ in found}
    assert ids == {"aaaa1111", "bbbb2222"}


def test_glob_scan_json_skips_already_seen_ids():
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as d:
        directory = Path(d)
        (directory / "scan_aaaa1111.json").write_text("{}")
        (directory / "scan_bbbb2222.json").write_text("{}")

        found = _glob_scan_json(directory, "scan_*.json", r"scan_([0-9a-f]+)\.json$", {"aaaa1111"})

        assert [scan_id for scan_id, _ in found] == ["bbbb2222"]


def test_glob_scan_json_adds_found_ids_to_seen_set(tmp_path):
    (tmp_path / "scan_aaaa1111.json").write_text("{}")
    seen: set[str] = set()

    _glob_scan_json(tmp_path, "scan_*.json", r"scan_([0-9a-f]+)\.json$", seen)

    assert seen == {"aaaa1111"}


def test_glob_scan_json_returns_empty_for_missing_directory(tmp_path):
    assert _glob_scan_json(tmp_path / "does-not-exist", "scan_*.json", r"scan_([0-9a-f]+)\.json$", set()) == []


def test_glob_scan_json_distinguishes_failure_files_from_report_files(tmp_path):
    (tmp_path / "scan_aaaa1111.json").write_text('{"kind": "report"}')
    (tmp_path / "scan_aaaa1111.failure.json").write_text('{"kind": "failure"}')

    reports = _glob_scan_json(tmp_path, "scan_*.json", r"scan_([0-9a-f]+)\.json$", set())
    failures = _glob_scan_json(tmp_path, "scan_*.failure.json", r"scan_([0-9a-f]+)\.failure\.json$", set())

    assert len(reports) == 1 and reports[0][1]["kind"] == "report"
    assert len(failures) == 1 and failures[0][1]["kind"] == "failure"
