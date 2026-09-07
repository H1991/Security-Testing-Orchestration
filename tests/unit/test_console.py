"""Unit tests for Layer 2 — stof.core.console (per-scan log file +
enterprise console output)."""
import logging

from stof.core.console import ScanConsole, _strip_ansi, attach_file_logging, detach_file_logging
from stof.core.logger import get_logger
from stof.modules.results import FAIL, PASS, TestCaseResult


def test_echo_writes_to_both_stdout_and_log_file(tmp_path, capsys):
    console = ScanConsole("abc123", log_dir=tmp_path)

    console.echo("hello world")
    console.close()

    captured = capsys.readouterr()
    assert "hello world" in captured.out
    log_content = console.log_path.read_text(encoding="utf-8")
    assert "hello world" in log_content


def test_log_path_is_scan_id_scoped(tmp_path):
    console = ScanConsole("deadbeef", log_dir=tmp_path)
    console.close()

    assert console.log_path == tmp_path / "scan_deadbeef.log"
    assert console.log_path.is_file()


def test_log_file_lines_are_timestamped(tmp_path):
    console = ScanConsole("abc123", log_dir=tmp_path)
    console.echo("a test line")
    console.close()

    line = console.log_path.read_text(encoding="utf-8").strip().splitlines()[0]
    # ISO-ish timestamp prefix: YYYY-MM-DDTHH:MM:SS.mmmZ <rest>
    timestamp, _, rest = line.partition(" ")
    assert timestamp.endswith("Z")
    assert "T" in timestamp
    assert rest == "a test line"


def test_log_file_strips_ansi_color_codes(tmp_path):
    console = ScanConsole("abc123", log_dir=tmp_path)
    console.echo("\x1b[32mgreen text\x1b[0m")
    console.close()

    content = console.log_path.read_text(encoding="utf-8")
    assert "\x1b[" not in content
    assert "green text" in content


def test_strip_ansi_removes_color_sequences():
    assert _strip_ansi("\x1b[31mred\x1b[0m") == "red"


def test_echo_appends_across_multiple_calls_same_scan(tmp_path):
    console = ScanConsole("abc123", log_dir=tmp_path)
    console.echo("line one")
    console.echo("line two")
    console.close()

    lines = console.log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert lines[0].endswith("line one")
    assert lines[1].endswith("line two")


def test_test_result_logs_pass_and_fail_distinctly(tmp_path):
    console = ScanConsole("abc123", log_dir=tmp_path)
    pass_result = TestCaseResult(
        test_id="TC-053", technique_id="TC-053.1", technique="Path substitution",
        vuln_type="IDOR", module_id="idor_tests", severity="Critical", status=PASS, detail="no distinct objects",
    )
    from stof.crawler.endpoint_store import Endpoint
    from stof.findings.models import Finding
    finding = Finding(
        module_id="idor_tests", vuln_type="IDOR", severity="High", cvss_score=8.1,
        endpoint=Endpoint(url="https://x/a", method="GET", endpoint_type="api"),
        user_role="admin", request_raw="GET x", response_raw="HTTP 200", description="d", recommendation="r",
    )
    fail_result = TestCaseResult(
        test_id="TC-053", technique_id="TC-053.2", technique="Query substitution",
        vuln_type="IDOR", module_id="idor_tests", severity="Critical", status=FAIL, detail="accepted", finding=finding,
    )

    console.test_result(pass_result)
    console.test_result(fail_result)
    console.close()

    content = console.log_path.read_text(encoding="utf-8")
    assert "TC-053.1" in content
    assert "TC-053.2" in content
    assert "[PASS]" in content
    assert "[FAIL]" in content


def test_test_result_never_prints_not_implemented_to_the_terminal(tmp_path, capsys):
    """Regression: interleaving "not applicable to this target"
    (SKIPPED) with "this tool has no code for it yet"
    (NOT_IMPLEMENTED) in the same live scrolling wall made a scan look
    like it was padding its technique count with things it can't
    actually do -- a real objection raised about the tool. The log
    file is still the complete record; only the terminal suppresses it
    here, and only for this one status."""
    console = ScanConsole("abc123", log_dir=tmp_path)
    result = TestCaseResult(
        test_id="TC-085", technique_id="TC-085.1", technique="Gadget-chain RCE",
        vuln_type="Insecure Deserialization", module_id="deserialization_tests", severity="Critical",
        status="NOT_IMPLEMENTED", detail="not implemented by design",
    )

    console.test_result(result)
    console.close()

    captured = capsys.readouterr()
    assert "TC-085.1" not in captured.out
    content = console.log_path.read_text(encoding="utf-8")
    assert "TC-085.1" in content
    assert "[N/A" in content


def test_not_automated_note_lists_not_implemented_technique_ids(tmp_path):
    console = ScanConsole("abc123", log_dir=tmp_path)
    results = [
        TestCaseResult(
            test_id="TC-085", technique_id="TC-085.1", technique="Gadget-chain RCE",
            vuln_type="Insecure Deserialization", module_id="deserialization_tests", severity="Critical",
            status="NOT_IMPLEMENTED", detail="not implemented by design",
        ),
        TestCaseResult(
            test_id="TC-085", technique_id="TC-085.2", technique="Type confusion",
            vuln_type="Insecure Deserialization", module_id="deserialization_tests", severity="Critical",
            status=PASS, detail="no deserialization-shaped error observed",
        ),
    ]

    console.not_automated_note(results)
    console.close()

    content = console.log_path.read_text(encoding="utf-8")
    assert "Not automated by this tool" in content
    assert "TC-085.1" in content
    assert "TC-085.2" not in content  # PASS result, not a not-automated one


def test_not_automated_note_prints_nothing_when_all_results_are_implemented(tmp_path, capsys):
    console = ScanConsole("abc123", log_dir=tmp_path)
    results = [
        TestCaseResult(
            test_id="TC-053", technique_id="TC-053.1", technique="Path substitution",
            vuln_type="IDOR", module_id="idor_tests", severity="Critical", status=PASS, detail="ok",
        ),
    ]

    console.not_automated_note(results)
    console.close()

    captured = capsys.readouterr()
    assert captured.out == ""
    assert console.log_path.read_text(encoding="utf-8") == ""


def test_summary_table_includes_grand_total(tmp_path):
    console = ScanConsole("abc123", log_dir=tmp_path)

    console.summary_table([
        ("idor_tests", {"PASS": 5, "FAIL": 2, "SKIPPED": 1, "NOT_IMPLEMENTED": 0, "ERROR": 0}),
        ("jwt_tests", {"PASS": 2, "FAIL": 0, "SKIPPED": 1, "NOT_IMPLEMENTED": 0, "ERROR": 0}),
    ])
    console.close()

    content = console.log_path.read_text(encoding="utf-8")
    assert "idor_tests" in content
    assert "jwt_tests" in content
    assert "TOTAL" in content


def test_findings_by_severity_lists_nonzero_severities(tmp_path):
    console = ScanConsole("abc123", log_dir=tmp_path)

    console.findings_by_severity({"Critical": 2, "High": 1, "Medium": 0})
    console.close()

    content = console.log_path.read_text(encoding="utf-8")
    assert "Critical 2" in content
    assert "High 1" in content
    assert "Medium 0" not in content  # zero-count severities are omitted


def test_findings_by_severity_shows_none_when_empty(tmp_path):
    console = ScanConsole("abc123", log_dir=tmp_path)

    console.findings_by_severity({})
    console.close()

    content = console.log_path.read_text(encoding="utf-8")
    assert "none" in content


def test_findings_by_severity_flags_unconfirmed_critical_high(tmp_path):
    console = ScanConsole("abc123", log_dir=tmp_path)

    console.findings_by_severity({"Critical": 3}, critical_high_likely=2)
    console.close()

    content = console.log_path.read_text(encoding="utf-8")
    assert "2 Critical/High finding(s) need manual confirmation" in content


def test_findings_by_severity_omits_confirmation_line_when_zero(tmp_path):
    console = ScanConsole("abc123", log_dir=tmp_path)

    console.findings_by_severity({"Critical": 3}, critical_high_likely=0)
    console.close()

    content = console.log_path.read_text(encoding="utf-8")
    assert "need manual confirmation" not in content


def test_application_profile_lists_role_auth_types_and_skips(tmp_path):
    console = ScanConsole("abc123", log_dir=tmp_path)

    console.application_profile(
        {"admin": "form_login", "normal": "form_login"},
        has_graphql=False,
        module_skips=['jwt_tests (no role configured with auth_type: "jwt")'],
    )
    console.close()

    content = console.log_path.read_text(encoding="utf-8")
    assert "admin" in content and "form_login" in content
    assert "not detected" in content
    assert "jwt_tests" in content


def test_application_profile_reports_graphql_detected(tmp_path):
    console = ScanConsole("abc123", log_dir=tmp_path)

    console.application_profile({"admin": "jwt"}, has_graphql=True, module_skips=[])
    console.close()

    content = console.log_path.read_text(encoding="utf-8")
    assert "detected" in content
    assert "not detected" not in content


# ---------------------------------------------------------------------------
# attach_file_logging / detach_file_logging
# ---------------------------------------------------------------------------


def test_attach_file_logging_captures_module_log_calls(tmp_path):
    log_path = tmp_path / "test.log"
    handler = attach_file_logging(log_path)
    try:
        get_logger("modules.idor_tests").info("a probe message")
    finally:
        detach_file_logging(handler)

    assert "a probe message" in log_path.read_text(encoding="utf-8")


def test_attach_file_logging_and_console_share_the_same_utc_clock(tmp_path):
    """Regression: live-verified against a real scan -- `_log.*` lines
    were timestamped in local time (IST, UTC+5:30) while `ScanConsole`'s
    own lines used real UTC, both labeled with a trailing "Z" as if
    they agreed. Both must land within a few seconds of each other."""
    console = ScanConsole("abc123", log_dir=tmp_path)
    handler = attach_file_logging(console.log_path)
    try:
        console.echo("console line")
        get_logger("modules.idor_tests").info("log line")
    finally:
        detach_file_logging(handler)
        console.close()

    lines = console.log_path.read_text(encoding="utf-8").strip().splitlines()
    timestamps = [line.split(" ", 1)[0] for line in lines if "console line" in line or "log line" in line]
    assert len(timestamps) == 2
    from datetime import datetime
    parsed = [datetime.fromisoformat(ts) for ts in timestamps]  # Python 3.11+ parses a trailing "Z" directly
    assert abs((parsed[0] - parsed[1]).total_seconds()) < 5


def test_detach_file_logging_stops_further_writes(tmp_path):
    log_path = tmp_path / "test.log"
    handler = attach_file_logging(log_path)
    get_logger("modules.idor_tests").info("before detach")
    detach_file_logging(handler)
    get_logger("modules.idor_tests").info("after detach")

    content = log_path.read_text(encoding="utf-8")
    assert "before detach" in content
    assert "after detach" not in content


def test_attach_file_logging_does_not_remove_console_handler(tmp_path):
    root = logging.getLogger("stof")
    handler_count_before = len(root.handlers)

    file_handler = attach_file_logging(tmp_path / "test.log")
    try:
        assert len(root.handlers) == handler_count_before + 1
    finally:
        detach_file_logging(file_handler)

    assert len(root.handlers) == handler_count_before


# ---------------------------------------------------------------------------
# workflow_replayed() -- structured event for --workflow's replay outcome
# ---------------------------------------------------------------------------


def _read_events(console: ScanConsole) -> list[dict]:
    import json
    return [json.loads(line) for line in console.events_path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_workflow_replayed_emits_a_structured_event_on_success(tmp_path):
    console = ScanConsole("abc123", log_dir=tmp_path)
    console.workflow_replayed("wf-1", "admin", True, 4, 4, "https://x/dashboard")
    console.close()

    events = [e for e in _read_events(console) if e["event"] == "workflow_replayed"]
    assert len(events) == 1
    assert events[0]["workflow_id"] == "wf-1"
    assert events[0]["role"] == "admin"
    assert events[0]["success"] is True
    assert events[0]["completed_actions"] == 4
    assert events[0]["total_actions"] == 4
    assert events[0]["final_url"] == "https://x/dashboard"
    assert events[0]["error"] is None


def test_workflow_replayed_emits_a_structured_event_on_failure(tmp_path):
    console = ScanConsole("abc123", log_dir=tmp_path)
    console.workflow_replayed("wf-2", "normal", False, 2, 5, "https://x/login", error="boom")
    console.close()

    events = [e for e in _read_events(console) if e["event"] == "workflow_replayed"]
    assert events[0]["success"] is False
    assert events[0]["error"] == "boom"


def test_workflow_replayed_also_prints_a_readable_log_line(tmp_path):
    console = ScanConsole("abc123", log_dir=tmp_path)
    console.workflow_replayed("wf-1", "admin", True, 7, 7, "https://x/bank/main.jsp")
    console.close()

    content = console.log_path.read_text(encoding="utf-8")
    assert "wf-1" in content
    assert "7/7" in content
    assert "https://x/bank/main.jsp" in content
