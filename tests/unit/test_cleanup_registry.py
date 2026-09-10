"""Unit tests for stof.cleanup.registry -- the planted-state cleanup
ledger closing the "state-changing techniques leave real writes behind
with nothing tracking them" gap flagged by external review."""
from __future__ import annotations

import pytest

from stof.cleanup import registry as cleanup


def _fresh_registry(tmp_path):
    return cleanup.CleanupRegistry(db_path=tmp_path / "stof.db")


# ---------------------------------------------------------------------------
# CleanupRegistry -- direct SQLite CRUD
# ---------------------------------------------------------------------------


def test_record_and_for_scan_round_trips(tmp_path):
    reg = _fresh_registry(tmp_path)

    entry_id = reg.record(
        scan_id="scan-1", module_id="xss_tests", technique_id="TC-128.4",
        kind="planted_content", identifier="stofxssabcd1234",
        endpoint_url="https://x/sendFeedback", role="normal",
        metadata={"field": "comments"},
    )

    rows = reg.for_scan("scan-1")
    assert len(rows) == 1
    assert rows[0]["id"] == entry_id
    assert rows[0]["module_id"] == "xss_tests"
    assert rows[0]["technique_id"] == "TC-128.4"
    assert rows[0]["kind"] == "planted_content"
    assert rows[0]["identifier"] == "stofxssabcd1234"
    assert rows[0]["endpoint_url"] == "https://x/sendFeedback"
    assert rows[0]["role"] == "normal"
    assert rows[0]["metadata"] == {"field": "comments"}
    assert rows[0]["cleanup_status"] == cleanup.NOT_ATTEMPTED
    assert "no generic revert mechanism" in rows[0]["cleanup_detail"]


def test_for_scan_only_returns_rows_for_that_scan(tmp_path):
    reg = _fresh_registry(tmp_path)
    reg.record(scan_id="scan-1", module_id="m", technique_id="t", kind="k", identifier="a")
    reg.record(scan_id="scan-2", module_id="m", technique_id="t", kind="k", identifier="b")

    assert [r["identifier"] for r in reg.for_scan("scan-1")] == ["a"]
    assert [r["identifier"] for r in reg.for_scan("scan-2")] == ["b"]


def test_for_scan_empty_when_nothing_recorded(tmp_path):
    reg = _fresh_registry(tmp_path)
    assert reg.for_scan("scan-1") == []


def test_mark_cleanup_result_updates_status_and_detail(tmp_path):
    reg = _fresh_registry(tmp_path)
    entry_id = reg.record(scan_id="scan-1", module_id="auth_tests", technique_id="TC-025.5", kind="password_change", identifier="normal")

    reg.mark_cleanup_result(entry_id, cleanup.REVERTED, "password reverted to its original value")

    rows = reg.for_scan("scan-1")
    assert rows[0]["cleanup_status"] == cleanup.REVERTED
    assert rows[0]["cleanup_detail"] == "password reverted to its original value"


def test_record_rejects_unknown_cleanup_status(tmp_path):
    reg = _fresh_registry(tmp_path)
    with pytest.raises(ValueError, match="unknown cleanup_status"):
        reg.record(scan_id="scan-1", module_id="m", technique_id="t", kind="k", identifier="a", cleanup_status="maybe")


def test_mark_cleanup_result_rejects_unknown_status(tmp_path):
    reg = _fresh_registry(tmp_path)
    entry_id = reg.record(scan_id="scan-1", module_id="m", technique_id="t", kind="k", identifier="a")
    with pytest.raises(ValueError, match="unknown cleanup_status"):
        reg.mark_cleanup_result(entry_id, "maybe", "detail")


def test_metadata_defaults_to_empty_dict(tmp_path):
    reg = _fresh_registry(tmp_path)
    reg.record(scan_id="scan-1", module_id="m", technique_id="t", kind="k", identifier="a")
    assert reg.for_scan("scan-1")[0]["metadata"] == {}


def test_second_registry_instance_reuses_the_same_db_file(tmp_path):
    """Crash-resume shape: a new CleanupRegistry instance pointed at the
    same db_path must see rows a prior instance wrote."""
    db_path = tmp_path / "stof.db"
    cleanup.CleanupRegistry(db_path=db_path).record(scan_id="scan-1", module_id="m", technique_id="t", kind="k", identifier="a")

    reopened = cleanup.CleanupRegistry(db_path=db_path)
    assert len(reopened.for_scan("scan-1")) == 1


# ---------------------------------------------------------------------------
# Module-level singleton: configure() / record_planted_state() /
# mark_cleanup_result() / summary_for_current_scan()
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Every test gets a clean process-wide singleton state -- these
    tests would otherwise leak configure() calls into each other, since
    the module-level globals persist across tests in the same process."""
    cleanup._registry = None
    cleanup._scan_id = None
    yield
    cleanup._registry = None
    cleanup._scan_id = None


def test_record_planted_state_is_a_noop_when_not_configured():
    """Every existing technique call site (and every unit test that
    constructs a module directly, bypassing main.py's scan entrypoint)
    must keep working unchanged when the registry was never configured."""
    entry_id = cleanup.record_planted_state(module_id="xss_tests", technique_id="TC-128.4", kind="planted_content", identifier="marker")
    assert entry_id is None


def test_mark_cleanup_result_is_a_noop_when_entry_id_is_none():
    cleanup.mark_cleanup_result(None, cleanup.REVERTED, "detail")  # must not raise


def test_summary_for_current_scan_empty_when_not_configured():
    assert cleanup.summary_for_current_scan() == []


def test_configure_then_record_and_summarize_round_trips(tmp_path):
    cleanup.configure(scan_id="scan-abc", db_path=tmp_path / "stof.db")

    entry_id = cleanup.record_planted_state(
        module_id="business_logic_tests", technique_id="TC-135.1", kind="account",
        identifier="stof-buslogic-ab12", endpoint_url="https://x/register", role="unauthenticated",
    )

    summary = cleanup.summary_for_current_scan()
    assert entry_id is not None
    assert len(summary) == 1
    assert summary[0]["module_id"] == "business_logic_tests"
    assert summary[0]["kind"] == "account"
    assert summary[0]["cleanup_status"] == cleanup.NOT_ATTEMPTED


def test_configure_then_mark_cleanup_result_updates_the_row(tmp_path):
    cleanup.configure(scan_id="scan-abc", db_path=tmp_path / "stof.db")
    entry_id = cleanup.record_planted_state(module_id="auth_tests", technique_id="TC-025.5", kind="password_change", identifier="normal")

    cleanup.mark_cleanup_result(entry_id, cleanup.REVERTED, "password reverted successfully")

    summary = cleanup.summary_for_current_scan()
    assert summary[0]["cleanup_status"] == cleanup.REVERTED
    assert summary[0]["cleanup_detail"] == "password reverted successfully"


def test_summary_for_current_scan_only_includes_the_configured_scan_id(tmp_path):
    """Two consecutive scans sharing the same db file (the real
    on-disk shape) must not leak each other's planted-state rows into
    the current scan's report."""
    db_path = tmp_path / "stof.db"
    cleanup.configure(scan_id="scan-1", db_path=db_path)
    cleanup.record_planted_state(module_id="m", technique_id="t", kind="k", identifier="from-scan-1")

    cleanup.configure(scan_id="scan-2", db_path=db_path)
    cleanup.record_planted_state(module_id="m", technique_id="t", kind="k", identifier="from-scan-2")

    summary = cleanup.summary_for_current_scan()
    assert [r["identifier"] for r in summary] == ["from-scan-2"]
