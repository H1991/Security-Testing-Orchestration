"""Unit tests for stof.findings.baseline -- baseline/diff mode, the
CI-usability feature every one of four independent external reviews
named as the highest-leverage next step."""
import json
from datetime import datetime, timezone

from stof.crawler.endpoint_store import Endpoint
from stof.findings.baseline import compute_diff, find_baseline_scan_id
from stof.findings.models import Finding


def _finding(fingerprint, **overrides) -> Finding:
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
        fingerprint=fingerprint,
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# compute_diff -- pure, no I/O
# ---------------------------------------------------------------------------


def test_finding_present_in_both_is_unchanged_not_new_or_resolved():
    a = _finding("fp1")
    b = _finding("fp1", finding_id="different-object-different-run")

    diff = compute_diff(previous=[a], current=[b], baseline_scan_id="scan-1")

    assert diff.new == []
    assert diff.resolved == []
    assert diff.unchanged_count == 1


def test_finding_only_in_current_is_new():
    diff = compute_diff(previous=[], current=[_finding("fp1")], baseline_scan_id="scan-1")

    assert [f.fingerprint for f in diff.new] == ["fp1"]
    assert diff.resolved == []
    assert diff.unchanged_count == 0


def test_finding_only_in_previous_is_resolved():
    diff = compute_diff(previous=[_finding("fp1")], current=[], baseline_scan_id="scan-1")

    assert diff.new == []
    assert [f.fingerprint for f in diff.resolved] == ["fp1"]
    assert diff.unchanged_count == 0


def test_mixed_new_resolved_and_unchanged():
    previous = [_finding("fp-stays", finding_id="p1"), _finding("fp-resolved", finding_id="p2")]
    current = [_finding("fp-stays", finding_id="c1"), _finding("fp-new", finding_id="c2")]

    diff = compute_diff(previous, current, baseline_scan_id="scan-1")

    assert [f.fingerprint for f in diff.new] == ["fp-new"]
    assert [f.fingerprint for f in diff.resolved] == ["fp-resolved"]
    assert diff.unchanged_count == 1


def test_fingerprintless_finding_is_always_new_never_resolvable():
    previous = [_finding(None, finding_id="p1")]
    current = [_finding(None, finding_id="c1")]

    diff = compute_diff(previous, current, baseline_scan_id="scan-1")

    assert [f.finding_id for f in diff.new] == ["c1"]
    assert diff.resolved == []  # the fingerprint-less previous finding can't be matched, so it's never "resolved"


def test_no_baseline_scan_id_means_every_current_finding_is_new():
    diff = compute_diff(previous=[], current=[_finding("fp1")], baseline_scan_id=None)
    assert diff.baseline_scan_id is None
    assert len(diff.new) == 1


def test_to_dict_shape():
    diff = compute_diff(previous=[_finding("fp-resolved")], current=[_finding("fp-new")], baseline_scan_id="scan-1")
    data = diff.to_dict()

    assert data["baseline_scan_id"] == "scan-1"
    assert data["new_count"] == 1
    assert data["resolved_count"] == 1
    assert data["unchanged_count"] == 0
    assert len(data["new"]) == 1
    assert len(data["resolved"]) == 1


# ---------------------------------------------------------------------------
# find_baseline_scan_id -- reads report JSON files
# ---------------------------------------------------------------------------


def _write_report(reports_dir, scan_id, target, generated_at):
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / f"scan_{scan_id}.json").write_text(
        json.dumps({"scan_id": scan_id, "target": target, "generated_at": generated_at}), encoding="utf-8"
    )


def test_find_baseline_scan_id_returns_none_when_no_reports_dir(tmp_path):
    assert find_baseline_scan_id("https://x", "scan-current", reports_dir=tmp_path / "does_not_exist") is None


def test_find_baseline_scan_id_returns_none_for_the_first_scan_of_a_target(tmp_path):
    reports_dir = tmp_path / "reports"
    _write_report(reports_dir, "scan-current", "https://x", "2026-01-01T00:00:00+00:00")

    assert find_baseline_scan_id("https://x", "scan-current", reports_dir) is None


def test_find_baseline_scan_id_returns_the_most_recent_prior_scan_of_the_same_target(tmp_path):
    reports_dir = tmp_path / "reports"
    _write_report(reports_dir, "scan-old", "https://x", "2026-01-01T00:00:00+00:00")
    _write_report(reports_dir, "scan-mid", "https://x", "2026-02-01T00:00:00+00:00")
    _write_report(reports_dir, "scan-current", "https://x", "2026-03-01T00:00:00+00:00")

    assert find_baseline_scan_id("https://x", "scan-current", reports_dir) == "scan-mid"


def test_find_baseline_scan_id_ignores_reports_for_a_different_target(tmp_path):
    reports_dir = tmp_path / "reports"
    _write_report(reports_dir, "scan-other-target", "https://y", "2026-02-01T00:00:00+00:00")
    _write_report(reports_dir, "scan-current", "https://x", "2026-03-01T00:00:00+00:00")

    assert find_baseline_scan_id("https://x", "scan-current", reports_dir) is None


def test_find_baseline_scan_id_skips_unreadable_report_files(tmp_path):
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True)
    (reports_dir / "scan_broken.json").write_text("not valid json{{{", encoding="utf-8")
    _write_report(reports_dir, "scan-good", "https://x", "2026-01-01T00:00:00+00:00")

    assert find_baseline_scan_id("https://x", "scan-current", reports_dir) == "scan-good"
