"""Unit tests for `_reconstructed_scan_times` in stof/ui/server.py --
the pure helper behind GET /api/scans and GET /api/scans/{id}'s
"reconstructed from disk" branch (a scan this server process never
launched, or a restart dropped the in-memory record for).

Regression coverage: this used to set BOTH started_at and finished_at
to the report's own `generated_at`, making every such scan's Duration
column on the Scans page read 0s even though the real duration was
already sitting in the report as `duration_seconds`.
"""
from stof.ui.server import _reconstructed_scan_times


def test_derives_started_at_from_generated_at_minus_duration():
    report = {"generated_at": "2026-09-08T10:05:10.813000+00:00", "duration_seconds": 1942.8}

    started_at, finished_at = _reconstructed_scan_times(report)

    assert finished_at == "2026-09-08T10:05:10.813000+00:00"
    assert started_at == "2026-09-08T09:32:48.013000+00:00"


def test_finished_at_is_always_the_report_generated_at():
    report = {"generated_at": "2026-09-08T10:05:10.813000+00:00", "duration_seconds": 30}
    _, finished_at = _reconstructed_scan_times(report)
    assert finished_at == report["generated_at"]


def test_missing_duration_falls_back_to_equal_timestamps():
    report = {"generated_at": "2026-09-08T10:05:10.813000+00:00"}
    started_at, finished_at = _reconstructed_scan_times(report)
    assert started_at == finished_at == report["generated_at"]


def test_missing_generated_at_returns_none_for_both():
    assert _reconstructed_scan_times({}) == (None, None)


def test_malformed_generated_at_falls_back_to_equal_timestamps_rather_than_crashing():
    report = {"generated_at": "not-a-real-timestamp", "duration_seconds": 120}
    started_at, finished_at = _reconstructed_scan_times(report)
    assert started_at == finished_at == "not-a-real-timestamp"


def test_zero_duration_yields_equal_timestamps():
    report = {"generated_at": "2026-09-08T10:05:10.813000+00:00", "duration_seconds": 0}
    started_at, finished_at = _reconstructed_scan_times(report)
    assert started_at == finished_at
