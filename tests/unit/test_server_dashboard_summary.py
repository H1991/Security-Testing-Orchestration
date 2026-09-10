"""Unit tests for the pure aggregation helpers behind
GET /api/dashboard/summary in stof/ui/server.py -- extracted out of the
endpoint itself so the OWASP portfolio breakdown and scan-duration
stats are testable without spinning up the FastAPI app or touching disk.
"""
from stof.ui.server import _attack_surface_summary, _duration_stats, _group_by_target, _owasp_totals, _technologies_from_recon


def _report(findings=None, duration_seconds=None):
    return {"findings": findings or [], "duration_seconds": duration_seconds}


# ---------------------------------------------------------------------------
# _owasp_totals
# ---------------------------------------------------------------------------


def test_owasp_totals_counts_across_multiple_reports():
    reports = [
        _report([{"owasp_category": "A03:2021 - Injection"}, {"owasp_category": "A01:2021 - Broken Access Control"}]),
        _report([{"owasp_category": "A03:2021 - Injection"}]),
    ]

    totals = _owasp_totals(reports)

    assert totals[0] == {"category": "A03:2021 - Injection", "count": 2}
    assert {"category": "A01:2021 - Broken Access Control", "count": 1} in totals


def test_owasp_totals_sorted_descending_by_count():
    reports = [_report([
        {"owasp_category": "A01:2021 - Broken Access Control"},
        {"owasp_category": "A03:2021 - Injection"},
        {"owasp_category": "A03:2021 - Injection"},
        {"owasp_category": "A03:2021 - Injection"},
    ])]

    totals = _owasp_totals(reports)

    assert [t["category"] for t in totals] == ["A03:2021 - Injection", "A01:2021 - Broken Access Control"]


def test_owasp_totals_buckets_missing_category_as_unmapped():
    """A report generated before Finding.owasp_category existed has no
    such key on its findings -- must count under "Unmapped", not crash
    or silently drop the finding from the portfolio total."""
    reports = [_report([{"vuln_type": "Something Old"}])]

    totals = _owasp_totals(reports)

    assert totals == [{"category": "Unmapped", "count": 1}]


def test_owasp_totals_empty_for_no_reports():
    assert _owasp_totals([]) == []


# ---------------------------------------------------------------------------
# _duration_stats
# ---------------------------------------------------------------------------


def test_duration_stats_computes_avg_min_max():
    reports = [_report(duration_seconds=10.0), _report(duration_seconds=30.0), _report(duration_seconds=20.0)]

    stats = _duration_stats(reports)

    assert stats == {"avg": 20.0, "min": 10.0, "max": 30.0, "count": 3}


def test_duration_stats_ignores_reports_with_no_duration():
    reports = [_report(duration_seconds=10.0), _report(duration_seconds=None)]

    stats = _duration_stats(reports)

    assert stats == {"avg": 10.0, "min": 10.0, "max": 10.0, "count": 1}


def test_duration_stats_none_when_no_report_has_a_duration():
    assert _duration_stats([_report(duration_seconds=None)]) is None


def test_duration_stats_none_for_no_reports():
    assert _duration_stats([]) is None


# ---------------------------------------------------------------------------
# _attack_surface_summary
# ---------------------------------------------------------------------------


def _endpoint(endpoint_type, parameters=None):
    return {"endpoint_type": endpoint_type, "parameters": parameters or []}


def test_attack_surface_summary_counts_by_type():
    endpoints = [
        _endpoint("page"), _endpoint("page"), _endpoint("form"), _endpoint("api"), _endpoint("api"), _endpoint("api"),
    ]

    summary = _attack_surface_summary(endpoints)

    assert summary == {"endpoints": 6, "pages": 2, "forms": 1, "api_endpoints": 3, "parameters": 0}


def test_attack_surface_summary_deduplicates_parameter_names():
    endpoints = [_endpoint("api", ["id", "q"]), _endpoint("api", ["id", "page"])]

    summary = _attack_surface_summary(endpoints)

    assert summary["parameters"] == 3  # id, q, page -- "id" not double-counted


def test_attack_surface_summary_empty_for_no_endpoints():
    assert _attack_surface_summary([]) == {"endpoints": 0, "pages": 0, "forms": 0, "api_endpoints": 0, "parameters": 0}


# ---------------------------------------------------------------------------
# _technologies_from_recon -- surfaces stof/recon/recon_engine.py's
# ReconReport.tech_stack (already computed on every `stof scan`, was
# never read by this server before) into the Dashboard's "Discovered
# attack surface" card.
# ---------------------------------------------------------------------------


def test_technologies_from_recon_dedupes_across_pages():
    recon = {"tech_stack": [
        {"url": "https://x.test/", "tech": ["nginx", "React"]},
        {"url": "https://x.test/about", "tech": ["nginx"]},
    ]}

    result = _technologies_from_recon(recon)

    assert [r["name"] for r in result] == ["React", "nginx"]


def test_technologies_from_recon_keeps_first_page_seen_as_evidence():
    recon = {"tech_stack": [
        {"url": "https://x.test/first", "tech": ["React"]},
        {"url": "https://x.test/second", "tech": ["React"]},
    ]}

    result = _technologies_from_recon(recon)

    assert result[0]["evidence"] == "seen on https://x.test/first"


def test_technologies_from_recon_empty_for_no_tech_stack():
    assert _technologies_from_recon({}) == []
    assert _technologies_from_recon({"tech_stack": []}) == []


def test_technologies_from_recon_handles_page_with_no_tech_detected():
    recon = {"tech_stack": [{"url": "https://x.test/", "tech": []}]}
    assert _technologies_from_recon(recon) == []


def test_technologies_from_recon_sorted_alphabetically():
    recon = {"tech_stack": [{"url": "https://x.test/", "tech": ["nginx", "Angular", "jQuery"]}]}

    names = [r["name"] for r in _technologies_from_recon(recon)]

    assert names == sorted(names)


# ---------------------------------------------------------------------------
# _group_by_target
# ---------------------------------------------------------------------------


def _target_report(target, scan_id, generated_at, total=0, by_severity=None):
    return {
        "target": target, "scan_id": scan_id, "generated_at": generated_at,
        "summary": {"total_findings": total, "by_severity": by_severity or {}},
    }


def test_group_by_target_splits_real_distinct_targets():
    reports = [
        _target_report("https://a.example", "s1", "2026-01-01T00:00:00Z"),
        _target_report("https://b.example", "s2", "2026-01-02T00:00:00Z"),
    ]

    groups = _group_by_target(reports)

    assert {g["target"] for g in groups} == {"https://a.example", "https://b.example"}
    assert all(g["scan_count"] == 1 for g in groups)


def test_group_by_target_counts_multiple_scans_of_the_same_target():
    reports = [
        _target_report("https://a.example", "s1", "2026-01-01T00:00:00Z"),
        _target_report("https://a.example", "s2", "2026-01-02T00:00:00Z"),
        _target_report("https://a.example", "s3", "2026-01-03T00:00:00Z"),
    ]

    groups = _group_by_target(reports)

    assert len(groups) == 1
    assert groups[0]["scan_count"] == 3


def test_group_by_target_latest_fields_come_from_the_most_recent_scan():
    """Reports arrive oldest-to-newest (the caller's own sort order) --
    the LAST report seen for a target must win, not the first."""
    reports = [
        _target_report("https://a.example", "s1", "2026-01-01T00:00:00Z", total=2, by_severity={"Critical": 1}),
        _target_report("https://a.example", "s2", "2026-01-05T00:00:00Z", total=9, by_severity={"Critical": 3}),
    ]

    groups = _group_by_target(reports)

    assert groups[0]["latest_scan_id"] == "s2"
    assert groups[0]["latest_total"] == 9
    assert groups[0]["latest_by_severity"] == {"Critical": 3}


def test_group_by_target_sorted_most_recently_scanned_first():
    reports = [
        _target_report("https://old.example", "s1", "2026-01-01T00:00:00Z"),
        _target_report("https://new.example", "s2", "2026-01-10T00:00:00Z"),
    ]

    groups = _group_by_target(reports)

    assert [g["target"] for g in groups] == ["https://new.example", "https://old.example"]


def test_group_by_target_empty_for_no_reports():
    assert _group_by_target([]) == []
