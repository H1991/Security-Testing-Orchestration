"""Unit tests for scripts/benchmark.py's pure scoring logic.

Not part of the `stof` package (the script itself lives in scripts/,
deliberately outside it -- see its own module docstring), so this test
imports it directly by path rather than as a package module.
"""
import importlib.util
import sys
from pathlib import Path

_SCRIPT_PATH = Path(__file__).resolve().parent.parent.parent / "scripts" / "benchmark.py"
_spec = importlib.util.spec_from_file_location("stof_benchmark_script", _SCRIPT_PATH)
benchmark = importlib.util.module_from_spec(_spec)
sys.modules["stof_benchmark_script"] = benchmark
_spec.loader.exec_module(benchmark)


def _finding(vuln_type: str, endpoint_url: str = "", severity: str = "Medium") -> dict:
    return {"vuln_type": vuln_type, "severity": severity, "endpoint": {"url": endpoint_url}}


def _case(**overrides) -> dict:
    base = {
        "id": "T-1", "category": "test", "description": "d",
        "expects_vuln_type_keywords": ["sql injection"],
        "expects_endpoint_keywords": ["login"],
        "expected_severity_at_least": "Medium",
    }
    base.update(overrides)
    return base


def test_matches_case_true_when_vuln_type_and_endpoint_both_match():
    finding = _finding("SQL Injection (login bypass)", "https://x/doLogin")
    assert benchmark._matches_case(finding, _case()) is True


def test_matches_case_false_when_vuln_type_matches_but_endpoint_does_not():
    finding = _finding("SQL Injection (login bypass)", "https://x/search")
    assert benchmark._matches_case(finding, _case()) is False


def test_matches_case_false_when_vuln_type_does_not_match():
    finding = _finding("Reflected Cross-Site Scripting", "https://x/doLogin")
    assert benchmark._matches_case(finding, _case()) is False


def test_matches_case_is_case_insensitive():
    finding = _finding("sql injection (LOGIN bypass)", "https://X/DOLOGIN")
    assert benchmark._matches_case(finding, _case()) is True


def test_matches_case_true_with_no_endpoint_keywords_required():
    case = _case(expects_endpoint_keywords=[])
    finding = _finding("SQL Injection somewhere", "https://x/anything")
    assert benchmark._matches_case(finding, case) is True


def test_matches_case_handles_endpoint_as_bare_string_not_dict():
    finding = {"vuln_type": "SQL Injection (login bypass)", "endpoint": "https://x/doLogin"}
    assert benchmark._matches_case(finding, _case()) is True


def test_score_computes_recall_and_separates_matched_missed_unmatched():
    ground_truth = {"cases": [
        _case(id="T-1", expects_vuln_type_keywords=["sql injection"], expects_endpoint_keywords=["login"]),
        _case(id="T-2", expects_vuln_type_keywords=["xss"], expects_endpoint_keywords=["search"]),
    ]}
    findings = [
        _finding("SQL Injection (login bypass)", "https://x/doLogin"),  # matches T-1
        _finding("Missing Security Headers", "https://x/"),  # matches neither -> unmatched
    ]

    result = benchmark._score(findings, ground_truth)

    assert result["recall"] == 0.5
    assert result["matched_count"] == 1
    assert result["total_cases"] == 2
    assert [c["case"]["id"] for c in result["matched_cases"]] == ["T-1"]
    assert [c["id"] for c in result["missed_cases"]] == ["T-2"]
    assert len(result["unmatched_findings_for_human_review"]) == 1
    assert result["unmatched_findings_for_human_review"][0]["vuln_type"] == "Missing Security Headers"


def test_score_full_recall_when_every_case_matched():
    ground_truth = {"cases": [_case(id="T-1")]}
    findings = [_finding("SQL Injection (login bypass)", "https://x/doLogin")]

    result = benchmark._score(findings, ground_truth)

    assert result["recall"] == 1.0
    assert result["missed_cases"] == []
    assert result["unmatched_findings_for_human_review"] == []


def test_score_zero_recall_with_no_matching_findings():
    ground_truth = {"cases": [_case(id="T-1")]}
    result = benchmark._score([], ground_truth)

    assert result["recall"] == 0.0
    assert result["matched_count"] == 0
    assert len(result["missed_cases"]) == 1


def test_score_does_not_double_count_one_finding_for_two_cases():
    # A single finding that would satisfy two different ground-truth
    # cases must only be consumed by the first match, not counted
    # toward both -- otherwise recall could exceed reality.
    ground_truth = {"cases": [
        _case(id="T-1", expects_vuln_type_keywords=["sql injection"], expects_endpoint_keywords=[]),
        _case(id="T-2", expects_vuln_type_keywords=["sql injection"], expects_endpoint_keywords=[]),
    ]}
    findings = [_finding("SQL Injection somewhere", "https://x/y")]

    result = benchmark._score(findings, ground_truth)

    assert result["matched_count"] == 1
    assert result["recall"] == 0.5
