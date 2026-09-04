"""Unit tests for Layer 9 — stof.modules.results."""
import pytest

from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding
from stof.modules.results import ERROR, FAIL, NOT_IMPLEMENTED, PASS, SKIPPED, TestCaseResult, extract_findings, summarize


def _finding() -> Finding:
    endpoint = Endpoint(url="https://x/api/orders/5", method="GET", endpoint_type="api", parameters=["id"])
    return Finding(
        module_id="idor_tests", vuln_type="IDOR", severity="Critical", cvss_score=8.1,
        endpoint=endpoint, user_role="admin", request_raw="GET x", response_raw="HTTP 200",
        description="desc", recommendation="rec",
    )


def _result(status: str, finding: Finding | None = None) -> TestCaseResult:
    return TestCaseResult(
        test_id="TC-053", technique_id="TC-053.1", technique="Path substitution",
        vuln_type="IDOR", module_id="idor_tests", severity="Critical",
        status=status, detail="detail", finding=finding,
    )


def test_fail_status_requires_a_finding():
    with pytest.raises(ValueError, match="requires a Finding"):
        _result(FAIL)


def test_fail_status_with_finding_is_valid():
    result = _result(FAIL, finding=_finding())
    assert result.status == FAIL
    assert result.finding is not None


def test_pass_skipped_not_implemented_error_do_not_require_a_finding():
    for status in (PASS, SKIPPED, NOT_IMPLEMENTED, ERROR):
        result = _result(status)
        assert result.finding is None


def test_unknown_status_rejected():
    with pytest.raises(ValueError, match="unknown TestCaseResult status"):
        _result("MAYBE")


def test_to_dict_includes_finding_id_only_when_present():
    passing = _result(PASS)
    failing = _result(FAIL, finding=_finding())

    assert passing.to_dict()["finding_id"] is None
    assert failing.to_dict()["finding_id"] == failing.finding.finding_id


def test_extract_findings_returns_only_fail_findings():
    f1, f2 = _finding(), _finding()
    results = [_result(PASS), _result(FAIL, finding=f1), _result(SKIPPED), _result(FAIL, finding=f2)]

    findings = extract_findings(results)

    assert findings == [f1, f2]


def test_extract_findings_deduplicates_a_finding_reused_across_techniques():
    """Regression: TC-050.1/.2-style techniques deliberately reuse
    another technique's already-confirmed Finding object as evidence
    for an umbrella category instead of probing again -- without
    dedup, the same underlying vulnerability was counted once per
    technique that reused it, inflating the Critical tally in a real
    scan's report."""
    shared = _finding()
    distinct = _finding()
    results = [
        _result(FAIL, finding=shared),  # e.g. TC-053.2
        _result(FAIL, finding=shared),  # e.g. TC-050.1, reusing TC-053.2's finding
        _result(FAIL, finding=shared),  # e.g. TC-050.2, reusing it again
        _result(FAIL, finding=distinct),
    ]

    findings = extract_findings(results)

    assert findings == [shared, distinct]


def test_extract_findings_stamps_technique_id_cwe_and_owasp_onto_the_finding():
    """Regression: `Finding` never carried the `technique_id` of the
    technique that produced it, forcing every downstream consumer
    (the walkthrough builder, the frontend's own CWE/OWASP display) to
    independently re-guess a classification from prose text. This is
    the one place (`extract_findings`) that has both objects in hand
    to stamp it once, authoritatively."""
    finding = _finding()  # module_id="idor_tests", vuln_type="IDOR"
    result = _result(FAIL, finding=finding)  # technique_id="TC-053.1"

    extracted = extract_findings([result])

    assert extracted[0].technique_id == "TC-053.1"
    assert extracted[0].cwe is not None and extracted[0].cwe != "Unmapped"
    assert extracted[0].owasp_category is not None and extracted[0].owasp_category != "Unmapped"


def test_extract_findings_empty_when_no_fail():
    results = [_result(PASS), _result(SKIPPED), _result(NOT_IMPLEMENTED)]
    assert extract_findings(results) == []


def test_summarize_counts_every_status():
    results = [_result(PASS), _result(PASS), _result(FAIL, finding=_finding()), _result(SKIPPED), _result(NOT_IMPLEMENTED), _result(ERROR)]

    counts = summarize(results)

    assert counts == {PASS: 2, FAIL: 1, SKIPPED: 1, NOT_IMPLEMENTED: 1, ERROR: 1}


def test_summarize_empty_list_yields_zero_counts():
    counts = summarize([])
    assert all(v == 0 for v in counts.values())
