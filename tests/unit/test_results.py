"""Unit tests for Layer 9 — stof.modules.results."""
import pytest

from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding
from stof.modules.results import ERROR, FAIL, NOT_IMPLEMENTED, PASS, SKIPPED, TestCaseResult, extract_findings, summarize


def _finding(url: str = "https://x/api/orders/5") -> Finding:
    endpoint = Endpoint(url=url, method="GET", endpoint_type="api", parameters=["id"])
    return Finding(
        module_id="idor_tests", vuln_type="IDOR", severity="High", cvss_score=8.1,
        endpoint=endpoint, user_role="admin", request_raw="GET x", response_raw="HTTP 200",
        description="desc", recommendation="rec",
    )


def _result(status: str, finding: Finding | None = None, technique_id: str = "TC-053.1", module_id: str = "idor_tests") -> TestCaseResult:
    return TestCaseResult(
        test_id=technique_id.split(".")[0], technique_id=technique_id, technique="Path substitution",
        vuln_type="IDOR", module_id=module_id, severity="Critical",
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
    f1, f2 = _finding(), _finding(url="https://x/api/orders/6")
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
    distinct = _finding(url="https://x/api/orders/6")  # a genuinely different endpoint/root cause
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


# ---------------------------------------------------------------------------
# Root-cause dedup -- DIFFERENT Finding objects from sibling sub-techniques
# of the same umbrella family, on the same endpoint, get consolidated.
# ---------------------------------------------------------------------------


def test_extract_findings_merges_independently_confirmed_sibling_techniques():
    """TC-055.1 and TC-055.5 each independently build their OWN Finding
    object (not a reused one) for the same real BFLA gap on the same
    endpoint -- these must consolidate into one, not count as two
    separate Critical findings."""
    low_severity = Finding(
        module_id="idor_tests", vuln_type="BFLA", severity="High", cvss_score=7.1,
        endpoint=Endpoint(url="https://x/admin/settings", method="GET", endpoint_type="page"),
        user_role="normal", request_raw="GET x", response_raw="HTTP 200",
        description="Reachable via URL-naming heuristic.", recommendation="rec",
    )
    high_severity = Finding(
        module_id="idor_tests", vuln_type="BFLA", severity="High", cvss_score=8.8,
        endpoint=Endpoint(url="https://x/admin/settings", method="GET", endpoint_type="page"),
        user_role="normal", request_raw="GET x", response_raw="HTTP 200",
        description="Reachable via role-differential matrix.", recommendation="rec",
    )
    results = [
        _result(FAIL, finding=low_severity, technique_id="TC-055.1"),
        _result(FAIL, finding=high_severity, technique_id="TC-055.5"),
    ]

    findings = extract_findings(results)

    assert len(findings) == 1
    assert findings[0] is high_severity  # the higher-severity one is kept
    assert "TC-055.1" in findings[0].description
    assert "Independently confirmed by 1 other technique" in findings[0].description


def test_extract_findings_keeps_different_technique_families_separate():
    """TC-053 (IDOR) and TC-055 (BFLA) on the identical endpoint are
    genuinely different vulnerability classes -- must never merge just
    because they share a module and endpoint."""
    idor = _finding()
    bfla = Finding(
        module_id="idor_tests", vuln_type="BFLA", severity="High", cvss_score=8.8,
        endpoint=idor.endpoint, user_role="normal", request_raw="GET x", response_raw="HTTP 200",
        description="desc", recommendation="rec",
    )
    results = [
        _result(FAIL, finding=idor, technique_id="TC-053.1"),
        _result(FAIL, finding=bfla, technique_id="TC-055.1"),
    ]

    findings = extract_findings(results)

    assert len(findings) == 2


def test_extract_findings_keeps_different_modules_separate():
    """A SQLi finding and an XSS finding on the identical endpoint --
    different modules, must never merge even if they somehow shared a
    top-level technique-id family by coincidence."""
    sqli = Finding(
        module_id="sqli_tests", vuln_type="SQL Injection", severity="Critical", cvss_score=9.8,
        endpoint=Endpoint(url="https://x/search", method="GET", endpoint_type="page"),
        user_role="normal", request_raw="GET x", response_raw="HTTP 200",
        description="desc", recommendation="rec",
    )
    xss = Finding(
        module_id="xss_tests", vuln_type="Reflected Cross-Site Scripting", severity="Medium", cvss_score=6.1,
        endpoint=sqli.endpoint, user_role="normal", request_raw="GET x", response_raw="HTTP 200",
        description="desc", recommendation="rec",
    )
    results = [
        _result(FAIL, finding=sqli, technique_id="TC-127.1", module_id="sqli_tests"),
        _result(FAIL, finding=xss, technique_id="TC-127.2", module_id="xss_tests"),
    ]

    findings = extract_findings(results)

    assert len(findings) == 2


def test_extract_findings_stamps_a_real_cvss_vector():
    result = _result(FAIL, finding=_finding())  # severity="High", cvss_score=8.1

    findings = extract_findings([result])

    assert findings[0].cvss_vector is not None
    assert findings[0].cvss_vector.startswith("CVSS:3.1/")


def test_summarize_counts_every_status():
    results = [_result(PASS), _result(PASS), _result(FAIL, finding=_finding()), _result(SKIPPED), _result(NOT_IMPLEMENTED), _result(ERROR)]

    counts = summarize(results)

    assert counts == {PASS: 2, FAIL: 1, SKIPPED: 1, NOT_IMPLEMENTED: 1, ERROR: 1}


def test_summarize_empty_list_yields_zero_counts():
    counts = summarize([])
    assert all(v == 0 for v in counts.values())
