"""Unit tests for stof.findings.fingerprint -- the stable cross-scan
identity closing the "every scan looks like N brand new findings, even
when N-1 are the same open issue" gap flagged by external review."""
from datetime import datetime, timezone

from stof.crawler.endpoint_store import Endpoint
from stof.findings.fingerprint import compute_fingerprint
from stof.findings.models import Finding


def _endpoint(**overrides) -> Endpoint:
    defaults = dict(url="https://x/bank/showAccount", method="GET", endpoint_type="api", parameters=["listAccounts"])
    defaults.update(overrides)
    return Endpoint(**defaults)


def _finding(**overrides) -> Finding:
    defaults = dict(
        module_id="idor_tests",
        vuln_type="Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization",
        severity="High",
        cvss_score=8.1,
        endpoint=_endpoint(),
        user_role="admin",
        request_raw="GET https://x/bank/showAccount?listAccounts=800001",
        response_raw="HTTP 200, 4213 bytes",
        description="desc",
        recommendation="rec",
        discovered_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_identical_technique_endpoint_role_produce_the_same_fingerprint():
    """The whole point: two findings from two DIFFERENT scans of the
    same target/technique/endpoint/role must hash identically, even
    with a fresh random finding_id and a different discovered_at."""
    a = _finding(technique_id="TC-053.1", discovered_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    b = _finding(technique_id="TC-053.1", discovered_at=datetime(2026, 3, 5, tzinfo=timezone.utc))

    assert compute_fingerprint(a) == compute_fingerprint(b)
    assert a.finding_id != b.finding_id  # sanity: these really are two distinct Finding objects


def test_query_string_does_not_affect_the_fingerprint():
    """A different candidate-id/marker value in the query string across
    runs must not make an otherwise-identical finding hash differently
    -- that's exactly the injected-payload noise a stable identity
    needs to strip out."""
    a = _finding(technique_id="TC-053.1", endpoint=_endpoint(url="https://x/bank/showAccount?listAccounts=800001"))
    b = _finding(technique_id="TC-053.1", endpoint=_endpoint(url="https://x/bank/showAccount?listAccounts=999999&extra=1"))

    assert compute_fingerprint(a) == compute_fingerprint(b)


def test_different_technique_id_produces_a_different_fingerprint():
    a = _finding(technique_id="TC-053.1")
    b = _finding(technique_id="TC-053.2")
    assert compute_fingerprint(a) != compute_fingerprint(b)


def test_different_endpoint_path_produces_a_different_fingerprint():
    a = _finding(technique_id="TC-053.1", endpoint=_endpoint(url="https://x/bank/showAccount"))
    b = _finding(technique_id="TC-053.1", endpoint=_endpoint(url="https://x/bank/transfer"))
    assert compute_fingerprint(a) != compute_fingerprint(b)


def test_different_method_produces_a_different_fingerprint():
    a = _finding(technique_id="TC-053.1", endpoint=_endpoint(method="GET"))
    b = _finding(technique_id="TC-053.1", endpoint=_endpoint(method="POST"))
    assert compute_fingerprint(a) != compute_fingerprint(b)


def test_different_role_produces_a_different_fingerprint():
    a = _finding(technique_id="TC-053.1", user_role="admin")
    b = _finding(technique_id="TC-053.1", user_role="normal")
    assert compute_fingerprint(a) != compute_fingerprint(b)


def test_falls_back_to_vuln_type_when_technique_id_is_unset():
    """A Finding constructed directly (e.g. in a unit test, or before
    extract_findings() stamps technique_id in) must still get a stable,
    non-raising fingerprint."""
    finding = _finding(technique_id=None)
    fp = compute_fingerprint(finding)
    assert isinstance(fp, str) and len(fp) == 16


def test_fingerprint_is_deterministic_across_repeated_calls():
    finding = _finding(technique_id="TC-053.1")
    assert compute_fingerprint(finding) == compute_fingerprint(finding)
