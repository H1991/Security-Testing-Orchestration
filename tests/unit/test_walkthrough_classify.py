"""Unit tests for Layer 13 — stof.reporting.walkthrough_classify."""
from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding
from stof.reporting.walkthrough_classify import (
    ANNOTATED_EVIDENCE,
    AUTHENTICATED_NAVIGATION,
    CSRF_NO_TOKEN,
    DOM_EXECUTION,
    LOGIN_FORM_INJECTION,
    NO_RATE_LIMIT,
    SESSION_AFTER_LOGOUT,
    STORED_PLANT_AND_VIEW,
    URL_REFLECTION,
    classify_finding,
    display_tc_id,
)


def _finding(vuln_type: str, description: str = "") -> Finding:
    endpoint = Endpoint(url="https://x/target", method="GET", endpoint_type="page")
    return Finding(
        module_id="sqli_tests", vuln_type=vuln_type, severity="High", cvss_score=7.0,
        endpoint=endpoint, user_role="normal", request_raw="GET https://x/target",
        response_raw="body", description=description,
        recommendation="fix it",
    )


def test_login_form_injection_matches_sql_login_bypass():
    finding = _finding("SQL Injection", "This SQL Injection allows a Login Bypass on the auth form.")
    assert classify_finding(finding) == LOGIN_FORM_INJECTION


def test_url_reflection_matches_reflected_xss():
    finding = _finding("Reflected Cross-Site Scripting")
    assert classify_finding(finding) == URL_REFLECTION


def test_dom_execution_matches_dom_based_xss():
    finding = _finding("DOM-based Cross-Site Scripting")
    assert classify_finding(finding) == DOM_EXECUTION


def test_stored_plant_and_view_matches_stored_xss():
    finding = _finding("Stored Cross-Site Scripting")
    assert classify_finding(finding) == STORED_PLANT_AND_VIEW


def test_stored_plant_and_view_matches_second_order():
    finding = _finding("SQL Injection (second-order)")
    assert classify_finding(finding) == STORED_PLANT_AND_VIEW


def test_session_after_logout_matches_exact_vuln_type():
    finding = _finding("Session Not Invalidated After Logout")
    assert classify_finding(finding) == SESSION_AFTER_LOGOUT


def test_no_rate_limit_matches_rate_limiting_vuln_type():
    finding = _finding("No Rate Limiting on Login")
    assert classify_finding(finding) == NO_RATE_LIMIT


def test_csrf_no_token_matches_csrf_vuln_type():
    finding = _finding("Cross-Site Request Forgery (CSRF)")
    assert classify_finding(finding) == CSRF_NO_TOKEN


def test_authenticated_navigation_matches_idor():
    finding = _finding("Insecure Direct Object Reference (IDOR)")
    assert classify_finding(finding) == AUTHENTICATED_NAVIGATION


def test_authenticated_navigation_matches_bfla():
    finding = _finding("Broken Function-Level Authorization")
    assert classify_finding(finding) == AUTHENTICATED_NAVIGATION


def test_annotated_evidence_is_the_unconditional_fallback():
    """Something never explicitly categorized -- e.g. a header/config
    disclosure finding -- must still get a real walkthrough via the
    true catch-all, never raise or return an unmapped name."""
    finding = _finding("Missing Security Header: X-Frame-Options")
    assert classify_finding(finding) == ANNOTATED_EVIDENCE


def test_classify_never_raises_on_empty_fields():
    endpoint = Endpoint(url="https://x/y", method="GET", endpoint_type="page")
    finding = Finding(
        module_id="m", vuln_type="", severity="Info", cvss_score=0.0,
        endpoint=endpoint, user_role="normal", request_raw="", response_raw="",
        description="", recommendation="",
    )
    assert classify_finding(finding) == ANNOTATED_EVIDENCE


def test_display_tc_id_matches_known_hint():
    finding = _finding("Reflected Cross-Site Scripting")
    assert display_tc_id(finding) == "TC-128.1"


def test_display_tc_id_falls_back_to_module_id_when_unmatched():
    finding = _finding("Some Novel Never-Before-Seen Vuln Type")
    assert display_tc_id(finding) == finding.module_id
