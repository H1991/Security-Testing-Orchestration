"""Unit tests for Layer 10 — stof.findings.classification.

The authoritative CWE/OWASP lookup that replaces what used to be
independently duplicated keyword-guessing in the frontend
(stof/ui/static/index.html) and stof/reporting/walkthrough_classify.py.
"""
from stof.findings.classification import (
    classify_cwe,
    classify_owasp,
)


def test_classify_cwe_falls_back_to_module_default():
    cwe = classify_cwe("sqli_tests", "some vuln type with no keyword match", "no keyword here either")
    assert cwe == "CWE-89 - SQL Injection"


def test_classify_cwe_keyword_override_wins_over_module_default():
    """A csrf_tests-module finding whose text happens to describe IDOR
    (e.g. a shared umbrella technique) should classify by content, not
    blindly by which module produced it."""
    cwe = classify_cwe("csrf_tests", "Insecure Direct Object Reference (IDOR)", "")
    assert cwe == "CWE-639 - Authorization Bypass Through User-Controlled Key"


def test_classify_cwe_unmapped_for_unknown_module_and_no_keyword():
    assert classify_cwe("totally_unknown_module", "nothing recognizable", "") == "Unmapped"


def test_classify_cwe_is_case_insensitive():
    cwe = classify_cwe("unknown_module", "SQL INJECTION found", "")
    assert cwe == "CWE-89 - SQL Injection"


def test_classify_owasp_prefers_api_2023_over_web_2025_for_api_shaped_modules():
    """ssrf_tests is API-shaped (SSRF has its own dedicated API Security
    Top 10:2023 category) -- that must win over the more general Web
    Top 10:2025 category a plain module-to-Web mapping would give it."""
    owasp = classify_owasp("ssrf_tests", "no keyword match here", "")
    assert owasp == "API7:2023 - Server Side Request Forgery (SSRF)"


def test_classify_owasp_falls_back_to_web_2025_module_default():
    """auth_tests has no dedicated API Security Top 10:2023 entry (it's
    general auth, not API-specific) -- falls through to the current Web
    Top 10:2025 category, not the 2021 one."""
    owasp = classify_owasp("auth_tests", "no keyword match here", "")
    assert owasp == "A07:2025 - Identification and Authentication Failures"


def test_classify_owasp_keyword_override_wins_over_module_default():
    owasp = classify_owasp("unknown_module", "Reflected Cross-Site Scripting", "")
    assert owasp == "A05:2025 - Injection"


def test_classify_owasp_mass_assignment_maps_to_its_own_api_2023_category():
    """A real, direct improvement over the old 2021-only mapping: mass
    assignment has its own precise API Security Top 10:2023 category
    (API3) rather than being lumped into a vague "Integrity Failures"
    Web bucket."""
    owasp = classify_owasp("mass_assignment_tests", "Mass Assignment", "")
    assert owasp == "API3:2023 - Broken Object Property Level Authorization"


def test_classify_owasp_business_logic_maps_to_its_own_api_2023_category():
    owasp = classify_owasp("business_logic_tests", "Business Logic Flaw", "")
    assert owasp == "API6:2023 - Unrestricted Access to Sensitive Business Flows"


def test_classify_owasp_unmapped_for_unknown_module_and_no_keyword():
    assert classify_owasp("totally_unknown_module", "nothing recognizable", "") == "Unmapped"


def test_classify_checks_description_as_well_as_vuln_type():
    cwe = classify_cwe("unknown_module", "Generic Finding", "this response leaked pii in the body")
    assert cwe == "CWE-200 - Exposure of Sensitive Information"
