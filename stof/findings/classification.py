"""Layer 10 — authoritative CWE / OWASP classification.

Single source of truth, promoted from what used to be independently
duplicated, drift-prone logic in `stof/ui/static/index.html` (client-side
`cweFor()`/`owaspCategoryFor()`) and `stof/reporting/walkthrough_classify.py`
(its own separate keyword matching, whose docstring explicitly notes
"`Finding` has no `technique_id` field of its own" as the reason it has
to guess). Neither of those guessed wrong on purpose -- there was
simply nowhere authoritative to look the answer up. Now there is: this
module is called once, from `stof.modules.results.extract_findings()`
(the one place every module's results already funnel through), and the
result is stamped onto the `Finding` itself (`technique_id`/`cwe`/
`owasp_category`) so nothing downstream has to re-derive it.

OWASP classification, in order of preference:
  1. OWASP API Security Top 10 -- 2023 (owasp.org/API-Security/editions/2023/),
     for techniques whose weakness is inherently API-shaped -- broken
     object/property/function-level authorization, unrestricted
     resource consumption, SSRF, sensitive business-flow abuse. These
     have a dedicated, MORE PRECISE category in the API-specific list
     than the general Web one would give them (e.g. mass assignment is
     exactly API3:2023, not a vague "Integrity Failures" bucket).
  2. OWASP Top 10 for Web Applications -- 2025 (owasp.org/Top10/2025/,
     released 2026-11-06), for everything else that maps cleanly onto
     a current Web category.
  3. OWASP Top 10 -- 2021 (Web), kept ONLY as a fallback for a module
     this file hasn't been taught a 2025/2023 mapping for yet -- every
     module STOF ships today has a tier-1 or tier-2 entry, so this
     tier exists for forward-compatibility, not because anything
     currently falls through to it.

CWE numbers are a separate, edition-independent taxonomy (MITRE, not
OWASP) -- unaffected by which OWASP Top 10 edition is current, so that
mapping doesn't need this same tiering.

Two-tier lookup within each list: a per-module default, refined by a
keyword check against `vuln_type`/`description` for modules whose
techniques span more than one weakness class. Still coarse -- a human
should confirm the exact CWE/category on a given finding before it
goes into a client-facing report -- but now computed once,
consistently, and available to every consumer (API JSON, SQLite, the
walkthrough builder) instead of independent guesses that could each
land on a different answer for the same finding.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from stof.findings.models import Finding

# ---------------------------------------------------------------- OWASP mapping
# Tier 1 -- OWASP API Security Top 10:2023. Modules whose entire
# technique set is inherently about API-shaped access-control/resource
# weaknesses get their category from here, not the general Web list.
OWASP_API_MODULE_DEFAULT_2023: dict[str, str] = {
    "idor_tests": "API1:2023 - Broken Object Level Authorization",
    "tenant_tests": "API1:2023 - Broken Object Level Authorization",
    "jwt_tests": "API2:2023 - Broken Authentication",
    "mass_assignment_tests": "API3:2023 - Broken Object Property Level Authorization",
    "bfla_tests": "API5:2023 - Broken Function Level Authorization",
    "role_tests": "API5:2023 - Broken Function Level Authorization",
    "business_logic_tests": "API6:2023 - Unrestricted Access to Sensitive Business Flows",
    "ssrf_tests": "API7:2023 - Server Side Request Forgery (SSRF)",
    "graphql_tests": "API8:2023 - Security Misconfiguration",
}

# Tier 2 -- OWASP Top 10 for Web Applications:2025 (current edition).
OWASP_WEB_MODULE_DEFAULT_2025: dict[str, str] = {
    "csrf_tests": "A01:2025 - Broken Access Control",
    "auth_tests": "A07:2025 - Identification and Authentication Failures",
    "oauth_tests": "A07:2025 - Identification and Authentication Failures",
    "sqli_tests": "A05:2025 - Injection",
    "xss_tests": "A05:2025 - Injection",
    "injection_variants_tests": "A05:2025 - Injection",
    "configuration_tests": "A02:2025 - Security Misconfiguration",
    "cache_tests": "A02:2025 - Security Misconfiguration",
    "disclosure_tests": "A02:2025 - Security Misconfiguration",
    "deserialization_tests": "A08:2025 - Software or Data Integrity Failures",
    "session_weakness_tests": "A07:2025 - Identification and Authentication Failures",
}

# Tier 3 -- OWASP Top 10:2021 (Web), fallback only. Kept as the full
# original mapping so a module added here without a tier-1/tier-2
# entry still gets a real category instead of "Unmapped".
OWASP_WEB_MODULE_FALLBACK_2021: dict[str, str] = {
    "idor_tests": "A01:2021 - Broken Access Control",
    "csrf_tests": "A01:2021 - Broken Access Control",
    "jwt_tests": "A07:2021 - Identification and Authentication Failures",
    "auth_tests": "A07:2021 - Identification and Authentication Failures",
    "oauth_tests": "A07:2021 - Identification and Authentication Failures",
    "sqli_tests": "A03:2021 - Injection",
    "xss_tests": "A03:2021 - Injection",
    "injection_variants_tests": "A03:2021 - Injection",
    "graphql_tests": "A05:2021 - Security Misconfiguration",
    "configuration_tests": "A05:2021 - Security Misconfiguration",
    "cache_tests": "A05:2021 - Security Misconfiguration",
    "disclosure_tests": "A05:2021 - Security Misconfiguration",
    "deserialization_tests": "A08:2021 - Software and Data Integrity Failures",
    "business_logic_tests": "A04:2021 - Insecure Design",
    "ssrf_tests": "A10:2021 - Server-Side Request Forgery",
    "bfla_tests": "A01:2021 - Broken Access Control",
    "role_tests": "A01:2021 - Broken Access Control",
    "tenant_tests": "A01:2021 - Broken Access Control",
    "mass_assignment_tests": "A08:2021 - Software and Data Integrity Failures",
    "session_weakness_tests": "A07:2021 - Identification and Authentication Failures",
}

# [keyword, category] pairs checked in order against vuln_type +
# description (lowercased) -- first match wins, before any module
# default, using whichever list (API-2023 or Web-2025) gives the most
# precise category for that specific weakness shape.
OWASP_KEYWORD_OVERRIDES: tuple[tuple[str, str], ...] = (
    ("mass assignment", "API3:2023 - Broken Object Property Level Authorization"),
    ("excessive data exposure", "API3:2023 - Broken Object Property Level Authorization"),
    ("object-level authorization", "API1:2023 - Broken Object Level Authorization"),
    ("idor", "API1:2023 - Broken Object Level Authorization"),
    ("cross-tenant", "API1:2023 - Broken Object Level Authorization"),
    ("function-level authorization", "API5:2023 - Broken Function Level Authorization"),
    ("privilege escalation", "API5:2023 - Broken Function Level Authorization"),
    ("role manipulation", "API5:2023 - Broken Function Level Authorization"),
    ("ssrf", "API7:2023 - Server Side Request Forgery (SSRF)"),
    ("rate limit", "API4:2023 - Unrestricted Resource Consumption"),
    ("brute force", "API4:2023 - Unrestricted Resource Consumption"),
    ("access control", "A01:2025 - Broken Access Control"),
    ("open redirect", "A01:2025 - Broken Access Control"),
    ("csrf", "A01:2025 - Broken Access Control"),
    ("weak secret", "A04:2025 - Cryptographic Failures"),
    ("httponly", "A04:2025 - Cryptographic Failures"),
    ("samesite", "A04:2025 - Cryptographic Failures"),
    ("secure flag", "A04:2025 - Cryptographic Failures"),
    ("alg:none", "A07:2025 - Identification and Authentication Failures"),
    ("algorithm confusion", "A07:2025 - Identification and Authentication Failures"),
    ("signature", "A07:2025 - Identification and Authentication Failures"),
    ("session fixation", "A07:2025 - Identification and Authentication Failures"),
    ("cors", "A02:2025 - Security Misconfiguration"),
    ("content security policy", "A02:2025 - Security Misconfiguration"),
    (" csp", "A02:2025 - Security Misconfiguration"),
    ("pii", "A02:2025 - Security Misconfiguration"),
    ("sensitive data", "A02:2025 - Security Misconfiguration"),
    ("command injection", "A05:2025 - Injection"),
    ("path traversal", "A05:2025 - Injection"),
    ("directory traversal", "A05:2025 - Injection"),
    ("nosql", "A05:2025 - Injection"),
    ("ldap injection", "A05:2025 - Injection"),
    ("sql injection", "A05:2025 - Injection"),
    ("cross-site scripting", "A05:2025 - Injection"),
    ("xss", "A05:2025 - Injection"),
    ("deserialization", "A08:2025 - Software or Data Integrity Failures"),
)

# ---------------------------------------------------------------- CWE mapping
# Unchanged by OWASP Top 10 edition -- CWE is MITRE's own, separate
# taxonomy of weakness *types*, not a ranked top-10 list that gets
# revised every few years the way OWASP's is.
CWE_MODULE_DEFAULT: dict[str, str] = {
    "idor_tests": "CWE-639 - Authorization Bypass Through User-Controlled Key",
    "csrf_tests": "CWE-352 - Cross-Site Request Forgery",
    "jwt_tests": "CWE-287 - Improper Authentication",
    "auth_tests": "CWE-287 - Improper Authentication",
    "oauth_tests": "CWE-287 - Improper Authentication",
    "sqli_tests": "CWE-89 - SQL Injection",
    "xss_tests": "CWE-79 - Cross-Site Scripting",
    "injection_variants_tests": "CWE-74 - Improper Neutralization of Special Elements",
    "graphql_tests": "CWE-284 - Improper Access Control",
    "configuration_tests": "CWE-16 - Configuration",
    "cache_tests": "CWE-524 - Use of Cache Containing Sensitive Information",
    "disclosure_tests": "CWE-200 - Exposure of Sensitive Information",
    "deserialization_tests": "CWE-502 - Deserialization of Untrusted Data",
    "business_logic_tests": "CWE-840 - Business Logic Errors",
    "ssrf_tests": "CWE-918 - Server-Side Request Forgery",
    "bfla_tests": "CWE-862 - Missing Authorization",
    "role_tests": "CWE-269 - Improper Privilege Management",
    "tenant_tests": "CWE-284 - Improper Access Control",
    "mass_assignment_tests": "CWE-915 - Improperly Controlled Modification of Object Attributes",
    "session_weakness_tests": "CWE-613 - Insufficient Session Expiration",
}

CWE_KEYWORD_OVERRIDES: tuple[tuple[str, str], ...] = (
    ("access control", "CWE-284 - Improper Access Control"),
    ("privilege escalation", "CWE-269 - Improper Privilege Management"),
    ("role manipulation", "CWE-269 - Improper Privilege Management"),
    ("object-level authorization", "CWE-639 - Authorization Bypass Through User-Controlled Key"),
    ("function-level authorization", "CWE-862 - Missing Authorization"),
    ("session fixation", "CWE-384 - Session Fixation"),
    ("httponly", "CWE-1004 - Sensitive Cookie Without 'HttpOnly' Flag"),
    ("samesite", "CWE-1275 - Sensitive Cookie with Improper SameSite Attribute"),
    ("secure flag", "CWE-614 - Sensitive Cookie Without 'Secure' Attribute"),
    ("weak secret", "CWE-326 - Inadequate Encryption Strength"),
    ("alg:none", "CWE-347 - Improper Verification of Cryptographic Signature"),
    ("algorithm confusion", "CWE-347 - Improper Verification of Cryptographic Signature"),
    ("signature", "CWE-347 - Improper Verification of Cryptographic Signature"),
    ("rate limit", "CWE-307 - Improper Restriction of Excessive Authentication Attempts"),
    ("brute force", "CWE-307 - Improper Restriction of Excessive Authentication Attempts"),
    ("cors", "CWE-346 - Origin Validation Error"),
    ("content security policy", "CWE-693 - Protection Mechanism Failure"),
    (" csp", "CWE-693 - Protection Mechanism Failure"),
    ("mass assignment", "CWE-915 - Improperly Controlled Modification of Object Attributes"),
    ("command injection", "CWE-78 - OS Command Injection"),
    ("path traversal", "CWE-22 - Path Traversal"),
    ("directory traversal", "CWE-22 - Path Traversal"),
    ("open redirect", "CWE-601 - URL Redirection to Untrusted Site"),
    ("nosql", "CWE-943 - Improper Neutralization in Data Query Logic"),
    ("ldap injection", "CWE-90 - LDAP Injection"),
    ("sql injection", "CWE-89 - SQL Injection"),
    ("cross-site scripting", "CWE-79 - Cross-Site Scripting"),
    ("xss", "CWE-79 - Cross-Site Scripting"),
    ("deserialization", "CWE-502 - Deserialization of Untrusted Data"),
    ("csrf", "CWE-352 - Cross-Site Request Forgery"),
    ("ssrf", "CWE-918 - Server-Side Request Forgery"),
    ("pii", "CWE-200 - Exposure of Sensitive Information"),
    ("sensitive data", "CWE-200 - Exposure of Sensitive Information"),
    ("idor", "CWE-639 - Authorization Bypass Through User-Controlled Key"),
    ("cross-tenant", "CWE-284 - Improper Access Control"),
)


def _haystack(vuln_type: str, description: str) -> str:
    return f"{vuln_type} {description}".lower()


def classify_cwe(module_id: str, vuln_type: str, description: str) -> str:
    hay = _haystack(vuln_type, description)
    for keyword, cwe in CWE_KEYWORD_OVERRIDES:
        if keyword in hay:
            return cwe
    return CWE_MODULE_DEFAULT.get(module_id, "Unmapped")


def classify_owasp(module_id: str, vuln_type: str, description: str) -> str:
    """API Security Top 10:2023 and Web Top 10:2025 keyword overrides
    are checked first (most precise, technique-level); then the
    module's own API-2023 default, then its Web-2025 default; the
    2021 Web mapping is a last-resort fallback for a module that
    somehow has no entry in either current list."""
    hay = _haystack(vuln_type, description)
    for keyword, category in OWASP_KEYWORD_OVERRIDES:
        if keyword in hay:
            return category
    if module_id in OWASP_API_MODULE_DEFAULT_2023:
        return OWASP_API_MODULE_DEFAULT_2023[module_id]
    if module_id in OWASP_WEB_MODULE_DEFAULT_2025:
        return OWASP_WEB_MODULE_DEFAULT_2025[module_id]
    return OWASP_WEB_MODULE_FALLBACK_2021.get(module_id, "Unmapped")


def classify_finding_taxonomy(finding: "Finding") -> tuple[str, str]:
    """Returns `(cwe, owasp_category)` for `finding` -- the single call
    site `extract_findings()` uses to stamp both fields at once.

    Named distinctly from `stof.reporting.walkthrough_classify.classify_finding`
    (a same-module-name-shape but unrelated function that picks a
    replay "player" for a finding, not a CWE/OWASP category) so the two
    are never confused at an import site."""
    cwe = classify_cwe(finding.module_id, finding.vuln_type, finding.description)
    owasp = classify_owasp(finding.module_id, finding.vuln_type, finding.description)
    return cwe, owasp
