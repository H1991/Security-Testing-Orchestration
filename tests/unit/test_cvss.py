"""Unit tests for Layer 10 — stof.findings.cvss.

`cvss_base_score` is checked against real, independently-verifiable
CVSS v3.1 reference vectors first (not just internal self-consistency)
-- see the module's own docstring for why that matters before trusting
it as the ground truth `cvss_vector_for`'s solver is built on.
"""
import pytest

from stof.findings.cvss import cvss_base_score, cvss_vector_for, vector_string

# ---------------------------------------------------------------------------
# cvss_base_score -- checked against well-known, widely-cited reference
# vectors (the textbook example for each vulnerability class).
# ---------------------------------------------------------------------------


def test_base_score_matches_canonical_reflected_xss_reference():
    # AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N -- the standard reference score for reflected XSS
    assert cvss_base_score("N", "L", "N", "R", "C", "L", "L", "N") == 6.1


def test_base_score_matches_canonical_sqli_full_compromise_reference():
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -- full-database-compromise SQLi
    assert cvss_base_score("N", "L", "N", "N", "U", "H", "H", "H") == 9.8


def test_base_score_matches_canonical_idor_read_only_reference():
    # AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N -- authenticated read-only IDOR
    assert cvss_base_score("N", "L", "L", "N", "U", "H", "N", "N") == 6.5


def test_base_score_matches_canonical_local_privesc_reference():
    # AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
    assert cvss_base_score("L", "L", "L", "N", "U", "H", "H", "H") == 7.8


def test_base_score_zero_impact_is_zero():
    assert cvss_base_score("N", "L", "N", "N", "U", "N", "N", "N") == 0.0


def test_base_score_never_exceeds_ten():
    assert cvss_base_score("N", "L", "N", "N", "C", "H", "H", "H") <= 10.0


# ---------------------------------------------------------------------------
# cvss_vector_for -- every vector returned must recompute to the exact
# score it was asked for (correct by construction, not by table lookup).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vuln_type,score", [
    ("Reflected Cross-Site Scripting", 6.1),
    ("Stored Cross-Site Scripting", 8.8),
    ("DOM-based Cross-Site Scripting", 6.1),
    ("SQL Injection (error-based)", 9.8),
    ("Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization", 8.1),
    ("Missing Function-Level Authorization (BFLA) via response manipulation", 7.1),
    ("Vertical Privilege Escalation / Broken Function Level Authorization", 8.8),
    ("Server-Side Request Forgery (blind, timing-based)", 7.5),
    ("Cross-Site Request Forgery (CSRF)", 6.1),
    ("JWT Role Manipulation", 8.8),
    ("Insecure Deserialization", 8.1),
    ("Account Takeover via Unauthorized Password Modification", 8.8),
    ("Default Configuration -- Server Version Disclosure", 4.3),
    ("Business Logic -- Workflow Step Skipping", 6.5),
    ("Web Cache Poisoning", 8.6),
])
def test_cvss_vector_for_recomputes_to_the_requested_score(vuln_type, score):
    vector = cvss_vector_for(vuln_type, score)
    assert vector is not None, f"no vector found for {vuln_type!r} @ {score}"
    assert vector.startswith("CVSS:3.1/")
    metrics = dict(part.split(":") for part in vector.split("/")[1:])
    recomputed = cvss_base_score(
        metrics["AV"], metrics["AC"], metrics["PR"], metrics["UI"],
        metrics["S"], metrics["C"], metrics["I"], metrics["A"],
    )
    assert recomputed == score


def test_cvss_vector_for_zero_score_returns_all_none_impact():
    vector = cvss_vector_for("Predictable/Sequential Object Identifiers", 0.0)
    assert vector is not None
    assert "/C:N/I:N/A:N" in vector


def test_cvss_vector_for_unclassified_vuln_type_still_tries_the_generic_baseline():
    # No keyword match at all -- must still attempt the fallback shape's
    # own variants rather than giving up immediately.
    vector = cvss_vector_for("Some Entirely Novel Weakness Class", 5.3)
    assert vector is not None


def test_cvss_vector_for_returns_none_for_a_genuinely_unreachable_score():
    """CVSS v3.1's discrete metric space has real gaps -- 1.0 is not
    reachable by ANY combination of the 8 base metrics (verified by
    exhaustive search across AV/AC/PR/UI/S x the 27 CIA combinations).
    Must return None honestly, never a vector that doesn't actually
    recompute to the score it claims."""
    assert cvss_vector_for("Default Configuration -- Password Autocomplete Enabled", 1.0) is None


def test_vector_string_formats_all_eight_metrics_in_order():
    assert vector_string("N", "L", "N", "R", "C", "L", "L", "N") == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
