"""Unit tests for Layer 10 — stof.findings.models."""
from datetime import datetime, timezone

import pytest

from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding, severity_for_score


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


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_finding_round_trips_through_dict():
    finding = _finding()

    restored = Finding.from_dict(finding.to_dict())

    assert restored == finding


def test_finding_round_trips_through_row():
    finding = _finding()

    restored = Finding.from_row(finding.to_row())

    assert restored == finding


def test_to_dict_matches_claude_md_documented_field_order():
    finding = _finding()

    keys = list(finding.to_dict().keys())

    assert keys == [
        "finding_id", "module_id", "vuln_type", "severity", "cvss_score", "endpoint",
        "user_role", "request_raw", "response_raw", "evidence_refs", "description",
        "recommendation", "discovered_at", "scanner_source",
        # Additive-only, appended after the CLAUDE.md-documented base
        # shape (same "extends, never reorders" precedent every other
        # additive Finding/Endpoint field in this project already
        # follows) -- see Finding.technique_id's own docstring.
        "technique_id", "cwe", "owasp_category", "confidence", "cvss_vector", "confirmed_role", "fingerprint",
    ]


def test_defaults_match_claude_md_spec():
    finding = _finding()

    assert finding.evidence_refs == []
    assert finding.scanner_source == "stof"
    assert finding.finding_id  # non-empty UUID string


def test_confidence_defaults_to_confirmed():
    assert _finding().confidence == "confirmed"


def test_severity_and_confidence_are_independent():
    """High severity + low confidence is a completely valid, expected
    combination (a potentially high-impact vulnerability with weak
    evidence) -- `__post_init__` only cross-checks severity against
    cvss_score, never confidence, and this must stay true."""
    finding = _finding(severity="Critical", cvss_score=9.1, confidence="likely")
    assert finding.severity == "Critical"
    assert finding.confidence == "likely"


def test_from_dict_defaults_missing_confidence_to_confirmed():
    finding = _finding()
    data = finding.to_dict()
    del data["confidence"]

    restored = Finding.from_dict(data)

    assert restored.confidence == "confirmed"


def test_from_row_defaults_missing_confidence_to_confirmed():
    finding = _finding()
    row = finding.to_row()
    row["confidence"] = None  # SQLite: a column that exists but is NULL for this row

    restored = Finding.from_row(row)

    assert restored.confidence == "confirmed"


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_from_dict_defaults_missing_evidence_refs_and_scanner_source():
    finding = _finding()
    data = finding.to_dict()
    del data["evidence_refs"]
    del data["scanner_source"]

    restored = Finding.from_dict(data)

    assert restored.evidence_refs == []
    assert restored.scanner_source == "stof"


# ---------------------------------------------------------------------------
# severity_for_score / Finding.__post_init__ -- CVSS v3.1 severity-band
# enforcement (see severity_for_score's own docstring: an audit found 54
# Finding(...) call sites across the vuln modules where the severity
# label and the numeric cvss_score had drifted, almost always inflated).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("score,expected", [
    (0.0, "Info"),
    (0.1, "Low"),
    (3.9, "Low"),
    (4.0, "Medium"),
    (6.9, "Medium"),
    (7.0, "High"),
    (8.9, "High"),
    (9.0, "Critical"),
    (10.0, "Critical"),
])
def test_severity_for_score_matches_cvss_v3_1_bands(score, expected):
    assert severity_for_score(score) == expected


def test_finding_construction_raises_when_severity_does_not_match_cvss_score():
    with pytest.raises(ValueError, match="High"):
        _finding(severity="Critical", cvss_score=7.5)


def test_finding_construction_succeeds_when_severity_matches_cvss_score():
    finding = _finding(severity="High", cvss_score=7.5)
    assert finding.severity == "High"


def test_finding_severity_validation_skipped_for_burp_scanner_source():
    """A Burp-imported finding (Phase 2) carries Burp's own severity
    judgment, which isn't always a pure function of a CVSS score alone
    (e.g. Burp's own "Information" findings have no CVSS score at
    all) -- STOF has no business overriding another scanner's
    classification, so validation only applies to scanner_source=="stof"."""
    finding = _finding(severity="Critical", cvss_score=0.0, scanner_source="burp")
    assert finding.severity == "Critical"


# ---------------------------------------------------------------------------
# confidence validation -- same "fail the call site's own unit test
# immediately" discipline as the severity/CVSS check above.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("confidence", ["confirmed", "likely", "tentative"])
def test_finding_construction_accepts_every_valid_confidence_tier(confidence):
    finding = _finding(confidence=confidence)
    assert finding.confidence == confidence


def test_finding_construction_raises_on_invalid_confidence():
    with pytest.raises(ValueError, match=r"confirmed.*likely.*tentative|tentative.*likely.*confirmed"):
        _finding(confidence="probably")
