"""Unit tests for Layer 10 — stof.findings.models."""
from datetime import datetime, timezone

from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding


def _endpoint(**overrides) -> Endpoint:
    defaults = dict(url="https://x/bank/showAccount", method="GET", endpoint_type="api", parameters=["listAccounts"])
    defaults.update(overrides)
    return Endpoint(**defaults)


def _finding(**overrides) -> Finding:
    defaults = dict(
        module_id="idor_tests",
        vuln_type="Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization",
        severity="Critical",
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
        "technique_id", "cwe", "owasp_category",
    ]


def test_defaults_match_claude_md_spec():
    finding = _finding()

    assert finding.evidence_refs == []
    assert finding.scanner_source == "stof"
    assert finding.finding_id  # non-empty UUID string


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
