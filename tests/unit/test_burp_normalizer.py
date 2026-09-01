"""Unit tests for Layer 11 — stof.findings.burp_normalizer.

Fixture issue shapes follow PortSwigger's published REST API docs as
closely as possible without a live instance to confirm against -- see
`burp_controller.py`'s module docstring.
"""
import base64

from stof.findings.burp_normalizer import (
    _decode_evidence,
    _extract_method,
    _map_severity,
    _strip_html,
    normalize_burp_issue,
    normalize_burp_issues,
)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _issue(**overrides) -> dict:
    defaults = dict(
        name="SQL injection",
        severity="high",
        path="https://demo.testfire.net/bank/showAccount?listAccounts=1",
        description_html="<p>The application is vulnerable to <b>SQL injection</b>.</p>",
        remediation_html="<p>Use parameterized queries.</p>",
        evidence=[{
            "request_response": {
                "request": _b64("GET /bank/showAccount?listAccounts=1' HTTP/1.1\r\nHost: demo.testfire.net\r\n\r\n"),
                "response": _b64("HTTP/1.1 500 Internal Server Error\r\n\r\nSQLSTATE[42000]"),
            }
        }],
    )
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_map_severity_known_values():
    assert _map_severity("High") == "High"
    assert _map_severity("medium") == "Medium"
    assert _map_severity("Low") == "Low"
    assert _map_severity("Information") == "Info"


def test_map_severity_never_produces_critical():
    """Burp has no Critical tier -- this must never invent one."""
    for raw in ("high", "medium", "low", "information", "unknown-thing", ""):
        assert _map_severity(raw) != "Critical"


def test_map_severity_unknown_defaults_to_info():
    assert _map_severity("something-new") == "Info"


def test_strip_html_removes_tags_and_unescapes_entities():
    assert _strip_html("<p>Uses <b>SQL &amp; NoSQL</b></p>") == "Uses SQL & NoSQL"


def test_strip_html_empty_string():
    assert _strip_html("") == ""


def test_decode_evidence_decodes_base64_pairs():
    evidence = [{"request_response": {"request": _b64("GET / HTTP/1.1"), "response": _b64("HTTP/1.1 200 OK")}}]

    request_raw, response_raw = _decode_evidence(evidence)

    assert request_raw == "GET / HTTP/1.1"
    assert response_raw == "HTTP/1.1 200 OK"


def test_decode_evidence_joins_multiple_pairs():
    evidence = [
        {"request_response": {"request": _b64("A"), "response": _b64("1")}},
        {"request_response": {"request": _b64("B"), "response": _b64("2")}},
    ]

    request_raw, response_raw = _decode_evidence(evidence)

    assert "A" in request_raw and "B" in request_raw
    assert "1" in response_raw and "2" in response_raw


def test_decode_evidence_missing_returns_placeholder():
    request_raw, response_raw = _decode_evidence([])
    assert "no request evidence" in request_raw
    assert "no response evidence" in response_raw


def test_decode_evidence_malformed_base64_does_not_crash():
    evidence = [{"request_response": {"request": "not-valid-base64!!!", "response": _b64("ok")}}]

    request_raw, response_raw = _decode_evidence(evidence)

    assert isinstance(request_raw, str)
    assert response_raw == "ok"


def test_extract_method_parses_request_line():
    assert _extract_method("POST /login HTTP/1.1\r\nHost: x") == "POST"


def test_extract_method_defaults_to_get_when_unparseable():
    assert _extract_method("(no request evidence provided by Burp for this issue)") == "GET"


# ---------------------------------------------------------------------------
# normalize_burp_issue — happy path
# ---------------------------------------------------------------------------


def test_normalize_burp_issue_maps_core_fields():
    finding = normalize_burp_issue(_issue())

    assert finding.module_id == "burp_active_scan"
    assert finding.scanner_source == "burp"
    assert finding.vuln_type == "SQL injection"
    assert finding.severity == "High"
    assert finding.cvss_score == 8.5
    assert finding.endpoint.url == "https://demo.testfire.net/bank/showAccount?listAccounts=1"
    assert finding.user_role == "n/a"


def test_normalize_burp_issue_decodes_request_response_evidence():
    finding = normalize_burp_issue(_issue())

    assert "listAccounts=1'" in finding.request_raw
    assert "SQLSTATE" in finding.response_raw


def test_normalize_burp_issue_strips_html_from_description_and_remediation():
    finding = normalize_burp_issue(_issue())

    assert "<" not in finding.description
    assert "<" not in finding.recommendation
    assert "SQL injection" in finding.description
    assert "parameterized queries" in finding.recommendation


def test_normalize_burp_issue_extracts_method_from_evidence():
    finding = normalize_burp_issue(_issue())
    assert finding.endpoint.method == "GET"


def test_normalize_burp_issues_processes_a_list():
    findings = normalize_burp_issues([_issue(name="A", severity="low"), _issue(name="B", severity="medium")])

    assert [f.vuln_type for f in findings] == ["A", "B"]
    assert [f.severity for f in findings] == ["Low", "Medium"]


# ---------------------------------------------------------------------------
# Input validation / missing fields
# ---------------------------------------------------------------------------


def test_normalize_burp_issue_missing_optional_fields_does_not_crash():
    finding = normalize_burp_issue({"name": "Bare Issue", "severity": "low"})

    assert finding.vuln_type == "Bare Issue"
    assert finding.description == "No description provided by Burp."
    assert finding.recommendation == "See Burp Suite's issue detail for remediation guidance."
    assert finding.endpoint.url == "unknown"


def test_normalize_burp_issue_empty_dict_does_not_crash():
    finding = normalize_burp_issue({})
    assert finding.vuln_type == "Burp Active Scan Finding"
    assert finding.severity == "Info"


def test_normalize_burp_issues_empty_list():
    assert normalize_burp_issues([]) == []
