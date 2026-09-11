"""Unit tests for Layer 2 -- stof.core.traffic_guard."""
import json

import pytest

from stof.core.traffic_guard import (
    OutOfScopeError,
    TrafficGuard,
    _redact_headers,
    _truncate,
    derive_allowed_origins,
)

# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_derive_allowed_origins_normalizes_scheme_host_and_default_port():
    origins = derive_allowed_origins("https://Example.com/login")
    assert origins == {"https://example.com:443"}


def test_derive_allowed_origins_includes_an_explicit_port():
    origins = derive_allowed_origins("http://x.example:8080/")
    assert origins == {"http://x.example:8080"}


def test_derive_allowed_origins_includes_extra_urls():
    origins = derive_allowed_origins("https://x.example", extra_urls=("https://api.x.example/v1",))
    assert origins == {"https://x.example:443", "https://api.x.example:443"}


def test_derive_allowed_origins_skips_empty_extra_urls():
    origins = derive_allowed_origins("https://x.example", extra_urls=("", None))
    assert origins == {"https://x.example:443"}


def test_redact_headers_masks_sensitive_values_but_keeps_the_key():
    redacted = _redact_headers({"Authorization": "Bearer secret", "X-Custom": "keep-me"})
    assert redacted["Authorization"] == "[redacted]"
    assert redacted["X-Custom"] == "keep-me"


def test_redact_headers_is_case_insensitive():
    redacted = _redact_headers({"cookie": "JSESSIONID=abc"})
    assert redacted["cookie"] == "[redacted]"


def test_redact_headers_handles_none_and_empty():
    assert _redact_headers(None) == {}
    assert _redact_headers({}) == {}


def test_truncate_leaves_short_bodies_untouched():
    assert _truncate("short body") == "short body"


def test_truncate_caps_long_bodies_and_notes_original_length():
    body = "x" * 3000
    truncated = _truncate(body)
    assert len(truncated) < len(body)
    assert "truncated" in truncated
    assert "3000" in truncated


def test_truncate_passes_through_none():
    assert _truncate(None) is None


# ---------------------------------------------------------------------------
# TrafficGuard.check_scope
# ---------------------------------------------------------------------------


def test_check_scope_allows_a_url_within_the_allowed_origin():
    guard = TrafficGuard(allowed_origins={"https://x.example:443"})
    guard.check_scope("https://x.example/some/path?q=1")  # must not raise


def test_check_scope_rejects_a_different_host():
    guard = TrafficGuard(allowed_origins={"https://x.example:443"})
    with pytest.raises(OutOfScopeError):
        guard.check_scope("https://evil.example/steal")


def test_check_scope_rejects_a_different_scheme_on_the_same_host():
    guard = TrafficGuard(allowed_origins={"https://x.example:443"})
    with pytest.raises(OutOfScopeError):
        guard.check_scope("http://x.example/downgrade")


def test_check_scope_rejects_a_different_port():
    guard = TrafficGuard(allowed_origins={"https://x.example:443"})
    with pytest.raises(OutOfScopeError):
        guard.check_scope("https://x.example:8443/other-service")


# ---------------------------------------------------------------------------
# TrafficGuard.record / build_entry
# ---------------------------------------------------------------------------


def test_record_writes_a_json_line_to_the_audit_path(tmp_path):
    audit_path = tmp_path / "scan-1" / "audit_log.jsonl"
    guard = TrafficGuard(allowed_origins={"https://x.example:443"}, audit_path=audit_path)

    entry = guard.build_entry(
        method="GET", url="https://x.example/a", role="admin",
        request_headers={"Authorization": "Bearer secret"}, request_body=None,
        response_status=200, response_headers={"content-type": "text/html"},
        response_body_len=1234, latency_ms=42.5, error=None,
    )
    guard.record(entry)

    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["method"] == "GET"
    assert parsed["url"] == "https://x.example/a"
    assert parsed["request_headers"]["Authorization"] == "[redacted]"
    assert parsed["response_status"] == 200


def test_record_appends_across_multiple_calls(tmp_path):
    audit_path = tmp_path / "audit_log.jsonl"
    guard = TrafficGuard(allowed_origins={"https://x.example:443"}, audit_path=audit_path)
    for i in range(3):
        entry = guard.build_entry(
            method="GET", url=f"https://x.example/{i}", role=None,
            request_headers=None, request_body=None,
            response_status=200, response_headers={}, response_body_len=0,
            latency_ms=1.0, error=None,
        )
        guard.record(entry)

    assert len(audit_path.read_text(encoding="utf-8").splitlines()) == 3
    assert guard.total_requests == 3


def test_record_is_a_noop_when_no_audit_path_configured():
    guard = TrafficGuard(allowed_origins={"https://x.example:443"}, audit_path=None)
    entry = guard.build_entry(
        method="GET", url="https://x.example/a", role=None,
        request_headers=None, request_body=None,
        response_status=200, response_headers={}, response_body_len=0,
        latency_ms=1.0, error=None,
    )
    guard.record(entry)  # must not raise
    assert guard.total_requests == 1


def test_record_survives_an_unwritable_audit_path(tmp_path):
    """A broken audit log must never abort the scan itself -- same
    resilience convention as every other I/O boundary in this
    codebase."""
    unwritable_dir = tmp_path / "not_a_directory"
    unwritable_dir.write_text("x")  # a FILE, not a directory
    guard = TrafficGuard(allowed_origins={"https://x.example:443"}, audit_path=unwritable_dir / "audit_log.jsonl")
    entry = guard.build_entry(
        method="GET", url="https://x.example/a", role=None,
        request_headers=None, request_body=None,
        response_status=200, response_headers={}, response_body_len=0,
        latency_ms=1.0, error=None,
    )
    guard.record(entry)  # must not raise despite the broken path
    assert guard.total_requests == 1
