"""Unit tests for Layer 3B — stof.engine.interceptor."""
import re
from types import SimpleNamespace

from stof.engine.interceptor import RequestInterceptor, compute_overrides

# ---------------------------------------------------------------------------
# Happy path — compute_overrides (pure, no Playwright objects needed)
# ---------------------------------------------------------------------------


def test_compute_overrides_applies_matching_header_injection():
    injections = [(re.compile(r"/api/"), {"headers": {"X-Injected": "1"}})]

    overrides = compute_overrides("https://x/api/users", injections)

    assert overrides == {"headers": {"X-Injected": "1"}}


def test_compute_overrides_applies_body_and_url_overrides():
    injections = [(re.compile(r"/login"), {"body": "user=admin' OR '1'='1", "url": "https://x/login2"})]

    overrides = compute_overrides("https://x/login", injections)

    assert overrides["post_data"] == "user=admin' OR '1'='1"
    assert overrides["url"] == "https://x/login2"


# ---------------------------------------------------------------------------
# Failure / no-match cases
# ---------------------------------------------------------------------------


def test_compute_overrides_ignores_non_matching_pattern():
    injections = [(re.compile(r"/admin/"), {"headers": {"X-Injected": "1"}})]

    overrides = compute_overrides("https://x/api/users", injections)

    assert overrides == {}


def test_compute_overrides_with_no_injections_returns_empty():
    assert compute_overrides("https://x/api/users", []) == {}


# ---------------------------------------------------------------------------
# Input validation — merge order / conflict resolution
# ---------------------------------------------------------------------------


def test_compute_overrides_merges_multiple_matches_last_wins_on_conflict():
    injections = [
        (re.compile(r"/api/"), {"headers": {"X-A": "1"}}),
        (re.compile(r"users"), {"headers": {"X-A": "2", "X-B": "3"}}),
    ]

    overrides = compute_overrides("https://x/api/users", injections)

    assert overrides == {"headers": {"X-A": "2", "X-B": "3"}}


def test_inject_payload_registers_a_working_regex_pattern():
    interceptor = RequestInterceptor(page=SimpleNamespace())

    interceptor.inject_payload(r"/login$", {"body": "user=admin"})

    assert len(interceptor._injections) == 1
    pattern, payload = interceptor._injections[0]
    assert pattern.search("https://x/app/login")
    assert not pattern.search("https://x/app/login/extra")
    assert payload == {"body": "user=admin"}
