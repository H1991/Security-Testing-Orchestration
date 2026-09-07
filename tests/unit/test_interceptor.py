"""Unit tests for Layer 3B — stof.engine.interceptor."""
import json
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from stof.engine.interceptor import (
    RequestInterceptor,
    apply_response_rewrite,
    compute_overrides,
    compute_response_rewrite,
)

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


# ---------------------------------------------------------------------------
# compute_response_rewrite / apply_response_rewrite (pure) -- TC-055.6's
# response-manipulation capability
# ---------------------------------------------------------------------------


def test_compute_response_rewrite_merges_matching_injections():
    injections = [
        (re.compile(r".*"), {"only_if_status": (401, 403), "status": 200}),
        (re.compile(r".*"), {"flip_false_fields": ("authorized",)}),
    ]

    rewrite = compute_response_rewrite("https://x/api/check", injections)

    assert rewrite == {"only_if_status": (401, 403), "status": 200, "flip_false_fields": ("authorized",)}


def test_compute_response_rewrite_returns_none_when_nothing_matches():
    injections = [(re.compile(r"/admin/"), {"status": 200})]

    assert compute_response_rewrite("https://x/api/users", injections) is None


def test_apply_response_rewrite_only_flips_status_when_original_was_denied():
    rewrite = {"only_if_status": (401, 403), "status": 200}

    status, body = apply_response_rewrite(403, "text/plain", b"Forbidden", rewrite)
    assert (status, body) == (200, b"Forbidden")

    # A 200 response is left completely untouched -- the whole point of
    # `only_if_status` is that a broad `.*` pattern never rewrites a
    # response that wasn't already a denial.
    status, body = apply_response_rewrite(200, "text/plain", b"OK", rewrite)
    assert (status, body) == (200, b"OK")


def test_apply_response_rewrite_flips_a_false_boolean_field_in_json():
    rewrite = {"flip_false_fields": ("authorized", "canEdit")}
    body = json.dumps({"authorized": False, "canEdit": False, "role": "viewer"}).encode()

    status, new_body = apply_response_rewrite(200, "application/json", body, rewrite)

    parsed = json.loads(new_body)
    assert status == 200
    assert parsed == {"authorized": True, "canEdit": True, "role": "viewer"}


def test_apply_response_rewrite_flips_a_false_field_case_insensitively():
    """A caller passes a lowercase field name (`authorized`) without
    knowing whether this target's real JSON key is camelCase
    (`isAuthorized`) -- the match must still work, and the original
    key's casing must be preserved on write."""
    rewrite = {"flip_false_fields": ("isauthorized",)}
    body = json.dumps({"isAuthorized": False}).encode()

    _status, new_body = apply_response_rewrite(200, "application/json", body, rewrite)

    assert json.loads(new_body) == {"isAuthorized": True}


def test_apply_response_rewrite_leaves_malformed_json_untouched():
    rewrite = {"flip_false_fields": ("authorized",)}

    status, body = apply_response_rewrite(200, "application/json", b"not json{{{", rewrite)

    assert (status, body) == (200, b"not json{{{")


def test_apply_response_rewrite_ignores_non_json_content_type():
    rewrite = {"flip_false_fields": ("authorized",)}
    body = json.dumps({"authorized": False}).encode()

    _status, new_body = apply_response_rewrite(200, "text/html", body, rewrite)

    assert new_body == body  # untouched -- flip_false_fields only ever applies to JSON


def test_inject_response_registers_a_working_regex_pattern():
    interceptor = RequestInterceptor(page=SimpleNamespace())

    interceptor.inject_response(r"/api/check$", {"status": 200})

    assert len(interceptor._response_injections) == 1
    pattern, rewrite = interceptor._response_injections[0]
    assert pattern.search("https://x/api/check")
    assert rewrite == {"status": 200}


# ---------------------------------------------------------------------------
# _handle_route -- the fetch+fulfill branch only activates when a
# response injection actually matches; otherwise behavior is unchanged
# (route.continue_, same as before this capability existed)
# ---------------------------------------------------------------------------


def _fake_request(method="GET", url="https://x/api/check", headers=None, post_data=None) -> SimpleNamespace:
    return SimpleNamespace(method=method, url=url, headers=headers or {}, post_data=post_data)


@pytest.mark.asyncio
async def test_handle_route_uses_continue_when_no_response_injection_registered():
    interceptor = RequestInterceptor(page=SimpleNamespace())
    route = AsyncMock()

    await interceptor._handle_route(route, _fake_request())

    route.continue_.assert_awaited_once()
    route.fetch.assert_not_called()
    route.fulfill.assert_not_called()


@pytest.mark.asyncio
async def test_handle_route_fetches_and_fulfills_when_a_response_injection_matches():
    interceptor = RequestInterceptor(page=SimpleNamespace())
    interceptor.inject_response(r".*", {"only_if_status": (401, 403), "status": 200})

    api_response = AsyncMock()
    api_response.status = 403
    api_response.headers = {"content-type": "text/plain"}
    api_response.body = AsyncMock(return_value=b"Forbidden")

    route = AsyncMock()
    route.fetch = AsyncMock(return_value=api_response)

    await interceptor._handle_route(route, _fake_request())

    route.continue_.assert_not_called()
    route.fetch.assert_awaited_once()
    route.fulfill.assert_awaited_once_with(response=api_response, status=200, body=b"Forbidden")
