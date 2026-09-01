"""Unit tests for Layer 9 -- stof.modules.cache_tests (TC-136)."""
from unittest.mock import AsyncMock

import pytest

from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.cache_tests import (
    CacheTestConfig,
    CacheTestsModule,
    _body_fingerprint,
    _cache_indicator,
    _find_cacheable_get_endpoint_urls,
    _find_sensitive_authenticated_endpoint,
)
from stof.modules.results import FAIL, PASS, SKIPPED

# ---------------------------------------------------------------------------
# Pure functions
# ---------------------------------------------------------------------------


def test_cache_indicator_detects_present_header():
    assert _cache_indicator({"cache-control": "max-age=60"}) == "cache-control"


def test_cache_indicator_none_when_no_signal():
    assert _cache_indicator({"content-type": "text/html"}) is None


def test_body_fingerprint_stable_for_same_body():
    assert _body_fingerprint("hello") == _body_fingerprint("hello")


def test_body_fingerprint_differs_for_different_body():
    assert _body_fingerprint("hello") != _body_fingerprint("world")


def test_find_cacheable_get_endpoint_urls_filters_and_limits():
    endpoints = [
        Endpoint(url="https://x/a", method="GET", endpoint_type="page", parameters=[]),
        Endpoint(url="https://x/b", method="POST", endpoint_type="form", parameters=[]),
        Endpoint(url="https://x/c", method="GET", endpoint_type="page", parameters=[]),
    ]
    urls = _find_cacheable_get_endpoint_urls(endpoints, limit=1)
    assert urls == ["https://x/a"]


def test_find_sensitive_authenticated_endpoint_matches_keyword():
    endpoints = [
        Endpoint(url="https://x/home", method="GET", endpoint_type="page", parameters=[]),
        Endpoint(url="https://x/account/profile", method="GET", endpoint_type="page", parameters=[]),
    ]
    found = _find_sensitive_authenticated_endpoint(endpoints)
    assert found is not None
    assert found.url == "https://x/account/profile"


def test_find_sensitive_authenticated_endpoint_none_when_no_match():
    endpoints = [Endpoint(url="https://x/home", method="GET", endpoint_type="page", parameters=[])]
    assert _find_sensitive_authenticated_endpoint(endpoints) is None


# ---------------------------------------------------------------------------
# run_techniques() / TC-136.1 -- async
# ---------------------------------------------------------------------------


def _response(status: int, body: str, headers: dict | None = None):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    resp.headers = headers or {}
    return resp


def _fake_context(get_side_effect=None):
    context = AsyncMock()
    if get_side_effect is not None:
        context.request.get = AsyncMock(side_effect=get_side_effect)
    return context


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


def _by_id(results):
    return {r.technique_id: r for r in results}


@pytest.mark.asyncio
async def test_run_techniques_skipped_when_probes_disabled():
    endpoint = Endpoint(url="https://x/page", method="GET", endpoint_type="page", parameters=[])
    pool = _pool_with_context(_fake_context())
    module = CacheTestsModule()  # allow_state_changing_probes defaults False

    results = await module.run_techniques([endpoint], None, pool)

    by_id = _by_id(results)
    assert len(by_id) == 2
    assert all(r.status == SKIPPED for r in by_id.values())
    assert "allow_state_changing_probes" in by_id["TC-136.1"].detail
    assert "allow_state_changing_probes" in by_id["TC-136.2"].detail


@pytest.mark.asyncio
async def test_cache_poisoning_skipped_when_no_cache_signal():
    endpoint = Endpoint(url="https://x/page", method="GET", endpoint_type="page", parameters=[])

    def fake_get(url, max_redirects=0, headers=None):
        return _response(200, "no cache headers here")

    context = _fake_context(get_side_effect=fake_get)
    pool = _pool_with_context(context)
    module = CacheTestsModule(config=CacheTestConfig(allow_state_changing_probes=True))

    result = await module._technique_cache_poisoning([endpoint], pool, evidence=None)

    assert result.status == SKIPPED


@pytest.mark.asyncio
async def test_cache_poisoning_fails_when_marker_confirmed_on_separate_request():
    endpoint = Endpoint(url="https://x/page", method="GET", endpoint_type="page", parameters=[])
    marker_holder: dict = {}

    def fake_get(url, max_redirects=0, headers=None):
        if headers is None:
            # baseline probe (finds cache signal) or the second, "clean" confirmation request
            body = f"reflected: {marker_holder['marker']}" if "marker" in marker_holder else "baseline body"
            return _response(200, body, headers={"cache-control": "max-age=60"})
        marker_holder["marker"] = headers["X-Forwarded-Host"]
        return _response(200, f"reflected: {headers['X-Forwarded-Host']}", headers={"cache-control": "max-age=60"})

    context = _fake_context(get_side_effect=fake_get)
    pool = _pool_with_context(context)
    module = CacheTestsModule(config=CacheTestConfig(allow_state_changing_probes=True))

    result = await module._technique_cache_poisoning([endpoint], pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "High"


@pytest.mark.asyncio
async def test_cache_poisoning_passes_when_marker_not_reflected():
    endpoint = Endpoint(url="https://x/page", method="GET", endpoint_type="page", parameters=[])

    def fake_get(url, max_redirects=0, headers=None):
        return _response(200, "static body, no reflection", headers={"cache-control": "max-age=60"})

    context = _fake_context(get_side_effect=fake_get)
    pool = _pool_with_context(context)
    module = CacheTestsModule(config=CacheTestConfig(allow_state_changing_probes=True))

    result = await module._technique_cache_poisoning([endpoint], pool, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_cache_deception_skipped_when_no_sensitive_endpoint():
    endpoint = Endpoint(url="https://x/home", method="GET", endpoint_type="page", parameters=[])
    pool = _pool_with_context(_fake_context())
    module = CacheTestsModule(config=CacheTestConfig(allow_state_changing_probes=True))

    result = await module._technique_cache_deception([endpoint], pool, evidence=None, session_manager=None)

    assert result.status == SKIPPED
