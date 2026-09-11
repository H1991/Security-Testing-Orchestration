"""Unit tests for Layer 7 -- stof.crawler.hidden_param_discovery."""
import pytest

from stof.crawler.endpoint_store import Endpoint
from stof.crawler.hidden_param_discovery import (
    HiddenParamConfig,
    _add_param,
    _rank_endpoints,
    discover_hidden_params,
)

# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_add_param_appends_with_question_mark_when_no_existing_query():
    url = _add_param("https://x.example/page", "debug")
    assert url.startswith("https://x.example/page?debug=")


def test_add_param_appends_with_ampersand_when_query_already_present():
    url = _add_param("https://x.example/page?id=1", "debug")
    assert url.startswith("https://x.example/page?id=1&debug=")


def test_rank_endpoints_excludes_non_get_methods():
    endpoints = [
        Endpoint(url="https://x/a", method="GET", endpoint_type="page"),
        Endpoint(url="https://x/b", method="POST", endpoint_type="form"),
    ]
    ranked = _rank_endpoints(endpoints, max_endpoints=10)
    assert [e.url for e in ranked] == ["https://x/a"]


def test_rank_endpoints_excludes_static_assets():
    endpoints = [
        Endpoint(url="https://x/app.js", method="GET", endpoint_type="page"),
        Endpoint(url="https://x/style.css", method="GET", endpoint_type="page"),
        Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page"),
    ]
    ranked = _rank_endpoints(endpoints, max_endpoints=10)
    assert [e.url for e in ranked] == ["https://x/dashboard"]


def test_rank_endpoints_dedups_by_url():
    endpoints = [
        Endpoint(url="https://x/a", method="GET", endpoint_type="page"),
        Endpoint(url="https://x/a", method="GET", endpoint_type="page", parameters=["q"]),
    ]
    ranked = _rank_endpoints(endpoints, max_endpoints=10)
    assert len(ranked) == 1


def test_rank_endpoints_prefers_fewest_known_params_first():
    endpoints = [
        Endpoint(url="https://x/heavy", method="GET", endpoint_type="page", parameters=["a", "b", "c"]),
        Endpoint(url="https://x/bare", method="GET", endpoint_type="page", parameters=[]),
    ]
    ranked = _rank_endpoints(endpoints, max_endpoints=10)
    assert [e.url for e in ranked] == ["https://x/bare", "https://x/heavy"]


def test_rank_endpoints_respects_max_endpoints_cap():
    endpoints = [Endpoint(url=f"https://x/{i}", method="GET", endpoint_type="page") for i in range(20)]
    ranked = _rank_endpoints(endpoints, max_endpoints=3)
    assert len(ranked) == 3


# ---------------------------------------------------------------------------
# discover_hidden_params -- fake HTTP context
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status: int, body: str):
        self.status = status
        self._body = body

    async def text(self):
        return self._body


class _FakeContext:
    """`context.request.get(url, ...)` -- `responder(url)` decides the
    (status, body) pair per URL, same "mock the I/O boundary" approach
    `test_openapi_discovery.py`'s own fake context already uses."""

    def __init__(self, responder):
        self._responder = responder
        self.request = self

    async def get(self, url: str, **kwargs):
        status, body = self._responder(url)
        return _FakeResponse(status, body)


BASELINE_BODY = "x" * 200  # clears min_content_length, distinct from any "found" body below


@pytest.mark.asyncio
async def test_discover_finds_a_parameter_that_changes_the_response():
    endpoint = Endpoint(url="https://x.example/settings", method="GET", endpoint_type="page")

    def responder(url: str):
        if "debug=" in url:
            return 200, "DEBUG MODE ENABLED -- verbose stack traces on" + "y" * 200
        return 200, BASELINE_BODY

    context = _FakeContext(responder)
    found = await discover_hidden_params(context, [endpoint], HiddenParamConfig(candidate_params=("debug", "harmless")))

    assert len(found) == 1
    assert found[0].url == "https://x.example/settings"
    assert found[0].parameters == ["debug"]


@pytest.mark.asyncio
async def test_discover_finds_nothing_when_every_candidate_matches_the_baseline():
    endpoint = Endpoint(url="https://x.example/page", method="GET", endpoint_type="page")
    context = _FakeContext(lambda url: (200, BASELINE_BODY))

    found = await discover_hidden_params(context, [endpoint], HiddenParamConfig(candidate_params=("admin", "debug")))

    assert found == []


@pytest.mark.asyncio
async def test_discover_does_not_misclassify_a_catch_all_spa_shell_as_every_parameter_being_real():
    """A soft-404/catch-all SPA that returns the SAME 200 shell for
    literally any query string must not report every candidate
    parameter as 'discovered' -- the control probe IS that same shell,
    so every real candidate fingerprint-matches it and gets discarded.
    This is the exact false-positive class configuration_tests.py's
    own control-fingerprint discipline exists to prevent."""
    endpoint = Endpoint(url="https://x.example/app", method="GET", endpoint_type="page")
    context = _FakeContext(lambda url: (200, "<html>SPA shell, same for everything</html>" + "z" * 200))

    found = await discover_hidden_params(context, [endpoint], HiddenParamConfig(candidate_params=("admin", "debug", "role")))

    assert found == []


@pytest.mark.asyncio
async def test_discover_ignores_a_short_body_below_the_content_length_floor():
    endpoint = Endpoint(url="https://x.example/page", method="GET", endpoint_type="page")

    def responder(url: str):
        if "debug=" in url:
            return 200, "ok"  # real difference from baseline, but too short to trust
        return 200, BASELINE_BODY

    context = _FakeContext(responder)
    found = await discover_hidden_params(context, [endpoint], HiddenParamConfig(candidate_params=("debug",)))

    assert found == []


@pytest.mark.asyncio
async def test_discover_skips_a_candidate_already_known_from_the_crawl():
    """No point re-probing a parameter the crawler already observed in
    a real form/XHR -- this module's whole point is finding NEW ones."""
    endpoint = Endpoint(url="https://x.example/page", method="GET", endpoint_type="page", parameters=["debug"])
    probed_urls = []

    def responder(url: str):
        probed_urls.append(url)
        return 200, BASELINE_BODY

    context = _FakeContext(responder)
    await discover_hidden_params(context, [endpoint], HiddenParamConfig(candidate_params=("debug",)))

    assert not any("debug=" in u for u in probed_urls)


@pytest.mark.asyncio
async def test_discover_survives_a_probe_failure_for_one_endpoint():
    good = Endpoint(url="https://x.example/ok", method="GET", endpoint_type="page")
    bad = Endpoint(url="https://x.example/broken", method="GET", endpoint_type="page")

    def responder(url: str):
        if "broken" in url:
            raise RuntimeError("connection reset")
        if "debug=" in url:
            return 200, "DIFFERENT" + "y" * 200
        return 200, BASELINE_BODY

    class _PartiallyBrokenContext(_FakeContext):
        async def get(self, url: str, **kwargs):
            status, body = self._responder(url)  # may raise -- discover_hidden_params must not propagate it
            return _FakeResponse(status, body)

    context = _PartiallyBrokenContext(responder)
    found = await discover_hidden_params(context, [bad, good], HiddenParamConfig(candidate_params=("debug",)))

    assert [e.url for e in found] == ["https://x.example/ok"]


@pytest.mark.asyncio
async def test_discover_returns_empty_list_for_no_endpoints():
    context = _FakeContext(lambda url: (200, BASELINE_BODY))
    assert await discover_hidden_params(context, []) == []
