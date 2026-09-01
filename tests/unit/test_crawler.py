"""Unit tests for Layer 7 — stof.crawler.crawler.

Uses a tiny in-memory fake "site" (url -> links/forms/api-calls) instead
of mocking Playwright call-by-call: the crawler makes multiple
`page.evaluate()` calls per page (forms, then links) and multiple
`page.goto()` calls across the BFS, so a script/URL-aware fake is far
more reliable here than juggling AsyncMock `side_effect` ordering.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from stof.crawler.crawler import CrawlerConfig, crawl, verify_auth_required
from stof.crawler.endpoint_store import Endpoint


class FakePage:
    def __init__(self, site: dict[str, dict]):
        self._site = site
        self.url = ""
        self.goto_calls: list[str] = []
        self._fail_remaining = {url: page.get("fail_times", 0) for url, page in site.items()}
        self._evaluate_fail_remaining = {
            url: page.get("evaluate_fail_times", 0) for url, page in site.items()
        }
        self._request_listeners: list = []
        self._response_listeners: list = []

    async def goto(self, url: str, timeout: int | None = None) -> None:
        self.goto_calls.append(url)
        if url not in self._site:
            raise RuntimeError(f"404 Not Found: {url}")
        if self._site[url].get("hang"):
            # Simulates a wedged CDP connection where `page.goto()`'s
            # own `timeout` never fires at all -- live-observed against
            # a real target (see CrawlerConfig.page_watchdog_s). Never
            # resolves on its own; only the watchdog's asyncio.wait_for
            # can end this.
            await asyncio.Event().wait()
        if self._fail_remaining.get(url, 0) > 0:
            self._fail_remaining[url] -= 1
            raise RuntimeError(f"transient failure loading {url}")
        self.url = self._site[url].get("redirect_to", url)
        for handler in list(self._request_listeners):
            for req in self._site[url].get("api_calls", []):
                handler(req)
        for handler in list(self._response_listeners):
            page_response = self._site[url].get("response")
            if page_response is not None:
                handler(page_response)

    async def evaluate(self, script: str):
        page = self._site.get(self.url, {})
        if page.get("evaluate_error"):
            raise RuntimeError("Execution context was destroyed, most likely because of a navigation")
        if self._evaluate_fail_remaining.get(self.url, 0) > 0:
            self._evaluate_fail_remaining[self.url] -= 1
            raise RuntimeError("Execution context was destroyed, most likely because of a navigation")
        if "a[href]" in script:
            return page.get("links", [])
        return page.get("forms", [])

    def on(self, event: str, handler) -> None:
        if event == "request":
            self._request_listeners.append(handler)
        elif event == "response":
            self._response_listeners.append(handler)

    def remove_listener(self, event: str, handler) -> None:
        if event == "request" and handler in self._request_listeners:
            self._request_listeners.remove(handler)
        elif event == "response" and handler in self._response_listeners:
            self._response_listeners.remove(handler)

    async def close(self) -> None:
        pass


class FakeContext:
    def __init__(self, site: dict[str, dict]):
        self.page = FakePage(site)

    async def new_page(self):
        return self.page


def _req(method: str, url: str, resource_type: str = "xhr"):
    from types import SimpleNamespace

    return SimpleNamespace(method=method, url=url, resource_type=resource_type)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_follows_same_origin_links_breadth_first():
    site = {
        "https://x/": {"links": ["/a", "/b", "https://external.com/evil"]},
        "https://x/a": {"links": ["/c"]},
        "https://x/b": {"links": []},
        "https://x/c": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(max_depth=3))

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/a", "https://x/b", "https://x/c"}


@pytest.mark.asyncio
async def test_crawl_does_not_guess_auth_required():
    """Regression: `crawl()` used to stamp every discovered endpoint
    `auth_required=True` on the theory that "the crawl was
    authenticated, so everything it found must require auth" -- a
    non-sequitur (a public marketing page reached by a logged-in
    crawl is still public), live-verified to mass-false-positive
    `idor_tests.py`'s TC-050.3 on a real target. `crawl()` no longer
    claims to know this at all; `verify_auth_required()` (a separate,
    real anonymous-probe-based check) is the actual source of truth,
    called by the caller that has an anonymous context available."""
    site = {"https://x/": {"links": []}}
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    assert all(not e.auth_required for e in endpoints)


class _FakeAnonRequest:
    def __init__(self, status_by_url: dict[str, int]):
        self._status_by_url = status_by_url
        self.calls: list[str] = []

    async def get(self, url, timeout=None, max_redirects=None):
        self.calls.append(url)
        resp = AsyncMock()
        resp.status = self._status_by_url.get(url, 200)
        return resp


class _FakeAnonContext:
    def __init__(self, status_by_url: dict[str, int]):
        self.request = _FakeAnonRequest(status_by_url)


@pytest.mark.asyncio
async def test_verify_auth_required_true_for_a_redirect():
    endpoints = [Endpoint(url="https://x/bank/main.jsp", method="GET", endpoint_type="page")]
    anon_context = _FakeAnonContext({"https://x/bank/main.jsp": 302})

    await verify_auth_required(endpoints, anon_context)

    assert endpoints[0].auth_required is True


@pytest.mark.asyncio
async def test_verify_auth_required_true_for_401_or_403():
    endpoints = [
        Endpoint(url="https://x/api/secret", method="GET", endpoint_type="api"),
        Endpoint(url="https://x/forbidden", method="GET", endpoint_type="page"),
    ]
    anon_context = _FakeAnonContext({"https://x/api/secret": 401, "https://x/forbidden": 403})

    await verify_auth_required(endpoints, anon_context)

    assert endpoints[0].auth_required is True
    assert endpoints[1].auth_required is True


@pytest.mark.asyncio
async def test_verify_auth_required_false_for_a_public_page():
    """Regression: this is the exact real-world case that motivated
    the fix -- a public page an authenticated crawl happened to walk
    through must NOT be flagged as requiring auth just because it was
    reachable during that crawl."""
    endpoints = [Endpoint(url="https://x/feedback.jsp", method="GET", endpoint_type="page")]
    anon_context = _FakeAnonContext({"https://x/feedback.jsp": 200})

    await verify_auth_required(endpoints, anon_context)

    assert endpoints[0].auth_required is False


@pytest.mark.asyncio
async def test_verify_auth_required_skips_non_get_endpoints():
    endpoints = [Endpoint(url="https://x/doLogin", method="POST", endpoint_type="form")]
    anon_context = _FakeAnonContext({})

    await verify_auth_required(endpoints, anon_context)

    assert anon_context.request.calls == []
    assert endpoints[0].auth_required is False


@pytest.mark.asyncio
async def test_verify_auth_required_leaves_endpoint_unchanged_on_probe_failure():
    endpoints = [Endpoint(url="https://x/flaky", method="GET", endpoint_type="page", auth_required=True)]

    class _RaisingRequest:
        async def get(self, url, timeout=None, max_redirects=None):
            raise RuntimeError("network error")

    class _RaisingContext:
        request = _RaisingRequest()

    await verify_auth_required(endpoints, _RaisingContext())

    assert endpoints[0].auth_required is True  # untouched, not silently reset


@pytest.mark.asyncio
async def test_crawl_captures_forms_and_api_calls_alongside_pages():
    site = {
        "https://x/": {
            "links": [],
            "forms": [{"action": "login", "method": "POST", "inputs": [{"name": "u"}]}],
            "api_calls": [_req("GET", "https://x/api/status")],
        }
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    types_found = {e.endpoint_type for e in endpoints}
    assert types_found == {"page", "form", "api"}


# ---------------------------------------------------------------------------
# Passive engine wiring -- opt-in only, must not change default behavior
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_without_passive_engine_configured_behaves_unchanged():
    """The default (no `passive_engine` passed) must register no extra
    listeners and return exactly what it always did -- the whole point
    of making this opt-in."""
    from types import SimpleNamespace

    site = {"https://x/": {"links": [], "forms": [], "response": SimpleNamespace(url="https://x/", status=200, headers={"server": "Apache-Coyote/1.1"})}}
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig())

    assert len(endpoints) == 1
    assert endpoints[0].endpoint_type == "page"


@pytest.mark.asyncio
async def test_crawl_feeds_a_configured_passive_engine_from_normal_traffic():
    """No extra request is sent -- the engine only sees the response
    the crawl already received while visiting the page normally."""
    from types import SimpleNamespace

    from stof.passive.engine import PassiveEngine

    site = {"https://x/": {"links": [], "forms": [], "response": SimpleNamespace(url="https://x/", status=200, headers={"server": "Apache-Coyote/1.1"})}}
    context = FakeContext(site)
    engine = PassiveEngine()

    await crawl("https://x/", context, CrawlerConfig(passive_engine=engine))

    assert any(o.kind == "server_version_disclosure" for o in engine.observations)


# ---------------------------------------------------------------------------
# Boundaries — max_depth / max_pages / same-origin
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_respects_max_depth():
    site = {
        "https://x/": {"links": ["/a"]},
        "https://x/a": {"links": ["/b"]},
        "https://x/b": {"links": ["/c"]},
        "https://x/c": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(max_depth=1))

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/a"}


@pytest.mark.asyncio
async def test_crawl_respects_max_pages():
    site = {f"https://x/{i}": {"links": [f"/{i + 1}"]} for i in range(10)}
    context = FakeContext(site)

    endpoints = await crawl("https://x/0", context, CrawlerConfig(max_depth=10, max_pages=3))

    page_urls = [e for e in endpoints if e.endpoint_type == "page"]
    assert len(page_urls) <= 3


@pytest.mark.asyncio
async def test_crawl_never_leaves_same_origin():
    site = {"https://x/": {"links": ["https://evil.example.com/phish", "/safe"]}, "https://x/safe": {"links": []}}
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert urls == {"https://x/", "https://x/safe"}


@pytest.mark.asyncio
async def test_crawl_deduplicates_repeated_links():
    site = {
        "https://x/": {"links": ["/a", "/a", "/a"]},
        "https://x/a": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = [e.url for e in endpoints if e.endpoint_type == "page"]
    assert sorted(page_urls) == ["https://x/", "https://x/a"]


# ---------------------------------------------------------------------------
# Failure resilience — a broken page must not abort the whole crawl
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_continues_past_a_page_that_fails_to_load():
    site = {
        "https://x/": {"links": ["/broken", "/ok"]},
        "https://x/ok": {"links": []},
        # "/broken" intentionally absent from `site` -> FakePage.goto raises
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/ok"}


@pytest.mark.asyncio
async def test_crawl_retries_a_transiently_failing_page_and_succeeds():
    site = {
        "https://x/": {"links": ["/flaky"]},
        "https://x/flaky": {"links": [], "fail_times": 1},  # fails once, then succeeds
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(retries_per_page=1))

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/flaky"}
    # goto was attempted twice for the flaky page: once failed, once succeeded
    assert context.page.goto_calls.count("https://x/flaky") == 2


@pytest.mark.asyncio
async def test_crawl_gives_up_after_exhausting_retries():
    site = {
        "https://x/": {"links": ["/always-broken"]},
        "https://x/always-broken": {"links": [], "fail_times": 99},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(retries_per_page=2))

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/"}
    # 1 initial attempt + 2 retries = 3 total attempts
    assert context.page.goto_calls.count("https://x/always-broken") == 3


@pytest.mark.asyncio
async def test_crawl_watchdog_recovers_from_a_page_that_never_resolves():
    """Regression: live-verified against a real target (AltoroMutual's
    careers page) that `page.goto()`'s own `timeout` can fail to fire
    at all if the underlying CDP connection is wedged, hanging the
    whole crawl indefinitely. `page_watchdog_s` is the hard backstop --
    this must complete promptly instead of hanging the test suite."""
    site = {
        "https://x/": {"links": ["/wedged", "/ok"]},
        "https://x/wedged": {"hang": True},
        "https://x/ok": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await asyncio.wait_for(
        crawl("https://x/", context, CrawlerConfig(retries_per_page=0, page_watchdog_s=0.05)),
        timeout=5,
    )

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/ok"}  # /wedged never completed, but didn't block the rest


@pytest.mark.asyncio
async def test_crawl_exclude_path_patterns_skips_matching_links():
    """The reliable mitigation for a page that destabilizes the
    browser (see CrawlerConfig.page_watchdog_s's own docstring): an
    operator-configured substring match keeps the crawler from ever
    visiting it, instead of hoping a timeout recovers cleanly."""
    site = {
        "https://x/": {"links": ["/careers?job=Teller", "/ok"]},
        "https://x/careers?job=Teller": {"links": []},
        "https://x/ok": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(exclude_path_patterns=("job=",)))

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/ok"}
    assert "https://x/careers?job=Teller" not in context.page.goto_calls


@pytest.mark.asyncio
async def test_crawl_does_not_duplicate_page_endpoint_after_a_retry():
    """A failed attempt appends to page_endpoints before the exception
    fires (goto succeeds, the forms scan fails afterwards) -- the retry
    must not leave that stray entry behind once the next attempt
    succeeds cleanly, or the page would show up twice."""
    site = {
        "https://x/": {"links": ["/flaky"]},
        "https://x/flaky": {"links": [], "evaluate_fail_times": 1},  # fails once, then succeeds
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(retries_per_page=2))

    page_urls = [e.url for e in endpoints if e.endpoint_type == "page"]
    assert page_urls.count("https://x/flaky") == 1


@pytest.mark.asyncio
async def test_crawl_continues_when_a_later_page_evaluate_fails_mid_page():
    """Regression test: a real crawl of demo.testfire.net hit a PDF link
    that made goto() raise "Download is starting" -- caught fine -- but
    then the *next* page's evaluate() call failed with "Execution
    context was destroyed", which used to crash the whole crawl because
    only goto() was wrapped in a try/except, not the forms/links calls
    that follow it.

    goto() itself succeeds here (only the later evaluate() call fails),
    so that page still counts as discovered -- it just won't have form
    endpoints. What this test actually pins down is that the crawl
    doesn't abort: a *sibling* page queued alongside it still gets
    visited, which it wouldn't if the exception had propagated out of
    the while loop."""
    site = {
        "https://x/": {"links": ["/broken-evaluate", "/ok"]},
        "https://x/broken-evaluate": {"links": [], "evaluate_error": True},
        "https://x/ok": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/broken-evaluate", "https://x/ok"}
    assert all(e.endpoint_type != "form" for e in endpoints)  # forms scan never completed


# ---------------------------------------------------------------------------
# Input validation — ignored href schemes / non-HTML downloads
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_skips_download_file_links_without_visiting_them():
    site = {
        "https://x/": {"links": ["/report.pdf", "/archive.zip", "/real"]},
        "https://x/real": {"links": []},
        # "/report.pdf" / "/archive.zip" deliberately absent from `site`:
        # error-recovery alone would also make page_urls come out right
        # if the crawler *attempted and failed* to visit them, so this
        # test asserts on goto_calls directly to prove they were skipped
        # proactively, not merely recovered from after the fact.
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/real"}
    assert not any(call.endswith((".pdf", ".zip")) for call in context.page.goto_calls)


@pytest.mark.asyncio
async def test_crawl_ignores_non_navigable_hrefs():
    site = {
        "https://x/": {"links": ["javascript:void(0)", "mailto:a@b.com", "#section", "", "/real"]},
        "https://x/real": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/real"}


# ---------------------------------------------------------------------------
# Session safety — regression tests for the demo.testfire.net finding:
# following a logout link mid-crawl silently kills the authenticated
# session for every page visited afterward, with no exception raised.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_never_follows_a_logout_link():
    site = {
        "https://x/": {"links": ["/logout.jsp", "/account", "/Sign-Out", "/safe"]},
        "https://x/account": {"links": []},
        "https://x/safe": {"links": []},
        # "/logout.jsp" and "/Sign-Out" deliberately absent from `site`:
        # if the crawler attempted them, FakePage.goto would 404 and
        # error-recovery would still make page_urls look right, so this
        # test asserts on goto_calls directly, proving they were never
        # even attempted -- the same pattern used for download links.
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/account", "https://x/safe"}
    assert not any("logout" in call.lower() or "sign-out" in call.lower() for call in context.page.goto_calls)


@pytest.mark.asyncio
async def test_crawl_records_the_landed_url_not_the_requested_url_after_a_redirect():
    """The core bug: a page that silently redirects (e.g. to a login
    page because the session was somehow lost) must never be recorded
    under the URL it was *supposed* to be, since that misrepresents what
    was actually captured -- the forms/content that follow are for
    whatever page was really landed on."""
    site = {
        "https://x/": {"links": ["/protected"]},
        "https://x/protected": {"redirect_to": "https://x/login", "links": []},
        "https://x/login": {"links": [], "forms": [{"action": "doLogin", "method": "POST", "inputs": [{"name": "u"}]}]},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert "https://x/protected" not in page_urls
    assert "https://x/login" in page_urls
    form_urls = {e.url for e in endpoints if e.endpoint_type == "form"}
    assert "https://x/doLogin" in form_urls


@pytest.mark.asyncio
async def test_crawl_retry_cleanup_matches_landed_url_after_redirect():
    """Regression for a bug introduced by the landed-url fix itself: the
    retry loop's "undo the partial append before retrying" cleanup used
    to compare against the *requested* URL, which never matches when a
    redirect happened -- silently leaving a stray duplicate page entry
    behind once the retry succeeded."""
    site = {
        "https://x/": {"links": ["/flaky"]},
        "https://x/flaky": {"redirect_to": "https://x/landed", "links": []},
        # evaluate() checks self.url, which is the *landed* url after a
        # redirect -- the fail-once counter has to live there, not on
        # the originally-requested "/flaky" entry.
        "https://x/landed": {"links": [], "evaluate_fail_times": 1},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(retries_per_page=2))

    page_urls = [e.url for e in endpoints if e.endpoint_type == "page"]
    assert page_urls.count("https://x/landed") == 1


@pytest.mark.asyncio
async def test_crawl_does_not_record_off_origin_redirect_as_endpoint():
    """A same-origin link can still redirect off-site (e.g. Juice
    Shop's own `/redirect?to=...` open redirect, confirmed live against
    the real target). The destination must never be recorded as one of
    *this* target's endpoints, and its own links must never be followed
    -- vulnerability modules and Burp's Active Scan both treat
    everything in the returned list as fair game to send test/attack
    traffic to, and a stray third-party URL would mean probing a real
    external site without authorization."""
    site = {
        "https://x/": {"links": ["/redirect?to=https://evil.example/"]},
        "https://x/redirect?to=https://evil.example/": {
            "redirect_to": "https://evil.example/",
            "links": ["/should-not-be-followed"],
        },
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    assert not any("evil.example" in e.url for e in endpoints)
    # goto_calls legitimately includes the *requesting* URL, whose own
    # query string names "evil.example" as the redirect target -- what
    # must never happen is actually navigating there for its own sake.
    assert not any(call.startswith("https://evil.example") for call in context.page.goto_calls)


@pytest.mark.asyncio
async def test_crawl_resolves_links_against_landed_url_after_same_origin_redirect():
    """Relative hrefs on the page actually reached must resolve against
    where the browser landed, not the URL that was originally
    requested -- resolving against the wrong base (a real bug found
    live: a redirect through a `/redirect?to=` page silently produced
    same-origin-*looking* URLs, all bogus, none of which were really
    discovered) silently corrupts the endpoint list."""
    site = {
        "https://x/": {"links": ["/go?to=/sub/"]},
        "https://x/go?to=/sub/": {"redirect_to": "https://x/sub/page"},
        "https://x/sub/page": {"links": ["sibling"]},
        "https://x/sub/sibling": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    urls = {e.url for e in endpoints}
    assert "https://x/sub/sibling" in urls
