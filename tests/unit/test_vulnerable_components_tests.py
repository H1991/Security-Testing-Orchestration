"""Unit tests for Layer 9 -- stof.modules.vulnerable_components_tests (TC-149).

Every technique mocks the I/O boundary (`context.request.get`) with a
fake context/response, matching `test_tls_tests.py`'s/
`test_openapi_discovery.py`'s own established "mock the I/O boundary,
not the library" convention -- never a real network call."""
from stof.crawler.endpoint_store import Endpoint
from stof.modules.results import ERROR, FAIL, PASS, SKIPPED
from stof.modules.vulnerable_components_tests import (
    VulnerableComponentsConfig,
    VulnerableComponentsModule,
    _match_from_filename,
    _v,
)

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status: int, body: str):
        self.status = status
        self._body = body

    async def text(self):
        return self._body


class _FakeRequest:
    def __init__(self, responder):
        self._responder = responder
        self.calls: list[str] = []

    async def get(self, url: str, **kwargs):
        self.calls.append(url)
        status, body = self._responder(url)
        return _FakeResponse(status, body)


class _FakeContext:
    def __init__(self, responder):
        self.request = _FakeRequest(responder)
        self.closed = False

    async def close(self):
        self.closed = True


class _FakeSessionPool:
    def __init__(self, context: _FakeContext):
        self._context = context

    async def new_anonymous_context(self):
        return self._context


class _FakeEvidence:
    def __init__(self):
        self.captures: list[tuple[str, str]] = []

    async def capture_raw(self, request_raw, response_raw, label=None):
        self.captures.append((request_raw, response_raw))
        return [f"evidence://{label}"]


def _run(html: str, module: VulnerableComponentsModule | None = None, script_responder=None, evidence=None):
    module = module or VulnerableComponentsModule(config=VulnerableComponentsConfig(base_url="https://x.example"))

    def responder(url: str):
        if url == "https://x.example":
            return 200, html
        if script_responder is not None:
            return script_responder(url)
        return 200, ""

    context = _FakeContext(responder)
    pool = _FakeSessionPool(context)
    endpoints = [Endpoint(url="https://x.example", method="GET", endpoint_type="page")]
    return module.run_techniques(endpoints, session_manager=None, session_pool=pool, evidence=evidence), context


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_v_parses_a_dotted_version_string():
    assert _v("3.5.0") == (3, 5, 0)


def test_match_from_filename_extracts_version_from_cdn_style_url():
    from stof.modules.vulnerable_components_tests import LIBRARY_SIGNATURES

    jquery_sig = next(s for s in LIBRARY_SIGNATURES if s.name == "jQuery")
    version = _match_from_filename("https://cdnjs.cloudflare.com/ajax/libs/jquery/1.7.2/jquery.min.js", jquery_sig)
    assert version == (1, 7, 2)


def test_match_from_filename_returns_none_when_no_version_in_url():
    from stof.modules.vulnerable_components_tests import LIBRARY_SIGNATURES

    jquery_sig = next(s for s in LIBRARY_SIGNATURES if s.name == "jQuery")
    assert _match_from_filename("https://x.example/js/jquery.min.js", jquery_sig) is None


# ---------------------------------------------------------------------------
# run_techniques -- via fake HTTP context
# ---------------------------------------------------------------------------


async def test_pass_when_no_scripts_on_the_page():
    coro, _context = _run("<html><body>no scripts here</body></html>")
    results = await coro
    assert len(results) == 1
    assert results[0].status == PASS


async def test_pass_when_only_a_safe_jquery_version_is_loaded():
    html = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>'
    coro, _context = _run(html)
    results = await coro
    assert len(results) == 1
    assert results[0].status == PASS
    assert "jQuery" in results[0].detail


async def test_fail_when_a_vulnerable_jquery_version_is_loaded_via_filename():
    html = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.7.2/jquery.min.js"></script>'
    coro, _context = _run(html)
    results = await coro
    assert len(results) == 1
    assert results[0].status == FAIL
    assert results[0].finding is not None
    assert "jQuery" in results[0].finding.description
    assert "CVE-2020-11022" in results[0].finding.description


async def test_fail_flags_any_angularjs_version_as_end_of_life():
    html = '<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"></script>'
    coro, _context = _run(html)
    results = await coro
    assert len(results) == 1
    assert results[0].status == FAIL
    assert "end-of-life" in results[0].finding.description.lower()


async def test_fetches_content_banner_when_filename_has_no_version():
    html = '<script src="https://x.example/js/lodash.min.js"></script>'

    def script_responder(url):
        assert url == "https://x.example/js/lodash.min.js"
        return 200, "/*! lodash v4.17.15 */\n(function(){...})();"

    coro, context = _run(html, script_responder=script_responder)
    results = await coro
    assert len(results) == 1
    assert results[0].status == FAIL
    assert "4.17.15" in results[0].finding.description
    assert context.request.calls.count("https://x.example/js/lodash.min.js") == 1


async def test_safe_version_found_via_banner_is_reported_as_checked_not_failed():
    html = '<script src="https://x.example/js/lodash.min.js"></script>'

    def script_responder(url):
        return 200, "/*! lodash v4.17.21 */"

    coro, _context = _run(html, script_responder=script_responder)
    results = await coro
    assert len(results) == 1
    assert results[0].status == PASS
    assert "lodash" in results[0].detail.lower()


async def test_unrecognized_scripts_are_ignored():
    html = '<script src="https://x.example/js/app-bundle-abc123.js"></script>'
    coro, _context = _run(html)
    results = await coro
    assert len(results) == 1
    assert results[0].status == PASS


async def test_content_fetch_budget_is_capped():
    scripts = "".join(f'<script src="https://x.example/js/lib{i}/lodash.min.js"></script>' for i in range(5))

    def script_responder(url):
        return 200, "/*! lodash v4.17.15 */"

    module = VulnerableComponentsModule(config=VulnerableComponentsConfig(base_url="https://x.example", max_content_fetches=2))
    coro, context = _run(scripts, module=module, script_responder=script_responder)
    await coro
    # 1 request for the page itself + at most max_content_fetches script fetches
    assert len(context.request.calls) <= 1 + 2


async def test_error_result_when_the_page_itself_cannot_be_fetched():
    module = VulnerableComponentsModule(config=VulnerableComponentsConfig(base_url="https://x.example"))

    class _BrokenContext(_FakeContext):
        pass

    async def broken_get(url, **kwargs):
        raise RuntimeError("connection reset")

    context = _FakeContext(lambda url: (200, ""))
    context.request.get = broken_get
    pool = _FakeSessionPool(context)
    endpoints = [Endpoint(url="https://x.example", method="GET", endpoint_type="page")]

    results = await module.run_techniques(endpoints, session_manager=None, session_pool=pool, evidence=None)
    assert len(results) == 1
    assert results[0].status == ERROR


async def test_skipped_when_there_is_no_target_url():
    module = VulnerableComponentsModule(config=VulnerableComponentsConfig(base_url=""))
    pool = _FakeSessionPool(_FakeContext(lambda url: (200, "")))
    results = await module.run_techniques([], session_manager=None, session_pool=pool, evidence=None)
    assert len(results) == 1
    assert results[0].status == SKIPPED


async def test_context_is_always_closed_even_on_a_fetch_failure():
    module = VulnerableComponentsModule(config=VulnerableComponentsConfig(base_url="https://x.example"))

    async def broken_get(url, **kwargs):
        raise RuntimeError("boom")

    context = _FakeContext(lambda url: (200, ""))
    context.request.get = broken_get
    pool = _FakeSessionPool(context)
    endpoints = [Endpoint(url="https://x.example", method="GET", endpoint_type="page")]

    await module.run_techniques(endpoints, session_manager=None, session_pool=pool, evidence=None)
    assert context.closed is True


async def test_evidence_is_captured_for_each_finding():
    html = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.7.2/jquery.min.js"></script>'
    evidence = _FakeEvidence()
    coro, _context = _run(html, evidence=evidence)
    results = await coro
    assert results[0].status == FAIL
    assert len(evidence.captures) == 1


async def test_run_delegates_to_run_techniques_and_extracts_findings():
    html = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.7.2/jquery.min.js"></script>'
    module = VulnerableComponentsModule(config=VulnerableComponentsConfig(base_url="https://x.example"))

    def responder(url):
        return 200, html

    context = _FakeContext(responder)
    pool = _FakeSessionPool(context)
    endpoints = [Endpoint(url="https://x.example", method="GET", endpoint_type="page")]

    findings = await module.run(endpoints, session_manager=None, session_pool=pool, evidence=None)
    assert len(findings) == 1
    assert findings[0].module_id == "vulnerable_components_tests"
