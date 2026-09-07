"""Unit tests for Layer 9 — stof.modules.configuration_tests (TC-017)."""
import ssl
from unittest.mock import AsyncMock

import pytest

from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.configuration_tests import (
    _ADMIN_PANEL_PATH_STACK,
    _SAMPLE_FILE_PATH_STACK,
    ConfigurationTestConfig,
    ConfigurationTestsModule,
    _csp_missing_or_weak,
    _find_cloud_storage_urls,
    _is_bucket_listing,
    _missing_security_headers,
    _mixed_content_hosts,
    _narrow_paths_for_stack,
    _password_autocomplete_gap,
    _path_relative_stylesheet_hrefs,
    _referrer_policy_gap,
)
from stof.modules.results import ERROR, FAIL, PASS, SKIPPED
from stof.recon.target_profile import TargetProfile


def _response(status: int, body: str, headers: dict | None = None):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    resp.headers = headers or {}
    return resp


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


@pytest.fixture(autouse=True)
def _no_real_tls_handshake(monkeypatch):
    """TC-017.15 (`_technique_tls_certificate`) does a genuine `ssl`/
    `socket` TLS handshake, not a Playwright-mocked HTTP call -- without
    this, every test in this file that calls `run_techniques()` (nearly
    all of them) would attempt a real network connection to whatever
    fake host the test's endpoint URL happens to use (e.g. "https://x/").
    That happened to fail fast via near-instant DNS resolution failure
    in this sandbox, but relying on that is fragile and not hermetic --
    stub it to a fixed, valid-for-90-days result so every test in this
    file is a real unit test, not an accidental integration test.
    Tests that specifically exercise TC-017.14/.15 override this
    per-test via `monkeypatch` themselves."""
    from datetime import datetime, timedelta, timezone

    import stof.modules.configuration_tests as _mod
    monkeypatch.setattr(_mod, "_fetch_tls_certificate", lambda hostname, port=443, timeout=8.0: {
        "not_after": datetime.now(timezone.utc) + timedelta(days=90),
        "days_remaining": 90,
    })


@pytest.mark.asyncio
async def test_admin_panel_fails_when_a_path_returns_content():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()

    async def fake_get(url, max_redirects=0):
        if url.endswith("/admin"):
            return _response(200, "Admin Dashboard" * 20)
        return _response(404, "not found")

    context.request.get = AsyncMock(side_effect=fake_get)
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.1"].status == FAIL
    assert by_id["TC-017.1"].finding is not None


@pytest.mark.asyncio
async def test_admin_panel_passes_when_nothing_reachable():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(404, "not found"))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.1"].status == PASS


def test_narrow_paths_for_stack_unknown_returns_everything():
    paths = ("/wp-admin", "/admin", "/manager/html")
    assert _narrow_paths_for_stack(paths, _ADMIN_PANEL_PATH_STACK, "unknown") == list(paths)


def test_narrow_paths_for_stack_java_drops_php_only_paths():
    paths = ("/wp-admin", "/admin", "/manager/html", "/phpmyadmin")
    result = _narrow_paths_for_stack(paths, _ADMIN_PANEL_PATH_STACK, "java")
    assert result == ["/admin", "/manager/html"]


def test_narrow_paths_for_stack_php_drops_java_only_paths():
    paths = ("/wp-admin", "/admin", "/manager/html")
    result = _narrow_paths_for_stack(paths, _ADMIN_PANEL_PATH_STACK, "php")
    assert result == ["/wp-admin", "/admin"]


def test_narrow_paths_for_stack_keeps_generic_paths_for_any_family():
    paths = ("/install.php", "/.env", "/web.config")
    result = _narrow_paths_for_stack(paths, _SAMPLE_FILE_PATH_STACK, "dotnet")
    assert result == ["/.env", "/web.config"]


@pytest.mark.asyncio
async def test_admin_panel_narrows_candidates_for_detected_java_stack():
    """Real-world regression: demo.testfire.net fingerprints as
    Apache-Coyote/Java -- /wp-admin, /phpmyadmin, /adminer.php are
    guaranteed-dead probes there and should be skipped, never FAIL
    just because they weren't tried."""
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    probed_urls = []

    async def fake_get(url, max_redirects=0):
        probed_urls.append(url)
        return _response(404, "not found")

    context = AsyncMock()
    context.request.get = AsyncMock(side_effect=fake_get)
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    config = ConfigurationTestConfig(target_profile=TargetProfile(stack_family="java", confidence="high"))
    module = ConfigurationTestsModule(config=config)

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.1"].status == PASS
    assert "narrowed" in by_id["TC-017.1"].detail
    assert not any(u.endswith(("/wp-admin", "/phpmyadmin")) for u in probed_urls)
    assert any(u.endswith("/admin") for u in probed_urls)


@pytest.mark.asyncio
async def test_admin_panel_does_not_narrow_when_stack_unknown():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    probed_urls = []

    async def fake_get(url, max_redirects=0):
        probed_urls.append(url)
        return _response(404, "not found")

    context = AsyncMock()
    context.request.get = AsyncMock(side_effect=fake_get)
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()  # no target_profile configured -- defaults to None/"unknown"

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.1"].status == PASS
    assert "narrowed" not in by_id["TC-017.1"].detail
    assert any(u.endswith("/wp-admin") for u in probed_urls)


@pytest.mark.asyncio
async def test_sample_files_narrows_candidates_for_detected_dotnet_stack():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    probed_urls = []

    async def fake_get(url, max_redirects=0):
        probed_urls.append(url)
        return _response(404, "not found")

    context = AsyncMock()
    context.request.get = AsyncMock(side_effect=fake_get)
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    config = ConfigurationTestConfig(target_profile=TargetProfile(stack_family="dotnet", confidence="high"))
    module = ConfigurationTestsModule(config=config)

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.4"].status == PASS
    assert not any(u.endswith(("/install.php", "/phpinfo.php")) for u in probed_urls)
    assert any(u.endswith("/web.config") for u in probed_urls)
    assert any(u.endswith("/.env") for u in probed_urls)  # generic path never narrowed away


@pytest.mark.asyncio
async def test_directory_listing_fails_on_index_of_marker():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()

    async def fake_get(url, max_redirects=0):
        if url.endswith("/uploads/"):
            return _response(200, "<html><title>Index of /uploads</title></html>")
        return _response(404, "not found")

    context.request.get = AsyncMock(side_effect=fake_get)
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.2"].status == FAIL


@pytest.mark.asyncio
async def test_sample_files_fails_when_env_file_exposed():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()

    async def fake_get(url, max_redirects=0):
        if url.endswith("/.env"):
            return _response(200, "DB_PASSWORD=hunter2")
        return _response(404, "not found")

    context.request.get = AsyncMock(side_effect=fake_get)
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.4"].status == FAIL


@pytest.mark.asyncio
async def test_version_disclosure_fails_on_versioned_server_header():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "hello", headers={"server": "Apache/2.4.41"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.5"].status == FAIL


@pytest.mark.asyncio
async def test_version_disclosure_passes_on_bare_product_name():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "hello", headers={"server": "nginx"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.5"].status == PASS


@pytest.mark.asyncio
async def test_debug_mode_passes_when_no_endpoints_discovered():
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(404, "not found"))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.3"].status == PASS


@pytest.mark.asyncio
async def test_admin_panel_passes_on_spa_catchall_that_serves_200_for_any_path():
    """A client-side-routed SPA (Angular etc.) serves an identical
    index.html shell -- HTTP 200, same bytes -- for ANY unmatched path,
    including the wordlist's own /admin candidate AND the module's random
    control probe. Without a baseline comparison this would look like
    every admin path is "reachable"; with it, PASS is correct since
    nothing distinguishes the candidate from a definitely-bogus path."""
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "<html>spa shell</html>" * 20))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.1"].status == PASS
    assert by_id["TC-017.4"].status == PASS


@pytest.mark.asyncio
async def test_sample_files_still_fails_on_spa_target_when_one_path_genuinely_differs():
    """Same SPA-catchall baseline as above, but /.env returns a distinct
    body -- must still be flagged, proving the baseline fix doesn't mask
    genuine findings on an SPA target."""
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()

    async def fake_get(url, max_redirects=0):
        if url.endswith("/.env"):
            return _response(200, "DB_PASSWORD=hunter2")
        return _response(200, "<html>spa shell</html>" * 20)

    context.request.get = AsyncMock(side_effect=fake_get)
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.4"].status == FAIL


def test_config_defaults():
    config = ConfigurationTestConfig()
    assert len(config.admin_panel_paths) > 0
    assert config.min_content_length == 100


@pytest.mark.parametrize(
    ("acao", "acac", "expected"),
    [
        ("https://stof-cors-probe.invalid", "true", True),
        ("https://stof-cors-probe.invalid", None, False),
        ("*", "true", False),
        ("https://trusted.example.com", "true", False),
    ],
)
def test_is_cors_misconfigured_pure_helper(acao, acac, expected):
    assert ConfigurationTestsModule._is_cors_misconfigured("https://stof-cors-probe.invalid", acao, acac) is expected


@pytest.mark.asyncio
async def test_cors_misconfiguration_fails_when_origin_reflected_with_credentials():
    endpoint = Endpoint(url="https://x/api/data", method="GET", endpoint_type="api")
    context = AsyncMock()
    context.request.get = AsyncMock(
        return_value=_response(
            200, "ok",
            headers={
                "access-control-allow-origin": "https://stof-cors-probe.invalid",
                "access-control-allow-credentials": "true",
            },
        )
    )
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.6"].status == FAIL
    assert by_id["TC-017.6"].finding is not None


@pytest.mark.asyncio
async def test_cors_misconfiguration_passes_on_static_wildcard_without_credentials():
    """The documented false-positive trap: a static ACAO: * with no/false
    Access-Control-Allow-Credentials must NOT be flagged."""
    endpoint = Endpoint(url="https://x/api/data", method="GET", endpoint_type="api")
    context = AsyncMock()
    context.request.get = AsyncMock(
        return_value=_response(200, "ok", headers={"access-control-allow-origin": "*"})
    )
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.6"].status == PASS


@pytest.mark.asyncio
async def test_cors_misconfiguration_reports_error_on_probe_failure():
    endpoint = Endpoint(url="https://x/api/data", method="GET", endpoint_type="api")
    context = AsyncMock()
    context.request.get = AsyncMock(side_effect=RuntimeError("net::ERR_CONNECTION_RESET"))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.6"].status == ERROR


@pytest.mark.asyncio
async def test_admin_panel_reports_error_not_false_pass_on_transient_network_error():
    """Batch 3 regression: a transient network error during the
    baseline/wordlist sweep must surface as ERROR, never a false PASS
    ("none of N paths reachable") -- the same class of bug already
    fixed for idor_tests.py's `_authenticated_context` (see
    test_idor_tests.py's own transient-error regression tests).
    `_control_fingerprint`/`_probe_paths` now re-raise a transient
    error instead of swallowing it into `None`/`continue`, and
    `run_techniques()`'s `_safe_result` wrapper turns that into a real
    ERROR `TestCaseResult` instead of the previous bare log-and-drop,
    which silently vanished the technique from `results` entirely.
    Sibling techniques (here TC-017.3, which has no endpoints to probe
    and never touches the network) must still run and report their own
    real outcome -- the transient failure in TC-017.1/.2/.4/.5 must not
    abort the loop."""
    context = AsyncMock()
    context.request.get = AsyncMock(side_effect=RuntimeError("net::ERR_NETWORK_CHANGED at https://x/admin"))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.1"].status == ERROR
    assert by_id["TC-017.1"].status != PASS
    assert by_id["TC-017.3"].status == PASS


# ---------------------------------------------------------------------------
# TC-017.7 — CSP analysis
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("content_type", "csp_header", "expected"),
    [
        # Not applicable at all -- a non-HTML response omitting CSP is normal.
        ("application/json", None, None),
        ("application/json", "default-src 'self'", None),
        # Missing header on an HTML response.
        ("text/html; charset=utf-8", None, "no CSP header present"),
        ("text/html", "", "no CSP header present"),
        # unsafe-inline without a nonce/hash source -- a hit.
        ("text/html", "script-src 'self' 'unsafe-inline'", "allows unsafe-inline script execution"),
        # unsafe-inline WITH a nonce present -- the guard, must be clean.
        ("text/html", "script-src 'self' 'unsafe-inline' 'nonce-abc123'", None),
        # unsafe-inline WITH a hash source present -- also guarded.
        ("text/html", "script-src 'self' 'unsafe-inline' 'sha256-abc123'", None),
        # unsafe-eval.
        ("text/html", "script-src 'self' 'unsafe-eval'", "allows unsafe-eval"),
        # Overly broad sources.
        ("text/html", "script-src *", "allows script execution from an overly broad source"),
        ("text/html", "script-src data:", "allows script execution from an overly broad source"),
        ("text/html", "default-src https:", "allows script execution from an overly broad source"),
        # A genuinely strict policy -- must never be flagged just for being short.
        ("text/html", "default-src 'self'", None),
        ("text/html", "script-src 'self'; object-src 'none'", None),
        # default-src fallback when script-src is absent.
        ("text/html", "default-src 'self' 'unsafe-inline'", "allows unsafe-inline script execution"),
        # script-src present takes precedence over a weak default-src.
        ("text/html", "default-src 'unsafe-inline'; script-src 'self'", None),
    ],
)
def test_csp_missing_or_weak_pure_helper(content_type, csp_header, expected):
    assert _csp_missing_or_weak(content_type, csp_header) == expected


@pytest.mark.asyncio
async def test_csp_weakness_fails_on_missing_header():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "<html></html>", headers={"content-type": "text/html"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.7"].status == FAIL
    assert by_id["TC-017.7"].finding is not None
    assert "no CSP header present" in by_id["TC-017.7"].finding.description


@pytest.mark.asyncio
async def test_csp_weakness_fails_on_unsafe_inline_without_nonce():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(
        200, "<html></html>",
        headers={"content-type": "text/html", "content-security-policy": "script-src 'self' 'unsafe-inline'"},
    ))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.7"].status == FAIL


@pytest.mark.asyncio
async def test_csp_weakness_passes_on_unsafe_inline_with_nonce():
    """The guard: unsafe-inline alongside a nonce source is a real,
    still-strict-for-modern-browsers backward-compat pattern."""
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(
        200, "<html></html>",
        headers={
            "content-type": "text/html",
            "content-security-policy": "script-src 'self' 'unsafe-inline' 'nonce-abc123'",
        },
    ))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.7"].status == PASS


@pytest.mark.asyncio
async def test_csp_weakness_passes_on_strict_default_src_self():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(
        200, "<html></html>",
        headers={"content-type": "text/html", "content-security-policy": "default-src 'self'"},
    ))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.7"].status == PASS


@pytest.mark.asyncio
async def test_csp_weakness_passes_on_non_html_content_type():
    """False-positive guard: a missing/weak CSP on a non-HTML (e.g. JSON
    API) response is normal and must not be flagged."""
    endpoint = Endpoint(url="https://x/api/data", method="GET", endpoint_type="api")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, '{"ok":true}', headers={"content-type": "application/json"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.7"].status == PASS


@pytest.mark.asyncio
async def test_csp_weakness_reports_error_on_probe_failure():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(side_effect=RuntimeError("net::ERR_CONNECTION_RESET"))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.7"].status == ERROR


# --- TC-017.8: missing clickjacking / MIME-sniffing security headers ---

@pytest.mark.parametrize(
    ("content_type", "headers", "expected"),
    [
        ("text/html", {}, ["X-Content-Type-Options", "X-Frame-Options"]),
        ("text/html", {"x-content-type-options": "nosniff", "x-frame-options": "DENY"}, []),
        # frame-ancestors in CSP supersedes X-Frame-Options -- must not double-flag.
        (
            "text/html",
            {"x-content-type-options": "nosniff", "content-security-policy": "frame-ancestors 'self'"},
            [],
        ),
        # non-HTML response: neither header matters.
        ("application/json", {}, []),
        # sniffing value must be exactly "nosniff".
        ("text/html", {"x-content-type-options": "none", "x-frame-options": "DENY"}, ["X-Content-Type-Options"]),
    ],
)
def test_missing_security_headers_pure_helper(content_type, headers, expected):
    assert _missing_security_headers(content_type, headers) == expected


@pytest.mark.asyncio
async def test_missing_security_headers_fails_when_both_absent():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "<html></html>", headers={"content-type": "text/html"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.8"].status == FAIL
    assert "X-Content-Type-Options" in by_id["TC-017.8"].finding.description
    assert "X-Frame-Options" in by_id["TC-017.8"].finding.description


@pytest.mark.asyncio
async def test_missing_security_headers_passes_when_present():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(
        200, "<html></html>",
        headers={"content-type": "text/html", "x-content-type-options": "nosniff", "x-frame-options": "DENY"},
    ))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.8"].status == PASS


@pytest.mark.asyncio
async def test_missing_security_headers_reports_error_on_probe_failure():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(side_effect=RuntimeError("net::ERR_CONNECTION_RESET"))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.8"].status == ERROR


# --- TC-017.9: TLS/transport analysis ---

@pytest.mark.asyncio
async def test_tls_fails_when_sensitive_endpoint_reachable_over_plaintext_http():
    endpoint = Endpoint(url="http://x/login", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "<html>login</html>", headers={"content-type": "text/html"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.9"].status == FAIL
    assert "plaintext HTTP" in by_id["TC-017.9"].finding.description


@pytest.mark.asyncio
async def test_tls_passes_when_sensitive_endpoint_is_https_only():
    """False-positive guard: a non-sensitive path (e.g. a static asset)
    served over plain HTTP is not this technique's concern."""
    endpoint = Endpoint(url="http://x/images/logo.png", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "binary", headers={"content-type": "image/png"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.9"].status == PASS


@pytest.mark.asyncio
async def test_tls_fails_when_https_target_missing_hsts():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "<html></html>", headers={"content-type": "text/html"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.9"].status == FAIL
    assert "Strict-Transport-Security" in by_id["TC-017.9"].finding.description


@pytest.mark.asyncio
async def test_tls_passes_when_https_target_has_hsts():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(
        200, "<html></html>",
        headers={"content-type": "text/html", "strict-transport-security": "max-age=31536000; includeSubDomains"},
    ))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.9"].status == PASS


# --- TC-017.10: public cloud storage exposure ---

@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("no urls here", []),
        (
            'link to <a href="https://my-bucket.s3.amazonaws.com/file.txt">asset</a>',
            ["https://my-bucket.s3.amazonaws.com/file.txt"],
        ),
        (
            "https://s3.amazonaws.com/other-bucket/key and https://acct.blob.core.windows.net/container/blob and https://storage.googleapis.com/gcs-bucket/obj",
            [
                "https://s3.amazonaws.com/other-bucket/key",
                "https://acct.blob.core.windows.net/container/blob",
                "https://storage.googleapis.com/gcs-bucket/obj",
            ],
        ),
    ],
)
def test_find_cloud_storage_urls_pure_helper(body, expected):
    assert _find_cloud_storage_urls(body) == expected


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("<ListBucketResult xmlns=\"...\"><Contents/></ListBucketResult>", True),
        ("<EnumerationResults><Blobs/></EnumerationResults>", True),
        ("<Error><Code>AccessDenied</Code></Error>", False),
        ("<Error><Code>NoSuchBucket</Code></Error>", False),
        ("", False),
    ],
)
def test_is_bucket_listing_pure_helper(body, expected):
    assert _is_bucket_listing(body) == expected


@pytest.mark.asyncio
async def test_cloud_storage_fails_on_open_bucket_listing():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()

    async def fake_get(url, max_redirects=0, **kwargs):
        if "s3.amazonaws.com" in url:
            return _response(200, "<ListBucketResult><Contents><Key>secret.txt</Key></Contents></ListBucketResult>")
        return _response(200, '<a href="https://open-bucket.s3.amazonaws.com/x">link</a>', headers={"content-type": "text/html"})

    context.request.get = AsyncMock(side_effect=fake_get)
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.10"].status == FAIL
    assert "open-bucket.s3.amazonaws.com" in by_id["TC-017.10"].finding.description


@pytest.mark.asyncio
async def test_cloud_storage_passes_on_access_denied_bucket():
    """False-positive guard: a referenced bucket that returns an
    AccessDenied error (not a listing) must not be flagged."""
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()

    async def fake_get(url, max_redirects=0, **kwargs):
        if "s3.amazonaws.com" in url:
            return _response(403, "<Error><Code>AccessDenied</Code></Error>")
        return _response(200, '<a href="https://locked-bucket.s3.amazonaws.com/x">link</a>', headers={"content-type": "text/html"})

    context.request.get = AsyncMock(side_effect=fake_get)
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.10"].status == PASS


@pytest.mark.asyncio
async def test_cloud_storage_passes_when_no_urls_referenced():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "<html>nothing here</html>", headers={"content-type": "text/html"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.10"].status == PASS


# --- TC-017.11: Referrer-Policy leakage ---

@pytest.mark.parametrize(
    "content_type,headers,expected",
    [
        ("text/html", {}, None),  # missing header falls back to browser's own safe default -- not flagged
        ("text/html", {"referrer-policy": "strict-origin-when-cross-origin"}, None),
        ("text/html", {"referrer-policy": "no-referrer"}, None),
        ("text/html", {"referrer-policy": "unsafe-url"}, "Referrer-Policy is explicitly set to 'unsafe-url', which leaks the full URL (including any query string) to every cross-origin link and sub-resource this page loads"),
        ("application/json", {"referrer-policy": "unsafe-url"}, None),  # non-HTML not applicable
    ],
)
def test_referrer_policy_gap_pure_helper(content_type, headers, expected):
    assert _referrer_policy_gap(content_type, headers) == expected


@pytest.mark.asyncio
async def test_referrer_policy_fails_on_unsafe_url():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(
        200, "<html></html>", headers={"content-type": "text/html", "referrer-policy": "unsafe-url"},
    ))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.11"].status == FAIL


@pytest.mark.asyncio
async def test_referrer_policy_passes_when_absent():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "<html></html>", headers={"content-type": "text/html"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.11"].status == PASS


# --- TC-017.12: mixed content ---

@pytest.mark.parametrize(
    "page_url,content_type,body,expected",
    [
        ("https://x/", "text/html", '<script src="http://cdn.example.com/a.js"></script>', ["cdn.example.com"]),
        ("https://x/", "text/html", '<img src="https://cdn.example.com/a.png">', []),  # already HTTPS
        ("http://x/", "text/html", '<script src="http://cdn.example.com/a.js"></script>', []),  # page itself is HTTP -- not mixed content
        ("https://x/", "text/html", 'see http://example.com for details', []),  # plain text mention, not a src/href
        ("https://x/", "application/json", '<script src="http://cdn.example.com/a.js"></script>', []),  # non-HTML
    ],
)
def test_mixed_content_hosts_pure_helper(page_url, content_type, body, expected):
    assert _mixed_content_hosts(page_url, content_type, body) == expected


@pytest.mark.asyncio
async def test_mixed_content_fails_on_http_subresource():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(
        200, '<html><script src="http://cdn.example.com/a.js"></script></html>',
        headers={"content-type": "text/html"},
    ))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.12"].status == FAIL
    assert "cdn.example.com" in by_id["TC-017.12"].finding.description


@pytest.mark.asyncio
async def test_mixed_content_passes_when_all_https():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(
        200, '<html><script src="https://cdn.example.com/a.js"></script></html>',
        headers={"content-type": "text/html"},
    ))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.12"].status == PASS


# --- TC-017.13: password autocomplete ---

@pytest.mark.parametrize(
    "content_type,body,expected_count",
    [
        ("text/html", '<input type="password" name="pw">', 1),
        ("text/html", '<input type="password" name="pw" autocomplete="off">', 0),
        ("text/html", '<input type="password" name="pw" autocomplete="new-password">', 0),
        ("text/html", '<input type="text" name="username">', 0),
        ("text/html", '<input type="password"><input type="password" autocomplete="off">', 1),
        ("application/json", '<input type="password">', 0),  # non-HTML
    ],
)
def test_password_autocomplete_gap_pure_helper(content_type, body, expected_count):
    assert _password_autocomplete_gap(content_type, body) == expected_count


@pytest.mark.asyncio
async def test_password_autocomplete_fails_when_enabled():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(
        200, '<html><input type="password" name="pw"></html>', headers={"content-type": "text/html"},
    ))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.13"].status == FAIL
    assert by_id["TC-017.13"].finding.severity == "Low"  # cvss_score=1.0 -- Low per the CVSS v3.1 scale


@pytest.mark.asyncio
async def test_password_autocomplete_passes_when_disabled_or_absent():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "<html></html>", headers={"content-type": "text/html"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.13"].status == PASS


# --- TC-017.14: path-relative stylesheet import (PRSSI) ---

@pytest.mark.parametrize(
    "content_type,body,expected",
    [
        ("text/html", '<link rel="stylesheet" href="css/app.css">', ["css/app.css"]),
        ("text/html", '<link rel="stylesheet" href="/css/app.css">', []),  # root-relative -- safe
        ("text/html", '<link rel="stylesheet" href="https://cdn.example.com/app.css">', []),  # absolute -- safe
        ("text/html", '<link rel="stylesheet" href="//cdn.example.com/app.css">', []),  # protocol-relative -- safe
        ("application/json", '<link rel="stylesheet" href="css/app.css">', []),  # non-HTML
        ("text/html", '<link rel="alternate" href="css/app.css">', []),  # not a stylesheet link
    ],
)
def test_path_relative_stylesheet_hrefs_pure_helper(content_type, body, expected):
    assert _path_relative_stylesheet_hrefs(content_type, body) == expected


@pytest.mark.asyncio
async def test_prssi_fails_on_relative_stylesheet_href():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(
        200, '<html><link rel="stylesheet" href="css/app.css"></html>', headers={"content-type": "text/html"},
    ))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.14"].status == FAIL
    assert "css/app.css" in by_id["TC-017.14"].finding.description


@pytest.mark.asyncio
async def test_prssi_passes_on_root_relative_stylesheet_href():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(
        200, '<html><link rel="stylesheet" href="/css/app.css"></html>', headers={"content-type": "text/html"},
    ))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.14"].status == PASS


# --- TC-017.15: TLS certificate expiry / chain / hostname validation ---

@pytest.mark.asyncio
async def test_tls_certificate_skipped_for_http_target():
    endpoint = Endpoint(url="http://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "<html></html>", headers={"content-type": "text/html"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.15"].status == SKIPPED


@pytest.mark.asyncio
async def test_tls_certificate_passes_when_valid_and_not_expiring_soon(monkeypatch):
    from datetime import datetime, timedelta, timezone

    import stof.modules.configuration_tests as _mod
    monkeypatch.setattr(_mod, "_fetch_tls_certificate", lambda hostname, port=443, timeout=8.0: {
        "not_after": datetime.now(timezone.utc) + timedelta(days=90), "days_remaining": 90,
    })
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "<html></html>", headers={"content-type": "text/html"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.15"].status == PASS


@pytest.mark.asyncio
async def test_tls_certificate_fails_when_expired(monkeypatch):
    from datetime import datetime, timedelta, timezone

    import stof.modules.configuration_tests as _mod
    monkeypatch.setattr(_mod, "_fetch_tls_certificate", lambda hostname, port=443, timeout=8.0: {
        "not_after": datetime.now(timezone.utc) - timedelta(days=5), "days_remaining": -5,
    })
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "<html></html>", headers={"content-type": "text/html"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.15"].status == FAIL
    assert by_id["TC-017.15"].finding.severity == "High"  # cvss_score=7.4 -- High per the CVSS v3.1 scale (7.0-8.9)


@pytest.mark.asyncio
async def test_tls_certificate_fails_when_expiring_soon(monkeypatch):
    from datetime import datetime, timedelta, timezone

    import stof.modules.configuration_tests as _mod
    monkeypatch.setattr(_mod, "_fetch_tls_certificate", lambda hostname, port=443, timeout=8.0: {
        "not_after": datetime.now(timezone.utc) + timedelta(days=7), "days_remaining": 7,
    })
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "<html></html>", headers={"content-type": "text/html"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.15"].status == FAIL
    assert by_id["TC-017.15"].finding.severity == "Medium"


@pytest.mark.asyncio
async def test_tls_certificate_fails_when_handshake_raises(monkeypatch):
    import stof.modules.configuration_tests as _mod

    def _raise(hostname, port=443, timeout=8.0):
        raise ssl.SSLCertVerificationError("hostname mismatch")

    monkeypatch.setattr(_mod, "_fetch_tls_certificate", _raise)
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "<html></html>", headers={"content-type": "text/html"}))
    context.close = AsyncMock()
    pool = _pool_with_context(context)
    module = ConfigurationTestsModule()

    results = await module.run_techniques([endpoint], None, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-017.15"].status == FAIL
    assert by_id["TC-017.15"].finding.severity == "Medium"  # cvss_score=6.5 -- Medium per the CVSS v3.1 scale (4.0-6.9)
    assert "hostname mismatch" in by_id["TC-017.15"].finding.description
