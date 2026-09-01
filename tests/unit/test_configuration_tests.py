"""Unit tests for Layer 9 — stof.modules.configuration_tests (TC-017)."""
from unittest.mock import AsyncMock

import pytest

from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.configuration_tests import (
    ConfigurationTestConfig,
    ConfigurationTestsModule,
    _csp_missing_or_weak,
    _find_cloud_storage_urls,
    _is_bucket_listing,
    _missing_security_headers,
)
from stof.modules.results import ERROR, FAIL, PASS


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
