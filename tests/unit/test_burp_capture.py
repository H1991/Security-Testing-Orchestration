"""Unit tests for Layer 3C (extension) — stof.engine.burp_capture.

Mocks Playwright's `Playwright.request.new_context()` / the resulting
`APIRequestContext`, same style as test_burp_controller.py.
"""
from unittest.mock import AsyncMock, MagicMock

import pytest

from stof.crawler.endpoint_store import Endpoint
from stof.engine.burp_capture import (
    _extract_request_parts,
    capture_findings_via_burp,
    capture_via_burp,
)
from stof.findings.models import Finding


def _finding(request_raw: str, finding_id: str = "f1", response_raw: str = "HTTP 200, 512 bytes") -> Finding:
    return Finding(
        module_id="sqli_tests", vuln_type="SQL Injection", severity="Critical", cvss_score=9.1,
        endpoint=Endpoint(url="https://target.example/search", method="GET", endpoint_type="page"),
        user_role="normal", request_raw=request_raw, response_raw=response_raw,
        description="d", recommendation="r", finding_id=finding_id,
    )


def _response(status=200, headers=None, text="body"):
    resp = AsyncMock()
    resp.status = status
    resp.headers = headers or {"content-type": "text/html"}
    resp.text = AsyncMock(return_value=text)
    # A real Playwright `APIResponse` has no `.request` attribute --
    # deleting it here (rather than a MagicMock() stand-in) means this
    # mock breaks the same way the real object would if the capture
    # code ever touches `.request` again, instead of silently
    # succeeding against a mock that's more permissive than reality.
    del resp.request
    return resp


def _playwright_with_context(request_context):
    pw = MagicMock()
    pw.request.new_context = AsyncMock(return_value=request_context)
    return pw


class TestExtractRequestParts:
    def test_happy_path_get_no_params(self):
        assert _extract_request_parts("GET https://x.example/search?q=1") == ("GET", "https://x.example/search?q=1", {})

    def test_extracts_quoted_payload_param(self):
        method, url, params = _extract_request_parts("POST https://x.example/doLogin\nuid=\"' OR '1'='1'-- -\"&passw=***")
        assert method == "POST"
        assert url == "https://x.example/doLogin"
        assert params == {"uid": "' OR '1'='1'-- -", "passw": "***"}

    def test_no_match_returns_none(self):
        assert _extract_request_parts("this is not a request line") is None

    def test_empty_string(self):
        assert _extract_request_parts("") is None


class TestCaptureViaBurp:
    @pytest.mark.asyncio
    async def test_happy_path_returns_captured_text(self):
        request_context = AsyncMock()
        request_context.get = AsyncMock(return_value=_response(status=200, text="<html>ok</html>"))
        request_context.dispose = AsyncMock()
        pw = _playwright_with_context(request_context)

        result = await capture_via_burp(pw, "http://127.0.0.1:8080", _finding("GET https://target.example/search?q=1"))

        assert result is not None
        request_raw, response_raw = result
        assert "GET https://target.example/search?q=1" in request_raw
        assert "User-Agent:" in request_raw  # real headers, not just a method+URL line
        assert "HTTP 200" in response_raw
        assert "<html>ok</html>" in response_raw
        request_context.dispose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_sends_the_real_payload_as_form_body_for_post(self):
        request_context = AsyncMock()
        request_context.post = AsyncMock(return_value=_response(status=200, text="ok"))
        request_context.dispose = AsyncMock()
        pw = _playwright_with_context(request_context)

        finding = _finding("POST https://target.example/doLogin\nuid=\"' OR '1'='1'-- -\"&passw=***")
        result = await capture_via_burp(pw, "http://127.0.0.1:8080", finding)

        assert result is not None
        request_context.post.assert_awaited_once()
        _, call_kwargs = request_context.post.await_args
        assert call_kwargs["form"] == {"uid": "' OR '1'='1'-- -", "passw": "***"}
        assert "uid=' OR '1'='1'-- -" in result[0]

    @pytest.mark.asyncio
    async def test_unparseable_request_raw_returns_none(self):
        pw = _playwright_with_context(AsyncMock())
        result = await capture_via_burp(pw, "http://127.0.0.1:8080", _finding("not a valid request line"))
        assert result is None

    @pytest.mark.asyncio
    async def test_unreachable_burp_returns_none_not_raises(self):
        pw = MagicMock()
        pw.request.new_context = AsyncMock(side_effect=ConnectionError("refused"))
        result = await capture_via_burp(pw, "http://127.0.0.1:8080", _finding("GET https://target.example/search"))
        assert result is None

    @pytest.mark.asyncio
    async def test_request_failure_after_connect_returns_none(self):
        request_context = AsyncMock()
        request_context.get = AsyncMock(side_effect=TimeoutError("timed out"))
        request_context.dispose = AsyncMock()
        pw = _playwright_with_context(request_context)
        result = await capture_via_burp(pw, "http://127.0.0.1:8080", _finding("GET https://target.example/search"))
        assert result is None
        request_context.dispose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_unsupported_method_returns_none(self):
        pw = _playwright_with_context(AsyncMock())
        result = await capture_via_burp(pw, "http://127.0.0.1:8080", _finding("TRACE https://target.example/search"))
        assert result is None


class TestCaptureFindingsViaBurp:
    @pytest.mark.asyncio
    async def test_enriches_successful_captures_only(self):
        good_context = AsyncMock()
        good_context.get = AsyncMock(return_value=_response(status=200, text="captured"))
        good_context.dispose = AsyncMock()

        pw = _playwright_with_context(good_context)
        findings = [
            _finding("GET https://target.example/a", "f1", response_raw="original module summary: HTTP 302"),
            _finding("not parseable", "f2"),
        ]
        original_f1_response = findings[0].response_raw
        original_f2_response = findings[1].response_raw

        enriched = await capture_findings_via_burp(pw, "http://127.0.0.1:8080", findings)

        assert enriched == 1
        # Appended, not replaced -- the technique's own original text
        # must still be there (this is the exact bug found live: an
        # early version overwrote a SQLi finding's real payload with a
        # generic reconstruction and lost it).
        assert original_f1_response in findings[0].response_raw
        assert "captured" in findings[0].response_raw
        assert findings[1].response_raw == original_f2_response  # untouched on failure
