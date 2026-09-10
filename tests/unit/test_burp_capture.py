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
from stof.session.models import Session


def _finding(
    request_raw: str, finding_id: str = "f1", response_raw: str = "HTTP 200, 512 bytes",
    user_role: str = "normal", confirmed_role: str | None = None,
) -> Finding:
    return Finding(
        module_id="sqli_tests", vuln_type="SQL Injection", severity="Critical", cvss_score=9.1,
        endpoint=Endpoint(url="https://target.example/search", method="GET", endpoint_type="page"),
        user_role=user_role, request_raw=request_raw, response_raw=response_raw,
        description="d", recommendation="r", finding_id=finding_id, confirmed_role=confirmed_role,
    )


def _session(role: str, cookies: dict | None = None, headers: dict | None = None) -> Session:
    return Session(
        user_id=f"{role}-01", role=role, auth_type="form_login",
        cookies=cookies if cookies is not None else {"JSESSIONID": f"{role}-cookie"}, headers=headers or {},
    )


class _FakeSessionManager:
    """Minimal stand-in for `SessionManager.peek_session()` -- these
    tests only need the synchronous cache read, not the full auth
    machinery."""

    def __init__(self, sessions: dict[str, Session]) -> None:
        self._sessions = sessions

    def peek_session(self, role: str) -> Session | None:
        return self._sessions.get(role)


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

        finding = _finding("POST https://target.example/doLogin\nuid=\"' OR '1'='1'-- -\"&passw=irrelevant")
        result = await capture_via_burp(pw, "http://127.0.0.1:8080", finding)

        assert result is not None
        request_context.post.assert_awaited_once()
        _, call_kwargs = request_context.post.await_args
        assert call_kwargs["form"] == {"uid": "' OR '1'='1'-- -", "passw": "irrelevant"}
        assert "uid=' OR '1'='1'-- -" in result[0]

    @pytest.mark.asyncio
    async def test_skips_replay_when_request_raw_still_carries_a_masked_credential(self):
        """Regression: a masked `***` placeholder baked into request_raw
        used to get parsed out and sent as the literal, non-functional
        replay value -- producing a captured "evidence" response that
        legitimately rejects (since `***` isn't the real credential) and
        flatly contradicts the finding's own real result. That eroded
        trust in a true positive (a real end-user report). Must skip
        the replay outright instead of lying about the outcome."""
        request_context = AsyncMock()
        request_context.post = AsyncMock(return_value=_response(status=200, text="ok"))
        request_context.dispose = AsyncMock()
        pw = _playwright_with_context(request_context)

        finding = _finding("POST https://target.example/doLogin\nemail=demo&password=***")
        result = await capture_via_burp(pw, "http://127.0.0.1:8080", finding)

        assert result is None
        request_context.post.assert_not_awaited()

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

    @pytest.mark.asyncio
    async def test_no_session_sends_no_cookie_header(self):
        """Regression for the real gap this was built to fix: a bare
        capture with no session must stay exactly as unauthenticated as
        before (never silently invent a Cookie header), so its request
        text and behavior are unchanged for a finding with no known
        session."""
        request_context = AsyncMock()
        request_context.get = AsyncMock(return_value=_response(status=200, text="ok"))
        request_context.dispose = AsyncMock()
        pw = _playwright_with_context(request_context)

        result = await capture_via_burp(pw, "http://127.0.0.1:8080", _finding("GET https://target.example/search"))

        assert result is not None
        _, call_kwargs = request_context.get.await_args
        assert "Cookie" not in call_kwargs["headers"]
        assert "unauthenticated replay" in result[0]

    @pytest.mark.asyncio
    async def test_session_sends_real_cookie_and_auth_headers(self):
        """The actual bug report this fixes: an unauthenticated replay
        of a login-gated finding tells a reviewer nothing about whether
        it's real. Passing the real `Session` must make the replayed
        request carry its actual cookies/headers, not a bare curl-
        equivalent request."""
        request_context = AsyncMock()
        request_context.get = AsyncMock(return_value=_response(status=200, text="ok"))
        request_context.dispose = AsyncMock()
        pw = _playwright_with_context(request_context)
        session = _session("admin", cookies={"JSESSIONID": "abc123"}, headers={"Authorization": "Bearer tok"})

        result = await capture_via_burp(pw, "http://127.0.0.1:8080", _finding("GET https://target.example/search"), session=session)

        assert result is not None
        _, call_kwargs = request_context.get.await_args
        assert call_kwargs["headers"]["Cookie"] == "JSESSIONID=abc123"
        assert call_kwargs["headers"]["Authorization"] == "Bearer tok"
        assert "role 'admin'" in result[0]


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

    @pytest.mark.asyncio
    async def test_uses_the_findings_own_role_session_when_session_manager_given(self):
        request_context = AsyncMock()
        request_context.get = AsyncMock(return_value=_response(status=200, text="captured"))
        request_context.dispose = AsyncMock()
        pw = _playwright_with_context(request_context)
        session_manager = _FakeSessionManager({"admin": _session("admin", cookies={"JSESSIONID": "admin-cookie"})})
        finding = _finding("GET https://target.example/a", user_role="admin")

        enriched = await capture_findings_via_burp(pw, "http://127.0.0.1:8080", [finding], session_manager=session_manager)

        assert enriched == 1
        _, call_kwargs = request_context.get.await_args
        assert call_kwargs["headers"]["Cookie"] == "JSESSIONID=admin-cookie"
        assert "role: admin" in finding.request_raw

    @pytest.mark.asyncio
    async def test_confirmed_role_captures_both_identities_side_by_side(self):
        """The real point of this whole feature: an IDOR/BOLA finding
        with a cross-session-confirming second identity
        (`Finding.confirmed_role`) gets BOTH real, authenticated
        requests captured -- not just the one that first observed the
        distinct content -- so a human reviewer can compare two real
        responses under two real sessions directly in Burp's Proxy
        history."""
        request_context = AsyncMock()
        request_context.get = AsyncMock(return_value=_response(status=200, text="captured"))
        request_context.dispose = AsyncMock()
        pw = _playwright_with_context(request_context)
        session_manager = _FakeSessionManager({
            "admin": _session("admin", cookies={"JSESSIONID": "admin-cookie"}),
            "normal": _session("normal", cookies={"JSESSIONID": "normal-cookie"}),
        })
        finding = _finding("GET https://target.example/a", user_role="admin", confirmed_role="normal")

        enriched = await capture_findings_via_burp(pw, "http://127.0.0.1:8080", [finding], session_manager=session_manager)

        assert enriched == 1
        assert request_context.get.await_count == 2
        cookies_sent = [call.kwargs["headers"]["Cookie"] for call in request_context.get.await_args_list]
        assert cookies_sent == ["JSESSIONID=admin-cookie", "JSESSIONID=normal-cookie"]
        assert "role: admin" in finding.request_raw
        assert "role: normal" in finding.request_raw

    @pytest.mark.asyncio
    async def test_confirmed_role_with_no_matching_session_only_captures_primary(self):
        """`confirmed_role` names a role, not a guaranteed live session
        -- if that role never authenticated this run (or no
        session_manager was given), the primary capture must still
        succeed on its own rather than the whole finding silently
        getting nothing."""
        request_context = AsyncMock()
        request_context.get = AsyncMock(return_value=_response(status=200, text="captured"))
        request_context.dispose = AsyncMock()
        pw = _playwright_with_context(request_context)
        session_manager = _FakeSessionManager({"admin": _session("admin")})
        finding = _finding("GET https://target.example/a", user_role="admin", confirmed_role="normal")

        enriched = await capture_findings_via_burp(pw, "http://127.0.0.1:8080", [finding], session_manager=session_manager)

        assert enriched == 1
        assert request_context.get.await_count == 1

    @pytest.mark.asyncio
    async def test_no_session_manager_still_captures_unauthenticated(self):
        """Backward-compatible default: omitting `session_manager`
        entirely (existing callers, existing tests above) keeps the
        original unauthenticated-capture behavior unchanged."""
        request_context = AsyncMock()
        request_context.get = AsyncMock(return_value=_response(status=200, text="captured"))
        request_context.dispose = AsyncMock()
        pw = _playwright_with_context(request_context)
        finding = _finding("GET https://target.example/a", user_role="admin", confirmed_role="normal")

        enriched = await capture_findings_via_burp(pw, "http://127.0.0.1:8080", [finding])

        assert enriched == 1
        assert request_context.get.await_count == 1
        _, call_kwargs = request_context.get.await_args
        assert "Cookie" not in call_kwargs["headers"]
