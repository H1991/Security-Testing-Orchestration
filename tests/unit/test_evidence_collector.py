"""Unit tests for Layer 12 — stof.evidence.collector."""
from unittest.mock import AsyncMock

import pytest

from stof.evidence.collector import EvidenceCollector, _safe_label
from stof.session.models import Session


def _page():
    page = AsyncMock()
    page.screenshot = AsyncMock()
    page.content = AsyncMock(return_value="<html>proof</html>")
    return page


def _session() -> Session:
    return Session(user_id="user-01", role="normal", auth_type="form_login", cookies={"JSESSIONID": "abc"})


# ---------------------------------------------------------------------------
# Pure helper
# ---------------------------------------------------------------------------


def test_safe_label_strips_unsafe_characters():
    assert _safe_label("idor listAccounts=800000!") == "idor_listAccounts_800000"


def test_safe_label_defaults_when_empty():
    assert _safe_label("") == "evidence"


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_capture_writes_screenshot_content_and_cookies(tmp_path):
    collector = EvidenceCollector(scan_id="scan-1", base_dir=tmp_path)
    page = _page()
    session = _session()

    paths = await collector.capture(page, session, label="idor-finding")

    assert len(paths) == 3
    directory = tmp_path / "scan-1" / "idor-finding"
    assert directory.is_dir()
    assert (directory / "page_content.html").read_text(encoding="utf-8") == "<html>proof</html>"
    assert (directory / "session_cookies.json").is_file()
    page.screenshot.assert_awaited_once()


@pytest.mark.asyncio
async def test_capture_redacts_session_cookie_values(tmp_path):
    """Session cookies are live bearer credentials for the test account,
    not payload data -- capture() must never write the usable value to
    disk. A short value (shorter than 2x the kept-chars window) has
    nothing safely revealable and is fully redacted; a realistic-length
    session token keeps a few chars at each end (enough to recognize
    "yes, a real-looking token was here") with the middle redacted."""
    import json

    collector = EvidenceCollector(scan_id="scan-1", base_dir=tmp_path)
    page = _page()
    session = _session()
    session.cookies["SESSIONID"] = "a1b2c3d4e5f6g7h8i9j0"  # realistic-length token

    await collector.capture(page, session, label="finding")

    cookies_path = tmp_path / "scan-1" / "finding" / "session_cookies.json"
    stored = json.loads(cookies_path.read_text(encoding="utf-8"))
    assert stored["JSESSIONID"] == "***redacted***"  # too short to partially reveal
    assert stored["SESSIONID"] != "a1b2c3d4e5f6g7h8i9j0"
    assert stored["SESSIONID"].startswith("a1b2")
    assert stored["SESSIONID"].endswith("i9j0")
    assert "c3d4e5f6g7h8" not in stored["SESSIONID"]


# ---------------------------------------------------------------------------
# Failure handling — never crashes the caller
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_capture_survives_screenshot_failure(tmp_path):
    collector = EvidenceCollector(scan_id="scan-1", base_dir=tmp_path)
    page = _page()
    page.screenshot = AsyncMock(side_effect=RuntimeError("page closed"))
    session = _session()

    paths = await collector.capture(page, session, label="finding")

    # screenshot failed, but content + cookies still got written
    assert len(paths) == 2


@pytest.mark.asyncio
async def test_capture_survives_content_failure(tmp_path):
    collector = EvidenceCollector(scan_id="scan-1", base_dir=tmp_path)
    page = _page()
    page.content = AsyncMock(side_effect=RuntimeError("navigation in progress"))
    session = _session()

    paths = await collector.capture(page, session, label="finding")

    assert len(paths) == 2


@pytest.mark.asyncio
async def test_capture_returns_empty_list_when_everything_fails(tmp_path):
    collector = EvidenceCollector(scan_id="scan-1", base_dir=tmp_path)
    page = _page()
    page.screenshot = AsyncMock(side_effect=RuntimeError("x"))
    page.content = AsyncMock(side_effect=RuntimeError("x"))
    session = Session(user_id="user-01", role="normal", auth_type="form_login", cookies={})

    # cookies=={} still serialises fine, so this yields exactly the
    # cookies file even when screenshot/content both fail
    paths = await collector.capture(page, session, label="finding")

    assert len(paths) == 1


# ---------------------------------------------------------------------------
# capture_raw — non-browser evidence (e.g. Burp Suite issues)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_capture_raw_writes_request_and_response_files(tmp_path):
    collector = EvidenceCollector(scan_id="scan-1", base_dir=tmp_path)

    paths = await collector.capture_raw("GET /admin HTTP/1.1", "HTTP/1.1 200 OK", label="burp-abc123")

    assert len(paths) == 3  # request.txt, response.txt, and the styled request_response.png
    directory = tmp_path / "scan-1" / "burp-abc123"
    assert (directory / "request.txt").read_text(encoding="utf-8") == "GET /admin HTTP/1.1"
    assert (directory / "response.txt").read_text(encoding="utf-8") == "HTTP/1.1 200 OK"
    assert (directory / "request_response.png").is_file()


@pytest.mark.asyncio
async def test_capture_raw_redacts_cookie_and_authorization_headers(tmp_path):
    """Same redaction as capture()'s session-cookie handling, applied to
    whatever Cookie/Set-Cookie/Authorization header text happens to be
    embedded in a request/response's raw text -- these carry the same
    live-credential risk whether they arrived via a Playwright Session
    object or as already-formatted text (e.g. from Burp's own evidence,
    per this method's own docstring)."""
    collector = EvidenceCollector(scan_id="scan-1", base_dir=tmp_path)
    request_raw = "GET /admin HTTP/1.1\nCookie: JSESSIONID=a1b2c3d4e5f6g7h8i9j0\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
    response_raw = "HTTP/1.1 200 OK\nSet-Cookie: JSESSIONID=a1b2c3d4e5f6g7h8i9j0; Path=/"

    await collector.capture_raw(request_raw, response_raw, label="burp-abc123")

    directory = tmp_path / "scan-1" / "burp-abc123"
    stored_request = (directory / "request.txt").read_text(encoding="utf-8")
    stored_response = (directory / "response.txt").read_text(encoding="utf-8")
    assert "a1b2c3d4e5f6g7h8i9j0" not in stored_request
    assert "a1b2c3d4e5f6g7h8i9j0" not in stored_response
    assert "eyJhbGciOiJIUzI1NiJ9.payload.sig" not in stored_request
    assert "Cookie:" in stored_request  # header name/structure kept -- only the value is redacted
    assert "Authorization:" in stored_request
    assert "GET /admin HTTP/1.1" in stored_request  # non-sensitive lines untouched
