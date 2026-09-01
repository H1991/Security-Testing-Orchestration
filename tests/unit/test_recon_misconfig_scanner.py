"""Unit tests for Recon Engine — stof.recon.misconfig_scanner."""
from unittest.mock import AsyncMock

import pytest

from stof.recon.misconfig_scanner import (
    check_missing_security_headers,
    find_error_disclosure,
    probe_error_disclosure,
    scan_exposed_paths,
)

# ---------------------------------------------------------------------------
# check_missing_security_headers
# ---------------------------------------------------------------------------


def test_check_missing_security_headers_flags_all_when_none_present():
    missing = check_missing_security_headers({})
    assert "content-security-policy" in missing
    assert "x-frame-options" in missing
    assert "strict-transport-security" in missing


def test_check_missing_security_headers_none_flagged_when_all_present():
    headers = {
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "strict-transport-security": "max-age=31536000",
        "referrer-policy": "no-referrer",
    }
    assert check_missing_security_headers(headers) == []


def test_check_missing_security_headers_partial():
    headers = {"x-frame-options": "DENY"}
    missing = check_missing_security_headers(headers)
    assert "x-frame-options" not in missing
    assert "content-security-policy" in missing


# ---------------------------------------------------------------------------
# find_error_disclosure
# ---------------------------------------------------------------------------


def test_find_error_disclosure_detects_java_stack_trace():
    body = "Internal error\n\tat com.altoromutual.BankServlet.doPost(BankServlet.java:142)"
    assert "Java stack trace" in find_error_disclosure(body)


def test_find_error_disclosure_detects_python_traceback():
    body = 'Traceback (most recent call last):\n  File "app.py", line 42, in handler'
    assert "Python traceback" in find_error_disclosure(body)


def test_find_error_disclosure_detects_sql_error():
    body = "SQLSTATE[42000]: Syntax error or access violation"
    assert "SQL error (SQLSTATE)" in find_error_disclosure(body)


def test_find_error_disclosure_clean_response_finds_nothing():
    assert find_error_disclosure("<html><body>404 Not Found</body></html>") == []


# ---------------------------------------------------------------------------
# scan_exposed_paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_exposed_paths_flags_only_200_responses():
    context = AsyncMock()

    async def fake_get(url, timeout=None):
        status = 200 if ".git" in url or ".env" in url else 404
        return AsyncMock(status=status)

    context.request.get = AsyncMock(side_effect=fake_get)

    found = await scan_exposed_paths(context, "https://x/")

    urls = {f.url for f in found}
    assert any(".git" in u for u in urls)
    assert any(".env" in u for u in urls)
    assert not any("swagger" in u for u in urls)


@pytest.mark.asyncio
async def test_scan_exposed_paths_continues_past_a_failed_probe():
    context = AsyncMock()

    async def fake_get(url, timeout=None):
        if ".git" in url:
            raise RuntimeError("connection reset")
        return AsyncMock(status=404)

    context.request.get = AsyncMock(side_effect=fake_get)

    found = await scan_exposed_paths(context, "https://x/")  # must not raise

    assert found == []


# ---------------------------------------------------------------------------
# probe_error_disclosure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_probe_error_disclosure_returns_none_when_clean():
    context = AsyncMock()
    response = AsyncMock(status=404)
    response.text = AsyncMock(return_value="<html>Not Found</html>")
    context.request.get = AsyncMock(return_value=response)

    result = await probe_error_disclosure(context, "https://x/missing")

    assert result is None


@pytest.mark.asyncio
async def test_probe_error_disclosure_returns_finding_when_leaky():
    context = AsyncMock()
    response = AsyncMock(status=500)
    response.text = AsyncMock(return_value="Warning: mysql_fetch_array() expects parameter 1")
    context.request.get = AsyncMock(return_value=response)

    result = await probe_error_disclosure(context, "https://x/broken")

    assert result is not None
    assert result.status_code == 500
    assert "PHP MySQL error" in result.leaked


@pytest.mark.asyncio
async def test_probe_error_disclosure_returns_none_on_request_failure():
    context = AsyncMock()
    context.request.get = AsyncMock(side_effect=RuntimeError("timeout"))

    result = await probe_error_disclosure(context, "https://x/broken")

    assert result is None
