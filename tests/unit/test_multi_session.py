"""Unit tests for Layer 3B — stof.engine.multi_session."""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from stof.engine.multi_session import SessionPool, _to_playwright_cookies


# ---------------------------------------------------------------------------
# Pure helper
# ---------------------------------------------------------------------------


def test_to_playwright_cookies_derives_domain_from_url():
    cookies = _to_playwright_cookies({"JSESSIONID": "abc123"}, "https://demo.testfire.net/bank")

    assert cookies == [
        {"name": "JSESSIONID", "value": "abc123", "domain": "demo.testfire.net", "path": "/"}
    ]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_context_creates_and_reuses_per_role():
    browser = AsyncMock()
    context_admin = AsyncMock()
    context_user = AsyncMock()
    browser.new_context = AsyncMock(side_effect=[context_admin, context_user])
    pool = SessionPool(browser)

    ctx1 = await pool.get_context("admin")
    ctx2 = await pool.get_context("admin")
    ctx3 = await pool.get_context("normal")

    assert ctx1 is ctx2 is context_admin
    assert ctx3 is context_user
    assert browser.new_context.await_count == 2


@pytest.mark.asyncio
async def test_ignore_https_errors_defaults_off_but_is_forwarded_when_set():
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=AsyncMock())
    default_pool = SessionPool(browser)
    await default_pool.get_context("admin")
    assert browser.new_context.await_args.kwargs["ignore_https_errors"] is False

    browser2 = AsyncMock()
    browser2.new_context = AsyncMock(return_value=AsyncMock())
    lenient_pool = SessionPool(browser2, ignore_https_errors=True)
    await lenient_pool.get_context("admin")
    assert browser2.new_context.await_args.kwargs["ignore_https_errors"] is True


@pytest.mark.asyncio
async def test_apply_session_sets_cookies_and_headers():
    browser = AsyncMock()
    context = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    pool = SessionPool(browser)
    session = SimpleNamespace(
        role="admin", cookies={"JSESSIONID": "abc"}, headers={"Authorization": "Bearer xyz"}
    )

    await pool.apply_session(session, "https://demo.testfire.net/bank")

    context.add_cookies.assert_awaited_once_with(
        [{"name": "JSESSIONID", "value": "abc", "domain": "demo.testfire.net", "path": "/"}]
    )
    context.set_extra_http_headers.assert_awaited_once_with({"Authorization": "Bearer xyz"})


# ---------------------------------------------------------------------------
# Cleanup / failure recovery
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_close_all_closes_every_context_and_clears_pool():
    browser = AsyncMock()
    ctx1, ctx2 = AsyncMock(), AsyncMock()
    browser.new_context = AsyncMock(side_effect=[ctx1, ctx2])
    pool = SessionPool(browser)
    await pool.get_context("admin")
    await pool.get_context("normal")

    await pool.close_all()

    ctx1.close.assert_awaited_once()
    ctx2.close.assert_awaited_once()

    # pool is empty again -- a fresh context is created for a role reused after close_all
    browser.new_context = AsyncMock(return_value=AsyncMock())
    await pool.get_context("admin")
    browser.new_context.assert_awaited_once()


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_apply_session_skips_cookie_and_header_calls_when_empty():
    browser = AsyncMock()
    context = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    pool = SessionPool(browser)
    session = SimpleNamespace(role="anon", cookies={}, headers={})

    await pool.apply_session(session, "https://demo.testfire.net")

    context.add_cookies.assert_not_awaited()
    context.set_extra_http_headers.assert_not_awaited()
