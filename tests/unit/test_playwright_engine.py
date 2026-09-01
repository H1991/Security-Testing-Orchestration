"""Unit tests for Layer 3B — stof.engine.playwright_engine.

The `workflow` dict shape matches exactly what Layer 3A's exporter
already produces, and `session` only needs the `SessionLike` structural
shape (role/cookies/headers) -- see playwright_engine.py's docstring.
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from stof.engine.playwright_engine import PlaywrightEngine


def _fake_page(url: str) -> AsyncMock:
    page = AsyncMock()
    page.url = url
    # page.on() / page.remove_listener() are synchronous in the real
    # Playwright API (event-emitter style, not awaited) -- AsyncMock's
    # default attribute behaviour would make these awaitable, which
    # doesn't match reality and trips "coroutine never awaited" noise.
    page.on = MagicMock()
    page.remove_listener = MagicMock()
    return page


def _fake_pool(page: AsyncMock) -> AsyncMock:
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=page)
    pool = AsyncMock()
    pool.apply_session = AsyncMock(return_value=context)
    return pool


def _session() -> SimpleNamespace:
    return SimpleNamespace(role="admin", cookies={}, headers={})


def _registered_response_callback(page: AsyncMock):
    """Pull out the callback `replay()` registered via `page.on("response", ...)`
    so a test can simulate the browser firing that event."""
    for call in page.on.call_args_list:
        if call.args[0] == "response":
            return call.args[1]
    raise AssertionError("page.on('response', ...) was never registered")


def _fake_document_response(url: str, status: int) -> SimpleNamespace:
    return SimpleNamespace(request=SimpleNamespace(resource_type="document"), url=url, status=status)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_executes_all_actions_and_reports_success():
    page = _fake_page("https://demo.testfire.net/dashboard")
    pool = _fake_pool(page)
    engine = PlaywrightEngine(pool)

    workflow = {
        "workflow_id": "wf-1",
        "target_url": "https://demo.testfire.net",
        "actions": [
            {"type": "navigate", "url": "https://demo.testfire.net/login"},
            {"type": "fill", "selector": "#user", "value": "admin"},
            {"type": "click", "selector": "button[type=submit]"},
            {"type": "wait_for", "selector": ".dashboard", "timeout_ms": 3000},
        ],
    }

    result = await engine.replay(workflow, _session())

    assert result.success is True
    assert result.completed_actions == 4
    assert result.total_actions == 4
    assert result.final_url == "https://demo.testfire.net/dashboard"
    page.goto.assert_awaited_once_with("https://demo.testfire.net/login")
    page.fill.assert_awaited_once_with("#user", "admin")
    page.click.assert_awaited_once_with("button[type=submit]")
    page.wait_for_selector.assert_awaited_once_with(".dashboard", timeout=3000)
    page.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_replay_records_document_response_status_codes():
    page = _fake_page("https://demo.testfire.net/bank/main.jsp")
    pool = _fake_pool(page)
    engine = PlaywrightEngine(pool)

    workflow = {
        "workflow_id": "wf-status",
        "target_url": "https://demo.testfire.net",
        "actions": [{"type": "navigate", "url": "https://demo.testfire.net/login.jsp"}],
    }

    # page.goto is mocked, so it won't fire a real "response" event --
    # simulate the browser doing so, the same way it would mid-navigate.
    async def _goto_and_fire_response(url: str) -> None:
        callback = _registered_response_callback(page)
        callback(_fake_document_response(url, 200))
        # a non-document response (e.g. an image) on the same page must
        # not count toward the tracked navigation status.
        callback(SimpleNamespace(request=SimpleNamespace(resource_type="image"), url=url + "/logo.png", status=404))

    page.goto = AsyncMock(side_effect=_goto_and_fire_response)

    result = await engine.replay(workflow, _session())

    assert result.final_status_code == 200
    assert result.response_log == [{"url": "https://demo.testfire.net/login.jsp", "status": 200}]


# ---------------------------------------------------------------------------
# Failure cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_stops_and_reports_failure_on_action_error():
    page = _fake_page("https://demo.testfire.net/login")
    page.click = AsyncMock(side_effect=RuntimeError("element not found"))
    pool = _fake_pool(page)
    engine = PlaywrightEngine(pool)

    workflow = {
        "workflow_id": "wf-2",
        "target_url": "https://demo.testfire.net",
        "actions": [
            {"type": "navigate", "url": "https://demo.testfire.net/login"},
            {"type": "click", "selector": "#missing"},
            {"type": "click", "selector": "#never-reached"},
        ],
    }

    result = await engine.replay(workflow, _session())

    assert result.success is False
    assert result.completed_actions == 1
    assert result.total_actions == 3
    assert "element not found" in result.error
    page.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_replay_success_true_does_not_imply_app_level_success():
    """Pins down the exact gap that prompted adding final_status_code/
    response_log: a workflow with no assertion step reports success=True
    purely because no Playwright error occurred, even though the app
    (e.g. a login form re-rendering on bad credentials) never reached
    its intended state. Callers that care must add a `wait_for` step."""
    page = _fake_page("https://demo.testfire.net/login.jsp")  # bounced back to login
    pool = _fake_pool(page)
    engine = PlaywrightEngine(pool)

    workflow = {
        "workflow_id": "wf-no-assertion",
        "target_url": "https://demo.testfire.net",
        "actions": [
            {"type": "navigate", "url": "https://demo.testfire.net/login.jsp"},
            {"type": "fill", "selector": "#uid", "value": "jsmith"},
            {"type": "fill", "selector": "#passw", "value": "wrong-password"},
            {"type": "click", "selector": "input[type=submit]"},
            # no wait_for assertion -- this is the gap
        ],
    }

    result = await engine.replay(workflow, _session())

    assert result.success is True  # no Playwright error was thrown
    assert result.final_url == "https://demo.testfire.net/login.jsp"  # ...but login didn't happen


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_reports_failure_for_unknown_action_type():
    page = _fake_page("https://demo.testfire.net")
    pool = _fake_pool(page)
    engine = PlaywrightEngine(pool)

    workflow = {
        "workflow_id": "wf-3",
        "target_url": "https://demo.testfire.net",
        "actions": [{"type": "teleport", "selector": "#x"}],
    }

    result = await engine.replay(workflow, _session())

    assert result.success is False
    assert result.completed_actions == 0
    assert "unknown action type" in result.error.lower()
