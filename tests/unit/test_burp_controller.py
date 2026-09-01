"""Unit tests for Layer 3C — stof.engine.burp_controller.

Mocks the Playwright `APIRequestContext`. The `Location`-header shapes
used below (bare task id, e.g. "4") match what a live Burp Suite
Professional 2021.7.1 instance actually returns -- see the module's
own docstring. A couple of path-style cases are kept to confirm
`_scan_status_url` still handles that shape too.
"""
from unittest.mock import AsyncMock

import pytest

from stof.engine.burp_controller import BurpApiError, BurpController


def _response(status: int, json_body: dict | None = None, text_body: str = "", headers: dict | None = None):
    resp = AsyncMock()
    resp.status = status
    resp.headers = headers or {}
    resp.json = AsyncMock(return_value=json_body or {})
    resp.text = AsyncMock(return_value=text_body)
    return resp


def _controller(request_context, poll_interval_s=0, timeout_s=10) -> BurpController:
    return BurpController(
        request_context, "http://192.168.1.69:1337", "my-api-key",
        poll_interval_s=poll_interval_s, timeout_s=timeout_s,
    )


# ---------------------------------------------------------------------------
# URL construction / auth
# ---------------------------------------------------------------------------


def test_url_embeds_api_key_in_path():
    controller = _controller(AsyncMock())
    assert controller._url("/v0.1/scan") == "http://192.168.1.69:1337/my-api-key/v0.1/scan"


def test_base_url_trailing_slash_is_stripped():
    controller = BurpController(AsyncMock(), "http://192.168.1.69:1337/", "key")
    assert controller._url("/v0.1/scan") == "http://192.168.1.69:1337/key/v0.1/scan"


def test_scan_status_url_from_bare_task_id():
    """Confirmed live shape: Burp's Location header is just the task id."""
    controller = _controller(AsyncMock())
    assert controller._scan_status_url("4") == "http://192.168.1.69:1337/my-api-key/v0.1/scan/4"


def test_scan_status_url_from_path_style_location():
    controller = _controller(AsyncMock())
    assert controller._scan_status_url("/v0.1/scan/1") == "http://192.168.1.69:1337/v0.1/scan/1"


def test_scan_status_url_from_full_url():
    controller = _controller(AsyncMock())
    full_url = "http://192.168.1.69:1337/v0.1/scan/1"
    assert controller._scan_status_url(full_url) == full_url


# ---------------------------------------------------------------------------
# start_scan — happy path / failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_scan_returns_location_header():
    request_context = AsyncMock()
    request_context.post = AsyncMock(return_value=_response(201, headers={"location": "4"}))
    controller = _controller(request_context)

    location = await controller.start_scan(["https://demo.testfire.net"])

    assert location == "4"
    request_context.post.assert_awaited_once()
    call_args = request_context.post.await_args
    assert call_args.args[0] == "http://192.168.1.69:1337/my-api-key/v0.1/scan"
    assert call_args.kwargs["data"]["urls"] == ["https://demo.testfire.net"]


@pytest.mark.asyncio
async def test_start_scan_includes_scope_when_given():
    request_context = AsyncMock()
    request_context.post = AsyncMock(return_value=_response(201, headers={"location": "4"}))
    controller = _controller(request_context)

    await controller.start_scan(["https://x/"], scope_prefixes=["https://x/"])

    payload = request_context.post.await_args.kwargs["data"]
    assert payload["scope"] == {"include": [{"rule": "https://x/"}]}


@pytest.mark.asyncio
async def test_start_scan_raises_on_error_status():
    request_context = AsyncMock()
    request_context.post = AsyncMock(return_value=_response(401, text_body="invalid API key"))
    controller = _controller(request_context)

    with pytest.raises(BurpApiError, match="401"):
        await controller.start_scan(["https://x/"])


@pytest.mark.asyncio
async def test_start_scan_raises_when_location_header_missing():
    request_context = AsyncMock()
    request_context.post = AsyncMock(return_value=_response(201, headers={}))
    controller = _controller(request_context)

    with pytest.raises(BurpApiError, match="Location"):
        await controller.start_scan(["https://x/"])


# ---------------------------------------------------------------------------
# get_scan_status / wait_for_completion
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_scan_status_returns_parsed_json():
    request_context = AsyncMock()
    request_context.get = AsyncMock(return_value=_response(200, json_body={"scan_status": "running"}))
    controller = _controller(request_context)

    status = await controller.get_scan_status("4")

    assert status == {"scan_status": "running"}
    request_context.get.assert_awaited_once_with("http://192.168.1.69:1337/my-api-key/v0.1/scan/4")


@pytest.mark.asyncio
async def test_get_scan_status_raises_on_error_status():
    request_context = AsyncMock()
    request_context.get = AsyncMock(return_value=_response(404, text_body="not found"))
    controller = _controller(request_context)

    with pytest.raises(BurpApiError, match="404"):
        await controller.get_scan_status("4")


@pytest.mark.asyncio
async def test_wait_for_completion_polls_until_succeeded():
    request_context = AsyncMock()
    request_context.get = AsyncMock(side_effect=[
        _response(200, json_body={"scan_status": "running"}),
        _response(200, json_body={"scan_status": "running"}),
        _response(200, json_body={"scan_status": "succeeded", "issue_events": []}),
    ])
    controller = _controller(request_context, poll_interval_s=0)

    result = await controller.wait_for_completion("4")

    assert result["scan_status"] == "succeeded"
    assert request_context.get.await_count == 3


@pytest.mark.asyncio
async def test_wait_for_completion_stops_on_failed_status():
    request_context = AsyncMock()
    request_context.get = AsyncMock(return_value=_response(200, json_body={"scan_status": "failed"}))
    controller = _controller(request_context, poll_interval_s=0)

    result = await controller.wait_for_completion("4")

    assert result["scan_status"] == "failed"


@pytest.mark.asyncio
async def test_wait_for_completion_times_out():
    request_context = AsyncMock()
    request_context.get = AsyncMock(return_value=_response(200, json_body={"scan_status": "running"}))
    controller = _controller(request_context, poll_interval_s=0, timeout_s=0)

    with pytest.raises(TimeoutError, match="did not complete"):
        await controller.wait_for_completion("4")


@pytest.mark.asyncio
async def test_wait_for_completion_allow_partial_returns_last_status_instead_of_raising():
    request_context = AsyncMock()
    request_context.get = AsyncMock(return_value=_response(200, json_body={
        "scan_status": "auditing",
        "issue_events": [{"issue": {"name": "SQL injection", "severity": "high"}}],
    }))
    controller = _controller(request_context, poll_interval_s=1, timeout_s=1)

    result = await controller.wait_for_completion("4", allow_partial=True)

    assert result["scan_status"] == "auditing"
    assert len(result["issue_events"]) == 1


@pytest.mark.asyncio
async def test_run_active_scan_returns_partial_issues_on_timeout():
    """A scan still 'auditing' when the timeout elapses must still
    surface whatever issues Burp had already found, not lose them."""
    request_context = AsyncMock()
    request_context.post = AsyncMock(return_value=_response(201, headers={"location": "4"}))
    request_context.get = AsyncMock(return_value=_response(200, json_body={
        "scan_status": "auditing",
        "issue_events": [{"issue": {"name": "Reflected XSS", "severity": "medium"}}],
    }))
    controller = _controller(request_context, poll_interval_s=1, timeout_s=1)

    issues = await controller.run_active_scan(["https://demo.testfire.net"])

    assert len(issues) == 1
    assert issues[0]["name"] == "Reflected XSS"


# ---------------------------------------------------------------------------
# run_active_scan — end to end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_active_scan_returns_issue_list():
    request_context = AsyncMock()
    request_context.post = AsyncMock(return_value=_response(201, headers={"location": "4"}))
    request_context.get = AsyncMock(return_value=_response(200, json_body={
        "scan_status": "succeeded",
        "issue_events": [
            {"issue": {"name": "SQL injection", "severity": "high"}},
            {"issue": {"name": "Reflected XSS", "severity": "medium"}},
        ],
    }))
    controller = _controller(request_context, poll_interval_s=0)

    issues = await controller.run_active_scan(["https://demo.testfire.net"])

    assert len(issues) == 2
    assert issues[0]["name"] == "SQL injection"


@pytest.mark.asyncio
async def test_run_active_scan_ignores_events_without_issue_key():
    request_context = AsyncMock()
    request_context.post = AsyncMock(return_value=_response(201, headers={"location": "4"}))
    request_context.get = AsyncMock(return_value=_response(200, json_body={
        "scan_status": "succeeded",
        "issue_events": [{"not_issue": {}}, {"issue": {"name": "X", "severity": "low"}}],
    }))
    controller = _controller(request_context, poll_interval_s=0)

    issues = await controller.run_active_scan(["https://x/"])

    assert len(issues) == 1


@pytest.mark.asyncio
async def test_run_active_scan_no_issues_returns_empty_list():
    request_context = AsyncMock()
    request_context.post = AsyncMock(return_value=_response(201, headers={"location": "4"}))
    request_context.get = AsyncMock(return_value=_response(200, json_body={"scan_status": "succeeded", "issue_events": []}))
    controller = _controller(request_context, poll_interval_s=0)

    issues = await controller.run_active_scan(["https://x/"])

    assert issues == []


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_close_disposes_request_context():
    request_context = AsyncMock()
    controller = _controller(request_context)

    await controller.close()

    request_context.dispose.assert_awaited_once()
