"""Unit tests for Layer 3A — stof.recorder.event_handler.

`attach()`/`detach()` need a real Playwright `Page`, so they're exercised
manually against a live Chrome instance rather than here. Everything
else — the browser-event callback, navigation dedup, and network
filtering — is pure Python and fully testable without a browser.
"""
from types import SimpleNamespace

from stof.recorder.event_handler import EventHandler


def _handler_with_fake_page(initial_url: str = "https://demo.testfire.net") -> tuple[EventHandler, SimpleNamespace]:
    handler = EventHandler()
    frame = SimpleNamespace(url=initial_url)
    handler._page = SimpleNamespace(main_frame=frame)
    return handler, frame


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_on_browser_event_records_click():
    handler = EventHandler()

    handler._on_browser_event({}, {"type": "click", "selector": "#submit"})

    assert handler.actions == [{"type": "click", "selector": "#submit"}]


def test_on_browser_event_records_fill_with_field_type():
    handler = EventHandler()

    handler._on_browser_event(
        {}, {"type": "fill", "selector": "#password", "value": "hunter2", "field_type": "password"}
    )

    assert handler.actions == [
        {"type": "fill", "selector": "#password", "value": "hunter2", "field_type": "password"}
    ]


def test_request_captures_xhr_and_fetch_only():
    handler = EventHandler()

    handler._on_request(SimpleNamespace(method="GET", url="https://x/api", resource_type="xhr"))
    handler._on_request(SimpleNamespace(method="POST", url="https://x/graphql", resource_type="fetch"))
    handler._on_request(SimpleNamespace(method="GET", url="https://x/img.png", resource_type="image"))

    assert handler.network_events == [
        {"method": "GET", "url": "https://x/api"},
        {"method": "POST", "url": "https://x/graphql"},
    ]


# ---------------------------------------------------------------------------
# Navigation dedup / filtering
# ---------------------------------------------------------------------------


def test_navigate_dedups_consecutive_identical_urls():
    handler, frame = _handler_with_fake_page("https://demo.testfire.net")
    handler.actions.clear()  # attach() isn't called; clear the implicit initial record

    handler._on_navigated(frame)
    handler._on_navigated(frame)

    assert handler.actions == [{"type": "navigate", "url": "https://demo.testfire.net"}]


def test_navigate_ignores_non_main_frames():
    handler, _frame = _handler_with_fake_page("https://demo.testfire.net")
    ad_frame = SimpleNamespace(url="https://ads.example.com/frame")

    handler._on_navigated(ad_frame)

    assert handler.actions == []


def test_navigate_ignores_blank_url():
    handler = EventHandler()

    handler._record_navigate("about:blank")
    handler._record_navigate("")

    assert handler.actions == []
