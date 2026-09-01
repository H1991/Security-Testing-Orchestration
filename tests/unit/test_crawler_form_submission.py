"""Unit tests for Layer 7's active form-submission probe
(stof.crawler.crawler.CrawlerConfig.submit_forms_with_test_data).

This is a deliberate, explicitly-requested deviation from CLAUDE.md's
"passive discovery only" rule -- see crawler.py's module docstring. On
by default (also at explicit user instruction); these tests cover both
the placeholder-data generation, the actual fill/submit mechanics, and
that the crawl loop respects an explicit opt-out.
"""
from __future__ import annotations

import re

import pytest
from test_crawler import FakeContext

import stof.crawler.crawler as crawler_module
from stof.crawler.crawler import CrawlerConfig, crawl

# ---------------------------------------------------------------------------
# _test_value_for -- pure function
# ---------------------------------------------------------------------------


def test_test_value_for_email_field():
    value = crawler_module._test_value_for("email", "user_email")
    assert value.startswith("stof-test-")
    assert value.endswith("@example.com")


def test_test_value_for_password_field():
    value = crawler_module._test_value_for("password", "passw")
    assert value.startswith("StofTest-")


def test_test_value_for_amount_like_field_is_a_small_number():
    assert crawler_module._test_value_for("text", "transferAmount") == "1"
    assert crawler_module._test_value_for("number", "qty") == "1"


def test_test_value_for_date_like_field_name_gets_a_date_not_a_tag():
    """Regression: startDate/endDate on this project's demo target are
    plain text inputs (type="text"), not type="date", but still have
    client-side date-format validation that a generic tagged string
    fails -- name-based detection is needed, not just the type attr."""
    value = crawler_module._test_value_for("text", "startDate")
    assert not value.startswith("stof-test-")


def test_test_value_for_unrecognised_field_is_tagged():
    value = crawler_module._test_value_for("text", "comments")
    assert value.startswith("stof-test-")


def test_test_value_for_is_randomised_between_calls():
    a = crawler_module._test_value_for("text", "notes")
    b = crawler_module._test_value_for("text", "notes")
    assert a != b


# ---------------------------------------------------------------------------
# _submit_form_with_test_data -- fill/submit mechanics
# ---------------------------------------------------------------------------


class _FakeFieldLocator:
    def __init__(self, page: "FakeProbePage", name: str):
        self._page = page
        self._name = name

    @property
    def first(self) -> "_FakeFieldLocator":
        return self

    async def fill(self, value: str, timeout: int | None = None) -> None:
        self._page.filled[self._name] = value

    async def check(self, timeout: int | None = None) -> None:
        self._page.checked.add(self._name)

    async def select_option(self, index: int | None = None, timeout: int | None = None) -> None:
        self._page.selected[self._name] = index


class _FakeDialog:
    def __init__(self, message: str):
        self.message = message
        self.dismissed = False

    async def dismiss(self) -> None:
        self.dismissed = True


class _FakeFormLocator:
    def __init__(self, page: "FakeProbePage"):
        self._page = page

    def nth(self, index: int) -> "_FakeFormLocator":
        return self

    def locator(self, selector: str) -> _FakeFieldLocator:
        match = re.search(r'name="([^"]+)"', selector)
        name = match.group(1) if match else selector
        return _FakeFieldLocator(self._page, name)

    async def evaluate(self, script: str) -> None:
        # Simulate client-side validation (onsubmit handler) popping a
        # blocking dialog, the way this project's own demo target's
        # transfer form does when From/To accounts match.
        if self._page.dialog_message_to_fire is not None:
            dialog = _FakeDialog(self._page.dialog_message_to_fire)
            for handler in list(self._page._dialog_handlers):
                await handler(dialog)
            self._page.fired_dialog = dialog
        self._page.submitted = True


class FakeProbePage:
    def __init__(self, forms_by_url: dict[str, list[dict]], dialog_message_to_fire: str | None = None):
        self._forms_by_url = forms_by_url
        self.dialog_message_to_fire = dialog_message_to_fire
        self.fired_dialog: _FakeDialog | None = None
        self._dialog_handlers: list = []
        self.url = ""
        self.goto_calls: list[str] = []
        self.filled: dict[str, str] = {}
        self.checked: set[str] = set()
        self.selected: dict[str, int | None] = {}
        self.submitted = False

    async def goto(self, url: str, timeout: int | None = None) -> None:
        self.goto_calls.append(url)
        self.url = url

    async def evaluate(self, script: str, arg: int | None = None):
        forms = self._forms_by_url.get(self.url, [])
        if arg is None or arg >= len(forms):
            return None
        return forms[arg]

    def locator(self, selector: str) -> _FakeFormLocator:
        return _FakeFormLocator(self)

    def on(self, event: str, handler) -> None:
        if event == "dialog":
            self._dialog_handlers.append(handler)

    def remove_listener(self, event: str, handler) -> None:
        if event == "dialog" and handler in self._dialog_handlers:
            self._dialog_handlers.remove(handler)

    async def wait_for_load_state(self, state: str, timeout: int | None = None) -> None:
        pass


@pytest.mark.asyncio
async def test_submit_form_fills_visible_fields_and_submits():
    page = FakeProbePage(
        {"https://x/login": [{"fields": [{"name": "uid", "type": "text"}, {"name": "passw", "type": "password"}]}]}
    )

    await crawler_module._submit_form_with_test_data(page, "https://x/login", 0, 5000)

    assert page.goto_calls == ["https://x/login"]
    assert "uid" in page.filled
    assert page.filled["passw"].startswith("StofTest-")
    assert page.submitted is True


@pytest.mark.asyncio
async def test_submit_form_uses_select_option_not_fill_for_dropdowns():
    """.fill() doesn't work on <select> in Playwright -- a bank transfer
    form's fromAccount/toAccount are very likely dropdowns, not text
    inputs, so this matters for real."""
    page = FakeProbePage(
        {"https://x/transfer": [{"fields": [{"name": "fromAccount", "type": "select"}, {"name": "amount", "type": "number"}]}]}
    )

    await crawler_module._submit_form_with_test_data(page, "https://x/transfer", 0, 5000)

    assert page.selected.get("fromAccount") == 0
    assert "fromAccount" not in page.filled
    assert page.filled.get("amount") == "1"


@pytest.mark.asyncio
async def test_submit_form_varies_indices_across_multiple_selects_in_one_form():
    """Regression: this project's own demo target has a transfer form
    with two <select>s (fromAccount/toAccount) that both defaulted to
    index 0, tripping the site's own "From/To account can't match"
    client-side validation and silently blocking every submission."""
    page = FakeProbePage(
        {
            "https://x/transfer": [
                {
                    "fields": [
                        {"name": "fromAccount", "type": "select", "optionCount": 3},
                        {"name": "toAccount", "type": "select", "optionCount": 3},
                    ]
                }
            ]
        }
    )

    await crawler_module._submit_form_with_test_data(page, "https://x/transfer", 0, 5000)

    assert page.selected["fromAccount"] != page.selected["toAccount"]


@pytest.mark.asyncio
async def test_submit_form_wraps_select_index_when_only_one_option_available():
    page = FakeProbePage(
        {
            "https://x/f": [
                {
                    "fields": [
                        {"name": "a", "type": "select", "optionCount": 1},
                        {"name": "b", "type": "select", "optionCount": 1},
                    ]
                }
            ]
        }
    )

    await crawler_module._submit_form_with_test_data(page, "https://x/f", 0, 5000)

    assert page.selected["a"] == 0
    assert page.selected["b"] == 0  # only one option exists -- can't help colliding


@pytest.mark.asyncio
async def test_submit_form_dismisses_blocking_validation_dialogs():
    page = FakeProbePage(
        {"https://x/transfer": [{"fields": [{"name": "fromAccount", "type": "select", "optionCount": 1}]}]},
        dialog_message_to_fire="From Account and To Account fields cannot be the same.",
    )

    await crawler_module._submit_form_with_test_data(page, "https://x/transfer", 0, 5000)

    assert page.fired_dialog is not None
    assert page.fired_dialog.dismissed is True


@pytest.mark.asyncio
async def test_submit_form_skips_hidden_and_submit_type_fields():
    page = FakeProbePage(
        {
            "https://x/f": [
                {
                    "fields": [
                        {"name": "csrf_token", "type": "hidden"},
                        {"name": "go", "type": "submit"},
                        {"name": "real_field", "type": "text"},
                    ]
                }
            ]
        }
    )

    await crawler_module._submit_form_with_test_data(page, "https://x/f", 0, 5000)

    assert "csrf_token" not in page.filled
    assert "go" not in page.filled
    assert "real_field" in page.filled


@pytest.mark.asyncio
async def test_submit_form_checks_checkboxes_and_radios():
    page = FakeProbePage({"https://x/f": [{"fields": [{"name": "agree", "type": "checkbox"}]}]})

    await crawler_module._submit_form_with_test_data(page, "https://x/f", 0, 5000)

    assert "agree" in page.checked


@pytest.mark.asyncio
async def test_submit_form_missing_index_is_a_harmless_noop():
    page = FakeProbePage({"https://x/f": []})

    await crawler_module._submit_form_with_test_data(page, "https://x/f", 0, 5000)

    assert page.submitted is False


# ---------------------------------------------------------------------------
# crawl() wiring — opt-in, dedup, POST-only
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_submits_forms_by_default(monkeypatch):
    calls: list[tuple[str, int]] = []

    async def fake_submit(probe_page, page_url, form_index, timeout_ms):
        calls.append((page_url, form_index))

    monkeypatch.setattr(crawler_module, "_submit_form_with_test_data", fake_submit)
    site = {"https://x/": {"links": [], "forms": [{"action": "doLogin", "method": "POST", "inputs": [{"name": "u"}]}]}}

    await crawl("https://x/", FakeContext(site))  # default config: submit_forms_with_test_data=True

    assert calls == [("https://x/", 0)]


@pytest.mark.asyncio
async def test_crawl_does_not_submit_forms_when_explicitly_disabled(monkeypatch):
    calls: list[tuple[str, int]] = []

    async def fake_submit(probe_page, page_url, form_index, timeout_ms):
        calls.append((page_url, form_index))

    monkeypatch.setattr(crawler_module, "_submit_form_with_test_data", fake_submit)
    site = {"https://x/": {"links": [], "forms": [{"action": "doLogin", "method": "POST", "inputs": [{"name": "u"}]}]}}

    await crawl("https://x/", FakeContext(site), CrawlerConfig(submit_forms_with_test_data=False))

    assert calls == []


@pytest.mark.asyncio
async def test_crawl_submits_only_post_forms_when_enabled(monkeypatch):
    calls: list[tuple[str, int]] = []

    async def fake_submit(probe_page, page_url, form_index, timeout_ms):
        calls.append((page_url, form_index))

    monkeypatch.setattr(crawler_module, "_submit_form_with_test_data", fake_submit)
    site = {
        "https://x/": {
            "links": [],
            "forms": [
                {"action": "search", "method": "GET", "inputs": [{"name": "q"}]},
                {"action": "doLogin", "method": "POST", "inputs": [{"name": "u"}]},
            ],
        }
    }

    await crawl("https://x/", FakeContext(site), CrawlerConfig(submit_forms_with_test_data=True))

    assert calls == [("https://x/", 1)]  # only the POST form (index 1)


@pytest.mark.asyncio
async def test_crawl_does_not_resubmit_the_same_form_seen_on_multiple_pages(monkeypatch):
    calls: list[str] = []

    async def fake_submit(probe_page, page_url, form_index, timeout_ms):
        calls.append(page_url)

    monkeypatch.setattr(crawler_module, "_submit_form_with_test_data", fake_submit)
    login_form = {"action": "doLogin", "method": "POST", "inputs": [{"name": "u"}]}
    site = {
        "https://x/": {"links": ["/other"], "forms": [login_form]},
        "https://x/other": {"links": [], "forms": [login_form]},
    }

    await crawl("https://x/", FakeContext(site), CrawlerConfig(submit_forms_with_test_data=True))

    assert len(calls) == 1
