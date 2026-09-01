"""Unit tests for Layer 7 — stof.crawler.form_detector."""
from unittest.mock import AsyncMock

import pytest

from stof.crawler.form_detector import detect_forms


def _page(url: str, forms: list[dict]) -> AsyncMock:
    page = AsyncMock()
    page.url = url
    page.evaluate = AsyncMock(return_value=forms)
    return page


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detect_forms_extracts_method_and_input_names():
    page = _page(
        "https://demo.testfire.net/login.jsp",
        [
            {
                "action": "doLogin",
                "method": "POST",
                "inputs": [
                    {"name": "uid", "type": "text"},
                    {"name": "passw", "type": "password"},
                ],
            }
        ],
    )

    endpoints = await detect_forms(page)

    assert len(endpoints) == 1
    assert endpoints[0].url == "https://demo.testfire.net/doLogin"
    assert endpoints[0].method == "POST"
    assert endpoints[0].endpoint_type == "form"
    assert endpoints[0].parameters == ["uid", "passw"]


@pytest.mark.asyncio
async def test_detect_forms_returns_empty_list_for_no_forms():
    page = _page("https://demo.testfire.net/", [])

    endpoints = await detect_forms(page)

    assert endpoints == []


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detect_forms_defaults_missing_action_to_current_page_url():
    page = _page(
        "https://demo.testfire.net/search.jsp",
        [{"action": "", "method": "GET", "inputs": [{"name": "q", "type": "text"}]}],
    )

    endpoints = await detect_forms(page)

    assert endpoints[0].url == "https://demo.testfire.net/search.jsp"


@pytest.mark.asyncio
async def test_detect_forms_ignores_inputs_with_no_name():
    page = _page(
        "https://demo.testfire.net/",
        [
            {
                "action": "submit",
                "method": "POST",
                "inputs": [{"name": "", "type": "submit"}, {"name": "csrf_token", "type": "hidden"}],
            }
        ],
    )

    endpoints = await detect_forms(page)

    assert endpoints[0].parameters == ["csrf_token"]


@pytest.mark.asyncio
async def test_detect_forms_defaults_missing_method_to_get():
    page = _page("https://demo.testfire.net/", [{"action": "x", "inputs": []}])

    endpoints = await detect_forms(page)

    assert endpoints[0].method == "GET"


# ---------------------------------------------------------------------------
# param_locations — POST forms tag "body", GET forms tag "query"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detect_forms_tags_post_form_params_as_body():
    page = _page(
        "https://demo.testfire.net/login.jsp",
        [
            {
                "action": "doLogin",
                "method": "POST",
                "inputs": [
                    {"name": "uid", "type": "text"},
                    {"name": "passw", "type": "password"},
                ],
            }
        ],
    )

    endpoints = await detect_forms(page)

    assert endpoints[0].param_locations == {"uid": "body", "passw": "body"}


@pytest.mark.asyncio
async def test_detect_forms_tags_get_form_params_as_query():
    page = _page(
        "https://demo.testfire.net/search.jsp",
        [{"action": "search", "method": "GET", "inputs": [{"name": "q", "type": "text"}]}],
    )

    endpoints = await detect_forms(page)

    assert endpoints[0].param_locations == {"q": "query"}


@pytest.mark.asyncio
async def test_detect_forms_skips_javascript_action_urls():
    """Regression: live-verified against a real target -- a
    `<form action="javascript:checkSiteStatus('AltoroMutual')">` was
    getting recorded as a "form endpoint" even though there's no real
    HTTP request behind it at all."""
    page = _page(
        "https://demo.testfire.net/",
        [
            {"action": "javascript:checkSiteStatus('AltoroMutual')", "method": "GET", "inputs": []},
            {"action": "doLogin", "method": "POST", "inputs": [{"name": "uid", "type": "text"}]},
        ],
    )

    endpoints = await detect_forms(page)

    assert len(endpoints) == 1
    assert endpoints[0].url == "https://demo.testfire.net/doLogin"


@pytest.mark.asyncio
async def test_detect_forms_skips_mailto_and_tel_action_urls():
    page = _page(
        "https://demo.testfire.net/",
        [
            {"action": "mailto:support@demo.testfire.net", "method": "GET", "inputs": []},
            {"action": "tel:+15555550100", "method": "GET", "inputs": []},
        ],
    )

    endpoints = await detect_forms(page)

    assert endpoints == []
