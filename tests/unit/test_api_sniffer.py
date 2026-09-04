"""Unit tests for Layer 7 — stof.crawler.api_sniffer."""
from types import SimpleNamespace

from stof.crawler.api_sniffer import ApiSniffer


def _request(
    method: str, url: str, resource_type: str, post_data: str | None = None, content_type: str = ""
) -> SimpleNamespace:
    headers = {"content-type": content_type} if content_type else {}
    return SimpleNamespace(
        method=method, url=url, resource_type=resource_type, post_data=post_data, headers=headers
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_captures_xhr_and_fetch_requests():
    sniffer = ApiSniffer()

    sniffer._on_request(_request("GET", "https://x/api/users?id=1", "xhr"))
    sniffer._on_request(_request("POST", "https://x/api/orders", "fetch"))

    urls = {e.url for e in sniffer.endpoints}
    assert urls == {"https://x/api/users?id=1", "https://x/api/orders"}


def test_extracts_query_parameter_names():
    sniffer = ApiSniffer()

    sniffer._on_request(_request("GET", "https://x/api/search?q=test&page=2", "xhr"))

    assert sniffer.endpoints[0].parameters == ["q", "page"]


def test_extracts_query_parameter_names_with_empty_values():
    """Regression: a search-as-you-type field captured before the user
    types anything (e.g. Juice Shop's own `?q=`) has a real, named
    parameter with an empty value -- `parse_qs`'s default
    (`keep_blank_values=False`) silently dropped it entirely, meaning
    the parameter was never even recorded as existing, let alone
    tested by an injection module."""
    sniffer = ApiSniffer()

    sniffer._on_request(_request("GET", "https://x/rest/products/search?q=", "xhr"))

    assert sniffer.endpoints[0].parameters == ["q"]


def test_extracts_form_urlencoded_body_parameter_names():
    """Regression: the previous version only ever looked at the query
    string, so a real POST's actual parameters (in the body) were
    silently dropped -- exactly the gap that prompted this fix."""
    sniffer = ApiSniffer()

    sniffer._on_request(
        _request(
            "POST", "https://x/doLogin", "document",
            post_data="uid=admin&passw=hunter2", content_type="application/x-www-form-urlencoded",
        )
    )

    assert sniffer.endpoints[0].parameters == ["uid", "passw"]


def test_extracts_json_body_parameter_names():
    sniffer = ApiSniffer()

    sniffer._on_request(
        _request(
            "POST", "https://x/api/orders", "fetch",
            post_data='{"item": "widget", "quantity": 3}', content_type="application/json",
        )
    )

    assert sniffer.endpoints[0].parameters == ["item", "quantity"]


def test_merges_query_and_body_parameters():
    sniffer = ApiSniffer()

    sniffer._on_request(
        _request(
            "POST", "https://x/api/orders?source=web", "fetch",
            post_data="item=widget", content_type="application/x-www-form-urlencoded",
        )
    )

    assert sniffer.endpoints[0].parameters == ["source", "item"]


# ---------------------------------------------------------------------------
# param_locations — query vs. body tagging
# ---------------------------------------------------------------------------


def test_tags_query_parameter_location():
    sniffer = ApiSniffer()

    sniffer._on_request(_request("GET", "https://x/api/search?q=test", "xhr"))

    assert sniffer.endpoints[0].param_locations == {"q": "query"}


def test_tags_body_parameter_location():
    sniffer = ApiSniffer()

    sniffer._on_request(
        _request(
            "POST", "https://x/doLogin", "document",
            post_data="uid=admin&passw=hunter2", content_type="application/x-www-form-urlencoded",
        )
    )

    assert sniffer.endpoints[0].param_locations == {"uid": "body", "passw": "body"}


def test_tags_mixed_query_and_body_locations():
    sniffer = ApiSniffer()

    sniffer._on_request(
        _request(
            "POST", "https://x/api/orders?source=web", "fetch",
            post_data="item=widget", content_type="application/x-www-form-urlencoded",
        )
    )

    assert sniffer.endpoints[0].param_locations == {"source": "query", "item": "body"}


def test_merging_two_requests_unions_param_locations():
    sniffer = ApiSniffer()

    sniffer._on_request(_request("GET", "https://x/api/users?id=1", "xhr"))
    sniffer._on_request(_request("GET", "https://x/api/users?name=admin", "xhr"))

    assert sniffer.endpoints[0].param_locations == {"id": "query", "name": "query"}


def test_captures_post_document_navigations_not_just_xhr_fetch():
    """A real full-page form submission (not an XHR/fetch call) is a
    resource_type of "document", which used to be filtered out
    entirely for any POST."""
    sniffer = ApiSniffer()

    sniffer._on_request(
        _request("POST", "https://x/doTransfer", "document", post_data="fromAccount=1&toAccount=2")
    )

    assert len(sniffer.endpoints) == 1
    assert sniffer.endpoints[0].parameters == ["fromAccount", "toAccount"]


def test_get_document_navigations_still_ignored():
    """Only POST/PUT/PATCH document requests are captured -- a plain GET
    page load is not an "endpoint" in the api_sniffer sense (that's
    crawler.py's job to record as a page)."""
    sniffer = ApiSniffer()

    sniffer._on_request(_request("GET", "https://x/some-page", "document"))

    assert sniffer.endpoints == []


# ---------------------------------------------------------------------------
# Filtering — non-XHR/fetch requests are ignored
# ---------------------------------------------------------------------------


def test_ignores_non_xhr_fetch_resource_types():
    sniffer = ApiSniffer()

    sniffer._on_request(_request("GET", "https://x/logo.png", "image"))
    sniffer._on_request(_request("GET", "https://x/app.js", "script"))
    sniffer._on_request(_request("GET", "https://x/", "document"))

    assert sniffer.endpoints == []


# ---------------------------------------------------------------------------
# Dedup by (method, path) — query strings on the same path merge
# ---------------------------------------------------------------------------


def test_dedupes_by_method_and_path_merging_parameters():
    sniffer = ApiSniffer()

    sniffer._on_request(_request("GET", "https://x/api/users?id=1", "xhr"))
    sniffer._on_request(_request("GET", "https://x/api/users?name=admin", "xhr"))

    assert len(sniffer.endpoints) == 1
    assert sniffer.endpoints[0].parameters == ["id", "name"]


def test_same_path_different_method_stays_separate():
    sniffer = ApiSniffer()

    sniffer._on_request(_request("GET", "https://x/api/users", "xhr"))
    sniffer._on_request(_request("DELETE", "https://x/api/users", "fetch"))

    assert len(sniffer.endpoints) == 2


# ---------------------------------------------------------------------------
# attach/detach wiring
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# origin_url filtering -- third-party embeds must never become endpoints
# ---------------------------------------------------------------------------


def test_ignores_cross_origin_requests_when_origin_url_given():
    """Confirmed live: crawling a real target with an embedded GitHub
    star-button widget captured XHR calls to github.com and
    collector.github.com as if they were the target's own API
    endpoints. Vulnerability modules and Burp's Active Scan both treat
    everything captured as fair game to send test/attack traffic to --
    a third-party origin must never end up in that list."""
    sniffer = ApiSniffer(origin_url="https://x/")

    sniffer._on_request(_request("GET", "https://x/api/orders", "xhr"))
    sniffer._on_request(_request("GET", "https://github.com/some/api", "xhr"))
    sniffer._on_request(_request("POST", "https://collector.github.com/collect", "fetch"))

    urls = {e.url for e in sniffer.endpoints}
    assert urls == {"https://x/api/orders"}


def test_allows_all_origins_when_origin_url_not_given():
    """Default (no origin_url) preserves the old unfiltered behavior for
    any caller that already scopes its own input."""
    sniffer = ApiSniffer()

    sniffer._on_request(_request("GET", "https://x/api/orders", "xhr"))
    sniffer._on_request(_request("GET", "https://other.example/api", "xhr"))

    urls = {e.url for e in sniffer.endpoints}
    assert urls == {"https://x/api/orders", "https://other.example/api"}


def test_attach_and_detach_register_and_remove_listener():
    sniffer = ApiSniffer()
    calls = []
    page = SimpleNamespace(
        on=lambda event, handler: calls.append(("on", event, handler)),
        remove_listener=lambda event, handler: calls.append(("off", event, handler)),
    )

    sniffer.attach(page)
    sniffer.detach(page)

    assert calls == [("on", "request", sniffer._on_request), ("off", "request", sniffer._on_request)]
