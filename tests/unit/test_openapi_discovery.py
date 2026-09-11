"""Unit tests for Layer 7 -- stof.crawler.openapi_discovery."""
import pytest

from stof.crawler.openapi_discovery import (
    _extract_param_names,
    _parse_spec_text,
    _spec_base_path,
    discover_openapi_endpoints,
    parse_openapi_spec,
)

# ---------------------------------------------------------------------------
# _parse_spec_text -- pure
# ---------------------------------------------------------------------------


def test_parse_spec_text_accepts_valid_openapi_v3_json():
    text = '{"openapi": "3.0.0", "paths": {"/users": {}}}'
    doc = _parse_spec_text(text)
    assert doc is not None
    assert doc["paths"] == {"/users": {}}


def test_parse_spec_text_accepts_valid_swagger_v2_yaml():
    text = "swagger: '2.0'\npaths:\n  /users:\n    get: {}\n"
    doc = _parse_spec_text(text)
    assert doc is not None
    assert "get" in doc["paths"]["/users"]


def test_parse_spec_text_rejects_json_without_paths_key():
    """A real, valid JSON response body that just isn't an OpenAPI
    spec -- must not be misclassified as one just because it parses."""
    assert _parse_spec_text('{"status": "ok", "version": "1.2.3"}') is None


def test_parse_spec_text_rejects_a_paths_key_with_no_version_field():
    """`paths` alone isn't enough -- some unrelated API could coincidentally
    have a top-level "paths" key. Requiring `swagger`/`openapi` too is
    what actually distinguishes a real spec."""
    assert _parse_spec_text('{"paths": {"/a": {}}}') is None


def test_parse_spec_text_rejects_malformed_input():
    assert _parse_spec_text("not json and not : valid : yaml : [") is None


def test_parse_spec_text_rejects_a_yaml_scalar_not_a_mapping():
    assert _parse_spec_text("just a plain string") is None


# ---------------------------------------------------------------------------
# _spec_base_path -- pure
# ---------------------------------------------------------------------------


def test_spec_base_path_uses_swagger_v2_base_path():
    assert _spec_base_path({"basePath": "/api/v1"}) == "/api/v1"


def test_spec_base_path_uses_openapi_v3_servers_url_path_only():
    assert _spec_base_path({"servers": [{"url": "https://api.example.com/v2"}]}) == "/v2"


def test_spec_base_path_defaults_to_root():
    assert _spec_base_path({}) == "/"


# ---------------------------------------------------------------------------
# _extract_param_names -- pure
# ---------------------------------------------------------------------------


def test_extract_param_names_keeps_query_path_and_header_only():
    operation = {
        "parameters": [
            {"name": "id", "in": "path"},
            {"name": "limit", "in": "query"},
            {"name": "X-Api-Key", "in": "header"},
            {"name": "session", "in": "cookie"},  # not extracted -- see module docstring's stated scope
        ]
    }
    assert _extract_param_names(operation) == ["id", "limit", "X-Api-Key"]


def test_extract_param_names_empty_when_none_declared():
    assert _extract_param_names({}) == []


# ---------------------------------------------------------------------------
# parse_openapi_spec -- pure, the real end-to-end transform
# ---------------------------------------------------------------------------


def test_parse_openapi_spec_builds_endpoints_for_every_method():
    doc = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.com/v1"}],
        "paths": {
            "/users": {
                "get": {"parameters": [{"name": "limit", "in": "query"}]},
                "post": {"requestBody": {}},
            },
            "/users/{id}": {
                "get": {"parameters": [{"name": "id", "in": "path"}]},
                "delete": {},
            },
        },
    }
    endpoints = parse_openapi_spec(doc, spec_url="https://api.example.com/openapi.json")
    urls_methods = sorted((e.url, e.method) for e in endpoints)
    assert urls_methods == [
        ("https://api.example.com/v1/users", "GET"),
        ("https://api.example.com/v1/users", "POST"),
        ("https://api.example.com/v1/users/{id}", "DELETE"),
        ("https://api.example.com/v1/users/{id}", "GET"),
    ]
    get_users = next(e for e in endpoints if e.url.endswith("/users") and e.method == "GET")
    assert get_users.parameters == ["limit"]
    assert get_users.endpoint_type == "api"


def test_parse_openapi_spec_marks_auth_required_from_operation_security():
    doc = {"openapi": "3.0.0", "paths": {"/private": {"get": {"security": [{"bearerAuth": []}]}}}}
    endpoints = parse_openapi_spec(doc, spec_url="https://api.example.com/openapi.json")
    assert endpoints[0].auth_required is True


def test_parse_openapi_spec_falls_back_to_document_level_security():
    doc = {"openapi": "3.0.0", "security": [{"bearerAuth": []}], "paths": {"/private": {"get": {}}}}
    endpoints = parse_openapi_spec(doc, spec_url="https://api.example.com/openapi.json")
    assert endpoints[0].auth_required is True


def test_parse_openapi_spec_ignores_non_path_keys_and_non_dict_operations():
    doc = {"openapi": "3.0.0", "paths": {"/ok": {"get": {}}, "not-a-path": {"get": {}}, "/bad": "not a dict"}}
    endpoints = parse_openapi_spec(doc, spec_url="https://api.example.com/openapi.json")
    assert [e.url for e in endpoints] == ["https://api.example.com/ok"]


# ---------------------------------------------------------------------------
# discover_openapi_endpoints -- fetch orchestration, fake HTTP context
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status: int, body: str):
        self.status = status
        self._body = body

    async def text(self):
        return self._body


class _FakeContext:
    """`context.request.get(url, ...)` -- the one surface this module
    talks to, matching Playwright's real `APIRequestContext` shape
    closely enough for these tests. `responses` maps an exact URL to a
    `_FakeResponse`; any URL not in the map 404s, the same as a real
    server would for every path this module tries that doesn't exist."""

    def __init__(self, responses: dict[str, _FakeResponse]):
        self._responses = responses
        self.request = self

    async def get(self, url: str, **kwargs):
        return self._responses.get(url, _FakeResponse(404, ""))


@pytest.mark.asyncio
async def test_discover_finds_a_spec_at_the_first_direct_path_checked():
    spec = '{"openapi": "3.0.0", "paths": {"/users": {"get": {}}}}'
    context = _FakeContext({"https://x.example/openapi.json": _FakeResponse(200, spec)})
    endpoints = await discover_openapi_endpoints(context, "https://x.example")
    assert len(endpoints) == 1
    assert endpoints[0].url == "https://x.example/users"


@pytest.mark.asyncio
async def test_discover_returns_empty_list_when_nothing_is_published():
    context = _FakeContext({})
    assert await discover_openapi_endpoints(context, "https://x.example") == []


@pytest.mark.asyncio
async def test_discover_falls_back_to_a_swagger_ui_pages_embedded_spec_url():
    ui_html = '<script>window.ui = SwaggerUIBundle({url: "/custom/my-api-spec.json", ...})</script>'
    spec = '{"swagger": "2.0", "paths": {"/ping": {"get": {}}}}'
    context = _FakeContext({
        "https://x.example/swagger-ui.html": _FakeResponse(200, ui_html),
        "https://x.example/custom/my-api-spec.json": _FakeResponse(200, spec),
    })
    endpoints = await discover_openapi_endpoints(context, "https://x.example")
    assert len(endpoints) == 1
    assert endpoints[0].url == "https://x.example/ping"


@pytest.mark.asyncio
async def test_discover_ignores_a_swagger_ui_page_with_no_recognizable_spec_reference():
    context = _FakeContext({"https://x.example/swagger-ui.html": _FakeResponse(200, "<html>nothing useful here</html>")})
    assert await discover_openapi_endpoints(context, "https://x.example") == []


@pytest.mark.asyncio
async def test_discover_does_not_misclassify_an_unrelated_200_response_as_a_spec():
    context = _FakeContext({"https://x.example/openapi.json": _FakeResponse(200, '{"error": "not found"}')})
    assert await discover_openapi_endpoints(context, "https://x.example") == []


@pytest.mark.asyncio
async def test_discover_survives_a_connection_error_on_an_individual_probe():
    class _ExplodingContext:
        request = None

        def __init__(self):
            self.request = self

        async def get(self, url, **kwargs):
            raise RuntimeError("connection reset")

    endpoints = await discover_openapi_endpoints(_ExplodingContext(), "https://x.example")
    assert endpoints == []
