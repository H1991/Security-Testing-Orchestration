"""Layer 7 — OpenAPI/Swagger spec discovery and ingestion.

Real gap this closes: the crawler already flags an exposed
`/swagger.json`/`swagger-ui.html` as a disclosure FINDING
(`stof/recon/misconfig_scanner.py`) but never reads what's actually
inside one to find more endpoints -- for an API target that publishes
its own spec, that's a complete, guaranteed-accurate list of every
endpoint, method, and parameter sitting right there, unused. This
module reads it and hands the result back as ordinary `Endpoint`
objects, merged into whatever the browsing crawler already found
(`stof/crawler/endpoint_store.py`'s own `merge()`) -- every
vulnerability module downstream is unaffected either way, since they
already only ever consume `endpoints.json` through that one file.

Modeled on `intruder-io/autoswagger`'s own two real discovery paths
(BSD-3-Clause, 2k+ stars) -- direct spec paths first, then a Swagger UI
page's own embedded spec-URL reference -- adapted to this project's own
`context.request` (Playwright's `APIRequestContext`, the same
authenticated-or-anonymous request object every other crawler/module
file already uses) instead of a separate HTTP client, per CLAUDE.md
rule 10 ("Crawler is Playwright-only").

**Scope, stated honestly**: extracts URL + HTTP method + query/path/
header parameter NAMES only. Deliberately does NOT resolve `$ref`
JSON-Schema pointers or walk a request body's nested `properties` --
this is endpoint DISCOVERY (handing the crawler's existing output a
more complete list), not a full OpenAPI type system. A body-carrying
operation (POST/PUT/PATCH) is still discovered as a real endpoint with
its real URL and method; injection modules already handle "an API
endpoint with no named parameters" the same way for any other
crawler-discovered endpoint whose body shape wasn't captured.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit

import yaml

from stof.core.logger import get_logger

from .endpoint_store import Endpoint

_log = get_logger("crawler.openapi_discovery")

# Checked first, in order -- covers the overwhelming majority of real
# targets: Swagger/OpenAPI tooling across every major framework
# (Springfox/Springdoc for Java, drf-yasg for Django, swagger-jsdoc for
# Node/Express, FastAPI's own built-in docs, NSwag for .NET...)
# defaults to one of these exact paths.
_DIRECT_SPEC_PATHS = (
    "/openapi.json", "/v3/api-docs", "/api/openapi.json", "/swagger.json",
    "/v2/swagger.json", "/v2/api-docs", "/api/swagger.json", "/swagger/v1/swagger.json",
    "/api-docs", "/api-docs.json", "/openapi.yaml", "/openapi.yml", "/swagger.yaml",
)

# Human-facing Swagger/Redoc UI pages -- the real spec URL is usually
# referenced from inside these (the UI's own JS config), even when it
# doesn't live at any of the direct paths above.
_SWAGGER_UI_PATHS = ("/swagger-ui.html", "/swagger-ui/index.html", "/swagger-ui/", "/api-docs/swagger-ui.html", "/docs", "/redoc")

_SPEC_URL_IN_HTML_RE = re.compile(r'url\s*[:=]\s*["\']([^"\']+\.(?:json|ya?ml))["\']', re.IGNORECASE)

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def _parse_spec_text(text: str) -> dict | None:
    """JSON first (most common, and unambiguous), YAML as a fallback --
    a valid JSON document also happens to be valid YAML, so trying JSON
    first isn't just an optimization: it avoids YAML's looser grammar
    quietly accepting some other JSON response body as "valid YAML"
    and this function misclassifying it as a spec. Returns `None`
    (never raises) for anything that doesn't parse as a dict with a
    `paths` key AND a `swagger`/`openapi` version field -- the two
    together are what actually distinguish a real spec from some
    unrelated JSON/YAML endpoint that happens to have a `paths` key."""
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            return None
    if not isinstance(doc, dict) or "paths" not in doc:
        return None
    if "swagger" not in doc and "openapi" not in doc:
        return None
    return doc


def _spec_base_path(doc: dict) -> str:
    """Where the paths in `doc["paths"]` are actually rooted --
    OpenAPI v2's `basePath`, v3's `servers[0].url` (may be a full URL
    or a path-only value), or "/" when neither is present."""
    if doc.get("basePath"):
        return str(doc["basePath"])
    servers = doc.get("servers") or []
    if servers and isinstance(servers[0], dict) and servers[0].get("url"):
        return urlsplit(str(servers[0]["url"])).path or "/"
    return "/"


def _extract_param_names(operation: dict) -> list[str]:
    return [
        param["name"]
        for param in (operation.get("parameters") or [])
        if isinstance(param, dict) and param.get("name") and param.get("in") in ("query", "path", "header")
    ]


def parse_openapi_spec(doc: dict, spec_url: str) -> list[Endpoint]:
    """Pure transform: a parsed spec dict -> the `Endpoint` list
    `endpoint_store.py`'s `merge()` can fold straight into whatever the
    browsing crawler already found. Split out from the network-fetching
    orchestration below so it's directly unit-testable against a
    hand-written spec dict, no fake HTTP context required."""
    base_path = _spec_base_path(doc).rstrip("/")
    parts = urlsplit(spec_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    endpoints: list[Endpoint] = []
    for path, path_item in (doc.get("paths") or {}).items():
        if not isinstance(path_item, dict) or not path.startswith("/"):
            continue
        url = f"{origin}{base_path}{path}"
        endpoint_security = doc.get("security")
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            auth_required = bool(operation.get("security", endpoint_security))
            endpoints.append(Endpoint(
                url=url, method=method.upper(), endpoint_type="api",
                parameters=_extract_param_names(operation), auth_required=auth_required,
            ))
    return endpoints


async def _fetch_text(context, url: str) -> str | None:
    try:
        resp = await context.request.get(url, max_redirects=2, timeout=8000)
    except Exception as exc:
        _log.debug(f"OpenAPI discovery probe failed for '{url}': {exc}")
        return None
    if resp.status != 200:
        return None
    try:
        return await resp.text()
    except Exception as exc:
        _log.debug(f"could not read response body for '{url}': {exc}")
        return None


async def _fetch_spec(context, url: str) -> dict | None:
    text = await _fetch_text(context, url)
    return _parse_spec_text(text) if text is not None else None


async def discover_openapi_endpoints(context, base_url: str) -> list[Endpoint]:
    """Tries, in order: (1) every well-known direct spec path, (2) each
    known Swagger/Redoc UI page's own embedded spec-URL reference.
    Returns an empty list (never an error, never raises) when nothing
    is found -- most targets simply don't publish a spec, and that is
    not a failure of this function; the caller merges whatever comes
    back into the browsing crawler's own results and moves on either
    way."""
    parts = urlsplit(base_url)
    origin = f"{parts.scheme}://{parts.netloc}"

    for path in _DIRECT_SPEC_PATHS:
        spec_url = origin + path
        doc = await _fetch_spec(context, spec_url)
        if doc is not None:
            _log.info(f"OpenAPI/Swagger spec found at '{spec_url}'")
            return parse_openapi_spec(doc, spec_url)

    for ui_path in _SWAGGER_UI_PATHS:
        ui_url = origin + ui_path
        html = await _fetch_text(context, ui_url)
        if html is None:
            continue
        match = _SPEC_URL_IN_HTML_RE.search(html)
        if not match:
            continue
        spec_url = urljoin(ui_url, match.group(1))
        doc = await _fetch_spec(context, spec_url)
        if doc is not None:
            _log.info(f"OpenAPI/Swagger spec found via '{ui_url}' -> '{spec_url}'")
            return parse_openapi_spec(doc, spec_url)

    return []
