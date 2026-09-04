"""Pure(-ish) helpers shared by `sqli_tests.py` and `xss_tests.py`.

Not `_idor_shared.py`: that file's helpers are about object-id
substitution and `AuthorizationDecision` allow/deny diffing -- a
different oracle shape from what these two injection modules need
(place one payload into one param, keep the rest of the request
well-formed, read back the response). Split out here specifically
because it's genuinely shared by both new modules, per this project's
own "shared *pure* helpers go in a leading-underscore shared file, not
duplicated per module" rule.
"""
from __future__ import annotations

import json
import time
from difflib import SequenceMatcher
from typing import TYPE_CHECKING

from stof.core.logger import get_logger

from ._idor_shared import _looks_privileged

if TYPE_CHECKING:
    from stof.crawler.endpoint_store import Endpoint

_log = get_logger("modules._injection_shared")

# Free-text-storage field name hints for the second-order/stored
# plant phase. Deliberately its own list, not folded into
# `_looks_like_object_reference`/`_looks_like_tenant_scope_param`
# (`_idor_shared.py`) -- those detect id/tenant-scope *parameters*,
# this detects free-text *content* fields, a different signal shape.
# Promoted from `sqli_tests.py` (Batch 1 of the stored-XSS wave).
_FREE_TEXT_FIELD_HINTS = ("comment", "message", "feedback", "subject", "notes", "name", "body")

# Reuses `idor_tests.py`'s own `IdorTestConfig.privileged_path_hints`
# literal (not imported -- that field lives on a sibling module's
# config dataclass, importing it would be a cross-module config
# coupling this project's own boundary rules don't allow) for the
# verify-phase "likely display/admin" endpoint heuristic. Promoted
# from `sqli_tests.py` alongside `_FREE_TEXT_FIELD_HINTS` above.
_PRIVILEGED_PATH_HINTS = (
    "/admin", "/manage", "/management", "/superuser", "/root",
    "/internal", "/config", "/dashboard-admin",
)


def _looks_like_free_text_field(name: str) -> bool:
    """A POST form field whose name suggests it stores free text
    (a comment/message/feedback box, a display name, ...) rather than
    a structured value -- the second-order/stored plant phase's
    candidate field selector. Promoted from `sqli_tests.py` (Batch 1
    of the stored-XSS wave): `xss_tests.py`'s TC-128.4 needs the exact
    same field-name heuristic, so this is genuinely shared, pure logic
    per this project's own shared-helper rule -- not duplicated per
    module."""
    lowered = name.lower()
    return any(hint in lowered for hint in _FREE_TEXT_FIELD_HINTS)


def _second_order_plant_candidates(endpoints: "list[Endpoint]", limit: int) -> "list[tuple[Endpoint, str]]":
    """Discovered POST endpoints with at least one free-text-shaped
    field, paired with the first such field name -- capped at `limit`,
    same discovery-order capping convention as every other bounded
    candidate sweep in this project."""
    candidates: list[tuple[Endpoint, str]] = []
    for endpoint in endpoints:
        if endpoint.method.upper() != "POST":
            continue
        field = next((p for p in endpoint.parameters if _looks_like_free_text_field(p)), None)
        if field is not None:
            candidates.append((endpoint, field))
    return candidates[:limit]


def _second_order_verify_candidates(endpoints: "list[Endpoint]", limit: int) -> "list[Endpoint]":
    """Discovered GET endpoints that look like a privileged/admin
    display or listing page -- capped at `limit`, the second-order/
    stored plant-verify technique's verify-phase candidate set."""
    candidates = [e for e in endpoints if e.method.upper() == "GET" and _looks_privileged(e.url, _PRIVILEGED_PATH_HINTS)]
    return candidates[:limit]


def injectable_endpoints(endpoints: "list[Endpoint]", limit: "int | None" = None) -> "list[Endpoint]":
    """Every discovered endpoint carrying at least one parameter whose
    location STOF knows (Wave 1's `param_locations`) -- GET or POST,
    any `endpoint_type` (a "form" login endpoint and an "api" search
    endpoint are equally valid injection targets). `limit` bounds how
    many are actually probed without changing which ones get picked
    (discovery order) -- the same "cap a wordlist/candidate sweep"
    precedent every other module here already follows (e.g.
    `_HIDDEN_ENDPOINT_WORDLIST`), needed here because SQLi/XSS probing
    is O(endpoints x params), unlike a fixed-size wordlist."""
    candidates = [e for e in endpoints if e.method.upper() in ("GET", "POST") and e.parameters]
    return candidates[:limit] if limit is not None else candidates


def placeholder_value(name: str) -> str:
    """Benign filler for every param NOT currently being probed, so a
    request with several fields and only one payload still looks like
    a plausible submission instead of an empty/malformed one the
    server rejects before ever reaching the vulnerable code path.
    Independently duplicated from `crawler.py`'s own `_test_value_for`
    rather than imported -- crawler.py (Layer 7) fills a real DOM
    form for passive endpoint discovery, this fills a raw HTTP
    request param for active injection testing; different purpose,
    small enough not to be worth a cross-layer import for."""
    lowered = name.lower()
    if "email" in lowered:
        return "stof-probe@example.com"
    if "pass" in lowered:
        return "Stof-Probe-1!"
    if any(h in lowered for h in ("id", "num", "amount", "qty", "quantity")):
        return "1"
    return "stof-probe"


def build_params(endpoint: "Endpoint", target_param: str, value: str) -> dict[str, str]:
    """Every one of `endpoint.parameters` at its benign placeholder
    value, except `target_param`, which gets `value`."""
    return {
        name: (value if name == target_param else placeholder_value(name))
        for name in endpoint.parameters
    }


async def send_probe(
    context, endpoint: "Endpoint", params: dict[str, str], target_location: str,
    extra_headers: "dict[str, str] | None" = None,
    extra_cookies: "dict[str, str] | None" = None,
    json_body: bool = False,
) -> "tuple[int, str, float, dict] | None":
    """Sends `params` to `endpoint`, placed in the query string or the
    request body depending on `target_location` ("query" or "body" --
    Wave 1's `Endpoint.location_for()`; anything else falls back to
    "query", matching `location_for()`'s own default). Returns
    `(status, body, elapsed_seconds, headers)`, or `None` on a
    request/read failure -- mirrors `VulnModule._probe_get`'s
    None-on-failure convention; every caller here already treats a
    failed probe as "skip this candidate", not a hard error, same as
    every other GET-probing module in this project. `elapsed_seconds`
    is measured on every call (not just for the time-based technique)
    and `headers` returned on every call (not just the login-bypass
    technique, which needs a redirect's `Location` header) so callers
    don't need a second, narrower variant of this function.

    `extra_headers` is optional and defaults to `None` -- purely
    additive, existing callers that never pass it get byte-identical
    behavior. When given, it's merged into the `headers=` kwarg passed
    to Playwright's request call, for TC-127.5's header-injection
    technique (injecting into `User-Agent`/`X-Forwarded-For`/`Referer`
    rather than the query/body).

    `extra_cookies` is the identical shape of additive parameter, for
    TC-127.8's cookie-injection technique: the caller passes the FULL
    cookie set it wants sent (normally the role's own currently-set
    session cookies, with exactly one non-auth cookie's value already
    overridden to the payload) and it's serialized into an explicit
    `Cookie` request header, which takes precedence over the browser
    context's own cookie jar for this one call only -- the context's
    real, currently-valid cookies (used by every other probe) are never
    mutated.

    `json_body` is also additive (default `False`, byte-identical
    behavior for every existing caller): when `True`, `params` is sent
    as a JSON object (`Content-Type: application/json`) instead of an
    `application/x-www-form-urlencoded` body, for TC-127.7's JSON-body
    technique -- same params, same target parameter/value, a different
    delivery mechanism only."""
    start = time.monotonic()
    try:
        request_kwargs = {"max_redirects": 0}
        req_headers = dict(extra_headers) if extra_headers else {}
        if extra_cookies:
            req_headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in extra_cookies.items())
        if json_body:
            req_headers["Content-Type"] = "application/json"
        if req_headers:
            request_kwargs["headers"] = req_headers
        if endpoint.method.upper() == "GET" or target_location != "body":
            resp = await context.request.get(endpoint.url, params=params, **request_kwargs)
        elif json_body:
            resp = await context.request.post(endpoint.url, data=json.dumps(params), **request_kwargs)
        else:
            resp = await context.request.post(endpoint.url, form=params, **request_kwargs)
        body = await resp.text()
        # Inside the same try, not after it: a malformed/unreadable
        # `resp.headers` must be treated as the same kind of probe
        # failure as a request/read error, not left to raise past this
        # function uncaught.
        headers = dict(resp.headers)
    except Exception as exc:
        _log.warning(f"injection probe failed for {endpoint.url}: {exc}")
        return None
    return resp.status, body, time.monotonic() - start, headers


# DB-error signatures across the major engines -- checked as plain
# lowercase substrings, not full parsers: a real error page rarely
# needs more than this to identify itself, and a substring match keeps
# this list easy to extend. Deliberately does NOT include generic
# words like "error" or "exception" alone -- those produce false
# positives on virtually any application error page that has nothing
# to do with SQL. Promoted from `sqli_tests.py` (TC-057.8's kid-header
# SQLi-signal variant needs the SAME fingerprint oracle for a
# JWT-header injection point, not a query/body one -- a second
# `VulnModule` reusing a genuinely shared *pure* helper is exactly
# what this file exists for, per this project's own "shared pure
# helpers go in a leading-underscore shared file, not duplicated per
# module" rule; `sqli_tests.py` re-imports these two names unchanged
# so its own call sites and tests are untouched).
_SQL_ERROR_FINGERPRINTS = (
    "sql syntax", "you have an error in your sql syntax", "mysql_fetch", "mysql_num_rows",
    "warning: mysql", "com.mysql.jdbc.exceptions",
    "unclosed quotation mark", "quoted string not properly terminated",
    "microsoft ole db provider for sql server", "sqlserver jdbc driver", "system.data.sqlclient.sqlexception",
    "postgresql query failed", "warning: pg_", "npgsql.postgresexception", "org.postgresql.util.psqlexception",
    "ora-00933", "ora-01756", "ora-00921", "ora-00936", "oracle error", "oracle.jdbc",
    "sqlite3.operationalerror", "sqlite_error", "sqlite.exception",
    "sqlstate", "odbc sql server driver", "jdbc driver", "syntax error at or near",
)


def looks_like_sql_error(body: str) -> "str | None":
    """Returns the matched fingerprint substring, or `None`."""
    lowered = body.lower()
    return next((sig for sig in _SQL_ERROR_FINGERPRINTS if sig in lowered), None)


# Shared by `sqli_tests.py`'s and `auth_tests.py`'s own login-success
# heuristics -- a login-bypass/default-credentials probe against a
# modern SPA backend (Angular/React/Vue, this project's own Juice Shop
# benchmark included) gets a JSON response carrying a bearer/session
# token, never an HTML redirect or "welcome"/"dashboard" page text.
# A success heuristic built only around those HTML-page shapes can
# structurally never detect success against this whole class of
# target -- confirmed live: STOF correctly found and probed Juice
# Shop's real `POST /rest/user/login`, but every genuine bypass
# attempt still reported "not vulnerable" because nothing was looking
# at the JSON body's own success shape.
_JSON_AUTH_TOKEN_KEYS = ("token", "access_token", "accesstoken", "jwt", "authentication", "sessionid", "session_id", "idtoken", "id_token")


def _dict_has_auth_token_key(value: object, depth: int) -> bool:
    if not isinstance(value, dict) or depth > 1:
        return False
    for key, val in value.items():
        if isinstance(val, str) and len(val) >= 8 and key.lower() in _JSON_AUTH_TOKEN_KEYS:
            return True
        if isinstance(val, dict) and _dict_has_auth_token_key(val, depth + 1):
            return True
    return False


def looks_json_authenticated(payload_body: str, baseline_body: str) -> bool:
    """True when `payload_body` parses as JSON and carries a plausible
    auth-token field (at the top level, or one level of nesting, e.g.
    `{"authentication": {"token": "..."}}}`) that `baseline_body` (the
    definitely-wrong-credentials reference response) lacks. Deliberately
    requires an actual token-shaped field, not just "the two JSON bodies
    differ" -- a login form very commonly returns a different (but still
    failed) JSON error shape across attempts (a nonce, a timestamp),
    which must never read as success on its own."""
    try:
        payload_json = json.loads(payload_body)
    except (json.JSONDecodeError, TypeError):
        return False
    if not _dict_has_auth_token_key(payload_json, depth=0):
        return False
    try:
        baseline_json = json.loads(baseline_body)
    except (json.JSONDecodeError, TypeError):
        return True
    return not _dict_has_auth_token_key(baseline_json, depth=0)


def response_similarity(a: str, b: str) -> float:
    """0..1 similarity ratio between two response bodies.

    Used for boolean-blind SQLi's true/false differential, where an
    exact-hash equality check (`_idor_shared._content_fingerprint`'s
    tool) is the wrong one: a true/false pair of requests against a
    real dynamic page (a timestamp, a CSRF nonce, a per-request id in
    the markup) will almost never hash-equal even when the
    *meaningful* content is identical, and a genuinely different page
    (a real result set vs. an empty one) can still share large
    stretches of boilerplate (nav/header/footer) that a pure hash
    comparison can't credit. `difflib.SequenceMatcher` gives a graded
    closeness instead of a binary match, which a differential oracle
    actually needs here."""
    return SequenceMatcher(None, a, b).ratio()
