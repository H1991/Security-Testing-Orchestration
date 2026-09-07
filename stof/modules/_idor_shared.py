"""Pure helpers and constants shared by `idor_tests.py` and the
technique modules it composes (`bfla_tests.py`, `role_tests.py`,
`mass_assignment_tests.py`).

Split out specifically to avoid a circular import: `idor_tests.py`
imports mixin classes from those three files, so anything they in turn
need from "the IDOR module" has to live somewhere none of them import
each other to reach.
"""
from __future__ import annotations

import hashlib
import json as json_module
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from stof.core.logger import get_logger
from stof.core.rate_limiter import throttled
from stof.crawler.endpoint_store import Endpoint
from stof.recon.parameter_discovery import guess_param_type

_log = get_logger("modules._idor_shared")

_ELEVATED_ROLE_VALUES = ("admin", "administrator", "true", "1", "superuser")

# A small, curated wordlist for TC-055.4's hidden-endpoint discovery --
# the same "known-patterns" approach the sprint plan's own catalog
# notes Burp's Scanner uses for path discovery, not an exhaustive
# dirsearch/gobuster-class wordlist.
_HIDDEN_ENDPOINT_WORDLIST = (
    "/api/admin", "/api/internal", "/api/debug", "/api/v1/admin", "/api/v2/admin",
    "/internal", "/debug", "/actuator", "/actuator/health", "/actuator/env",
    "/swagger.json", "/swagger-ui.html", "/openapi.json", "/graphql",
    "/api/users/all", "/api/config", "/api/private", "/_internal", "/metrics",
)

# Fields whose presence in an IDOR-exposed record (TC-052.3) or a mass-
# assignment response (TC-052.4) signals privilege-relevant data, not
# just PII -- role/permission markers and live credentials.
_PRIVILEGE_FIELD_NAMES = ("role", "isadmin", "is_admin", "admin", "permission", "token", "apikey", "api_key", "password")

# Object-reference substrings, checked in addition to
# `guess_param_type()`'s id/number guess. `guess_param_type()` was built
# for recon's general type-guessing report and is deliberately narrow
# (exact/suffix match on "id"/"uuid"/"guid" only) -- it doesn't
# recognise this project's own confirmed real IDOR parameter,
# `listAccounts`, as an object reference at all ("account" isn't in its
# heuristic). Being generous here is safe: this list only selects which
# parameters get *probed*, not what counts as a finding -- a probed
# parameter that isn't actually an object reference will simply return
# identical content for every candidate ID and produce no finding (see
# `_test_horizontal_idor`'s distinct-content check).
_OBJECT_REFERENCE_HINTS = (
    "id", "uuid", "guid", "account", "user", "order", "invoice",
    "record", "ref", "num", "code", "index", "item",
)

_PATH_ID_SEGMENT_RE = re.compile(
    r"^\d+$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# 2-10 digit runs or UUIDs, used to spot object ids leaked inside a
# response body that weren't in the caller-supplied candidate list --
# e.g. an order-history response that happens to mention order id
# 4821 the current session doesn't itself own.
_LEAKED_ID_RE = re.compile(
    r"\b(\d{2,10}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b"
)


def _looks_like_object_reference(param_name: str) -> bool:
    return guess_param_type(param_name) in ("id", "number") or any(
        hint in param_name.lower() for hint in _OBJECT_REFERENCE_HINTS
    )


# Tenant/org-scoping parameter hints -- deliberately a SEPARATE list and
# function from `_OBJECT_REFERENCE_HINTS`/`_looks_like_object_reference`
# above (per the tenant-isolation BOLA family in `stof/payloads/
# idor_knowledge_base.json`): a parameter can be a per-object identifier
# OR an organizational-scope identifier, and the two attack shapes must
# never be conflated -- substituting a tenant id tests "can I reach a
# DIFFERENT ORGANIZATION'S data", not "can I reach a different object
# owned within my own scope".
_TENANT_SCOPE_HINTS = (
    "org_id", "organization_id", "tenant_id", "tenantid", "company_id", "workspace_id",
)


def _looks_like_tenant_scope_param(param_name: str) -> bool:
    lowered = param_name.lower()
    return any(hint in lowered for hint in _TENANT_SCOPE_HINTS)


def _object_ref_endpoints(endpoints: list[Endpoint], methods: tuple[str, ...] = ("GET",)) -> list[tuple[Endpoint, str]]:
    """The `[(e, e.parameters[0]) for e in endpoints if e.method.upper()
    in methods and len(e.parameters) == 1 and
    _looks_like_object_reference(e.parameters[0])]` object-reference
    filter duplicated across `idor_tests.py` (x3) and
    `mass_assignment_tests.py` (x1) -- always the same shape, differing
    only in which HTTP method(s) each technique probes."""
    return [
        (e, e.parameters[0])
        for e in endpoints
        if e.method.upper() in methods and len(e.parameters) == 1 and _looks_like_object_reference(e.parameters[0])
    ]


def _tenant_scope_endpoints(endpoints: list[Endpoint], methods: tuple[str, ...] = ("GET", "POST")) -> list[tuple[Endpoint, str]]:
    """Same shape as `_object_ref_endpoints` above, but selecting on
    `_looks_like_tenant_scope_param` instead -- kept as its own function
    (not a parameterised version of `_object_ref_endpoints`) so the two
    attack shapes stay visibly distinct call sites, matching the
    knowledge base's own "these must never be conflated" note."""
    return [
        (e, e.parameters[0])
        for e in endpoints
        if e.method.upper() in methods and len(e.parameters) == 1 and _looks_like_tenant_scope_param(e.parameters[0])
    ]


_METHOD_REQUEST_ATTRS = {"GET": "get", "POST": "post", "PUT": "put", "PATCH": "patch", "DELETE": "delete"}


def _method_request_fn(context, method: str):
    """The `{"POST": context.request.post, "PUT": context.request.put,
    ...}` verb-dispatch dict duplicated across every write-verb IDOR-
    family technique (`idor_tests.py`, `bfla_tests.py`, `role_tests.py`,
    `mass_assignment_tests.py` x2) -- returns an async callable for
    `method` (already uppercased by every caller) that behaves exactly
    like the bound `context.request.<verb>` method callers already
    expect, wrapped through the shared request throttle
    (`stof.core.rate_limiter`) so every write-verb probe gets the same
    concurrency cap `_probe_get()` already applies to GETs."""
    bound = getattr(context.request, _METHOD_REQUEST_ATTRS[method])

    async def _throttled_call(*args, **kwargs):
        return await throttled(bound(*args, **kwargs))

    return _throttled_call


def _set_query_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[name] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _content_fingerprint(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()


def _looks_privileged(url: str, hints: tuple[str, ...]) -> bool:
    path = urlsplit(url).path.lower()
    return any(hint in path for hint in hints)


def _synthetic_endpoint(url: str, method: str = "GET") -> Endpoint:
    """A `Finding` needs an `Endpoint`, but a probe URL built from a
    wordlist/DOM link isn't necessarily one the crawler discovered."""
    return Endpoint(url=url, method=method, endpoint_type="api", auth_required=False)


def _numeric_path_segment_indexes(url: str) -> list[int]:
    """Indexes into the URL's `/`-split path of every segment that
    looks like a bare object id (an integer or a UUID) rather than a
    fixed route word -- e.g. for `/api/orders/5`, only the index of
    `"5"` is returned, not `"orders"`."""
    segments = urlsplit(url).path.split("/")
    return [i for i, seg in enumerate(segments) if seg and _PATH_ID_SEGMENT_RE.match(seg)]


def _set_path_segment(url: str, index: int, value: str) -> str:
    parts = urlsplit(url)
    segments = parts.path.split("/")
    segments[index] = value
    return urlunsplit((parts.scheme, parts.netloc, "/".join(segments), parts.query, parts.fragment))


def _observed_query_value(url: str, param: str) -> str | None:
    """The real value `param` actually held in THIS crawled endpoint's
    own URL -- e.g. for `/api/orders?orderId=800042`, the value for
    `orderId` is `"800042"`. This is the seed the active id-substitution
    techniques derive candidates from now (`_endpoint_candidate_ids`
    below), instead of only ever trying a target-wide configured list
    that has no relationship to what this specific endpoint actually
    showed."""
    for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if name == param and value:
            return value
    return None


def _observed_path_segment_value(url: str, index: int) -> str | None:
    """The real value already sitting at `index` in this endpoint's own
    path -- e.g. for `/api/orders/800042` at index 2, `"800042"`. Same
    role as `_observed_query_value` above, for the path-segment id
    techniques."""
    segments = urlsplit(url).path.split("/")
    if 0 <= index < len(segments) and segments[index]:
        return segments[index]
    return None


def _numeric_neighbors(value: str, spread: int = 5) -> list[str]:
    """Small, nearest-first set of candidate ids around a REAL id
    already observed at one specific endpoint -- the standard adjacent-
    id IDOR probe (an attacker who can already see id 800042 tries
    800041/800043 next, not an arbitrary unrelated value), and the
    reason this project no longer needs a human to pre-guess a target's
    numeric range in config.json: the range comes from whatever id the
    crawler actually saw at THIS endpoint, not a value configured once
    for the whole target (see `_endpoint_candidate_ids` below).

    Only meaningful for a decimal-digit id -- `_id_shape(value) ==
    "sequential_int"` territory (TC-053.6's own classification, reused
    conceptually here); a uuid or long-random-token observed value has
    no numerically-adjacent neighbor worth trying, so this returns `[]`
    for anything non-digit rather than a numerically meaningless probe.
    Preserves the observed value's zero-padding width (e.g. "007" ->
    "006"/"008") since some apps validate id format strictly. Never
    includes `value` itself -- probing the id the current session
    already legitimately owns proves nothing."""
    if not value.isdigit():
        return []
    width = len(value)
    n = int(value)
    out: list[str] = []
    for delta in range(1, spread + 1):
        for neighbor in (n - delta, n + delta):
            if neighbor >= 0:
                out.append(str(neighbor).zfill(width))
    return out


def _endpoint_candidate_ids(observed_value: str | None, configured: list[str], spread: int = 5) -> list[str]:
    """The full per-endpoint candidate list for an object-reference
    substitution technique: real neighbors of whatever id THIS endpoint
    actually showed, first (a live attacker always probes near an id
    they can already see), then the caller's configured/generic list as
    a supplementary set -- covers a target with nothing numeric to
    derive from yet (no value observed, or a uuid/opaque id) and still
    lets an operator who already knows a specific valid id add it
    explicitly via `target.idor_candidate_ids`. De-duplicated, order-
    preserving, so a value that happens to appear in both sources is
    only probed once."""
    seen: dict[str, None] = {}
    if observed_value:
        for candidate in _numeric_neighbors(observed_value, spread=spread):
            seen.setdefault(candidate, None)
    for candidate in configured:
        seen.setdefault(candidate, None)
    return list(seen.keys())


def _control_candidate_value() -> str:
    """A per-probe-set random value guaranteed not to correspond to any
    real object -- the same "random, definitely-nonexistent" principle
    `stof/modules/_probe_shared.py`'s `control_fingerprint()` already
    uses for wordlist sweeps (shared `stof-control-` marker prefix),
    applied here as a substituted CANDIDATE VALUE into an existing
    endpoint instead of an appended path. A fresh random token per call
    (not a fixed constant), so a target that somehow caches/special-
    cases one specific probe value can't quietly defeat this."""
    return f"stof-control-{secrets.token_hex(6)}"


def _exclude_control_fingerprint(responses: dict[str, str], control_fingerprint: str | None) -> dict[str, str]:
    """Drops every candidate whose response body fingerprint matches
    the control/baseline probe's fingerprint (`_control_candidate_
    value` above) -- the real, confirmed false-positive class this
    guards against: a soft-404/catch-all response that returns HTTP 200
    with a body that VARIES per requested id (e.g. it echoes the id
    into an "Object <id> not found" message) still produces 2+ DISTINCT
    fingerprints across candidates, which the plain "are these bodies
    different from each other" check alone cannot tell apart from a
    real distinct object. Same "discard any hit indistinguishable from
    a known-invalid control" rule `stof/modules/_probe_shared.py`'s
    `sweep_paths()` already applies for wordlist hits, extended here to
    id-substitution. `control_fingerprint=None` (the control probe
    itself failed/returned nothing usable) is a no-op -- silently
    discarding every real candidate because the control probe didn't
    work would blind the technique, not make it safer."""
    if control_fingerprint is None:
        return responses
    return {cid: body for cid, body in responses.items() if _content_fingerprint(body) != control_fingerprint}


async def _control_fingerprint_body_field(method_fn, url: str, param: str, min_content_length: int) -> str | None:
    """POST/PUT-body-field counterpart of the GET-based control-probe
    principle above: substitutes a random, definitely-nonexistent value
    into the JSON body field instead of a query string/path segment,
    same reasoning, shared by the write-verb content-differential
    techniques in `mass_assignment_tests.py` and `tenant_tests.py`
    (both already build a bound async `method_fn` the same way
    `_method_request_fn` does). Not fully pure (issues a real HTTP
    request), same "shared, leading-underscore file" convention
    `stof/modules/_probe_shared.py` already documents for its own
    control-probe helper. Returns `None` on any probe failure or a
    non-200/too-short response -- callers treat that as "nothing to
    baseline against", not a hard error."""
    payload = {param: _control_candidate_value()}
    try:
        resp = await method_fn(url, data=json_module.dumps(payload), headers={"Content-Type": "application/json"}, max_redirects=0)
        body = await resp.text()
    except Exception as exc:
        _log.warning(f"control probe failed for {url}: {exc}")
        return None
    if resp.status == 200 and len(body) >= min_content_length:
        return _content_fingerprint(body)
    return None


# TC-053.6's minimum sample size before drawing any conclusion about
# whether a target's id scheme is sequential/enumerable -- a single
# short numeric id proves nothing (it could be anything from "user #7"
# to a coincidence), and this project's own knowledge base
# (`stof/payloads/idor_knowledge_base.json`'s cross-cutting evidence
# principle) is explicit that weak signal must never be dressed up as a
# confident finding.
_MIN_ID_PREDICTABILITY_SAMPLE = 5


def _collect_observed_ids(endpoints: list[Endpoint]) -> list[str]:
    """Every id-shaped path segment and object-reference query-
    parameter VALUE already present in `endpoints` -- purely
    re-reading data this scan's crawler/earlier techniques already
    captured, no new network request. Order-preserving de-dup so a
    small, noisy discovered set doesn't get inflated by the same id
    appearing on several endpoints."""
    seen: dict[str, None] = {}
    for endpoint in endpoints:
        parts = urlsplit(endpoint.url)
        for segment in parts.path.split("/"):
            if segment and _PATH_ID_SEGMENT_RE.match(segment):
                seen.setdefault(segment, None)
        for name, value in parse_qsl(parts.query, keep_blank_values=True):
            if value and _looks_like_object_reference(name):
                seen.setdefault(value, None)
    return list(seen.keys())


def _id_shape(token: str) -> str:
    """Classifies one id-shaped value for TC-053.6's predictability
    analysis. `"sequential_int"` covers the shape a database
    auto-increment primary key produces when used directly as an
    externally-visible identifier (this project's demo target's own
    800000-800010 account-id range is exactly this shape) -- short
    enough that a linear/binary sweep of the space is cheap. `"uuid"`
    and `"long_random_token"` are the properly-random counterexample.
    Anything else (a short non-numeric token, e.g. a 4-6 char opaque
    code) is `"opaque_other"` -- deliberately its own bucket rather than
    being folded into either side, since it's neither confirmed-
    predictable nor confirmed-random."""
    if re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", token):
        return "uuid"
    if token.isdigit():
        # A 10+ digit run is far more likely a unix-ms timestamp or a
        # snowflake-style id than a plain auto-increment counter --
        # only shorter digit runs count as "sequential_int" here.
        return "sequential_int" if len(token) <= 9 else "opaque_other"
    if len(token) >= 20:
        return "long_random_token"
    return "opaque_other"


def _extract_leaked_ids(texts: list[str], known: set[str], limit: int = 5) -> list[str]:
    found: list[str] = []
    for text in texts:
        for match in _LEAKED_ID_RE.finditer(text):
            token = match.group(0)
            if token not in known and token not in found:
                found.append(token)
            if len(found) >= limit:
                return found
    return found
