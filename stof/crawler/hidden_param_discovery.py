"""Layer 7 — hidden HTTP parameter discovery.

Real gap this closes: the crawler only ever records a parameter it
directly OBSERVED (a real form field, an XHR body/query STOF's own
browser actually saw during the crawl) -- it has no way to find a
parameter that exists and is honored by the server but never rendered
or called anywhere in the UI the crawl walked. That's exactly the class
of bug `idor_tests.py`'s mass-assignment mixin and `bfla_tests.py`
already test FOR once a parameter name is known (`isAdmin=true`
accepted server-side with no ownership check) -- this module is what
finds that the parameter exists at all, so those techniques have
something real to test on a target whose vulnerable flag is never
surfaced in any form STOF's browser ever sees.

Modeled on `s0md3v/Arjun`'s own technique (MIT license, the de-facto
standard tool for this: https://github.com/s0md3v/Arjun) -- send a
baseline (control) request, then one request per candidate parameter
name, and treat any response that differs meaningfully from the
baseline as "this parameter is real and the server does something
different when it's present." Arjun's own default dictionary has
~25,890 entries; this module uses a much smaller (~110), hand-curated,
HIGH-SIGNAL subset instead -- generic web-app parameter names most
likely to reveal a real behavioral difference (access/privilege flags,
redirect/SSRF-adjacent targets, id-shaped references) -- matching this
project's own "small, curated, cited wordlist, not an exhaustive brute
force" convention (`configuration_tests.py`'s own SecLists-derived
path lists use the same restraint), and bounded to a capped number of
endpoints per scan (`max_endpoints`) so this stays a bounded addition
to a scan's request budget, not a second full crawl.

Baseline-diffed the same way `configuration_tests.py`'s own
`_control_fingerprint`/`_probe_paths` already are (this project's own
established detection-quality rule): a candidate whose response is
indistinguishable from a control probe (a definitely-nonexistent
parameter name) is discarded, not reported -- the exact false-positive
class a soft-404/catch-all SPA response would otherwise produce.

Purely a DISCOVERY enrichment, same shape as `openapi_discovery.py`:
returns `Endpoint` objects (existing URLs, newly-discovered parameter
names) for the caller to fold into the crawl's own results via
`endpoint_store.merge()` -- it never reports a Finding itself. Whether
a discovered parameter is actually exploitable is exactly what the
downstream vulnerability modules (IDOR/mass-assignment/BFLA) already
exist to determine; this module's only job is making sure they get the
chance to test it in the first place.
"""
from __future__ import annotations

import asyncio
import hashlib
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from stof.core.logger import get_logger

from .endpoint_store import Endpoint

_log = get_logger("crawler.hidden_param_discovery")

# Curated, not exhaustive -- see module docstring. Grouped by the real
# vulnerability classes a hidden parameter of this shape most commonly
# turns out to feed: access/privilege flags (mass assignment/BFLA),
# redirect/webhook targets (open redirect/SSRF), file/path/command
# fields, id-shaped object references (IDOR), and generic
# sort/filter/output controls that sometimes gate real behavior.
CANDIDATE_PARAMS: tuple[str, ...] = (
    "admin", "is_admin", "isAdmin", "role", "roles", "access_level", "level",
    "permission", "permissions", "privilege", "superuser", "root", "internal",
    "debug", "test", "dev", "development", "staging", "bypass", "override",
    "force", "skip_auth", "no_auth", "auth", "authenticated", "verified",
    "active", "enabled", "disabled", "hidden", "private", "public", "status",
    "state", "approved", "confirmed", "locked", "banned", "blocked",
    "redirect", "redirect_uri", "redirect_url", "return_url", "return_to",
    "next", "url", "target", "dest", "destination", "callback", "callback_url",
    "webhook", "webhook_url", "continue", "goto", "link", "site", "host",
    "file", "filename", "path", "filepath", "dir", "folder", "page", "template",
    "include", "load", "view", "action", "cmd", "command", "exec", "run",
    "source", "src",
    "id", "uid", "user_id", "userId", "account_id", "order_id", "doc_id",
    "ref", "reference", "key", "token", "api_key", "apikey", "secret",
    "session_id", "session", "sid",
    "format", "output", "type", "content_type", "jsonp",
    "sort", "order", "order_by", "filter", "search", "q", "query", "limit",
    "offset", "page_size", "per_page",
    "lang", "locale", "currency", "amount", "price", "discount", "coupon",
    "version", "v", "env", "environment", "config", "settings", "verbose",
)

_STATIC_ASSET_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".map", ".pdf", ".zip",
)


@dataclass
class HiddenParamConfig:
    candidate_params: tuple[str, ...] = field(default_factory=lambda: CANDIDATE_PARAMS)
    # Bounds this module's own request budget -- a target with hundreds
    # of discovered GET endpoints must not turn into
    # `len(endpoints) * len(candidate_params)` requests. Endpoints with
    # the FEWEST already-known parameters are tried first (see
    # `_rank_endpoints` below): those are the ones most likely to still
    # be hiding something, since a heavily-parameterized endpoint's
    # surface is already well understood from the crawl alone.
    max_endpoints: int = 15
    min_content_length: int = 100


def _fingerprint(status: int, body: str) -> tuple[int, str]:
    return status, hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()


def _rank_endpoints(endpoints: list[Endpoint], max_endpoints: int) -> list[Endpoint]:
    """GET endpoints only (a hidden parameter's behavioral signal is
    read off the response body, which a HEAD/OPTIONS probe wouldn't
    reliably have, and probing every write-verb endpoint here would
    risk state changes this module has no business making); static
    assets excluded (a parameter can't meaningfully change what a
    `.css`/`.png` file serves); ordered by fewest already-known
    parameters first, then by URL for determinism -- see
    `HiddenParamConfig.max_endpoints`'s own docstring for why that
    order."""
    candidates = [
        e for e in endpoints
        if e.method.upper() == "GET" and not urlsplit(e.url).path.lower().endswith(_STATIC_ASSET_EXTENSIONS)
    ]
    # Dedup by URL -- the crawler can discover the same page via
    # multiple link paths; probing it twice wastes budget for zero
    # additional signal.
    seen: set[str] = set()
    deduped = []
    for e in candidates:
        if e.url not in seen:
            seen.add(e.url)
            deduped.append(e)
    deduped.sort(key=lambda e: (len(e.parameters), e.url))
    return deduped[:max_endpoints]


async def _probe(context, url: str) -> tuple[int, str] | None:
    try:
        resp = await context.request.get(url, max_redirects=0, timeout=8000)
        body = await resp.text()
    except Exception as exc:
        _log.debug(f"hidden-param probe failed for '{url}': {exc}")
        return None
    return resp.status, body


def _add_param(url: str, name: str) -> str:
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{name}={secrets.token_hex(4)}"


async def _probe_candidate(context, endpoint_url: str, name: str, control_fp: tuple[int, str] | None, min_content_length: int) -> str | None:
    """One candidate parameter's own probe-and-compare -- split out so
    `_discover_for_endpoint` can run every candidate CONCURRENTLY
    (`asyncio.gather`) instead of one at a time. Real, live-measured
    gap this closes: this loop used to `await` each of a target's
    ~110 candidates in strict sequence, even though
    `core.rate_limiter.throttled()` (which `_probe` already routes
    every request through) already permits up to
    `rate_limiter.MAX_CONCURRENT_REQUESTS` (6 by default) requests in
    flight at once -- the concurrency budget existed, this code just
    never used it, making a full scan's crawl/discovery phase take
    roughly `MAX_CONCURRENT_REQUESTS`x longer than it needed to.
    Returns `name` if it's a real, newly-discovered parameter, `None`
    otherwise -- the caller just filters `None`s out, so result order
    (which `asyncio.gather` preserves anyway) never mattered."""
    probe = await _probe(context, _add_param(endpoint_url, name))
    if probe is None:
        return None
    status, body = probe
    if len(body) < min_content_length:
        return None
    fp = _fingerprint(status, body)
    return name if (control_fp is None or fp != control_fp) else None


async def _discover_for_endpoint(context, endpoint: Endpoint, config: HiddenParamConfig) -> Endpoint | None:
    """One endpoint's sweep: a control probe (a definitely-fake
    parameter name) establishes the baseline, then every candidate is
    probed and kept only if it differs from that baseline AND clears
    `min_content_length` -- the same two-part "distinct from control,
    not just an empty/error page" rule `configuration_tests.py`'s own
    `_probe_paths` already applies. Returns `None` (not an empty
    `Endpoint`) when nothing new was found, so the caller can filter
    cleanly rather than merging in a pile of zero-parameter no-ops."""
    control_probe = await _probe(context, _add_param(endpoint.url, f"stof_probe_{secrets.token_hex(6)}"))
    if control_probe is None:
        return None
    control_status, control_body = control_probe
    control_fp = _fingerprint(control_status, control_body) if len(control_body) >= config.min_content_length else None

    candidates = [name for name in config.candidate_params if name not in endpoint.parameters]
    results = await asyncio.gather(*(
        _probe_candidate(context, endpoint.url, name, control_fp, config.min_content_length)
        for name in candidates
    ))
    discovered = [name for name in results if name is not None]

    if not discovered:
        return None
    _log.info(f"hidden parameter(s) discovered at '{endpoint.url}': {discovered}")
    return Endpoint(url=endpoint.url, method=endpoint.method, endpoint_type=endpoint.endpoint_type, parameters=discovered, auth_required=endpoint.auth_required)


async def discover_hidden_params(context, endpoints: list[Endpoint], config: HiddenParamConfig | None = None) -> list[Endpoint]:
    """Entry point -- mirrors `openapi_discovery.discover_openapi_
    endpoints`'s own shape (an authenticated-or-anonymous
    `context.request`, a list of `Endpoint` results the caller merges
    into the crawl's own output via `endpoint_store.merge()`). Never
    raises: a single endpoint's probe failing is logged and skipped,
    not fatal to the rest of the sweep, matching this project's own
    "a probe failure must never take down the whole module" resilience
    convention."""
    config = config or HiddenParamConfig()
    results: list[Endpoint] = []
    for endpoint in _rank_endpoints(endpoints, config.max_endpoints):
        try:
            found = await _discover_for_endpoint(context, endpoint, config)
        except Exception as exc:
            _log.warning(f"hidden-param sweep failed for '{endpoint.url}': {exc}")
            continue
        if found is not None:
            results.append(found)
    return results
