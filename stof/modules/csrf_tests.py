"""Layer 9 — `stof/modules/csrf_tests.py`: Cross-Site Request Forgery
(TC-130).

A standalone `VulnModule` -- not a mixin -- since `csrf_tests` already
has its own reserved `ModulesConfig` flag (`stof/config/schema.py`,
`validator.py`, `test_orchestrator.py`), the same "declared before
implemented" precedent `sqli_tests`/`xss_tests` followed in Wave 2.
Template: `graphql_tests.py`'s crafted-request-and-inspect-response
shape; the Origin/Referer-spoofing mechanism itself is the same
`context.request.post(url, headers={...})` pattern `auth_tests.py`'s
own `_technique_host_header_injection` already proved reusable here.

Four techniques, run per discovered state-changing POST form endpoint
(`_candidate_form_endpoints`, capped at `CsrfTestConfig.
max_endpoints_to_probe` -- this is a real-write-issuing technique family
against a live target, so the request volume stays small and bounded,
the same "resilience-first" spirit as the time-based SQLi cap in Wave 2):

  - TC-130.1 -- the discovered form has no field whose name looks like
    an anti-CSRF token at all (a structural/naming check).
  - TC-130.2 -- a real POST submission with that token field *stripped*
    still succeeds, proving the server doesn't actually validate the
    token's presence.
  - TC-130.3 -- a real POST submission carrying a spoofed cross-site
    `Origin`/`Referer` header (simulating a request forged from an
    attacker's own page) still succeeds using the role's real cookies.
  - TC-130.4 -- a real POST submission using a SECOND role's ("victim")
    own authenticated session cookies still succeeds when it carries a
    token value harvested from the FIRST role's ("attacker") own
    session -- proving the server checks a token is well-formed/known
    but never that it belongs to the session presenting it (PortSwigger's
    "CSRF where token is not tied to user session" lab; HackerOne
    #182487/GitLab). Needs two independently authenticatable, non-JWT
    roles configured (`CsrfTestConfig.test_role` + `.victim_role`) --
    the same two-role harness `idor_tests.py` already uses for
    horizontal-priv-esc -- and SKIPs cleanly, not ERRORs, when only one
    is available.

TC-130.2/.3 share one baseline submission per endpoint (`_probe_
endpoint_write_techniques`) rather than each fetching their own --
halving the real write volume against the target for testing one
candidate endpoint (baseline + stripped + spoofed = 3 POSTs, not 4),
in the same non-destructive spirit the safety boundary calls for. All
three techniques -- including TC-130.1, which alone needs no live
request -- are gated uniformly behind `CsrfTestConfig.
allow_state_changing_probes` (off by default): CSRF probing as a whole
is being treated as one engagement decision here, not something to
half-run.

Every technique explicitly skips any role whose `auth_type` is `"jwt"`
before running anything, rather than silently probing it into a
meaningless PASS: CSRF exploits the browser's automatic, ambient
attachment of cookies to a cross-site request, which has no equivalent
for a bearer token sent in an `Authorization` header -- a cross-site
page has no way to make the victim's browser attach one.

Every `Finding.description` here states only the observed signal (a
field name absent, an HTTP status/response shape matching or diverging
from a known-working baseline) -- never a claim that real account data
was actually created or altered, per this project's own convention.
"""
from __future__ import annotations

import asyncio
import json as json_module
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from stof.core.logger import get_logger
from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding

from .base import VulnModule
from .results import FAIL, PASS, SKIPPED, TestCaseResult, extract_findings

# Pure, stateless, no-I/O helper reused from session_weakness_tests.py
# (TC-129.5's own "which cookie is newly issued/changed across the
# login boundary" diff). Both files are Layer 9 siblings in the same
# `stof/modules/` package -- this is data reuse across two techniques
# in the same layer, not the cross-LAYER import CLAUDE.md's boundary
# rule actually forbids (crawler->modules, modules->auth, etc). Not
# re-implemented locally because TC-130.5 needs the exact same
# "new-or-changed" cookie identity TC-129.5 already established, not a
# second, potentially-drifting definition of "the session cookie".
from .session_weakness_tests import _new_or_changed_cookies

if TYPE_CHECKING:
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.csrf_tests")

# Small, well-known anti-CSRF field-name conventions (Django/Rails/ASP.NET/
# generic) -- same "small and high-signal" philosophy as auth_tests.py's
# own API-key-pattern list, not an exhaustive framework survey.
_CSRF_TOKEN_NAME_HINTS: tuple[str, ...] = (
    "csrf", "xsrf", "authenticity_token", "requestverificationtoken", "_token", "anti-forgery", "antiforgery",
)

# Response-body phrases that mean "rejected", even on a 200 -- the same
# soft-403-aware idea `authorization.decision.classify_response()`
# already applies for read checks, hand-rolled narrowly here since a
# write-verb success signal (a redirect, a 2xx with no body at all)
# doesn't fit that helper's own "substantial body required" ALLOWED
# rule (see that module's docstring for why write-verb checks don't
# route through it).
_REJECTION_MARKERS: tuple[str, ...] = (
    "csrf", "invalid token", "invalid csrf", "session expired", "security check failed",
    "forbidden", "request could not be verified", "access denied",
)

_TECHNIQUES: tuple[tuple[str, str, str], ...] = (
    ("TC-130.1", "State-changing POST has no anti-CSRF token field at all", "Missing Anti-CSRF Token"),
    ("TC-130.2", "State-changing POST succeeds with the anti-CSRF token field stripped", "CSRF Token Not Validated (stripped-token request accepted)"),
    ("TC-130.3", "State-changing POST succeeds with a spoofed cross-site Origin/Referer", "CSRF Not Prevented By Origin/Referer Validation"),
    ("TC-130.4", "State-changing POST succeeds when the anti-CSRF token belongs to a DIFFERENT user's session", "CSRF Token Not Bound To Session"),
    ("TC-130.5", "Session cookie's SameSite attribute does not meaningfully protect this endpoint from CSRF", "SameSite Attribute Provides No Meaningful CSRF Protection"),
    ("TC-130.6", "JSON-body API endpoint's protection does not survive a form-shaped Content-Type switch", "CSRF Protection Bypassed By Content-Type Switch"),
)

_SPOOFED_ORIGIN = "https://attacker-controlled.invalid"


def _looks_like_csrf_token_field(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _CSRF_TOKEN_NAME_HINTS)


def find_csrf_token_field(endpoint: Endpoint) -> str | None:
    return next((p for p in endpoint.parameters if _looks_like_csrf_token_field(p)), None)


def _placeholder_value(name: str) -> str:
    lowered = name.lower()
    if "email" in lowered:
        return "stof-probe@example.invalid"
    if any(h in lowered for h in ("amount", "sum", "total", "qty", "quantity", "number", "num")):
        return "1"
    return "stofprobe"


def _field_values(endpoint: Endpoint) -> dict[str, str]:
    """A crawl-time-captured value (a hidden CSRF token's real value,
    a `<select>`'s default option) wins where one exists; every other
    field gets a small, harmless placeholder -- same "legitimate-shaped,
    non-destructive test data" spirit as every other gated write-verb
    technique in this codebase."""
    return {name: endpoint.parameter_values.get(name) or _placeholder_value(name) for name in endpoint.parameters}


def _extract_hidden_field_value(body: str, field_name: str) -> str | None:
    """Best-effort `value=` extraction for one named `<input>` field out
    of raw HTML -- the form-field counterpart to `auth_tests.py`'s own
    `_extract_token_field` (which parses a JSON body instead). Needed
    for TC-130.4: the attacker role's own fresh token has to come from
    a LIVE GET of the form as that role, since `_field_values()`'s
    crawl-time `parameter_values` snapshot reflects whichever role
    crawled the target, not necessarily the attacker role this
    technique needs a token for. Deliberately a small regex, not a
    real HTML parser -- same "small and high-signal" scope as the rest
    of this file, matches `name=`/`value=` in either attribute order
    since real markup varies."""
    escaped = re.escape(field_name)
    for pattern in (
        rf'name=["\']{escaped}["\'][^>]*?value=["\']([^"\']*)["\']',
        rf'value=["\']([^"\']*)["\'][^>]*?name=["\']{escaped}["\']',
    ):
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def _candidate_form_endpoints(endpoints: list[Endpoint], limit: int) -> list[Endpoint]:
    forms = [e for e in endpoints if e.endpoint_type == "form" and e.method.upper() == "POST" and e.parameters]
    deduped = list({e.url: e for e in forms}.values())
    return deduped[:limit]


def _candidate_json_api_endpoints(endpoints: list[Endpoint], limit: int) -> list[Endpoint]:
    """TC-130.6's candidate set -- deliberately disjoint from
    `_candidate_form_endpoints()`: a real `<form endpoint_type=='api'`
    endpoint with at least one field the crawler tagged
    `param_location=='body'`. `api_sniffer.py`'s own `_body_param_names`
    only ever tags a field 'body' when it successfully parsed a real
    `application/json` request body (see that function) -- so this is a
    reliable, code-verified proxy for "this endpoint's caller sent
    JSON", not a name-based guess. A "form" endpoint never reaches this
    list; it has no JSON-only content-type assumption to bypass, and is
    already TC-130.1-.4's own territory."""
    apis = [
        e for e in endpoints
        if e.endpoint_type == "api"
        and e.method.upper() in ("POST", "PUT", "PATCH")
        and any(e.location_for(p) == "body" for p in e.parameters)
    ]
    deduped = list({e.url: e for e in apis}.values())
    return deduped[:limit]


def _samesite_csrf_issue(cookie: dict, token_field_missing: bool, origin_not_validated: bool) -> str | None:
    """Pure, directly-unit-testable CSRF-framed SameSite check --
    deliberately NOT `session_weakness_tests._cookie_flag_issue`, which
    checks the same underlying attribute for a different question
    (does this flag combination expose the cookie to theft/replay).
    This one asks: does SameSite, as actually set on THIS cookie,
    provide real CSRF protection for a specific endpoint this module
    has already probed live.

    - `SameSite=None` is an unconditional gap by spec (RFC 6265bis):
      sent on every cross-site request regardless of navigation type.
      Always flagged, no compounding needed.
    - `SameSite=Strict` is the strongest setting and is never flagged,
      even alongside other gaps on the same endpoint -- it blocks the
      forged cross-site request outright.
    - `SameSite=Lax` (the modern Chrome/Edge/Opera default -- NOT
      Firefox/Safari) or no explicit attribute at all is flagged ONLY
      when this SAME endpoint independently failed both TC-130.1 (no
      token field) and TC-130.3 (Origin/Referer not validated): Lax
      does block a classic cross-site POST-form submission in most
      current browsers, so flagging it alone here would just restate
      TC-129.5's own missing-flag finding under a new ID. It does NOT
      block a top-level cross-site GET navigation, and Chrome's own
      'Lax+POST' default-cookie behavior leaves roughly a 2-minute
      window after issuance where a cross-site POST still carries it
      -- so when the OTHER two independent layers (token, origin) are
      also both absent on this endpoint, "SameSite alone is holding
      the line" is a real, non-redundant compounding-risk statement.
    """
    name = cookie.get("name", "")
    same_site = cookie.get("sameSite")
    if same_site == "None":
        return f"cookie '{name}' sets SameSite=None, which provides no CSRF protection at all from this mechanism by design"
    if same_site == "Strict":
        return None
    if token_field_missing and origin_not_validated:
        qualifier = f"SameSite={same_site!r}" if same_site else "no explicit SameSite attribute (relying on the browser's Lax default, which not every browser applies)"
        return (
            f"cookie '{name}' has {qualifier}, and this same endpoint also has no anti-CSRF token field "
            "(TC-130.1) and does not validate Origin/Referer (TC-130.3) -- SameSite=Lax/default blocks a "
            "classic cross-site POST-form submission in most current browsers, but not a top-level cross-site "
            "GET navigation, and leaves a real bypass window shortly after the cookie is issued, so with both "
            "other independent CSRF defenses also absent on this endpoint, SameSite is the ONLY layer standing"
        )
    return None


def _looks_like_successful_submission(status: int, body: str) -> bool:
    if status in (401, 403, 429):
        return False
    if any(marker in body.lower() for marker in _REJECTION_MARKERS):
        return False
    return status < 400  # 2xx or a 3xx redirect -- both common "the write went through" shapes


async def _submit_form(context, url: str, fields: dict[str, str], headers: dict[str, str] | None = None) -> tuple[int, str]:
    try:
        resp = await context.request.post(url, form=fields, headers=headers or {}, max_redirects=0)
        return resp.status, await resp.text()
    except Exception as exc:
        return 0, str(exc)


async def _submit_json(context, url: str, fields: dict[str, str]) -> tuple[int, str]:
    """TC-130.6's JSON-baseline counterpart to `_submit_form` -- a real
    `application/json` request body, matching how the crawler's own
    `api_sniffer.py` originally observed this endpoint being called."""
    try:
        resp = await context.request.post(
            url, data=json_module.dumps(fields), headers={"Content-Type": "application/json"}, max_redirects=0,
        )
        return resp.status, await resp.text()
    except Exception as exc:
        return 0, str(exc)


@dataclass
class CsrfTestConfig:
    test_role: str | None = None
    # The `test_role` user's own configured `auth_type` -- supplied by
    # the caller (main.py, from already-loaded `UserConfig`) rather than
    # this module importing `stof.config`/`stof.auth` internals, the
    # same "receive it as a parameter" rule CLAUDE.md's own no-cross-
    # sibling-import section states.
    role_auth_type: str | None = None
    # TC-130.4 only: a second, independently authenticatable role whose
    # own session is used to submit a state-changing POST carrying the
    # FIRST role's (`test_role`'s) harvested token -- mirrors the
    # `low_priv_role`/`high_priv_role` two-role convention `idor_tests.py`
    # already uses, kept as a distinct field (not overloading `test_role`)
    # since TC-130.1-.3 are single-role and must stay that way unchanged.
    victim_role: str | None = None
    # Kept distinct from `role_auth_type` (which already means "test_role's
    # own auth_type") rather than overloading it, since TC-130.4 needs both
    # roles' auth_types checked independently and TC-130.1-.3 must not be
    # affected by whatever the victim role's auth_type is.
    victim_role_auth_type: str | None = None
    allow_state_changing_probes: bool = False
    max_endpoints_to_probe: int = 3
    # TC-130.6 only: a separate, small cap for the disjoint JSON-API
    # candidate set (`_candidate_json_api_endpoints`) -- kept distinct
    # from `max_endpoints_to_probe` so tuning the form-endpoint cap
    # never silently changes how many JSON-API endpoints get probed,
    # and vice versa.
    max_json_endpoints_to_probe: int = 3


class CsrfTestsModule(VulnModule):
    module_id = "csrf_tests"
    name = "Cross-Site Request Forgery (CSRF) Tests"
    phase = 1

    def __init__(self, config: CsrfTestConfig | None = None) -> None:
        self.config = config or CsrfTestConfig()

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _result(self, technique_id: str, technique: str, vuln_type: str, status: str, detail: str,
                endpoint: Endpoint | None = None, finding: Finding | None = None) -> TestCaseResult:
        return self._make_result(
            test_id="TC-130", technique_id=technique_id, technique=technique, vuln_type=vuln_type,
            status=status, detail=detail, role=self.config.test_role, endpoint=endpoint, finding=finding,
        )

    def _skip_all(self, reason: str) -> list[TestCaseResult]:
        return [self._result(tid, technique, vuln_type, SKIPPED, reason) for tid, technique, vuln_type in _TECHNIQUES]

    # --- TC-130.1 No anti-CSRF token field at all -------------------------

    def _check_missing_token_field(self, endpoint: Endpoint) -> TestCaseResult:
        tid, technique, vuln_type = _TECHNIQUES[0]
        token_field = find_csrf_token_field(endpoint)
        if token_field is None:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.1,
                endpoint=endpoint, user_role=self.config.test_role,
                request_raw=f"POST {endpoint.url} (fields discovered: {endpoint.parameters})",
                response_raw="(structural check against the discovered form -- no live request made)",
                description=(
                    f"'{endpoint.url}' is a discovered state-changing POST form with no field whose "
                    f"name looks like an anti-CSRF token among its {len(endpoint.parameters)} "
                    f"discovered field(s): {endpoint.parameters}."
                ),
                recommendation="Add a per-session, per-request anti-CSRF token to every state-changing form, and validate it server-side on submission.",
            )
            return self._result(tid, technique, vuln_type, FAIL, finding.description, endpoint=endpoint, finding=finding)
        return self._result(tid, technique, vuln_type, PASS,
                             f"'{endpoint.url}' has a token-shaped field ('{token_field}') among its discovered fields "
                             "-- presence alone doesn't confirm real server-side validation, see TC-130.2/.3", endpoint=endpoint)

    # --- TC-130.2 / TC-130.3 -- share one baseline submission -------------

    async def _probe_endpoint_write_techniques(self, context, endpoint: Endpoint, evidence) -> tuple[TestCaseResult, TestCaseResult]:
        tid2, technique2, vuln_type2 = _TECHNIQUES[1]
        tid3, technique3, vuln_type3 = _TECHNIQUES[2]
        token_field = find_csrf_token_field(endpoint)
        full_fields = _field_values(endpoint)

        baseline_status, baseline_body = await _submit_form(context, endpoint.url, full_fields)
        if not _looks_like_successful_submission(baseline_status, baseline_body):
            detail = f"could not establish a working baseline submission for '{endpoint.url}' (HTTP {baseline_status}) to compare against"
            return (
                self._result(tid2, technique2, vuln_type2, "ERROR", detail, endpoint=endpoint),
                self._result(tid3, technique3, vuln_type3, "ERROR", detail, endpoint=endpoint),
            )

        result2 = await self._check_stripped_token(context, endpoint, token_field, full_fields, baseline_status, evidence)
        result3 = await self._check_spoofed_origin(context, endpoint, full_fields, baseline_status, evidence)
        return result2, result3

    async def _check_stripped_token(self, context, endpoint: Endpoint, token_field: str | None,
                                     full_fields: dict[str, str], baseline_status: int, evidence) -> TestCaseResult:
        tid, technique, vuln_type = _TECHNIQUES[1]
        if token_field is None:
            return self._result(tid, technique, vuln_type, SKIPPED,
                                 f"'{endpoint.url}' has no anti-CSRF-token-shaped field to strip (see TC-130.1)", endpoint=endpoint)

        stripped_fields = {k: v for k, v in full_fields.items() if k != token_field}
        status, body = await _submit_form(context, endpoint.url, stripped_fields)
        if _looks_like_successful_submission(status, body):
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.1,
                endpoint=endpoint, user_role=self.config.test_role,
                request_raw=f"POST {endpoint.url} (fields: {sorted(stripped_fields)}, '{token_field}' field removed)",
                response_raw=f"HTTP {status} (baseline submission with the token included: HTTP {baseline_status})",
                description=(
                    f"'{endpoint.url}' accepted a state-changing POST with its '{token_field}' anti-CSRF "
                    f"token field removed entirely (HTTP {status}), the same as the baseline request that "
                    f"included it (HTTP {baseline_status}) -- the server does not actually validate the "
                    "token's presence."
                ),
                recommendation="Reject any state-changing request missing its anti-CSRF token field server-side, and validate the token's value against the session, not just its presence in the form markup.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"csrf-stripped-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
            return self._result(tid, technique, vuln_type, FAIL, finding.description, endpoint=endpoint, finding=finding)
        return self._result(tid, technique, vuln_type, PASS,
                             f"removing the '{token_field}' field caused a different/rejected response (HTTP {status} vs. baseline HTTP {baseline_status})", endpoint=endpoint)

    async def _check_spoofed_origin(self, context, endpoint: Endpoint, full_fields: dict[str, str],
                                     baseline_status: int, evidence) -> TestCaseResult:
        tid, technique, vuln_type = _TECHNIQUES[2]
        status, body = await _submit_form(
            context, endpoint.url, full_fields,
            headers={"Origin": _SPOOFED_ORIGIN, "Referer": f"{_SPOOFED_ORIGIN}/csrf-poc.html"},
        )
        if _looks_like_successful_submission(status, body):
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.1,
                endpoint=endpoint, user_role=self.config.test_role,
                request_raw=f"POST {endpoint.url}\nOrigin: {_SPOOFED_ORIGIN}\nReferer: {_SPOOFED_ORIGIN}/csrf-poc.html",
                response_raw=f"HTTP {status} (baseline same-site submission: HTTP {baseline_status})",
                description=(
                    f"'{endpoint.url}' accepted a state-changing POST carrying a spoofed cross-site "
                    f"Origin/Referer header ('{_SPOOFED_ORIGIN}') alongside the role's real cookies "
                    f"(HTTP {status}), the same as a legitimate same-site request (HTTP {baseline_status}) "
                    "-- the server does not validate the request's origin."
                ),
                recommendation="Validate the Origin (falling back to Referer) header server-side on every state-changing request, in addition to a per-session anti-CSRF token.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"csrf-origin-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
            return self._result(tid, technique, vuln_type, FAIL, finding.description, endpoint=endpoint, finding=finding)
        return self._result(tid, technique, vuln_type, PASS,
                             f"a spoofed cross-site Origin/Referer caused a different/rejected response (HTTP {status} vs. baseline HTTP {baseline_status})", endpoint=endpoint)

    # --- TC-130.4 -- token harvested from a DIFFERENT session's role ------

    def _victim_role_usable(self) -> str | None:
        """`None` when TC-130.4 can actually run; otherwise the reason
        string for cleanly SKIPping just TC-130.4 -- kept separate from
        `run_techniques()`'s top-of-function `_skip_all` gates (which
        apply to all four techniques) since a single-role target is a
        legitimate reason to skip TC-130.4 alone without touching
        TC-130.1-.3, per the plan's SKIP-not-ERROR convention."""
        if not self.config.victim_role:
            return "no victim_role configured for this target -- TC-130.4 needs a second, independently authenticatable role"
        if self.config.victim_role == self.config.test_role:
            return "victim_role is the same as test_role -- TC-130.4 needs two distinct roles to demonstrate a cross-session token"
        if self.config.victim_role_auth_type == "jwt":
            return (
                f"victim role '{self.config.victim_role}' authenticates via a bearer token/header (auth_type "
                "'jwt'), which has no session-cookie concept for a token-not-bound-to-session check to test"
            )
        return None

    async def _harvest_attacker_token(self, attacker_context, endpoint: Endpoint, token_field: str) -> str | None:
        probe = await self._probe_get(attacker_context, endpoint.url)
        if probe is None:
            return None
        _status, body = probe
        return _extract_hidden_field_value(body, token_field)

    async def _check_token_not_bound_to_session(
        self, attacker_context, session_manager, session_pool, endpoint: Endpoint, token_field: str | None, evidence,
    ) -> TestCaseResult:
        tid, technique, vuln_type = _TECHNIQUES[3]
        if token_field is None:
            return self._result(tid, technique, vuln_type, SKIPPED,
                                 f"'{endpoint.url}' has no anti-CSRF-token-shaped field to test cross-session (see TC-130.1)", endpoint=endpoint)

        harvested_token = await self._harvest_attacker_token(attacker_context, endpoint, token_field)
        if harvested_token is None:
            return self._result(tid, technique, vuln_type, "ERROR",
                                 f"could not harvest a fresh '{token_field}' value from a live GET of '{endpoint.url}' as role '{self.config.test_role}'",
                                 endpoint=endpoint)

        try:
            _victim_session, victim_context = await self._authenticated_context(
                session_manager, session_pool, self.config.victim_role, endpoint.url
            )
        except KeyError as exc:
            return self._result(tid, technique, vuln_type, SKIPPED, f"victim role not configured: {exc}", endpoint=endpoint)

        full_fields = _field_values(endpoint)
        baseline_status, baseline_body = await _submit_form(victim_context, endpoint.url, full_fields)
        if not _looks_like_successful_submission(baseline_status, baseline_body):
            return self._result(tid, technique, vuln_type, "ERROR",
                                 f"could not establish a working baseline submission for '{endpoint.url}' under victim role "
                                 f"'{self.config.victim_role}' (HTTP {baseline_status}) to compare against", endpoint=endpoint)

        cross_fields = {**full_fields, token_field: harvested_token}
        status, body = await _submit_form(victim_context, endpoint.url, cross_fields)
        if _looks_like_successful_submission(status, body):
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.1,
                endpoint=endpoint, user_role=self.config.victim_role,
                request_raw=(
                    f"POST {endpoint.url} (fields: {sorted(cross_fields)}, '{token_field}'={harvested_token!r} "
                    f"harvested from role '{self.config.test_role}''s own session) submitted using role "
                    f"'{self.config.victim_role}''s session cookies"
                ),
                response_raw=f"HTTP {status} (victim's own known-working same-session baseline: HTTP {baseline_status})",
                description=(
                    f"'{endpoint.url}' accepted a state-changing POST submitted with role "
                    f"'{self.config.victim_role}''s session cookies but carrying a '{token_field}' anti-CSRF "
                    f"token value harvested from a DIFFERENT role's ('{self.config.test_role}''s) own session "
                    f"(HTTP {status}), the same response shape as a known-working same-session baseline "
                    f"(HTTP {baseline_status}) -- the server validates that a token is well-formed/known but "
                    "not that it belongs to the specific session presenting it. Evidence bar actually met: "
                    "response status/body matches a known-working baseline with no rejection marker (the "
                    "same status/body evidence TC-130.2/.3 use) -- this does not additionally confirm, via a "
                    "before/after read-back, that the state change was independently observed to apply under "
                    "the victim's own account."
                ),
                recommendation="Bind every anti-CSRF token to the specific session/user it was issued for, and validate that binding server-side on submission -- not just the token's presence or general well-formedness.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"csrf-cross-session-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
            return self._result(tid, technique, vuln_type, FAIL, finding.description, endpoint=endpoint, finding=finding)
        return self._result(tid, technique, vuln_type, PASS,
                             f"submitting role '{self.config.victim_role}''s session with role '{self.config.test_role}''s "
                             f"token caused a different/rejected response (HTTP {status} vs. baseline HTTP {baseline_status})",
                             endpoint=endpoint)

    # --- TC-130.5 SameSite attribute CSRF relevance ------------------------

    async def _session_cookies_for_samesite(self, context, session_pool, target_url: str) -> dict[str, dict]:
        """Computed ONCE per `run_techniques()` call (not per endpoint):
        the cookie's `SameSite` attribute is a property of how the
        session was issued, not of any one endpoint. Returns `{}` (not
        raising) on any failure to reach `target_url` anonymously --
        callers treat an empty result as "no session cookie identified",
        the same SKIP-worthy outcome TC-129.5 already gives that case."""
        anon_context = await session_pool.new_anonymous_context()
        try:
            probe = await self._probe_get(anon_context, target_url)
            if probe is None:
                return {}
            anon_cookies = await anon_context.cookies()
        finally:
            await anon_context.close()
        authenticated_cookies = await context.cookies()
        return _new_or_changed_cookies(anon_cookies, authenticated_cookies)

    def _check_samesite_csrf_relevance(
        self, endpoint: Endpoint, session_cookies: dict[str, dict], token_result: TestCaseResult, origin_result: TestCaseResult,
    ) -> TestCaseResult:
        tid, technique, vuln_type = _TECHNIQUES[4]
        if not session_cookies:
            return self._result(tid, technique, vuln_type, SKIPPED,
                                 "no session/auth cookie identified for this role (e.g. a non-cookie-based auth target)", endpoint=endpoint)

        token_field_missing = token_result.status == FAIL
        origin_not_validated = origin_result.status == FAIL
        for name in sorted(session_cookies):
            issue = _samesite_csrf_issue(session_cookies[name], token_field_missing, origin_not_validated)
            if issue is None:
                continue
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.4,
                endpoint=endpoint, user_role=self.config.test_role,
                request_raw=f"session cookie '{name}' for role '{self.config.test_role}', observed against '{endpoint.url}'",
                response_raw=f"cookie '{name}': sameSite={session_cookies[name].get('sameSite')!r}; this endpoint's TC-130.1={token_result.status}, TC-130.3={origin_result.status}",
                description=f"'{endpoint.url}': {issue}.",
                recommendation="Set SameSite=Strict where the application's navigation flow allows it, or SameSite=Lax at minimum with Secure set, and do not rely on SameSite alone -- pair it with a validated anti-CSRF token and Origin/Referer checking.",
            )
            return self._result(tid, technique, vuln_type, FAIL, finding.description, endpoint=endpoint, finding=finding)
        return self._result(tid, technique, vuln_type, PASS,
                             f"{len(session_cookies)} session cookie(s) either set SameSite=Strict, or this endpoint's own "
                             f"anti-CSRF token/Origin checks (TC-130.1={token_result.status}, TC-130.3={origin_result.status}) "
                             "mean SameSite isn't the sole defense here", endpoint=endpoint)

    # --- TC-130.6 Content-Type switch bypass --------------------------------

    async def _check_content_type_switch(self, context, endpoint: Endpoint, evidence) -> TestCaseResult:
        tid, technique, vuln_type = _TECHNIQUES[5]
        fields = _field_values(endpoint)
        json_status, json_body = await _submit_json(context, endpoint.url, fields)
        if not _looks_like_successful_submission(json_status, json_body):
            return self._result(tid, technique, vuln_type, "ERROR",
                                 f"could not establish a working JSON baseline submission for '{endpoint.url}' (HTTP {json_status}) to compare against", endpoint=endpoint)

        form_status, form_body = await _submit_form(context, endpoint.url, fields)
        if _looks_like_successful_submission(form_status, form_body):
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
                endpoint=endpoint, user_role=self.config.test_role,
                request_raw=f"POST {endpoint.url} (fields: {sorted(fields)}) as Content-Type: application/x-www-form-urlencoded (a plain HTML <form> can produce this without JavaScript)",
                response_raw=f"HTTP {form_status} (application/json baseline for the same fields: HTTP {json_status})",
                description=(
                    f"'{endpoint.url}' is a discovered JSON-body API endpoint whose handler accepted the same "
                    f"field data resubmitted as application/x-www-form-urlencoded (HTTP {form_status}), the "
                    f"same as an application/json baseline (HTTP {json_status}) -- any CSRF-defense argument "
                    "resting on 'this endpoint only accepts JSON, which a cross-site <form> can't send without "
                    "JavaScript' does not hold here, since the handler does not actually gate on Content-Type."
                ),
                recommendation="Reject requests whose Content-Type doesn't match what the handler expects, and don't rely on Content-Type restriction as a CSRF defense on its own -- pair it with a validated anti-CSRF token.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"csrf-contenttype-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
            return self._result(tid, technique, vuln_type, FAIL, finding.description, endpoint=endpoint, finding=finding)
        return self._result(tid, technique, vuln_type, PASS,
                             f"the form-urlencoded resubmission caused a different/rejected response (HTTP {form_status} vs. JSON baseline HTTP {json_status})", endpoint=endpoint)

    async def run_techniques(
        self,
        endpoints: list["Endpoint"],
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[TestCaseResult]:
        role = self.config.test_role
        if not role:
            return self._skip_all("no test_role configured for this target")
        if self.config.role_auth_type == "jwt":
            return self._skip_all(
                f"role '{role}' authenticates via a bearer token/header (auth_type 'jwt'), which a cross-site "
                "request can't get the victim's browser to attach the way it automatically attaches a cookie "
                "-- CSRF doesn't meaningfully apply"
            )
        if not self.config.allow_state_changing_probes:
            return self._skip_all(
                "CSRF probing submits real state-changing requests (a baseline, a stripped-token retry, a "
                "spoofed-origin retry) and is disabled by default -- set CsrfTestConfig."
                "allow_state_changing_probes=True for an authorized engagement window"
            )

        candidates = _candidate_form_endpoints(endpoints, self.config.max_endpoints_to_probe)
        json_candidates = _candidate_json_api_endpoints(endpoints, self.config.max_json_endpoints_to_probe)
        if not candidates and not json_candidates:
            return self._skip_all("no discovered state-changing POST form endpoint or JSON-body-shaped API endpoint to test")

        try:
            _session, context = await self._authenticated_context(
                session_manager, session_pool, role, (candidates or json_candidates)[0].url
            )
        except KeyError as exc:
            return self._skip_all(f"role not configured: {exc}")

        if not candidates:
            # TC-130.1-.5 all need a discovered state-changing POST FORM
            # endpoint (SameSite relevance is framed relative to those
            # techniques' own results); TC-130.6 alone has its own,
            # disjoint JSON-API candidate set and still runs below.
            results = [
                self._result(tid, technique, vuln_type, SKIPPED, "no discovered state-changing POST form endpoint to test")
                for tid, technique, vuln_type in _TECHNIQUES[:5]
            ]
            results.extend(await self._run_content_type_switch_checks(context, json_candidates, evidence))
            return results

        victim_skip_reason = self._victim_role_usable()
        session_cookies = await self._session_cookies_for_samesite(context, session_pool, candidates[0].url)

        per_endpoint = await asyncio.gather(*(
            self._check_csrf_endpoint(context, session_manager, session_pool, endpoint, victim_skip_reason, session_cookies, evidence)
            for endpoint in candidates
        ))
        results: list[TestCaseResult] = []
        for endpoint_results in per_endpoint:
            results.extend(endpoint_results)

        results.extend(await self._run_content_type_switch_checks(context, json_candidates, evidence))
        return results

    async def _check_csrf_endpoint(
        self, context, session_manager, session_pool, endpoint, victim_skip_reason, session_cookies, evidence,
    ) -> list[TestCaseResult]:
        """One endpoint's own full CSRF check sequence (missing-token
        field, write-technique probes, cross-session token check,
        SameSite relevance) -- split out of the caller's loop so
        different endpoints (different forms, different resources) can
        run concurrently. The steps WITHIN one endpoint stay in their
        original order/sequence, unchanged."""
        results: list[TestCaseResult] = []
        result1 = self._check_missing_token_field(endpoint)
        results.append(result1)
        try:
            result2, result3 = await self._probe_endpoint_write_techniques(context, endpoint, evidence)
            results.append(result2)
            results.append(result3)
        except Exception as exc:
            _log.warning(f"CSRF probe failed for '{endpoint.url}': {exc}")
            _, technique2, vuln_type2 = _TECHNIQUES[1]
            _, technique3, vuln_type3 = _TECHNIQUES[2]
            result3 = self._result("TC-130.3", technique3, vuln_type3, "ERROR", str(exc), endpoint=endpoint)
            results.append(self._result("TC-130.2", technique2, vuln_type2, "ERROR", str(exc), endpoint=endpoint))
            results.append(result3)

        tid4, technique4, vuln_type4 = _TECHNIQUES[3]
        if victim_skip_reason:
            results.append(self._result(tid4, technique4, vuln_type4, SKIPPED, victim_skip_reason, endpoint=endpoint))
        else:
            try:
                token_field = find_csrf_token_field(endpoint)
                results.append(await self._check_token_not_bound_to_session(
                    context, session_manager, session_pool, endpoint, token_field, evidence
                ))
            except Exception as exc:
                _log.warning(f"CSRF cross-session probe failed for '{endpoint.url}': {exc}")
                results.append(self._result(tid4, technique4, vuln_type4, "ERROR", str(exc), endpoint=endpoint))

        results.append(self._check_samesite_csrf_relevance(endpoint, session_cookies, result1, result3))
        return results

    async def _run_content_type_switch_checks(self, context, json_candidates: list[Endpoint], evidence) -> list[TestCaseResult]:
        """TC-130.6's own loop, factored out so both the normal
        (form-candidates-found) path and the form-candidates-empty path
        above can share it without duplicating the SKIP/ERROR shape."""
        tid6, technique6, vuln_type6 = _TECHNIQUES[5]
        if not json_candidates:
            return [self._result(tid6, technique6, vuln_type6, SKIPPED,
                                  "no discovered JSON-body-shaped API endpoint to test (endpoint_type=='api' with a crawler-observed JSON body field)")]
        async def _check_one(json_endpoint) -> TestCaseResult:
            try:
                return await self._check_content_type_switch(context, json_endpoint, evidence)
            except Exception as exc:
                _log.warning(f"CSRF content-type-switch probe failed for '{json_endpoint.url}': {exc}")
                return self._result(tid6, technique6, vuln_type6, "ERROR", str(exc), endpoint=json_endpoint)

        return list(await asyncio.gather(*(_check_one(e) for e in json_candidates)))
