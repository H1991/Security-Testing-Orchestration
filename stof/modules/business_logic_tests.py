"""Layer 9 — `stof/modules/business_logic_tests.py`: Business Logic /
Identity Testing (TC-135), grounded in OWASP WSTG-BUSL and
WSTG-IDNT-01/02.

Business logic vulnerabilities are, almost by definition, application-
specific -- a generic scanner cannot know what "the discount should
never exceed 50%" or "a negative quantity should be rejected" means for
an arbitrary target. This module deliberately builds only the narrow
slice of WSTG-BUSL/IDNT that is genuinely target-agnostic and safely
automatable, and says so explicitly rather than padding out fake
"generic" coverage:

- TC-135.1 / TC-135.2 (WSTG-IDNT-01 "Testing Role Definitions" /
  WSTG-IDNT-02 "Test User Registration Process"): IF the crawler
  discovered a self-service registration/account-creation form, probe
  it for (a) reserved/privileged username acceptance and (b) a role/
  privilege-shaped field on the form itself being honored at signup.
  Both are real, bounded, WSTG-endorsed checks that need nothing
  target-specific beyond "does a registration form exist."
- TC-135.3 (WSTG-BUSL "Test Business Logic Data Validation" family --
  specifically the workflow-integrity sub-case, sometimes catalogued as
  "Testing for Process Timing" / "Test Upload of Unexpected File Types"
  siblings under WSTG-BUSL): IF the crawler discovered 2+ endpoints that
  look like sequential steps of one flow (shared path prefix, an
  explicit step/stage-shaped query param or path segment), check
  whether a later step is reachable directly, skipping the earlier
  step(s) it should depend on.

Deliberately NOT built here, and why: price manipulation, quantity/
negative-value tampering, discount/coupon-code abuse, and shopping-cart
subtotal manipulation are all real, well-documented WSTG-BUSL
categories -- but each requires knowing, for THIS target, what a valid
price/quantity/discount even looks like (a field named `qty` could be
a page-size selector, a transfer amount, or a literal cart quantity;
there is no safe, generic way to pick a value that's "wrong" without
already knowing the schema). Automating them generically produces
either false positives (flagging a value the app was always going to
reject) or false negatives (missing exploitable ranges) -- see
`stof/payloads/business_logic_knowledge_base.json` for the full
reasoning. They stay a human pentester's job for this project's Phase 1
scope, same as the "candidate-detect vs. auto-exploit" line this
project already draws for RCE/DoS gadget chains.

Both TC-135.1/.2 (account creation) and TC-135.3 (skipping a step of a
real workflow) are write-verb / state-creating actions against the live
target, so -- matching `mass_assignment_tests.py`'s / `configuration_
tests.py`'s convention for anything that isn't a pure read -- both are
gated behind `allow_state_changing_probes`.
"""
from __future__ import annotations

import asyncio
import re
import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlsplit

from stof.core.logger import get_logger
from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding

from ._idor_shared import _PRIVILEGE_FIELD_NAMES, _method_request_fn
from .base import _PASSWORD_FIELD_HINTS, _USERNAME_FIELD_HINTS, VulnModule
from .results import FAIL, PASS, SKIPPED, TestCaseResult

if TYPE_CHECKING:
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.business_logic_tests")

# WSTG-IDNT-02's own worked examples: usernames a registration flow
# should always reject as already-reserved/system identities, regardless
# of whether an account literally exists with that name yet.
_RESERVED_USERNAMES: tuple[str, ...] = ("admin", "administrator", "root", "support")

# Path-shape hints for a self-service registration/account-creation
# form -- same "small, curated, high-signal" convention as this
# project's other hint lists (`configuration_tests._ADMIN_PANEL_PATHS`,
# `base.py`'s own `_USERNAME_FIELD_HINTS`).
_REGISTRATION_PATH_HINTS: tuple[str, ...] = ("register", "signup", "sign-up", "sign_up", "createaccount", "create-account", "create_account", "newaccount", "new-account")

# Substrings in a response body that indicate the app correctly rejected
# a signup attempt (username taken/reserved/invalid) -- checked so a 200
# response that's actually an inline validation-error page isn't
# mistaken for a successful account creation.
_SIGNUP_REJECTION_SIGNATURES: tuple[str, ...] = (
    "already exists", "already taken", "already registered", "in use",
    "not available", "reserved", "invalid username", "cannot be used", "unavailable",
)

# Step/stage-shaped query-param or path-segment names for TC-135.3's
# multi-step-workflow detection.
_STEP_PARAM_NAMES: tuple[str, ...] = ("step", "stage", "phase")
_STEP_PATH_SEGMENT_RE = re.compile(r"^(?:step|stage|wizard)[-_]?(\d+)$", re.IGNORECASE)
_STEP_QUERY_VALUE_RE = re.compile(r"^\d+$")


# TC-135.4 -- URL-shaped hints for a "should only succeed once per
# request" endpoint (redeem a code, cast a vote, claim a reward). No
# generic way to know a target's actual once-only semantics, so this
# stays a hint-keyword candidate list, same "detect a plausible
# candidate, never assume" convention as every other endpoint-hint
# list in this codebase (`_REGISTRATION_PATH_HINTS`, `_URL_PARAM_HINTS`
# in `ssrf_tests.py`, ...).
_LIMITED_USE_PATH_HINTS: tuple[str, ...] = (
    "redeem", "claim", "vote", "apply-coupon", "apply_coupon", "coupon",
    "activate", "use-code", "use_code", "checkout", "submit-once",
)


def _find_limited_use_endpoint(endpoints: list[Endpoint]) -> Endpoint | None:
    return next(
        (e for e in endpoints if e.method.upper() in ("POST", "PUT") and any(hint in e.url.lower() for hint in _LIMITED_USE_PATH_HINTS)),
        None,
    )


def _find_registration_endpoint(endpoints: list[Endpoint]) -> Endpoint | None:
    """A discovered POST endpoint on a registration-shaped path whose
    parameters look like a username field AND a password field --
    the same generic "field-name hint, not hardcoded exact name"
    convention as `base.find_login_endpoint`, applied to account
    creation instead of login. Prefers `endpoint_type == "form"` (the
    crawler's own HTML-form discovery) for the same reason
    `find_login_endpoint` does."""
    candidates = [
        e for e in endpoints
        if e.method.upper() == "POST"
        and any(hint in e.url.lower() for hint in _REGISTRATION_PATH_HINTS)
        and any(h in p.lower() for p in e.parameters for h in _USERNAME_FIELD_HINTS)
        and any(h in p.lower() for p in e.parameters for h in _PASSWORD_FIELD_HINTS)
    ]
    if not candidates:
        return None
    return next((e for e in candidates if e.endpoint_type == "form"), candidates[0])


def _username_param(endpoint: Endpoint) -> str | None:
    return next((p for p in endpoint.parameters if any(h in p.lower() for h in _USERNAME_FIELD_HINTS)), None)


def _password_params(endpoint: Endpoint) -> list[str]:
    return [p for p in endpoint.parameters if any(h in p.lower() for h in _PASSWORD_FIELD_HINTS)]


def _role_like_param(endpoint: Endpoint) -> str | None:
    """Reuses `_idor_shared._PRIVILEGE_FIELD_NAMES` -- the exact
    role/privilege-shaped field-name convention `mass_assignment_
    tests.py`'s TC-052.4 already established for this project -- but
    applied here to a CREATE/registration form's own declared
    parameters (does the signup form itself expose a role-shaped
    field?) rather than to a profile-UPDATE response body (does an
    injected field get echoed back as applied?). Those are genuinely
    different questions -- TC-052.4 tests whether an UNDECLARED field
    is silently bound; this tests whether a DECLARED field is honored
    with an elevated value -- so the shared constant is reused rather
    than the whole mass-assignment technique."""
    return next(
        (p for p in endpoint.parameters if p.lower() in _PRIVILEGE_FIELD_NAMES and not any(h in p.lower() for h in _PASSWORD_FIELD_HINTS)),
        None,
    )


def _fill_registration_payload(endpoint: Endpoint, username: str, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Builds a payload matching the registration form's OWN declared
    parameter names -- username/password params filled with the
    supplied/random values, everything else filled with a generic
    placeholder so the submission is well-formed regardless of this
    target's exact field naming."""
    password = f"Stof-{secrets.token_hex(6)}!"
    payload: dict[str, str] = {}
    username_param = _username_param(endpoint)
    password_params = _password_params(endpoint)
    for param in endpoint.parameters:
        if param == username_param:
            payload[param] = username
        elif param in password_params:
            payload[param] = password
        elif "email" in param.lower():
            payload[param] = f"stof-{secrets.token_hex(4)}@stof-probe.invalid"
        else:
            payload[param] = f"stof-{secrets.token_hex(3)}"
    if extra:
        payload.update(extra)
    return payload


def _looks_like_signup_success(status: int, body: str) -> bool:
    if status not in (200, 201, 302):
        return False
    lowered = (body or "").lower()
    return not any(sig in lowered for sig in _SIGNUP_REJECTION_SIGNATURES)


def _step_value(url: str) -> tuple[str, int] | None:
    """Returns `(prefix, step_number)` if `url` looks like one step of a
    multi-step flow -- either a `?step=N`/`?stage=N`/`?phase=N` query
    param, or a `/wizard/N`, `/step-N`, `/stageN` path segment. `prefix`
    is the URL with the step-carrying piece stripped out, so two
    endpoints of the SAME flow at DIFFERENT steps compare equal on it."""
    parts = urlsplit(url)
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if name.lower() in _STEP_PARAM_NAMES and _STEP_QUERY_VALUE_RE.match(value):
            prefix = urlsplit(url)._replace(query="").geturl()
            return prefix, int(value)
    segments = parts.path.split("/")
    for i, segment in enumerate(segments):
        m = _STEP_PATH_SEGMENT_RE.match(segment)
        if m:
            prefix_segments = segments.copy()
            prefix_segments[i] = "{step}"
            prefix = urlsplit(url)._replace(path="/".join(prefix_segments)).geturl()
            return prefix, int(m.group(1))
    return None


def _find_multistep_flow(endpoints: list[Endpoint]) -> tuple[Endpoint, Endpoint] | None:
    """Groups discovered endpoints by their step-stripped prefix; if any
    group has 2+ distinct step numbers, returns `(earliest, latest)` --
    the pair TC-135.3 needs to test "can the latest step be reached
    directly, without going through the earliest one first." Returns
    `None` if no such multi-step group exists (the honest, expected
    outcome for a target with no wizard-shaped flow)."""
    by_prefix: dict[str, list[tuple[int, Endpoint]]] = {}
    for endpoint in endpoints:
        parsed = _step_value(endpoint.url)
        if parsed is None:
            continue
        prefix, step = parsed
        by_prefix.setdefault(prefix, []).append((step, endpoint))
    for group in by_prefix.values():
        if len({step for step, _ in group}) >= 2:
            group.sort(key=lambda pair: pair[0])
            return group[0][1], group[-1][1]
    return None


@dataclass
class BusinessLogicTestConfig:
    allow_state_changing_probes: bool = False
    reserved_usernames: tuple[str, ...] = field(default_factory=lambda: _RESERVED_USERNAMES)
    min_content_length: int = 50


class BusinessLogicTestsModule(VulnModule):
    module_id = "business_logic_tests"
    name = "Business Logic / Identity Tests"
    phase = 1

    def __init__(self, config: BusinessLogicTestConfig | None = None) -> None:
        self.config = config or BusinessLogicTestConfig()

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        from .results import extract_findings
        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _result(self, technique_id: str, technique: str, status: str, detail: str,
                endpoint=None, finding: Finding | None = None) -> TestCaseResult:
        return self._make_result(
            test_id="TC-135", technique_id=technique_id, technique=technique,
            vuln_type="Business Logic / Identity Testing", status=status, detail=detail,
            role="unauthenticated", endpoint=endpoint, finding=finding,
        )

    def _gated_skip(self, technique_id: str, technique: str, reason: str) -> TestCaseResult:
        return self._result(technique_id, technique, SKIPPED,
                             f"{reason} -- set BusinessLogicTestConfig.allow_state_changing_probes=True for an authorized engagement window")

    async def _technique_reserved_username(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-135.1", "Reserved/privileged username accepted at self-service registration (WSTG-IDNT-02)"
        vuln_type = "Business Logic -- Reserved Username Accepted at Registration"
        registration_endpoint = _find_registration_endpoint(endpoints)
        if registration_endpoint is None:
            return self._result(tid, technique, SKIPPED, "no self-service registration/account-creation form discovered by the crawler")
        if not self.config.allow_state_changing_probes:
            return self._gated_skip(tid, technique, "reserved-username registration probing creates real accounts and is disabled by default")

        context = await session_pool.new_anonymous_context()
        try:
            for username in self.config.reserved_usernames:
                payload = _fill_registration_payload(registration_endpoint, username)
                try:
                    resp = await _method_request_fn(context, "POST")(registration_endpoint.url, form=payload, max_redirects=0)
                    body = await resp.text()
                except Exception as exc:
                    _log.warning(f"reserved-username probe failed for {registration_endpoint.url} ({username!r}): {exc}")
                    continue
                if _looks_like_signup_success(resp.status, body) and len(body) >= self.config.min_content_length:
                    finding = Finding(
                        module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.3,
                        endpoint=registration_endpoint, user_role="unauthenticated",
                        request_raw=f"POST {registration_endpoint.url}\n{payload}",
                        response_raw=f"HTTP {resp.status}, {len(body)} bytes, no rejection signature present",
                        description=(
                            f"'{registration_endpoint.url}' accepted a self-service registration for the reserved/"
                            f"privileged username '{username}' (HTTP {resp.status}) instead of rejecting it, "
                            "risking impersonation of a system/support identity or collision with a future real admin account."
                        ),
                        recommendation="Reject registration attempts for reserved/system usernames (admin, administrator, root, support, ...) server-side, independent of whether that literal account currently exists.",
                    )
                    finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"buslogic-reserved-username-{username}") if evidence else []
                    return self._result(tid, technique, FAIL, finding.description, endpoint=registration_endpoint, finding=finding)
            return self._result(tid, technique, PASS, f"'{registration_endpoint.url}': {len(self.config.reserved_usernames)} reserved username(s) tried; all were rejected")
        finally:
            await context.close()

    async def _technique_self_assigned_privilege(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-135.2", "Self-assigned elevated privilege honored at registration (WSTG-IDNT-01)"
        vuln_type = "Business Logic -- Self-Assigned Privilege at Registration"
        registration_endpoint = _find_registration_endpoint(endpoints)
        if registration_endpoint is None:
            return self._result(tid, technique, SKIPPED, "no self-service registration/account-creation form discovered by the crawler")
        role_param = _role_like_param(registration_endpoint)
        if role_param is None:
            return self._result(tid, technique, SKIPPED, f"'{registration_endpoint.url}': registration form exposes no role/privilege-shaped field")
        if not self.config.allow_state_changing_probes:
            return self._gated_skip(tid, technique, "self-assigned-privilege registration probing creates a real account and is disabled by default")

        username = f"stof-buslogic-{secrets.token_hex(4)}"
        elevated_value = "true" if role_param.lower() in ("isadmin", "is_admin", "admin") else "admin"
        payload = _fill_registration_payload(registration_endpoint, username, extra={role_param: elevated_value})
        context = await session_pool.new_anonymous_context()
        try:
            try:
                resp = await _method_request_fn(context, "POST")(registration_endpoint.url, form=payload, max_redirects=0)
                body = await resp.text()
            except Exception as exc:
                return self._result(tid, technique, "ERROR", f"probe failed: {exc}")
        finally:
            await context.close()

        signed_up = _looks_like_signup_success(resp.status, body) and len(body) >= self.config.min_content_length
        role_echoed = f'"{role_param}"' in body.replace(" ", "").lower() and elevated_value.lower() in body.lower()
        if signed_up and role_echoed:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=8.6,
                endpoint=registration_endpoint, user_role="unauthenticated",
                request_raw=f"POST {registration_endpoint.url}\n{payload}",
                response_raw=f"HTTP {resp.status}, {body[:300]}",
                description=(
                    f"'{registration_endpoint.url}' exposes a role/privilege-shaped field ('{role_param}') on its "
                    f"self-service registration form and honored an elevated value ('{elevated_value}') supplied "
                    "by an anonymous, unauthenticated signup request, letting any visitor create a privileged account for themselves."
                ),
                recommendation="Never accept role/privilege fields from a public registration endpoint; assign the default lowest-privilege role server-side and require an authenticated admin action to elevate any account.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="buslogic-self-assigned-privilege") if evidence else []
            return self._result(tid, technique, FAIL, finding.description, endpoint=registration_endpoint, finding=finding)
        return self._result(tid, technique, PASS, f"'{registration_endpoint.url}': registering with '{role_param}={elevated_value}' was not honored (signed_up={signed_up}, role_echoed={role_echoed})")

    async def _technique_workflow_step_skipping(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-135.3", "Business-logic authorization bypass via workflow step skipping (WSTG-BUSL)"
        vuln_type = "Business Logic -- Workflow Step Skipping"
        flow = _find_multistep_flow(endpoints)
        if flow is None:
            return self._result(tid, technique, SKIPPED, "no multi-step workflow (shared path prefix with a step/stage-shaped query param or path segment) discovered by the crawler")
        earliest, latest = flow
        if not self.config.allow_state_changing_probes:
            return self._gated_skip(tid, technique, "workflow-step probing requests real state-creating endpoints out of sequence and is disabled by default")

        context = await session_pool.new_anonymous_context()
        try:
            method_fn = _method_request_fn(context, latest.method.upper())
            try:
                resp = await method_fn(latest.url, max_redirects=0)
                body = await resp.text()
            except Exception as exc:
                return self._result(tid, technique, "ERROR", f"probe failed: {exc}")
        finally:
            await context.close()

        reached_directly = resp.status == 200 and len(body) >= self.config.min_content_length and not any(
            sig in body.lower() for sig in ("please complete step", "session expired", "start over", "invalid step")
        )
        if reached_directly:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=6.5,
                endpoint=latest, user_role="unauthenticated",
                request_raw=f"{latest.method} {latest.url}",
                response_raw=f"HTTP {resp.status}, {len(body)} bytes, no step-order rejection signature",
                description=(
                    f"'{latest.url}', a later step of the multi-step flow beginning at '{earliest.url}', was reachable "
                    "directly with a fresh, unauthenticated-of-that-flow session, without completing the earlier step(s) first."
                ),
                recommendation="Track workflow progress server-side (e.g. a per-session flow-state token) and reject any request for a later step whose prerequisite step(s) haven't been completed in this session.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="buslogic-workflow-step-skip") if evidence else []
            return self._result(tid, technique, FAIL, finding.description, endpoint=latest, finding=finding)
        return self._result(tid, technique, PASS, f"'{latest.url}' was not reachable directly ahead of '{earliest.url}' (HTTP {resp.status})")

    async def _technique_race_condition(self, endpoints, session_pool, evidence) -> TestCaseResult:
        """TC-135.4 (tracker TC-096) -- fires two structurally identical
        requests at a discovered limited-use-shaped endpoint
        CONCURRENTLY (`asyncio.gather`, not sequential) and checks
        whether both come back looking like independent successes. This
        can never itself prove the underlying state was double-applied
        (STOF has no way to inspect the target's database/ledger), so a
        hit is reported honestly as "both concurrent requests succeeded
        independently -- worth manual review for a real race window",
        never as a confirmed double-spend/double-redemption. Bounded at
        exactly two concurrent requests -- enough to observe the
        signal, never a real load/stress test against the target."""
        tid, technique = "TC-135.4", "Concurrent duplicate submission to a limited-use endpoint (race condition)"
        vuln_type = "Business Logic -- Race Condition on Limited-Use Action"
        target = _find_limited_use_endpoint(endpoints)
        if target is None:
            return self._result(tid, technique, SKIPPED, "no redeem/claim/vote/coupon-shaped endpoint discovered by the crawler")
        if not self.config.allow_state_changing_probes:
            return self._gated_skip(tid, technique, "sends two real concurrent write requests to a limited-use endpoint and is disabled by default")

        context = await session_pool.new_anonymous_context()
        try:
            method_fn = _method_request_fn(context, target.method.upper())
            payload = {p: "stof-race-probe" for p in target.parameters}
            try:
                resp_a, resp_b = await asyncio.gather(
                    method_fn(target.url, form=payload, max_redirects=0),
                    method_fn(target.url, form=payload, max_redirects=0),
                )
                body_a, body_b = await resp_a.text(), await resp_b.text()
            except Exception as exc:
                return self._result(tid, technique, "ERROR", f"probe failed: {exc}")
        finally:
            await context.close()

        conflict_signals = ("already", "duplicate", "used", "conflict", "one at a time", "try again")
        both_look_successful = (
            resp_a.status < 400 and resp_b.status < 400
            and not any(sig in body_a.lower() for sig in conflict_signals)
            and not any(sig in body_b.lower() for sig in conflict_signals)
        )
        if both_look_successful:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.9,
                endpoint=target, user_role="unauthenticated",
                request_raw=f"2x concurrent {target.method} {target.url}",
                response_raw=f"HTTP {resp_a.status} and HTTP {resp_b.status}, neither response contains a conflict/duplicate/already-used signal",
                description=(
                    f"Two structurally identical requests fired concurrently at '{target.url}' both came back looking like "
                    "independent successes, with no conflict/duplicate-shaped rejection on either -- consistent with (but not "
                    "proof of) a race window that could let a limited-use action be applied more than once. STOF cannot inspect "
                    "the target's own state/ledger to confirm the underlying effect was actually double-applied; this needs manual review."
                ),
                recommendation="Serialize limited-use actions server-side (a DB-level unique constraint, row lock, or atomic compare-and-set) rather than relying on request-level validation alone, which two concurrent requests can both pass before either has committed its effect.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="buslogic-race-condition") if evidence else []
            return self._result(tid, technique, FAIL, finding.description, endpoint=target, finding=finding)
        return self._result(tid, technique, PASS,
                             f"'{target.url}': two concurrent requests returned HTTP {resp_a.status}/{resp_b.status} with no both-succeeded signal")

    @staticmethod
    async def _sequential_usage_probes(method_fn, target: Endpoint, count: int) -> list[tuple[int, bool]]:
        """The actual `count`-call sequential loop for TC-135.5, pulled
        out of the technique method itself purely to keep that method's
        own cyclomatic complexity in line with its sibling techniques in
        this file -- no behavior difference from an inline loop."""
        conflict_signals = ("already", "duplicate", "used", "conflict", "one at a time", "try again", "limit", "not eligible")
        payload = {p: "stof-usage-limit-probe" for p in target.parameters}
        responses: list[tuple[int, bool]] = []
        for _ in range(count):
            resp = await method_fn(target.url, form=payload, max_redirects=0)
            body = await resp.text()
            looks_rejected = resp.status >= 400 or any(sig in body.lower() for sig in conflict_signals)
            responses.append((resp.status, looks_rejected))
        return responses

    async def _technique_function_usage_limit(self, endpoints, session_pool, evidence) -> TestCaseResult:
        """TC-135.5 (tracker TC-098, WSTG-BUSL-05 "Test Function Usage
        Limits"): fires the SAME structurally identical request at a
        discovered limited-use-shaped endpoint several times in a row,
        sequentially (unlike TC-135.4's concurrent probe) -- checking
        whether an app-defined usage cap (one redemption per coupon, one
        vote per poll, one claim per reward) is enforced at all once the
        first call has actually completed, not just whether two
        simultaneous calls can both slip through. Bounded at exactly 3
        sequential calls: enough to observe "the 2nd/3rd call still
        looks like a fresh success" without hammering the target."""
        tid, technique = "TC-135.5", "Sequential over-limit calls to a limited-use endpoint are not rejected (WSTG-BUSL-05)"
        vuln_type = "Business Logic -- Missing Function Usage Limit"
        target = _find_limited_use_endpoint(endpoints)
        if target is None:
            return self._result(tid, technique, SKIPPED, "no redeem/claim/vote/coupon-shaped endpoint discovered by the crawler")
        if not self.config.allow_state_changing_probes:
            return self._gated_skip(tid, technique, "sends 3 real sequential write requests to a limited-use endpoint and is disabled by default")

        context = await session_pool.new_anonymous_context()
        try:
            method_fn = _method_request_fn(context, target.method.upper())
            try:
                responses = await self._sequential_usage_probes(method_fn, target, count=3)
            except Exception as exc:
                return self._result(tid, technique, "ERROR", f"probe failed: {exc}")
        finally:
            await context.close()

        all_succeeded = all(not rejected for _, rejected in responses)
        if all_succeeded:
            statuses = ", ".join(str(s) for s, _ in responses)
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.3,
                endpoint=target, user_role="unauthenticated",
                request_raw=f"3x sequential {target.method} {target.url} (same payload each time)",
                response_raw=f"HTTP {statuses}, none contained a limit/duplicate/rejection signal",
                description=(
                    f"The same request sent 3 times in a row to '{target.url}' looked like an independent success every "
                    "time, with no limit/duplicate-shaped rejection appearing even on the 2nd or 3rd call -- consistent "
                    "with a missing usage cap on what looks like a one-time action (redeem/claim/vote/coupon)."
                ),
                recommendation="Enforce the intended usage limit server-side (a redeemed/claimed flag checked and set atomically before applying the action's effect), not just at first-call time.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="buslogic-function-usage-limit") if evidence else []
            return self._result(tid, technique, FAIL, finding.description, endpoint=target, finding=finding)
        rejected_at = next(i + 1 for i, (_, rejected) in enumerate(responses) if rejected)
        return self._result(tid, technique, PASS, f"'{target.url}': call #{rejected_at} of 3 was rejected -- a usage limit appears enforced")

    async def run_techniques(
        self,
        endpoints: list["Endpoint"],
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[TestCaseResult]:
        results: list[TestCaseResult] = []
        for tid, technique, coro in (
            ("TC-135.1", "Reserved/privileged username accepted at self-service registration (WSTG-IDNT-02)", self._technique_reserved_username(endpoints, session_pool, evidence)),
            ("TC-135.2", "Self-assigned elevated privilege honored at registration (WSTG-IDNT-01)", self._technique_self_assigned_privilege(endpoints, session_pool, evidence)),
            ("TC-135.3", "Business-logic authorization bypass via workflow step skipping (WSTG-BUSL)", self._technique_workflow_step_skipping(endpoints, session_pool, evidence)),
            ("TC-135.4", "Concurrent duplicate submission to a limited-use endpoint (race condition)", self._technique_race_condition(endpoints, session_pool, evidence)),
            ("TC-135.5", "Sequential over-limit calls to a limited-use endpoint are not rejected (WSTG-BUSL-05)", self._technique_function_usage_limit(endpoints, session_pool, evidence)),
        ):
            results.append(await self._safe_result(coro, "TC-135", tid, technique, "Business Logic / Identity Testing", role="unauthenticated"))
        return results
