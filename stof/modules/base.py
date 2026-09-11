"""Layer 9 — Vulnerability Modules: the `VulnModule` plugin contract.

Signature deviates from CLAUDE.md's documented shape in one place, and
it's called out here rather than silently changed:

    CLAUDE.md:  async def run(self, endpoints, session_manager, runner, evidence) -> list[Finding]

    Here:       async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]

- `runner: WorkflowRunner` dropped. `WorkflowRunner` (Layer 6) replays
  *recorded* browser workflows -- login flows, multi-step journeys. The
  Phase-1 modules built so far (IDOR, privilege escalation, JWT
  tampering) test *discovered endpoints* directly via raw authenticated
  HTTP requests (`context.request.get/post`, reusing the session's
  cookies/headers) -- the same technique Burp's own IDOR/BFLA testing
  uses. A module that DOES need to replay a recorded flow (e.g. a CSRF
  test that must resubmit a real multi-step form) should still take
  `runner` -- this base class doesn't forbid a wider `run()` signature,
  it just doesn't require the parameter every module has no use for.
- `session_pool: SessionPool` (Layer 3B) stays alongside `evidence`,
  not instead of it: modules still need the authenticated
  `BrowserContext` for raw request probing, which is a different job
  than evidence capture.
- `evidence: EvidenceCollector | None = None` -- now that Layer 12
  exists, this matches CLAUDE.md's spec, but stays optional and
  defaults to `None` rather than required: a module must still run
  correctly (just with `Finding.evidence_refs` left empty) when no
  collector is wired in, matching "screenshot.py is called ... when a
  finding is confirmed" -- evidence capture is opportunistic, not a
  hard dependency of the finding logic itself. This also keeps every
  unit test written before Layer 12 existed passing unchanged.

`registry.py` is expected to update every call site the same way Layer
8's `test_orchestrator.py` already anticipated (see its own docstring).

`run_techniques()` -- added alongside `run()`, not instead of it -- is
the structured, per-exploit-technique counterpart CLAUDE.md's original
`run() -> list[Finding]` contract can't express: a Finding only ever
exists for a confirmed vulnerability, so `run()` alone has no way to
report "this technique ran and the target resisted it" (a PASS) versus
"this technique never got to run on this target" (a SKIP). Deliberately
NOT made abstract -- `run()` stays the one required method, so every
`VulnModule` written before `TestCaseResult` (Layer 9's own
`results.py`) existed keeps satisfying the ABC unchanged (see
`tests/unit/test_modules_base.py`, which instantiates a subclass that
implements only `run()`). The default implementation below degrades
gracefully for such a module: it calls `run()` and reports each
resulting Finding as a single FAIL, with no PASS/SKIP visibility into
techniques that found nothing -- a module that wants the real
per-technique breakdown overrides `run_techniques()` directly instead
(see `idor_tests.py` / `jwt_tests.py`).
"""
from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from stof.cleanup import mark_cleanup_result, record_planted_state
from stof.core.logger import get_logger
from stof.core.rate_limiter import throttled

if TYPE_CHECKING:
    from stof.crawler.endpoint_store import Endpoint
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.findings.models import Finding
    from stof.session.session_manager import SessionManager

    from .results import TestCaseResult

_log = get_logger("modules.base")

# Substrings that mark a transient browser/network failure -- the kind
# that should be retried, not reported as a security result. Originally
# `idor_tests.py`-only (live-observed against this project's own demo
# target: a single `net::ERR_NETWORK_CHANGED` during authentication used
# to propagate out of a module's whole base run and get silently
# swallowed into an empty result, which then reported as PASS ("target
# resisted") instead of ERROR ("couldn't test") -- a false clean scan),
# promoted here so every `VulnModule`'s `_authenticated_context` gets
# the same retry-before-reporting-a-negative-result protection, not
# just IDOR's.
_TRANSIENT_ERROR_MARKERS = (
    "ERR_NETWORK_CHANGED", "ERR_NETWORK", "ERR_CONNECTION", "ERR_TIMED_OUT",
    "ERR_INTERNET_DISCONNECTED", "ERR_ABORTED", "ERR_CONNECTION_RESET",
    "Execution context was destroyed", "Timeout", "net::", "is interrupted by another navigation",
)


def _is_transient_error(exc: Exception) -> bool:
    message = str(exc)
    return any(marker in message for marker in _TRANSIENT_ERROR_MARKERS)


# Field-name hints for spotting a real HTML login form among discovered
# endpoints, regardless of a target's own field naming (`uid`/`passw`,
# `username`/`password`, ...). Originally `sqli_tests.py`-only (built
# for TC-127.4's login-bypass technique); promoted here alongside
# `_is_transient_error` so `auth_tests.py`/`session_weakness_tests.py`
# can discover the same real login form as a fallback when no
# JSON-API login endpoint is configured for a target, instead of each
# re-deriving their own copy of this logic.
_USERNAME_FIELD_HINTS = ("user", "uid", "email", "login")
_PASSWORD_FIELD_HINTS = ("pass", "pwd", "passw")


def find_login_endpoint(endpoints: "list[Endpoint]") -> "Endpoint | None":
    """A discovered POST endpoint whose parameters look like a
    username field AND a password field together -- the generic
    signal a real login form always has, regardless of this target's
    own field names (`uid`/`passw` here, `username`/`password`
    elsewhere). Prefers `endpoint_type == "form"` (the crawler's own
    HTML-form discovery) over an API-shaped POST that happens to share
    those field names, since the HTML form is the real login
    submission target this technique needs -- not a JSON-API-only
    config value with no HTML-form equivalent (the exact gap this
    function exists to close)."""
    candidates = [
        e for e in endpoints
        if e.method.upper() == "POST"
        and any(h in p.lower() for p in e.parameters for h in _USERNAME_FIELD_HINTS)
        and any(h in p.lower() for p in e.parameters for h in _PASSWORD_FIELD_HINTS)
    ]
    if not candidates:
        return None
    return next((e for e in candidates if e.endpoint_type == "form"), candidates[0])


class VulnModule(ABC):
    module_id: str
    name: str
    phase: int

    async def _new_page(self, session_pool: "SessionPool", role: str):
        context = await session_pool.get_context(role)
        return await context.new_page()

    async def _authenticated_context(self, session_manager, session_pool, role: str, target_url: str, attempts: int = 3):
        """Every technique in every module gets its authenticated
        context through here (promoted from `IdorTestsModule`, which
        had this fix first -- see `_TRANSIENT_ERROR_MARKERS` above for
        why). A transient browser/network failure during authentication
        must NOT propagate out and get swallowed into an empty result
        that then reports as PASS -- that produced a false clean scan
        where the real tests silently never ran. A `KeyError` (role not
        configured) is a real, non-transient signal and is re-raised
        immediately so the caller's existing SKIPPED handling still
        fires."""
        last_exc: Exception | None = None
        for attempt in range(attempts):
            try:
                page = await self._new_page(session_pool, role)
                try:
                    session = await session_manager.get_session(role, page)
                finally:
                    await page.close()
                context = await session_pool.apply_session(session, target_url)
                return session, context
            except KeyError:
                raise  # role/provider not configured -- not transient, don't retry
            except Exception as exc:
                last_exc = exc
                if not _is_transient_error(exc) or attempt == attempts - 1:
                    raise
                _log.warning(f"transient error authenticating role '{role}' (attempt {attempt + 1}/{attempts}), retrying: {exc}")
                await asyncio.sleep(1.0)
        raise last_exc  # unreachable: the loop either returns or raises

    def _register_cleanup(
        self, technique_id: str, kind: str, identifier: str,
        endpoint_url: "str | None" = None, role: "str | None" = None,
        metadata: "dict | None" = None,
    ) -> "str | None":
        """Every state-changing technique (gated behind
        `allow_state_changing_probes`) calls this right after its real
        write succeeds -- see `stof/cleanup/registry.py`'s own docstring
        for why this exists. `identifier` should be whatever unique
        marker/username/value the technique already generated for its
        own detection oracle (every write-verb technique in this
        codebase already builds one); do not invent a second one just
        for cleanup tracking. A no-op (returns `None`, never raises)
        when no scan is currently configured for cleanup tracking (e.g.
        a unit test constructing this module directly) -- every
        existing technique keeps working unchanged either way."""
        return record_planted_state(
            module_id=self.module_id, technique_id=technique_id, kind=kind, identifier=identifier,
            endpoint_url=endpoint_url, role=role, metadata=metadata,
        )

    def _mark_cleanup_result(self, entry_id: "str | None", status: str, detail: str) -> None:
        """Companion to `_register_cleanup` for a technique that DOES
        have a real, already-implemented revert path (e.g.
        `auth_tests.py`'s password-change probes reverting in their own
        `finally` block) -- call this with the outcome so it's visible
        in the report. `entry_id` is whatever `_register_cleanup`
        returned (may be `None` if cleanup tracking wasn't configured,
        in which case this is a silent no-op)."""
        mark_cleanup_result(entry_id, status, detail)

    async def _probe_get(self, context, url: str, **kwargs) -> "tuple[int, str] | None":
        """The try/GET/read-body/except-log-continue shape duplicated
        across ~20+ technique call sites in every GET-probing module
        (`idor_tests.py`, `bfla_tests.py`, `role_tests.py`,
        `auth_tests.py`, `configuration_tests.py`, `disclosure_tests.py`).
        Returns `None` on any request/read failure (network error,
        timeout, ...) instead of raising -- every existing call site
        already treated a failed probe as "skip/continue", not a hard
        error, so centralizing the try/except here changes no outcome,
        only removes the copy-paste. `max_redirects=0` matches every
        caller's existing behavior; pass `max_redirects=...` in
        `kwargs` to override it for a caller that needs to."""
        kwargs.setdefault("max_redirects", 0)
        try:
            resp = await throttled(context.request.get(url, **kwargs))
            body = await resp.text()
        except Exception as exc:
            _log.warning(f"probe failed for {url}: {exc}")
            return None
        return resp.status, body

    async def _safe_result(
        self, coro, test_id: str, technique_id: str, technique: str, vuln_type: str,
        role: "str | None" = None,
    ) -> "TestCaseResult":
        """Unifies `idor_tests.py`'s old `_safe_one` and `auth_tests.py`'s
        old `_safe_call`: run one technique coroutine, converting any
        unexpected exception into an ERROR `TestCaseResult` instead of
        aborting every other technique in the module's `run_techniques()`
        loop. Calls `self._make_result()` directly (not a module's own
        `_result()` wrapper) -- verified field-by-field against every
        module's own `_result()` before this substitution: `idor_tests.py`'s
        passes `role=None` through unchanged (matching `_make_result`'s own
        default, so omitting it here changes nothing), but `auth_tests.py`'s
        `_result()` fixes `role=self.config.test_role` on every call, which
        `_make_result` alone can't reproduce -- hence the explicit `role`
        parameter here (defaults to `None`, `auth_tests.py`'s call sites
        pass `self.config.test_role`) rather than assuming every module's
        wrapper does nothing beyond what `_make_result` already does."""
        try:
            return await coro
        except Exception as exc:
            _log.warning(f"technique {technique_id} failed unexpectedly: {exc}")
            return self._make_result(
                test_id=test_id, technique_id=technique_id, technique=technique,
                vuln_type=vuln_type, status="ERROR", detail=str(exc), role=role,
            )

    def _make_result(
        self, *, test_id: str, technique_id: str, technique: str, vuln_type: str,
        status: str, detail: str, severity: str = "Critical", role: "str | None" = None,
        endpoint=None, finding: "Finding | None" = None,
    ) -> "TestCaseResult":
        """Shared `TestCaseResult` construction every vuln module's own
        `_result()` used to duplicate near-identically (same fields,
        same `module_id`/`severity` plumbing, differing only in which
        pieces each module fixes vs. takes as a parameter). Each
        module keeps its own `_result()` with its own natural call-site
        shape -- e.g. `configuration_tests.py` fixes `test_id`/
        `vuln_type`/`role` and only takes `technique_id`/`status`/
        `detail` -- and delegates the actual construction here.

        `finding.severity` -- when a `Finding` is attached -- always
        wins over the `severity` parameter/default. Real, live bug this
        fixes: almost no module's own `_result()` wrapper ever passed
        `severity=` through explicitly, so every FAIL silently fell back
        to this function's `"Critical"` default regardless of the
        finding's REAL severity (a High/Medium/Low finding still
        reported as Critical in the terminal, the per-scan log, and the
        live `finding` WebSocket event/dashboard KPI -- confirmed live:
        a 27-finding scan with a real 2/18/6/1 Critical/High/Medium/Info
        split showed "33 Critical, 0 High" everywhere BUT the final
        saved report, because only `extract_findings()` (Layer 10) ever
        read `finding.severity` directly; this constructor didn't).
        A PASS/SKIP/ERROR result has no finding, so `severity` there
        still just passes through unchanged -- there is nothing more
        authoritative to prefer for those."""
        from .results import TestCaseResult

        return TestCaseResult(
            test_id=test_id, technique_id=technique_id, technique=technique, vuln_type=vuln_type,
            module_id=self.module_id, severity=finding.severity if finding is not None else severity,
            status=status, detail=detail, user_role=role, endpoint=endpoint, finding=finding,
        )

    @abstractmethod
    async def run(
        self,
        endpoints: list["Endpoint"],
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list["Finding"]:
        ...

    async def run_techniques(
        self,
        endpoints: list["Endpoint"],
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list["TestCaseResult"]:
        from .results import FAIL, TestCaseResult

        findings = await self.run(endpoints, session_manager, session_pool, evidence)
        return [
            TestCaseResult(
                test_id=f.vuln_type,
                technique_id=f.finding_id,
                technique=f.vuln_type,
                vuln_type=f.vuln_type,
                module_id=self.module_id,
                severity=f.severity,
                status=FAIL,
                detail=f.description,
                user_role=f.user_role,
                endpoint=f.endpoint,
                finding=f,
            )
            for f in findings
        ]
