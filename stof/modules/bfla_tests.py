"""TC-055 -- Missing Function-Level Authorization (BFLA) techniques,
split out of `idor_tests.py` (which had grown to 1,576 lines carrying
every authorization family in one file).

`BFLATechniquesMixin` is composed into `IdorTestsModule` via multiple
inheritance, not registered as its own `VulnModule` -- it has no
`module_id`/`config`/`authorization_matrix` of its own and isn't
usable standalone. That's deliberate: TC-050/TC-052's reuse logic
(`_techniques_tc050`, `_techniques_tc052` in `idor_tests.py`) depends
on TC-053/TC-055/TC-056 findings all having run inside the same scan
pass and shares session/evidence/matrix plumbing that would otherwise
have to cross a real module boundary -- CLAUDE.md's own rule against
cross-module imports between siblings. A mixin keeps the *file*
split (smaller, focused, independently readable) without adding a
second module identity, config flag, or registry entry for something
that was never a separate testable unit.

Every GET-based ALLOWED/DENIED decision below routes through
`classify_response()`/`AuthorizationDecision` and records into
`self.authorization_matrix`, same as `idor_tests.py`'s own TC-053.5.
TC-055.2 (`_technique_bfla_state_changing`) is the one exception:
it's a write-verb success/failure check (POST/PUT/PATCH/DELETE), where
a 204 No Content response is a legitimate "the write succeeded"
signal -- `classify_response()`'s ALLOWED branch requires a
substantial body, which is the right rule for "can I read this" but
would wrongly reclassify a real DELETE success as UNKNOWN. Left as a
direct status-code check for that reason, not an oversight.
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from stof.authorization.decision import AuthorizationDecision, classify_response
from stof.core.logger import get_logger
from stof.engine.interceptor import RequestInterceptor
from stof.findings.models import Finding

from ._idor_shared import _HIDDEN_ENDPOINT_WORDLIST, _content_fingerprint, _looks_privileged, _method_request_fn, _synthetic_endpoint
from ._probe_shared import control_fingerprint, sweep_paths
from .results import FAIL, PASS, SKIPPED, TestCaseResult

_log = get_logger("modules.bfla_tests")

# TC-055.6's own "does this look like a phrase a real denial page would
# show" wordlist. Deliberately phrase-based, not a content/byte diff --
# confirmed live against a real target that a plain length/hash
# comparison of the same authorized page loaded twice false-positives
# constantly (a relative timestamp like "13 days ago" changes between
# two loads of the IDENTICAL, correctly-authorized page). Presence/
# absence of an explicit denial phrase, plus whether the SPA's own
# client-side router redirected away from the requested URL, is a far
# more precise signal.
_DENIAL_TEXT_MARKERS = (
    "access denied", "unauthorized", "you do not have permission", "you don't have permission",
    "forbidden", "not authorized", "permission denied", "you don't have access", "you do not have access",
)

# Narrow, precise field-name heuristic for TC-055.6's JSON response
# rewriting -- deliberately a short, specific list (not a guess at
# every possible boolean field) to keep the false-positive rate near
# zero: these are the field names an authorization-check response
# realistically uses, not generic app data.
_AUTHZ_BOOLEAN_FIELD_NAMES = (
    "authorized", "isauthorized", "canedit", "canview", "candelete", "canapprove",
    "hasaccess", "haspermission", "allowed", "isallowed", "isadmin",
)


def _looks_denied(final_url: str, requested_url: str, body_text: str) -> bool:
    """TC-055.6's pure denial-detection signal: either the SPA's own
    client-side router redirected away from the URL that was actually
    requested, or the rendered text contains an explicit denial phrase.
    Deliberately NOT a content-length/hash diff against a baseline --
    confirmed live against a real target that natural per-load noise
    (a relative timestamp like "13 days ago", a notification counter)
    changes between two loads of the exact same, correctly-authorized
    page, which would make any raw diff false-positive constantly."""
    if final_url.rstrip("/") != requested_url.rstrip("/"):
        return True
    lowered = body_text.lower()
    return any(marker in lowered for marker in _DENIAL_TEXT_MARKERS)


class BFLATechniquesMixin:
    async def _test_vertical_privilege_escalation(self, endpoints, session_manager, session_pool, target_url, evidence=None) -> list[Finding]:
        # Deduped by URL, not (method, url): this probe always issues a
        # GET regardless of how the endpoint was discovered, so a page
        # the crawler saw twice (e.g. a GET page load AND a POST form
        # targeting the same admin.jsp URL) must only be probed once --
        # confirmed against this project's own demo target, which
        # crawled `/admin/admin.jsp` as both a GET page and a POST form
        # and produced a duplicate finding before this dedup existed.
        privileged_endpoints = list({
            e.url: e for e in endpoints if _looks_privileged(e.url, self.config.privileged_path_hints)
        }.values())
        if not privileged_endpoints:
            return []

        session, context = await self._authenticated_context(session_manager, session_pool, self.low_priv_role, target_url)

        findings: list[Finding] = []
        for endpoint in privileged_endpoints:
            probe = await self._probe_get(context, endpoint.url)
            if probe is None:
                continue
            status, body = probe
            decision = classify_response(status, body, min_content_length=self.config.min_content_length)
            self.authorization_matrix.record(endpoint, self.low_priv_role, decision)
            if decision == AuthorizationDecision.ALLOWED:
                finding = Finding(
                    module_id=self.module_id,
                    vuln_type="Vertical Privilege Escalation / Broken Function Level Authorization",
                    severity="High",
                    cvss_score=8.8,
                    endpoint=endpoint,
                    user_role=self.low_priv_role,
                    request_raw=f"GET {endpoint.url}",
                    response_raw=f"HTTP {status}, {len(body)} bytes",
                    description=(
                        f"A low-privileged, authenticated session (role '{self.low_priv_role}') "
                        f"was able to fully access '{endpoint.url}', a path that pattern-matches "
                        f"a privileged/administrative function, receiving HTTP {status} and "
                        f"{len(body)} bytes of content instead of being denied."
                    ),
                    recommendation=(
                        "Enforce function-level authorization server-side on every privileged "
                        "endpoint: verify the authenticated user's role/permissions grant access "
                        "to this specific function before executing it, independent of whether "
                        "the endpoint happens to be unlinked from the UI that role can see -- "
                        "hiding a link is not access control."
                    ),
                )
                finding.evidence_refs = await self._capture_evidence(
                    evidence, context, session, endpoint.url, label=f"privesc-{endpoint.url.rsplit('/', 1)[-1]}", finding=finding)
                findings.append(finding)
        return findings

    async def _technique_bfla_state_changing(self, endpoints, session_manager, session_pool, target_url, evidence) -> list[TestCaseResult]:
        test_id, tid, technique = "TC-055", "TC-055.2", "Calling a privileged operation (state-changing) with a normal-user session"
        vuln_type = "Missing Function-Level Authorization (BFLA) via a state-changing request"
        if not self.config.allow_state_changing_probes:
            return [self._gated_skip(test_id, tid, technique, vuln_type, "state-changing BFLA probing is disabled by default")]
        # NOT gated on `_looks_privileged()`'s URL-naming heuristic --
        # confirmed live against a real target whose write endpoints are
        # plainly named (`/api/add-category`, `/api/delete-category`,
        # `/api/publish-article`, no "admin"/"manage" anywhere) but
        # still had ZERO independent server-side authorization: a
        # read-only session could call them directly and the server
        # accepted every one. Requiring an admin-sounding URL before
        # even trying this probe was silently skipping exactly the
        # class of app this technique exists to catch. Every write
        # endpoint is a real BFLA candidate regardless of what it's
        # named; privileged-looking ones are tried first since they're
        # the highest-confidence candidates, capped by
        # `max_bfla_write_endpoints` so a target with a large discovered
        # surface doesn't turn this into an unbounded write-probe spree.
        write_endpoints = {
            e.url: e for e in endpoints if e.method.upper() in ("POST", "PUT", "PATCH", "DELETE")
        }
        ranked = sorted(write_endpoints.values(), key=lambda e: not _looks_privileged(e.url, self.config.privileged_path_hints))
        privileged_write_endpoints = ranked[: self.config.max_bfla_write_endpoints]
        if not privileged_write_endpoints:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, "no POST/PUT/PATCH/DELETE endpoint discovered")]
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.low_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        results: list[TestCaseResult] = []
        for endpoint in privileged_write_endpoints:
            try:
                resp = await _method_request_fn(context, endpoint.method.upper())(endpoint.url, max_redirects=0)
            except Exception as exc:
                results.append(self._result(test_id, tid, technique, vuln_type, "ERROR", f"probe failed: {exc}", role=self.low_priv_role, endpoint=endpoint))
                continue
            if resp.status in (200, 201, 204):
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.8,
                    endpoint=endpoint, user_role=self.low_priv_role,
                    request_raw=f"{endpoint.method} {endpoint.url}", response_raw=f"HTTP {resp.status}",
                    description=f"A low-privileged session (role '{self.low_priv_role}') successfully invoked the privileged operation '{endpoint.url}' ({endpoint.method}), receiving HTTP {resp.status}.",
                    recommendation="Enforce function-level authorization server-side on every state-changing privileged endpoint.",
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"bfla-write-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
                results.append(self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, role=self.low_priv_role, endpoint=endpoint, finding=finding))
            else:
                results.append(self._result(test_id, tid, technique, vuln_type, PASS, f"'{endpoint.url}': {endpoint.method} returned HTTP {resp.status} -- denied", role=self.low_priv_role, endpoint=endpoint))
        return results

    async def _technique_bfla_verb_tampering(self, endpoints, session_manager, session_pool, target_url, evidence) -> list[TestCaseResult]:
        test_id, tid, technique = "TC-055", "TC-055.3", "HTTP verb tampering to bypass a method-scoped authorization check"
        vuln_type = "Missing Function-Level Authorization (BFLA) via HTTP verb tampering"
        # Same widening as TC-055.2 above, and lower-risk still: this
        # technique only ever issues a GET (downgrading the verb, never
        # replaying the real write), so there's no added blast radius
        # from dropping the URL-naming requirement here.
        write_endpoints = {
            e.url: e for e in endpoints if e.method.upper() in ("POST", "PUT", "PATCH", "DELETE")
        }
        ranked = sorted(write_endpoints.values(), key=lambda e: not _looks_privileged(e.url, self.config.privileged_path_hints))
        privileged_write_endpoints = ranked[: self.config.max_bfla_write_endpoints]
        if not privileged_write_endpoints:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, "no POST/PUT/PATCH/DELETE endpoint discovered to downgrade to GET")]
        try:
            session, context = await self._authenticated_context(session_manager, session_pool, self.low_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        results: list[TestCaseResult] = []
        for endpoint in privileged_write_endpoints:
            probe = await self._probe_get(context, endpoint.url)
            if probe is None:
                results.append(self._result(test_id, tid, technique, vuln_type, "ERROR", "GET probe failed", role=self.low_priv_role, endpoint=endpoint))
                continue
            status, body = probe
            decision = classify_response(status, body, min_content_length=self.config.min_content_length)
            self.authorization_matrix.record(endpoint, self.low_priv_role, decision)
            if decision == AuthorizationDecision.ALLOWED:
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.7,
                    endpoint=endpoint, user_role=self.low_priv_role,
                    request_raw=f"GET {endpoint.url}", response_raw=f"HTTP {status}, {len(body)} bytes",
                    description=(
                        f"'{endpoint.url}' was discovered as a privileged {endpoint.method} endpoint, but "
                        f"a low-privileged session (role '{self.low_priv_role}') downgrading the verb to "
                        f"GET received HTTP {status} with {len(body)} bytes instead of a denial."
                    ),
                    recommendation="Apply the same authorization middleware to every HTTP verb a privileged route accepts.",
                )
                finding.evidence_refs = await self._capture_evidence(evidence, context, session, endpoint.url, label=f"bfla-verb-{endpoint.url.rsplit('/', 1)[-1]}", finding=finding)
                results.append(self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, role=self.low_priv_role, endpoint=endpoint, finding=finding))
            else:
                results.append(self._result(test_id, tid, technique, vuln_type, PASS, f"'{endpoint.url}': GET returned HTTP {status} -- denied", role=self.low_priv_role, endpoint=endpoint))
        return results

    async def _technique_hidden_endpoint_discovery(self, endpoints, session_manager, session_pool, target_url, evidence) -> list[TestCaseResult]:
        test_id, tid, technique = "TC-055", "TC-055.4", "Hidden/undocumented endpoint discovery and access"
        vuln_type = "Missing Function-Level Authorization (BFLA) via hidden endpoint"
        try:
            session, context = await self._authenticated_context(session_manager, session_pool, self.low_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        origin = target_url.split("/#/")[0].rstrip("/")
        known_paths = {urlsplit(e.url).path for e in endpoints}

        # SPA-catch-all-aware wordlist sweep (baseline-control-probe
        # pattern shared with `configuration_tests.py`'s TC-017
        # techniques and `auth_tests.py`'s TC-022.3) -- see
        # `_probe_shared.py` for why.
        baseline = await control_fingerprint(context, origin)
        hits = await sweep_paths(context, origin, [p for p in _HIDDEN_ENDPOINT_WORDLIST if p not in known_paths], baseline)

        results: list[TestCaseResult] = []
        for url, status, body in hits:
            decision = classify_response(status, body, min_content_length=self.config.min_content_length)
            if decision == AuthorizationDecision.ALLOWED:
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.1,
                    endpoint=_synthetic_endpoint(url), user_role=self.low_priv_role,
                    request_raw=f"GET {url}", response_raw=f"HTTP {status}, {len(body)} bytes",
                    description=f"'{url}' -- not in the crawler's discovered endpoint list -- is reachable by a low-privileged session (role '{self.low_priv_role}') with a full HTTP {status} response.",
                    recommendation="Apply the same authorization checks to every route a server actually handles, whether or not it's linked from the UI or documented.",
                )
                path = url[len(origin):]
                finding.evidence_refs = await self._capture_evidence(evidence, context, session, url, label=f"bfla-hidden-{path.strip('/').replace('/', '_')}", finding=finding)
                results.append(self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, role=self.low_priv_role, endpoint=finding.endpoint, finding=finding))
                return results  # one confirmed hidden endpoint is enough evidence for this technique
        results.append(self._result(test_id, tid, technique, vuln_type, PASS, f"none of {len(_HIDDEN_ENDPOINT_WORDLIST)} common hidden-path candidates (not already discovered) were reachable", role=self.low_priv_role))
        return results

    async def _technique_role_differential_access(self, endpoints, session_manager, session_pool, target_url, evidence) -> list[TestCaseResult]:
        """TC-055.5 -- complements TC-055.1, doesn't replace it. TC-055.1
        only tests endpoints whose URL *looks* privileged
        (`privileged_path_hints`); real BFLA frequently doesn't
        (`/api/orders/approve`, `/api/users/123/disable`, ...). This
        technique instead builds a small authorization matrix --
        anonymous / low-priv / high-priv responses for the same
        endpoint -- and flags one directly from that comparison: an
        endpoint that requires *some* authentication (anonymous denied)
        but returns byte-identical content to both privilege levels has
        no function-level authorization at all, independent of what its
        URL happens to be named. Endpoints TC-055.1 already covers are
        excluded here to avoid duplicate findings for the same gap."""
        test_id, tid, technique = "TC-055", "TC-055.5", "Role-differential function-level access (systematic matrix, not URL naming)"
        vuln_type = "Missing Function-Level Authorization (BFLA) via role-differential access"
        # This technique's whole signal is "two DIFFERENT roles got the
        # same response." With only one account configured, low_priv_role
        # and high_priv_role resolve to the identical session -- every
        # probe would trivially match itself, which isn't "no privilege
        # gap found," it's a guaranteed FALSE POSITIVE (the exact
        # `boundary_bypassed` condition below would fire on every allowed
        # endpoint). Skip honestly instead of reporting a fabricated PASS
        # or FAIL either one would misrepresent what was actually tested.
        if self.low_priv_role == self.high_priv_role:
            return [self._result(
                test_id, tid, technique, vuln_type, SKIPPED,
                f"low_priv_role and high_priv_role both resolve to '{self.low_priv_role}' -- only one "
                "account is configured, so there's no second privilege level to compare responses against",
            )]
        try:
            low_session, low_context = await self._authenticated_context(session_manager, session_pool, self.low_priv_role, target_url)
            _high_session, high_context = await self._authenticated_context(session_manager, session_pool, self.high_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        candidates = [
            e for e in endpoints
            if e.method.upper() == "GET" and not _looks_privileged(e.url, self.config.privileged_path_hints)
        ][: self.config.max_role_differential_endpoints]
        if not candidates:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, "no non-obviously-privileged GET endpoint discovered to matrix-test")]

        results: list[TestCaseResult] = []
        anon_context = await session_pool.new_anonymous_context()
        try:
            for endpoint in candidates:
                finding = await self._check_role_differential_candidate(
                    anon_context, low_context, high_context, low_session, vuln_type, evidence, endpoint)
                if finding is not None:
                    results.append(self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, role=self.low_priv_role, endpoint=endpoint, finding=finding))
        finally:
            await anon_context.close()

        if not results:
            results.append(self._result(
                test_id, tid, technique, vuln_type, PASS,
                f"{len(candidates)} endpoint(s) matrix-tested across anonymous/{self.low_priv_role}/{self.high_priv_role}; "
                "no role-differential access gap found"))
        return results

    async def _check_role_differential_candidate(self, anon_context, low_context, high_context, low_session, vuln_type: str, evidence, endpoint) -> Finding | None:
        """Per-endpoint probe-and-check body of
        `_technique_role_differential_access`'s loop, extracted so that
        method drops to setup + orchestration only -- same branches,
        same order, just named and separated."""
        anon_probe = await self._probe_get(anon_context, endpoint.url)
        low_probe = await self._probe_get(low_context, endpoint.url)
        high_probe = await self._probe_get(high_context, endpoint.url)
        if anon_probe is None or low_probe is None or high_probe is None:
            return None
        anon_status, anon_body = anon_probe
        low_status, low_body = low_probe
        high_status, high_body = high_probe

        anon_decision = classify_response(anon_status, anon_body, min_content_length=self.config.min_content_length)
        low_decision = classify_response(low_status, low_body, min_content_length=self.config.min_content_length)
        high_decision = classify_response(high_status, high_body, min_content_length=self.config.min_content_length)
        self.authorization_matrix.record(endpoint, "anonymous", anon_decision)
        self.authorization_matrix.record(endpoint, self.low_priv_role, low_decision)
        self.authorization_matrix.record(endpoint, self.high_priv_role, high_decision)
        boundary_bypassed = (
            high_decision == AuthorizationDecision.ALLOWED
            and low_decision == AuthorizationDecision.ALLOWED
            and anon_decision == AuthorizationDecision.DENIED
            and _content_fingerprint(low_body) == _content_fingerprint(high_body)
        )
        if not boundary_bypassed:
            return None

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.1,
            endpoint=endpoint, user_role=self.low_priv_role,
            request_raw=f"GET {endpoint.url}",
            response_raw=(
                f"anonymous: HTTP {anon_status}; "
                f"{self.low_priv_role}: HTTP {low_status}, {len(low_body)} bytes; "
                f"{self.high_priv_role}: HTTP {high_status}, {len(high_body)} bytes (identical content)"
            ),
            description=(
                f"'{endpoint.url}' requires authentication (an anonymous request was denied), "
                f"but roles '{self.low_priv_role}' and '{self.high_priv_role}' received "
                f"byte-identical responses. Detected via direct cross-role response "
                f"comparison, not URL naming, so this endpoint doesn't distinguish between "
                f"privilege levels regardless of what its path is called."
            ),
            recommendation=(
                "Enforce function-level authorization server-side, keyed to the authenticated "
                "user's actual role/permissions, on every endpoint -- not just ones with an "
                "admin-sounding URL. If this endpoint is legitimately available to every "
                "authenticated role, no action is needed; if not, add an explicit permission check."
            ),
        )
        finding.evidence_refs = await self._capture_evidence(
            evidence, low_context, low_session, endpoint.url,
            label=f"role-diff-{endpoint.url.rsplit('/', 1)[-1]}", finding=finding)
        return finding

    async def _load_and_read(self, page, url: str, timeout_ms: int = 15000) -> tuple[str, str] | tuple[None, None]:
        """Navigate a real page to `url` and read back what actually
        rendered -- the shared "load, then look" half of TC-055.6's two
        loads (baseline and response-rewritten). Returns `(None, None)`
        on a failed navigation so the caller can report ERROR instead of
        misreading an empty page as "denied". The settle delay after
        `goto()` gives a client-side router time to actually perform a
        redirect-away-if-unauthorized before `page.url`/`inner_text` are
        read -- reading immediately after `goto()` resolves would only
        ever see the pre-redirect state."""
        try:
            await asyncio.wait_for(page.goto(url, timeout=timeout_ms), timeout=(timeout_ms / 1000) + 5)
        except Exception as exc:
            _log.warning(f"response-manipulation probe navigation failed for {url}: {exc}")
            return None, None
        await asyncio.sleep(0.5)
        try:
            text = await page.inner_text("body")
        except Exception:
            text = ""
        return text, page.url

    async def _probe_response_manipulation(self, context, endpoint, evidence) -> TestCaseResult:
        """Per-endpoint body of TC-055.6, extracted so
        `_technique_response_manipulation_bypass` stays setup +
        orchestration only. Two real page loads: a BASELINE (untouched)
        and a REWRITTEN one where every response that was actually
        401/403 during the load gets flipped to 200, and any JSON
        response carrying a recognised authorization-boolean field gets
        that field flipped from false to true. If the baseline wasn't
        denied in the first place, there's nothing this technique can
        add over TC-055.1/.5's own direct probing, so it's a clean
        PASS-with-no-finding rather than a fabricated result."""
        test_id, tid, technique = "TC-055", "TC-055.6", "Client-side access-control bypass via response manipulation"
        vuln_type = "Missing Function-Level Authorization (BFLA) via response manipulation"

        baseline_page = await context.new_page()
        try:
            baseline_text, baseline_final_url = await self._load_and_read(baseline_page, endpoint.url)
        finally:
            await baseline_page.close()
        if baseline_text is None:
            return self._result(test_id, tid, technique, vuln_type, "ERROR", f"navigation to '{endpoint.url}' failed", role=self.low_priv_role, endpoint=endpoint)
        if not _looks_denied(baseline_final_url, endpoint.url, baseline_text):
            return self._result(test_id, tid, technique, vuln_type, PASS, f"'{endpoint.url}': already reachable without any manipulation for this role -- nothing for this technique to test", role=self.low_priv_role, endpoint=endpoint)

        rewritten_page = await context.new_page()
        interceptor = RequestInterceptor(rewritten_page)
        interceptor.inject_response(r".*", {"only_if_status": (401, 403), "status": 200})
        interceptor.inject_response(r".*", {"flip_false_fields": _AUTHZ_BOOLEAN_FIELD_NAMES})
        await interceptor.start()
        try:
            rewritten_text, rewritten_final_url = await self._load_and_read(rewritten_page, endpoint.url)
        finally:
            await interceptor.stop()
            await rewritten_page.close()
        if rewritten_text is None:
            return self._result(test_id, tid, technique, vuln_type, "ERROR", f"re-navigation to '{endpoint.url}' failed", role=self.low_priv_role, endpoint=endpoint)

        if _looks_denied(rewritten_final_url, endpoint.url, rewritten_text):
            return self._result(test_id, tid, technique, vuln_type, PASS, f"'{endpoint.url}': still denied after flipping every 401/403 sub-response to 200 and every authorization-boolean field to true -- enforcement doesn't rely on client-trusted response data", role=self.low_priv_role, endpoint=endpoint)

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.1,
            endpoint=endpoint, user_role=self.low_priv_role,
            request_raw=f"GET {endpoint.url}",
            response_raw=(
                f"baseline load: denied (final URL {baseline_final_url!r}); "
                f"after rewriting this load's own 401/403 sub-responses to 200 and any "
                f"authorization-boolean field to true: fully rendered at {rewritten_final_url!r} "
                "with no denial indicator"
            ),
            description=(
                f"'{endpoint.url}' denies a low-privileged session (role '{self.low_priv_role}') on a "
                "normal load, but rewriting only the CLIENT-VISIBLE responses this same page's own "
                "JavaScript received during that load -- never the actual server round-trip for the "
                "page's own top-level request, and never any request STOF made on the low-priv "
                "session's behalf -- was enough for the page to render as if the request had been "
                "authorized. This means the access-control decision for this page depends on data the "
                "client itself can be shown a manipulated version of, not on the server independently "
                "re-verifying the session's actual privileges."
            ),
            recommendation=(
                "Never let client-side routing/rendering decisions substitute for server-side "
                "authorization. Every privileged action the manipulated page then allows the user to "
                "attempt must still be independently authorized by the server on that action's own "
                "request -- verify this manually for whatever action(s) this page now exposes."
            ),
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"response-manip-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
        return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, role=self.low_priv_role, endpoint=endpoint, finding=finding)

    async def _technique_response_manipulation_bypass(self, endpoints, session_manager, session_pool, target_url, evidence) -> list[TestCaseResult]:
        """TC-055.6 -- WSTG-ATHZ-02 adjacent. Distinct from every other
        TC-055.x technique in this file: those all probe a discovered
        endpoint directly via `context.request` and never render a real
        page, so none of them can see a purely CLIENT-SIDE authorization
        gate (an SPA route guard that redirects away, or hides content,
        based on a response its own JS received) -- an endpoint gated
        that way returns the identical HTTP 200/full-body page-shell
        response to every role (client-side routing), so
        `classify_response()`'s ALLOWED/DENIED comparison sees no
        difference at all and would never flag it. This technique
        drives a real browser instead, so it can observe (and defeat)
        exactly that gate.

        Gated behind `allow_state_changing_probes` even though STOF
        itself only ever issues GETs here: once the page believes it's
        authorized, its own JS runs uncontrolled (auto-save timers,
        analytics beacons, ...) and could fire a real write as a side
        effect -- the same "can't guarantee this stays read-only"
        reasoning `_technique_bfla_state_changing` above documents for
        actual write-verb probing.
        """
        test_id, tid, technique = "TC-055", "TC-055.6", "Client-side access-control bypass via response manipulation"
        vuln_type = "Missing Function-Level Authorization (BFLA) via response manipulation"
        if not self.config.allow_state_changing_probes:
            return [self._gated_skip(test_id, tid, technique, vuln_type, "response-manipulation probing renders a real page whose own JS could trigger a write as a side effect, and is disabled by default")]

        candidates = list({
            e.url: e for e in endpoints
            if e.endpoint_type == "page" and e.method.upper() == "GET" and _looks_privileged(e.url, self.config.privileged_path_hints)
        }.values())[: self.config.max_response_manipulation_endpoints]
        if not candidates:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, "no privileged-looking page endpoint discovered")]

        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.low_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        return [await self._probe_response_manipulation(context, endpoint, evidence) for endpoint in candidates]

    async def _techniques_tc055(self, endpoints, session_manager, session_pool, target_url, evidence, base_findings: list[Finding]) -> list[TestCaseResult]:
        results: list[TestCaseResult] = []
        privesc_findings = [f for f in base_findings if "Privilege Escalation" in f.vuln_type]
        privileged_get_endpoints = list({e.url: e for e in endpoints if _looks_privileged(e.url, self.config.privileged_path_hints)}.values())
        if not privileged_get_endpoints:
            results.append(self._result("TC-055", "TC-055.1", "Forced browsing to an admin-only endpoint as a low-privilege user", "Vertical Privilege Escalation / Broken Function Level Authorization", SKIPPED, "no privileged-looking endpoint discovered"))
        else:
            results.extend(self._reused_result("TC-055", "TC-055.1", "Forced browsing to an admin-only endpoint as a low-privilege user",
                                                "Vertical Privilege Escalation / Broken Function Level Authorization", PASS, self.low_priv_role, privesc_findings,
                                                base_error=self._base_test_errors.get("vertical_privesc")))
        results.extend(await self._safe(self._technique_bfla_state_changing(endpoints, session_manager, session_pool, target_url, evidence)))
        results.extend(await self._safe(self._technique_bfla_verb_tampering(endpoints, session_manager, session_pool, target_url, evidence)))
        results.extend(await self._safe(self._technique_hidden_endpoint_discovery(endpoints, session_manager, session_pool, target_url, evidence)))
        results.extend(await self._safe(self._technique_role_differential_access(endpoints, session_manager, session_pool, target_url, evidence)))
        results.extend(await self._safe(self._technique_response_manipulation_bypass(endpoints, session_manager, session_pool, target_url, evidence)))
        return results
