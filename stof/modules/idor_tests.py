"""Layer 9 — `stof/modules/idor_tests.py`: IDOR / privilege-escalation
tests, per CLAUDE.md's own line for this file ("horizontal + vertical
priv-esc (Phase 1)").

Covers every `config/testcases.json` "authorization" entry that is
genuinely IDOR/privilege-related, via three concrete tests rather than
eight separate ones -- several test-case IDs name the same underlying
mechanism from different angles:

  - `_test_horizontal_idor`             -> TC-053 IDOR, TC-054 BOLA
  - `_test_vertical_privilege_escalation` -> TC-050 Broken Access Control,
                                              TC-051 Bypassing Authorization
                                              Schema (forced browsing),
                                              TC-052 Privilege Escalation,
                                              TC-055 BFLA
  - `_test_role_parameter_tampering`    -> TC-056 Role Manipulation

TC-057 (JWT Role Manipulation) lives in `jwt_tests.py` instead --
CLAUDE.md's own Layer 9 file list already assigns JWT-specific work
("JWT replay, expiry, alg:none") to that module, and this project's
demo target authenticates via session cookies, not JWTs, so a JWT test
has no live surface here regardless of which file it's in.

TC-108 (Rate Limit on Token Level) is out of scope: it's a rate-limiting
control, not an authorization/IDOR flaw, despite sharing the
"authorization" grouping in testcases.json.

Real-target grounding: every technique here was hand-verified against
this project's own demo target (demo.testfire.net) before being coded
up --
  - `GET /bank/showAccount?listAccounts=<id>`: a single admin session
    retrieved three distinct, genuinely different accounts (800000/
    800001/800002) with no ownership check -- the exact shape
    `_test_horizontal_idor` looks for.
  - `GET /admin/admin.jsp`: a non-admin authenticated session ('normal'/
    jsmith) got a full 200/27863-byte response, while the same path
    unauthenticated correctly 302-redirects -- proving this is
    specifically an authorization gap, not an authentication bypass,
    the exact shape `_test_vertical_privilege_escalation` looks for.

IDOR testing is fundamentally ID enumeration -- there's no way to know a
target's valid object-ID range without either observing one or trying a
caller-supplied set of candidates (`IdorTestConfig.candidate_ids`); this
is the same approach Burp's own Intruder-based IDOR testing uses, not a
shortcut specific to this target. The default range is a small,
generic 1-5; callers targeting a known ID space (e.g. this project's
demo run using 800000-800010) pass their own.

Module layout -- this file used to carry every authorization technique
(1,576 lines, 12 methods at C-complexity 11-20). TC-055 (BFLA) and
TC-056 (Role Manipulation) now live in `bfla_tests.py`/`role_tests.py`;
TC-052.4/TC-053.3 (mass assignment / body-field tampering) live in
`mass_assignment_tests.py`. Each is a plain mixin composed into
`IdorTestsModule` below, not a separate `VulnModule` -- see
`bfla_tests.py`'s module docstring for why (short version: TC-050/052's
reuse logic needs same-scan-pass results from all of them, and a real
module boundary would mean crossing it, which CLAUDE.md's own rules
already say siblings shouldn't do). `IdorTestsModule` itself keeps the
core object-reference families (TC-053.1/.2/.4/.5, TC-054) plus every
piece of cross-cutting plumbing (session/evidence/matrix/payload-
registry access, `_safe`/`_result`/`_reused_result`, and the
`_techniques_tc0NN`/`run_techniques` orchestration) that the mixins
depend on via `self`.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from stof.authorization.decision import AuthorizationDecision, classify_response
from stof.authorization.matrix import AuthorizationMatrix
from stof.core.logger import get_logger
from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding
from stof.payloads.generators import StaticValueGenerator
from stof.payloads.models import PayloadContext, ProbeContext
from stof.payloads.registry import PayloadRegistry

from ._idor_shared import (
    _MIN_ID_PREDICTABILITY_SAMPLE,
    _PRIVILEGE_FIELD_NAMES,
    _collect_observed_ids,
    _content_fingerprint,
    _extract_leaked_ids,
    _id_shape,
    _looks_like_object_reference,  # noqa: F401 -- re-exported: tests/unit/test_idor_tests.py imports it from here
    _method_request_fn,
    _numeric_path_segment_indexes,
    _object_ref_endpoints,
    _set_path_segment,
    _set_query_param,
    _synthetic_endpoint,
)
from .base import VulnModule
from .bfla_tests import BFLATechniquesMixin
from .mass_assignment_tests import MassAssignmentTechniquesMixin
from .results import ERROR, FAIL, PASS, SKIPPED, TestCaseResult
from .role_tests import RoleTechniquesMixin
from .tenant_tests import TenantTechniquesMixin

if TYPE_CHECKING:
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.idor_tests")


@dataclass
class IdorTestConfig:
    candidate_ids: list[str] = field(default_factory=lambda: [str(i) for i in range(1, 6)])
    # Ignore near-empty/error responses when comparing content -- a
    # bare "500 Internal Server Error" page isn't evidence of IDOR.
    min_content_length: int = 100
    privileged_path_hints: tuple[str, ...] = (
        "/admin", "/manage", "/management", "/superuser", "/root",
        "/internal", "/config", "/dashboard-admin",
    )
    role_param_hints: tuple[str, ...] = (
        "role", "group", "isadmin", "is_admin", "admin", "level",
        "perm", "privilege", "access_level",
    )
    # Cap on how many discovered GET endpoints `_technique_role_
    # differential_access` (TC-055.5) probes -- it tests every
    # candidate against 3 identities (anonymous/low-priv/high-priv),
    # so this bounds the request volume for a target with a large
    # endpoint list the same way other techniques in this file already
    # cap their own probe counts.
    max_role_differential_endpoints: int = 40
    # Bound on TC-055.2/TC-055.3's discovered-write-endpoint candidate
    # set (see bfla_tests.py) now that it's no longer filtered down to
    # only URL-naming-privileged endpoints -- caps the request volume
    # against a target with a large discovered write surface, same
    # rationale as max_role_differential_endpoints above.
    max_bfla_write_endpoints: int = 30
    # Off by default: PUT/PATCH/DELETE-based technique probes (TC-054.2/
    # .3, TC-055.2, TC-056.2) actually write or destroy data on the
    # target if they succeed -- per this project's own safety rule for
    # risky/destructive actions, that must be an explicit, informed
    # opt-in for an authorized engagement window, never a scan default.
    # Every read-only (GET-based) technique runs regardless of this flag.
    allow_state_changing_probes: bool = False


class IdorTestsModule(VulnModule, BFLATechniquesMixin, RoleTechniquesMixin, MassAssignmentTechniquesMixin, TenantTechniquesMixin):
    module_id = "idor_tests"
    name = "IDOR / Privilege Escalation Tests"
    phase = 1

    def __init__(
        self,
        config: IdorTestConfig | None = None,
        high_priv_role: str = "admin",
        low_priv_role: str = "normal",
        target_url: str | None = None,
    ) -> None:
        self.config = config or IdorTestConfig()
        self.high_priv_role = high_priv_role
        self.low_priv_role = low_priv_role
        # Only needed to derive the cookie domain for
        # `SessionPool.apply_session()` -- defaults to the first
        # discovered endpoint's origin when not given explicitly.
        self.target_url = target_url
        # Shared authorization-boundary state: the BFLA-shaped
        # techniques (TC-055.1, TC-055.5) each record every
        # endpoint/role response they classify here instead of keeping
        # their own private pass/fail bookkeeping -- one scan run, one
        # matrix, so a future technique can ask "does this endpoint
        # already have a known boundary" instead of re-deriving it.
        self.authorization_matrix = AuthorizationMatrix()
        # TC-053's candidate-id techniques source their values through
        # here now (Step 2 of the payload-engine migration) instead of
        # reading `self.config.candidate_ids` directly -- same values,
        # same order, registered once per module instance so a probe
        # key could later be built from `payload_id` without re-
        # deriving it. Deliberately not extended to TC-054/055/056 yet
        # (per the reviewer's own "one family at a time" sequencing);
        # nothing about request execution, response classification,
        # confirmation, evidence, or Finding construction changed.
        self.payload_registry = PayloadRegistry()
        self._register_candidate_id_payloads()
        # Records which of `run()`'s three base tests errored out (keyed
        # by a stable name), so the reused-result techniques that depend
        # on their findings can report ERROR ("couldn't test") instead of
        # a misleading PASS ("target resisted") when the base test never
        # actually completed. Reset at the start of each `run()`.
        self._base_test_errors: dict[str, str] = {}

    def _register_candidate_id_payloads(self) -> None:
        self.payload_registry.register_all(list(
            StaticValueGenerator("TC-053.1", "object_id", self.config.candidate_ids, contexts=("path",)).generate()
        ))
        self.payload_registry.register_all(list(
            StaticValueGenerator("TC-053.2", "object_id", self.config.candidate_ids, contexts=("query",)).generate()
        ))

    def _candidate_ids(self, testcase_id: str, location: PayloadContext) -> list:
        """The exact same values `self.config.candidate_ids` always
        held, now retrieved through the payload registry."""
        context = ProbeContext(testcase_id=testcase_id, location=location)
        return [p.value for p in self.payload_registry.for_context(context)]

    async def run(
        self,
        endpoints: list["Endpoint"],
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[Finding]:
        target_url = self.target_url or (endpoints[0].url if endpoints else "")
        findings: list[Finding] = []
        self._base_test_errors = {}

        for test_name, test in (
            ("horizontal_idor", self._test_horizontal_idor),
            ("vertical_privesc", self._test_vertical_privilege_escalation),
            ("role_tampering", self._test_role_parameter_tampering),
        ):
            try:
                findings.extend(await test(endpoints, session_manager, session_pool, target_url, evidence))
            except KeyError as exc:
                # Role/provider not configured for this run -- skip
                # that one test rather than failing the whole module,
                # matching SessionManager's own KeyError contract. This
                # is a legit "not applicable", not an error, so it is NOT
                # recorded in `_base_test_errors` (reused results still PASS/SKIP).
                _log.warning(f"skipping {test_name}: {exc}")
            except Exception as exc:
                # A non-KeyError failure (e.g. a transient network error
                # that survived `_authenticated_context`'s own retries)
                # is caught PER-TEST so one test's failure no longer
                # aborts the other two, and is recorded so the reused-
                # result techniques downstream report ERROR rather than a
                # false PASS. This is the fix for a real scan where a
                # single `net::ERR_NETWORK_CHANGED` during admin auth
                # silently wiped every base test and reported them clean.
                self._base_test_errors[test_name] = str(exc)
                _log.warning(f"base test '{test_name}' errored -- its reused results will report ERROR, not PASS: {exc}")

        return findings

    async def _capture_evidence(self, evidence, context, session, url: str, label: str, finding: Finding | None = None) -> list[str]:
        """Opportunistic: called only after a finding is already
        confirmed, per Layer 12's "never called speculatively" rule.
        Navigates a fresh page to the exact vulnerable URL so the
        screenshot shows the actual proof, not just the endpoint's
        landing state. `finding`, when given, also gets its request/
        response text rendered as a styled evidence image alongside
        the screenshot."""
        if evidence is None:
            return []
        page = None
        try:
            page = await context.new_page()
            await page.goto(url)
            request_raw = finding.request_raw if finding is not None else ""
            response_raw = finding.response_raw if finding is not None else ""
            return await evidence.capture(page, session, label=label, request_raw=request_raw, response_raw=response_raw)
        except Exception as exc:
            _log.warning(f"evidence capture failed for {url}: {exc}")
            return []
        finally:
            if page is not None:
                await page.close()

    async def _confirm_cross_session(self, confirm_context, url: str, param: str, candidate_ids: list[str]) -> list[str]:
        """Replays `candidate_ids` against `url` using a second,
        already-authenticated context (a genuinely different identity
        than whichever session discovered them) -- the candidate IDs
        it can also retrieve are the cross-identity-confirmed ones.
        Returns `[]` (not an error) when `confirm_context` is `None`,
        the caller's signal that no second identity was available."""
        if confirm_context is None:
            return []
        confirmed: list[str] = []
        for cid in candidate_ids:
            probe_url = _set_query_param(url, param, cid)
            probe = await self._probe_get(confirm_context, probe_url)
            if probe is None:
                continue
            status, body = probe
            if status == 200 and len(body) >= self.config.min_content_length:
                confirmed.append(cid)
        return confirmed

    def _idor_description(self, url: str, param: str, response_count: int, sample_ids: list[str], confirmed_ids: list[str]) -> str:
        if confirmed_ids:
            return (
                f"CONFIRMED via a second identity: a session authenticated as role "
                f"'{self.high_priv_role}' retrieved {response_count} distinct objects from "
                f"'{url}' by varying the '{param}' parameter across {sample_ids}; "
                f"a completely different session, authenticated as role "
                f"'{self.low_priv_role}', was ALSO able to retrieve "
                f"{'object' if len(confirmed_ids) == 1 else 'objects'} {confirmed_ids} with no "
                f"apparent server-side check that the requested object belongs to the "
                f"requesting identity."
            )
        return (
            f"A single authenticated session (role '{self.high_priv_role}') retrieved "
            f"{response_count} distinct, substantially different objects from "
            f"'{url}' by varying the '{param}' parameter across "
            f"{sample_ids}, with no apparent server-side check that the requested "
            f"object belongs to the requesting user. Unconfirmed with a second "
            f"identity: no distinct low-privilege role was configured/reachable for "
            f"this target, so this is single-session enumeration evidence only, not a "
            f"cross-identity-confirmed authorization bypass."
        )

    async def _test_horizontal_idor(self, endpoints, session_manager, session_pool, target_url, evidence=None) -> list[Finding]:
        candidate_endpoints = _object_ref_endpoints(endpoints)
        if not candidate_endpoints:
            return []

        session, context = await self._authenticated_context(session_manager, session_pool, self.high_priv_role, target_url)

        # A second, genuinely different identity used to replay whatever
        # the first identity finds -- single-session ID enumeration alone
        # only proves "role X can see multiple objects," which a
        # legitimate admin view can do too; it does NOT prove the
        # authorization boundary between two identities is missing.
        # Live-verified against a real target: an 'admin' session
        # enumerating /bank/showAccount found 3 distinct real accounts,
        # and a completely different 'normal' session could ALSO pull
        # every one of them by ID -- that cross-identity replay is the
        # actual proof, not the enumeration step by itself. `None` when
        # no distinct low-priv role is configured/reachable -- graceful
        # fallback to the single-identity signal below, not a hard
        # requirement that would silently lose coverage for a target
        # with only one usable test account.
        confirm_context = None
        if self.low_priv_role != self.high_priv_role:
            try:
                _, confirm_context = await self._authenticated_context(session_manager, session_pool, self.low_priv_role, target_url)
            except KeyError as exc:
                _log.warning(f"cross-session IDOR confirmation unavailable: {exc}")

        findings: list[Finding] = []
        for endpoint, param in candidate_endpoints:
            finding = await self._check_horizontal_idor_candidate(context, session, confirm_context, evidence, endpoint, param)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _check_horizontal_idor_candidate(self, context, session, confirm_context, evidence, endpoint, param) -> Finding | None:
        """Per-candidate probe-and-check body of `_test_horizontal_idor`'s
        loop, extracted so that method drops to setup + orchestration
        only -- same branches, same order, just named and separated."""
        responses: dict[str, str] = {}
        statuses: dict[str, int] = {}
        for candidate in self._candidate_ids("TC-053.2", "query"):
            probe_url = _set_query_param(endpoint.url, param, candidate)
            probe = await self._probe_get(context, probe_url)
            if probe is None:
                continue
            status, body = probe
            statuses[candidate] = status
            if status == 200 and len(body) >= self.config.min_content_length:
                responses[candidate] = body

        distinct_fingerprints = {_content_fingerprint(b) for b in responses.values()}
        if not (len(responses) >= 2 and len(distinct_fingerprints) >= 2):
            return None

        sample_ids = list(responses.keys())[:3]
        confirmed_ids = await self._confirm_cross_session(confirm_context, endpoint.url, param, sample_ids)
        if confirm_context is not None and not confirmed_ids:
            _log.info(f"IDOR candidate at '{endpoint.url}' ({param}) not confirmed: role '{self.low_priv_role}' was denied every object role '{self.high_priv_role}' could see")
            return None
        description = self._idor_description(endpoint.url, param, len(responses), sample_ids, confirmed_ids)
        finding = Finding(
            module_id=self.module_id,
            vuln_type="Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization",
            severity="Critical",
            cvss_score=8.1,
            endpoint=endpoint,
            user_role=self.high_priv_role,
            request_raw="\n".join(f"GET {_set_query_param(endpoint.url, param, cid)}" for cid in sample_ids),
            response_raw="\n".join(f"[{param}={cid}] HTTP {statuses.get(cid)}, {len(responses[cid])} bytes" for cid in sample_ids),
            description=description,
            recommendation=(
                "Enforce object-level authorization on every request that takes an object "
                "id from the client: verify the authenticated user actually owns/may access "
                "the specific object id requested, not just that they are authenticated."
            ),
        )
        finding.evidence_refs = await self._capture_evidence(
            evidence, context, session,
            _set_query_param(endpoint.url, param, sample_ids[0]),
            label=f"idor-{param}-{sample_ids[0]}", finding=finding)
        return finding

    def _result(
        self, test_id: str, technique_id: str, technique: str, vuln_type: str,
        status: str, detail: str, role: str | None = None, endpoint=None, finding: Finding | None = None,
    ) -> TestCaseResult:
        return self._make_result(
            test_id=test_id, technique_id=technique_id, technique=technique, vuln_type=vuln_type,
            status=status, detail=detail, role=role, endpoint=endpoint, finding=finding,
        )

    def _gated_skip(self, test_id: str, technique_id: str, technique: str, vuln_type: str, reason: str) -> TestCaseResult:
        """The `if not self.config.allow_state_changing_probes: return
        [self._result(..., SKIPPED, "<reason> -- set IdorTestConfig.
        allow_state_changing_probes=True for an authorized engagement
        window")]` guard clause duplicated across every write-verb
        IDOR-family technique (`bfla_tests.py`, `role_tests.py`,
        `mass_assignment_tests.py` x2, and this file's own
        `_technique_bola_write_methods`). `reason` is each site's full,
        already-worded explanation up through "...disabled by default"
        -- deliberately not further templated, so each technique keeps
        its own precise wording instead of being forced into one
        generic sentence shape. `auth_tests.py` has the same guard-
        clause shape 3 times over but deliberately stays separate -- it
        gates on `AuthTestConfig.allow_state_changing_probes`, a
        different config class with its own message wording, not this
        one."""
        return self._result(test_id, technique_id, technique, vuln_type, SKIPPED,
                             f"{reason} -- set IdorTestConfig.allow_state_changing_probes=True for an authorized engagement window")

    async def _probe_candidates(self, context, candidates, url_for) -> tuple[dict[str, str], dict[str, int]]:
        """Shared by every technique below that substitutes a set of
        candidate ids into a URL-transform and compares the resulting
        bodies -- the same primitive `_test_horizontal_idor` above
        hand-codes for the query-parameter case specifically."""
        responses: dict[str, str] = {}
        statuses: dict[str, int] = {}
        for candidate in candidates:
            probe_url = url_for(candidate)
            probe = await self._probe_get(context, probe_url)
            if probe is None:
                continue
            status, body = probe
            statuses[candidate] = status
            if status == 200 and len(body) >= self.config.min_content_length:
                responses[candidate] = body
        return responses, statuses

    def _object_ref_finding(self, endpoint, role, label, url_for, statuses, responses, vuln_type, cvss, description, recommendation) -> Finding:
        sample_ids = list(responses.keys())[:3]
        return Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=cvss,
            endpoint=endpoint, user_role=role,
            request_raw="\n".join(f"GET {url_for(cid)}" for cid in sample_ids),
            response_raw="\n".join(f"[{label}={cid}] HTTP {statuses.get(cid)}, {len(responses[cid])} bytes" for cid in sample_ids),
            description=description, recommendation=recommendation,
        )

    async def _technique_idor_path_param(self, endpoints, session_manager, session_pool, target_url, evidence) -> list[TestCaseResult]:
        test_id, tid, technique = "TC-053", "TC-053.1", "Path-parameter ID substitution"
        vuln_type = "Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (path parameter)"
        candidates = [e for e in endpoints if e.method.upper() == "GET" and _numeric_path_segment_indexes(e.url)]
        if not candidates:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                  "no GET endpoint with a numeric/UUID path segment was discovered on this target")]
        try:
            session, context = await self._authenticated_context(session_manager, session_pool, self.high_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        results: list[TestCaseResult] = []
        for endpoint in candidates:
            seg_index = _numeric_path_segment_indexes(endpoint.url)[-1]
            url_for = lambda cid, e=endpoint, i=seg_index: _set_path_segment(e.url, i, cid)
            responses, statuses = await self._probe_candidates(context, self._candidate_ids("TC-053.1", "path"), url_for)
            distinct = {_content_fingerprint(b) for b in responses.values()}
            if len(responses) >= 2 and len(distinct) >= 2:
                finding = self._object_ref_finding(
                    endpoint, self.high_priv_role, "path segment", url_for, statuses, responses, vuln_type, 8.1,
                    description=(
                        f"A single authenticated session (role '{self.high_priv_role}') retrieved "
                        f"{len(responses)} distinct objects from '{endpoint.url}' by varying its "
                        f"trailing path segment across {list(responses.keys())[:3]}, with no apparent "
                        "server-side ownership check."
                    ),
                    recommendation=(
                        "Enforce object-level authorization on every request that takes an object id "
                        "from the URL path, not just from query parameters."
                    ),
                )
                sample_id = next(iter(responses.keys()))
                finding.evidence_refs = await self._capture_evidence(evidence, context, session, url_for(sample_id), label=f"idor-path-{sample_id}", finding=finding)
                results.append(self._result(test_id, tid, technique, vuln_type, FAIL, finding.description,
                                             role=self.high_priv_role, endpoint=endpoint, finding=finding))
            else:
                results.append(self._result(
                    test_id, tid, technique, vuln_type, PASS,
                    f"'{endpoint.url}': path-segment candidates {self.config.candidate_ids} returned no distinct objects",
                    role=self.high_priv_role, endpoint=endpoint,
                ))
        return results

    async def _technique_idor_leaked_ids(self, endpoints, session_manager, session_pool, target_url, evidence, seen_bodies: list[str]) -> list[TestCaseResult]:
        test_id, tid, technique = "TC-053", "TC-053.4", "ID enumeration via IDs leaked in other responses"
        vuln_type = "Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (leaked-id enumeration)"
        object_ref_endpoints = _object_ref_endpoints(endpoints)
        if not object_ref_endpoints:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, "no object-reference query parameter discovered to probe leaked ids against")]

        leaked_ids = _extract_leaked_ids(seen_bodies, known=set(self.config.candidate_ids))
        if not leaked_ids:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                  "no id-shaped tokens beyond the configured candidate list were observed in this run's responses")]
        try:
            session, context = await self._authenticated_context(session_manager, session_pool, self.high_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        results: list[TestCaseResult] = []
        for endpoint, param in object_ref_endpoints:
            url_for = lambda cid, e=endpoint, p=param: _set_query_param(e.url, p, cid)
            responses, statuses = await self._probe_candidates(context, leaked_ids, url_for)
            distinct = {_content_fingerprint(b) for b in responses.values()}
            if len(responses) >= 1 and len(distinct) >= 1:
                finding = self._object_ref_finding(
                    endpoint, self.high_priv_role, param, url_for, statuses, responses, vuln_type, 8.1,
                    description=(
                        f"Object id(s) {leaked_ids} observed elsewhere in this scan's own traffic (not "
                        f"in the configured candidate list) were accepted by '{endpoint.url}' via "
                        f"'{param}', returning content for role '{self.high_priv_role}' with no ownership check."
                    ),
                    recommendation="Enforce object-level authorization regardless of how an attacker obtained a valid-looking id.",
                )
                sample_id = next(iter(responses.keys()))
                finding.evidence_refs = await self._capture_evidence(evidence, context, session, url_for(sample_id), label=f"idor-leaked-{sample_id}", finding=finding)
                results.append(self._result(test_id, tid, technique, vuln_type, FAIL, finding.description,
                                             role=self.high_priv_role, endpoint=endpoint, finding=finding))
            else:
                results.append(self._result(
                    test_id, tid, technique, vuln_type, PASS,
                    f"'{endpoint.url}': leaked id(s) {leaked_ids} were rejected or returned nothing",
                    role=self.high_priv_role, endpoint=endpoint,
                ))
        return results

    def _technique_id_predictability_analysis(self, endpoints, base_findings: list[Finding] | None = None) -> list[TestCaseResult]:
        """TC-053.6 -- purely ANALYTICAL, zero new network requests,
        distinct from every ID-SUBSTITUTION technique above it in this
        file (TC-053.1/.2/.4/.5 actually probe a candidate id and check
        access; this one only classifies the SHAPE of ids this scan
        already observed). Real-world grounding: this project's own
        knowledge base (`stof/payloads/idor_knowledge_base.json`,
        `direct_object_reference` family) already records that 60.8% of
        confirmed real-world direct-object-reference BOLA cases used
        plain sequential-integer identifiers -- the same pattern that
        makes ID-substitution IDOR attacks trivial to automate/enumerate
        at scale, independent of whether any single substitution attempt
        this scan made actually succeeded. OWASP's API3:2023 (Broken
        Object Level Authorization) names this same auto-increment-
        primary-key-as-external-id pattern as a contributing risk factor
        for exactly this reason. Reported as a contributing-risk FAIL,
        not a confirmed IDOR -- it never claims unauthorized access was
        observed, only that the id space is easy to enumerate.

        Two id sources, both already-observed data from this scan pass,
        neither costing a new request: (1) id-shaped path segments/
        query-param values already sitting in the discovered `endpoints`
        list, and (2) ids surfaced in `base_findings`' own request/
        response text -- e.g. TC-053.2's query-substitution finding
        names every distinct account id it confirmed, even though the
        crawler itself only discovered the bare `/bank/showAccount` URL
        with no query string at all. Source (2) matters in practice:
        without it, a target whose object ids only ever appear via
        substitution (never as a literal query value the crawler
        happened to see) would always SKIP here for lack of sample,
        despite the substitution techniques right above having just
        demonstrated the id space is a plain sequential range."""
        test_id, tid, technique = "TC-053", "TC-053.6", "Object-id predictability analysis (sequential/enumerable id scheme)"
        vuln_type = "Predictable/Sequential Object Identifiers"
        observed_ids = _collect_observed_ids(endpoints)
        finding_texts = [f"{f.request_raw}\n{f.response_raw}" for f in (base_findings or [])]
        for extra_id in _extract_leaked_ids(finding_texts, known=set(observed_ids), limit=50):
            observed_ids.append(extra_id)
        if len(observed_ids) < _MIN_ID_PREDICTABILITY_SAMPLE:
            return [self._result(
                test_id, tid, technique, vuln_type, SKIPPED,
                f"only {len(observed_ids)} id-shaped value(s) discovered on this target -- too few to draw a "
                f"conclusion about the id scheme (minimum sample size: {_MIN_ID_PREDICTABILITY_SAMPLE})",
            )]

        shapes = [_id_shape(i) for i in observed_ids]
        total = len(shapes)
        sequential = sum(1 for s in shapes if s == "sequential_int")
        random_shaped = sum(1 for s in shapes if s in ("uuid", "long_random_token"))
        sample = observed_ids[:5]
        if sequential / total > 0.5:
            description = (
                f"{sequential}/{total} object id(s) discovered on this target (sample: {sample}) are short, "
                "plain sequential/incrementing integers -- consistent with database auto-increment primary "
                "keys used directly as externally-visible identifiers. This does not by itself confirm an "
                "IDOR, but it dramatically lowers the bar for one: sequential ids are trivial to enumerate/"
                "automate at scale, the same real-world pattern behind 60.8% of confirmed direct-object-"
                "reference BOLA cases per this project's own knowledge base. Flag as a contributing risk "
                "factor even independent of any single confirmed IDOR finding on this scan."
            )
            # No new network request is made by this technique -- it is
            # purely re-classifying ids already discovered elsewhere in
            # the scan -- so there is no single "the" vulnerable
            # endpoint; `endpoints[0]` is attached only so the Finding
            # (which requires one) is anchored to this target/run.
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Info", cvss_score=0.0,
                endpoint=endpoints[0], user_role=self.high_priv_role,
                request_raw="(analytical -- no request sent)",
                response_raw=f"observed id sample: {sample} (id-shape classification only, {total} id(s) total)",
                description=description,
                recommendation=(
                    "Use non-sequential, unguessable identifiers (UUIDv4, cryptographically random tokens) "
                    "for any externally-visible object reference, in addition to (not instead of) enforcing "
                    "server-side object-level authorization."
                ),
            )
            return [self._result(test_id, tid, technique, vuln_type, FAIL, description, role=self.high_priv_role, finding=finding)]
        if random_shaped / total > 0.5:
            return [self._result(
                test_id, tid, technique, vuln_type, PASS,
                f"{random_shaped}/{total} object id(s) discovered on this target (sample: {sample}) look like "
                "UUIDs or long random tokens rather than sequential integers -- not easily enumerable",
            )]
        return [self._result(
            test_id, tid, technique, vuln_type, PASS,
            f"object id(s) discovered on this target ({total} sampled: {sample}) are not predominantly "
            "sequential integers -- no clear enumerable id pattern",
        )]

    async def _technique_idor_method_override(self, endpoints, session_manager, session_pool, target_url, evidence) -> list[TestCaseResult]:
        """TC-053.5 -- a real reviewer flagged this technique's original
        logic as too aggressive: "a POST endpoint can legitimately also
        support GET" (e.g. `/api/orders` GET-lists, POST-creates -- a
        normal REST pattern, not a bypass). A bare `GET returns 200`
        check alone can't tell those apart. Without also issuing the
        write verb (deliberately out of scope here -- that's what the
        gated `_technique_bola_write_methods` is for), the strongest
        read-only signal available is whether GET requires
        authentication at all: an anonymous GET denied but an
        authenticated low-priv GET allowed proves this URL sits behind
        *some* access-control boundary that a bare method switch
        crossed, whereas a GET any anonymous caller can also reach was
        never protected in the first place. Flagged at Medium, not
        Critical, and honestly caveated: this proves a response-code
        differential, not that GET exposes the same privileged
        data/operation the discovered write verb does."""
        test_id, tid, technique = "TC-053", "TC-053.5", "IDOR via HTTP method override (GET allowed where POST/PUT is blocked)"
        vuln_type = "Insecure Direct Object Reference (IDOR) via HTTP method override"
        write_endpoints = [e for e in endpoints if e.method.upper() in ("POST", "PUT", "PATCH", "DELETE")]
        if not write_endpoints:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, "no POST/PUT/PATCH/DELETE endpoint discovered to probe with GET")]
        try:
            session, context = await self._authenticated_context(session_manager, session_pool, self.low_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        results: list[TestCaseResult] = []
        anon_context = await session_pool.new_anonymous_context()
        try:
            for endpoint in write_endpoints:
                probe = await self._probe_get(context, endpoint.url)
                if probe is None:
                    results.append(self._result(test_id, tid, technique, vuln_type, "ERROR", "GET probe failed", role=self.low_priv_role, endpoint=endpoint))
                    continue
                status, body = probe
                low_decision = classify_response(status, body, min_content_length=self.config.min_content_length)
                self.authorization_matrix.record(endpoint, self.low_priv_role, low_decision)
                if low_decision != AuthorizationDecision.ALLOWED:
                    results.append(self._result(test_id, tid, technique, vuln_type, PASS,
                                                  f"'{endpoint.url}': GET returned HTTP {status} ({len(body)} bytes) -- not a bypass",
                                                  role=self.low_priv_role, endpoint=endpoint))
                    continue
                anon_probe = await self._probe_get(anon_context, endpoint.url)
                if anon_probe is None:
                    results.append(self._result(test_id, tid, technique, vuln_type, PASS,
                                                  f"'{endpoint.url}': GET returned HTTP {status} but the anonymous baseline probe failed -- cannot confirm an authorization boundary exists",
                                                  role=self.low_priv_role, endpoint=endpoint))
                    continue
                anon_status, anon_body = anon_probe
                anon_decision = classify_response(anon_status, anon_body, min_content_length=self.config.min_content_length)
                self.authorization_matrix.record(endpoint, "anonymous", anon_decision)
                if anon_decision == AuthorizationDecision.ALLOWED:
                    results.append(self._result(test_id, tid, technique, vuln_type, PASS,
                                                  f"'{endpoint.url}': GET is reachable anonymously too -- never protected in the first place, not a method-based bypass",
                                                  role=self.low_priv_role, endpoint=endpoint))
                    continue
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.3,
                    endpoint=endpoint, user_role=self.low_priv_role,
                    request_raw=f"GET {endpoint.url}",
                    response_raw=f"anonymous: HTTP {anon_status}; {self.low_priv_role}: HTTP {status}, {len(body)} bytes",
                    description=(
                        f"'{endpoint.url}' was discovered as a {endpoint.method} endpoint. An anonymous GET "
                        f"against the same URL was denied (HTTP {anon_status}), but an authenticated "
                        f"'{self.low_priv_role}' GET succeeded (HTTP {status}, {len(body)} bytes) -- the URL "
                        f"is behind some access-control boundary that responds to method rather than being "
                        f"denied outright. This is a response-code differential, not a confirmed data/state "
                        f"exposure: it does not prove the GET returns the same privileged content the "
                        f"{endpoint.method} handler protects, only that a bare method switch changes the "
                        "outcome. Manually verify what GET actually returns before treating this as more than a candidate."
                    ),
                    recommendation="Enforce identical authorization checks on every HTTP method a route responds to, not only the one the UI normally uses.",
                )
                finding.evidence_refs = await self._capture_evidence(evidence, context, session, endpoint.url, label=f"idor-method-override-{endpoint.url.rsplit('/', 1)[-1]}", finding=finding)
                results.append(self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, role=self.low_priv_role, endpoint=endpoint, finding=finding))
        finally:
            await anon_context.close()
        return results

    async def _technique_bola_write_methods(self, endpoints, session_manager, session_pool, target_url, evidence, http_method: str, test_technique_id: str) -> list[TestCaseResult]:
        test_id, technique = "TC-054", f"{http_method} object-id substitution"
        vuln_type = f"Missing Object-Level Authorization (BOLA) via {http_method}"
        if not self.config.allow_state_changing_probes:
            return [self._gated_skip(test_id, test_technique_id, technique, vuln_type, f"{http_method}-based BOLA probing is state-changing and disabled by default")]
        candidates = _object_ref_endpoints(endpoints, methods=(http_method,))
        if not candidates:
            return [self._result(test_id, test_technique_id, technique, vuln_type, SKIPPED, f"no {http_method} endpoint with an object-reference parameter discovered")]
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.high_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, test_technique_id, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        method_fn = _method_request_fn(context, http_method)
        results: list[TestCaseResult] = []
        for endpoint, param in candidates:
            results.append(await self._check_bola_write_candidate(
                method_fn, http_method, test_id, test_technique_id, technique, vuln_type, evidence, endpoint, param, context))
        return results

    async def _check_bola_write_candidate(
        self, method_fn, http_method: str, test_id: str, test_technique_id: str, technique: str, vuln_type: str,
        evidence, endpoint, param: str, context,
    ) -> TestCaseResult:
        """Per-endpoint probe-and-check body of
        `_technique_bola_write_methods`'s loop, extracted so that method
        drops to setup + orchestration only -- same branches, same
        order, just named and separated.

        A bare 200/201/204 on the write itself is NOT sufficient
        evidence per this project's own IDOR knowledge base (`stof/
        payloads/idor_knowledge_base.json`'s `cross_cutting_evidence_
        principle`: "a 200/201/204 status code is never sufficient
        evidence on its own"). For DELETE, a "succeeded" candidate is
        re-verified with a follow-up GET against the same object --
        only a genuinely-gone object (404, or DENIED per
        `classify_response()`) counts as confirmed. For PUT/PATCH, a
        small unique marker is written into the payload and the
        follow-up GET must reflect it back -- proving the write
        persisted against that specific object, not just that the
        endpoint returned success."""
        outcomes: dict[str, int] = {}
        markers: dict[str, str] = {}
        for candidate in self.config.candidate_ids:
            probe_url = _set_query_param(endpoint.url, param, candidate)
            kwargs: dict = {"max_redirects": 0}
            if http_method in ("PUT", "PATCH"):
                marker = f"stofbola{secrets.token_hex(4)}"
                markers[candidate] = marker
                kwargs["data"] = f"{param}={candidate}&stof_probe={marker}"
                kwargs["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
            try:
                resp = await method_fn(probe_url, **kwargs)
            except Exception as exc:
                _log.warning(f"{http_method} probe failed for {probe_url}: {exc}")
                continue
            outcomes[candidate] = resp.status
        succeeded = [cid for cid, status in outcomes.items() if status in (200, 201, 204)]
        if len(succeeded) < 2:
            return self._result(test_id, test_technique_id, technique, vuln_type, PASS,
                                 f"'{endpoint.url}': {http_method} succeeded for at most one candidate id -- no cross-object access shown",
                                 role=self.high_priv_role, endpoint=endpoint)

        confirmed, evidence_lines = await self._confirm_bola_write(context, http_method, endpoint, param, succeeded, markers)
        if len(confirmed) < 2:
            return self._result(
                test_id, test_technique_id, technique, vuln_type, PASS,
                f"'{endpoint.url}': {http_method} returned a success status for {len(succeeded)} candidate id(s) "
                f"({succeeded[:3]}), but a follow-up read-back could not confirm the object actually changed for "
                "2 or more of them -- a bare success status is not sufficient evidence.",
                role=self.high_priv_role, endpoint=endpoint,
            )

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=8.6,
            endpoint=endpoint, user_role=self.high_priv_role,
            request_raw="\n".join(f"{http_method} {_set_query_param(endpoint.url, param, cid)}" for cid in confirmed[:3]),
            response_raw="\n".join(evidence_lines[:3]),
            description=(
                f"A single session (role '{self.high_priv_role}') successfully executed "
                f"{http_method} against {len(confirmed)} different objects on '{endpoint.url}' "
                f"by varying '{param}' across {confirmed[:3]}, with no apparent ownership check. "
                f"CONFIRMED via follow-up read-back (not just the write's own status code): "
                + " ".join(evidence_lines[:3])
            ),
            recommendation=f"Enforce object-level authorization on {http_method} handlers, not only on GET.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"bola-{http_method.lower()}-{confirmed[0]}") if evidence else []
        return self._result(test_id, test_technique_id, technique, vuln_type, FAIL, finding.description, role=self.high_priv_role, endpoint=endpoint, finding=finding)

    async def _confirm_bola_write(
        self, context, http_method: str, endpoint, param: str, succeeded: list[str], markers: dict[str, str],
    ) -> tuple[list[str], list[str]]:
        """Re-GET each candidate object that returned a write-success
        status and decide, per method, whether the write actually took
        effect:

        - DELETE: confirmed only if the follow-up GET shows the object
          is genuinely gone (404, or DENIED per `classify_response()`).
          A DELETE that returns 204 but still GETs fine afterward is
          NOT confirmed.
        - PUT/PATCH: confirmed only if the follow-up GET's body
          contains this candidate's unique marker value -- proving the
          write persisted against that specific object.

        Returns `(confirmed_ids, evidence_lines)` -- `evidence_lines`
        states the observed before/after signal for each confirmed id,
        never a claim beyond what this read-only probe itself observed.
        """
        confirmed: list[str] = []
        evidence_lines: list[str] = []
        for cid in succeeded:
            probe_url = _set_query_param(endpoint.url, param, cid)
            probe = await self._probe_get(context, probe_url)
            if probe is None:
                continue
            status, body = probe
            if http_method == "DELETE":
                decision = classify_response(status, body, min_content_length=self.config.min_content_length)
                if status == 404 or decision == AuthorizationDecision.DENIED:
                    confirmed.append(cid)
                    evidence_lines.append(f"[{param}={cid}] DELETE returned {http_method} success; follow-up GET confirmed the object is now absent (HTTP {status}).")
            else:  # PUT / PATCH
                marker = markers.get(cid)
                if marker and marker in body:
                    confirmed.append(cid)
                    evidence_lines.append(f"[{param}={cid}] {http_method} returned success; follow-up GET reflected the write's unique marker value, confirming the write persisted against this object.")
        return confirmed, evidence_lines

    async def _technique_nested_object_reference(self, endpoints, session_manager, session_pool, target_url, evidence) -> list[TestCaseResult]:
        test_id, tid, technique = "TC-054", "TC-054.4", "Nested object reference inside a related sub-resource"
        vuln_type = "Missing Object-Level Authorization (BOLA) via nested reference"
        candidates = [(e, _numeric_path_segment_indexes(e.url)) for e in endpoints if e.method.upper() == "GET"]
        candidates = [(e, idxs) for e, idxs in candidates if len(idxs) >= 2]
        if not candidates:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, "no GET endpoint with 2+ numeric/UUID path segments discovered")]
        try:
            session, context = await self._authenticated_context(session_manager, session_pool, self.high_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        results: list[TestCaseResult] = []
        for endpoint, idxs in candidates:
            outer_index = idxs[0]  # vary the outermost id, keep the inner (last) one fixed
            url_for = lambda cid, e=endpoint, i=outer_index: _set_path_segment(e.url, i, cid)
            responses, statuses = await self._probe_candidates(context, self.config.candidate_ids, url_for)
            distinct = {_content_fingerprint(b) for b in responses.values()}
            if len(responses) >= 2 and len(distinct) >= 2:
                finding = self._object_ref_finding(
                    endpoint, self.high_priv_role, "outer path segment", url_for, statuses, responses, vuln_type, 8.1,
                    description=(
                        f"'{endpoint.url}' has a nested object reference (2+ id-shaped path segments); varying the outer "
                        f"segment across {list(responses.keys())[:3]} while keeping the inner one fixed still returned "
                        f"{len(responses)} distinct objects, for role '{self.high_priv_role}'."
                    ),
                    recommendation="Verify ownership of the OUTER object in a nested resource path too, not only the innermost one.",
                )
                sample_id = next(iter(responses.keys()))
                finding.evidence_refs = await self._capture_evidence(evidence, context, session, url_for(sample_id), label=f"idor-nested-{sample_id}", finding=finding)
                results.append(self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, role=self.high_priv_role, endpoint=endpoint, finding=finding))
            else:
                results.append(self._result(test_id, tid, technique, vuln_type, PASS, f"'{endpoint.url}': varying the outer path segment returned no distinct objects", role=self.high_priv_role, endpoint=endpoint))
        return results

    async def _technique_client_side_only_access_control(self, session_manager, session_pool, target_url) -> list[TestCaseResult]:
        test_id, tid, technique = "TC-050", "TC-050.4", "Client-side-only access control (hidden UI element still reachable via direct request)"
        vuln_type = "Broken Access Control via client-side-only enforcement"
        try:
            _high_session, high_context = await self._authenticated_context(session_manager, session_pool, self.high_priv_role, target_url)
            _low_session, low_context = await self._authenticated_context(session_manager, session_pool, self.low_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        high_links = await self._visible_nav_links(high_context, target_url)
        low_links = await self._visible_nav_links(low_context, target_url)
        if high_links is None or low_links is None:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, "could not extract DOM navigation links from one or both sessions")]

        hidden_from_low_priv = sorted(high_links - low_links)
        if not hidden_from_low_priv:
            return [self._result(test_id, tid, technique, vuln_type, PASS, "no navigation link was visible to the high-priv session but hidden from the low-priv session")]

        results: list[TestCaseResult] = []
        for link_url in hidden_from_low_priv[:5]:  # bounded sweep
            probe = await self._probe_get(low_context, link_url)
            if probe is None:
                continue
            status, body = probe
            decision = classify_response(status, body, min_content_length=self.config.min_content_length)
            if decision == AuthorizationDecision.ALLOWED:
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=6.5,
                    endpoint=_synthetic_endpoint(link_url), user_role=self.low_priv_role,
                    request_raw=f"GET {link_url}", response_raw=f"HTTP {status}, {len(body)} bytes",
                    description=f"'{link_url}' is hidden from the UI for role '{self.low_priv_role}' (not in its rendered navigation) but still fully reachable via a direct request.",
                    recommendation="Enforce access control server-side for every route; hiding a link/button in the UI is not a substitute.",
                )
                results.append(self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, role=self.low_priv_role, endpoint=finding.endpoint, finding=finding))
                return results
        results.append(self._result(test_id, tid, technique, vuln_type, PASS, f"{len(hidden_from_low_priv[:5])} UI-hidden link(s) checked; all were also denied via direct request", role=self.low_priv_role))
        return results

    async def _visible_nav_links(self, context, target_url: str) -> set[str] | None:
        page = None
        try:
            page = await context.new_page()
            await page.goto(target_url)
            hrefs = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            return {h for h in hrefs if h.startswith(("http://", "https://"))}
        except Exception as exc:
            _log.warning(f"DOM nav-link extraction failed for {target_url}: {exc}")
            return None
        finally:
            if page is not None:
                await page.close()

    def _technique_privilege_escalation_chaining(self, base_findings: list[Finding]) -> TestCaseResult:
        tid, technique = "TC-052.3", "Horizontal-to-vertical chaining (compromise a peer account, pivot to admin)"
        vuln_type = "Privilege Escalation via chained compromise"
        idor_findings = [f for f in base_findings if f.vuln_type.startswith("Insecure Direct Object Reference")]
        if not idor_findings:
            return self._result("TC-052", tid, technique, vuln_type, SKIPPED, "no confirmed IDOR (TC-053/TC-054) finding this run to chain from")

        for finding in idor_findings:
            body_lower = finding.response_raw.lower()
            hit_fields = [name for name in _PRIVILEGE_FIELD_NAMES if f'"{name}"' in body_lower or f"'{name}'" in body_lower]
            if hit_fields:
                return self._result("TC-052", tid, technique, vuln_type, FAIL,
                                     f"IDOR-exposed data from '{finding.endpoint.url}' contains privilege-relevant field(s) {hit_fields} -- chaining the IDOR could expose another user's role/credentials.",
                                     finding=finding)
        return self._result("TC-052", tid, technique, vuln_type, PASS, f"{len(idor_findings)} confirmed IDOR finding(s) checked; none exposed a privilege-relevant field ({', '.join(_PRIVILEGE_FIELD_NAMES)})")

    async def _technique_forced_browsing_unauthenticated(self, endpoints, session_pool, evidence) -> list[TestCaseResult]:
        test_id, tid, technique = "TC-050", "TC-050.3", "Forced browsing to a protected page while unauthenticated"
        vuln_type = "Broken Access Control (unauthenticated forced browsing)"
        protected_endpoints = [e for e in endpoints if e.method.upper() == "GET" and e.auth_required]
        if not protected_endpoints:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, "no endpoint marked auth_required was discovered")]

        anon_context = await session_pool.new_anonymous_context()
        try:
            results: list[TestCaseResult] = []
            for endpoint in protected_endpoints:
                probe = await self._probe_get(anon_context, endpoint.url)
                if probe is None:
                    results.append(self._result(test_id, tid, technique, vuln_type, "ERROR", "GET probe failed", endpoint=endpoint))
                    continue
                status, body = probe
                decision = classify_response(status, body, min_content_length=self.config.min_content_length)
                if decision == AuthorizationDecision.ALLOWED:
                    finding = Finding(
                        module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.1,
                        endpoint=endpoint, user_role="unauthenticated",
                        request_raw=f"GET {endpoint.url}\n(no session cookies/headers)",
                        response_raw=f"HTTP {status}, {len(body)} bytes",
                        description=f"'{endpoint.url}' is marked as requiring authentication, but an unauthenticated request received a full HTTP {status} response ({len(body)} bytes) instead of being denied.",
                        recommendation="Enforce authentication server-side on every endpoint that requires it, independent of what the client-side router/UI shows.",
                    )
                    finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"bac-anon-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
                    results.append(self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, role="unauthenticated", endpoint=endpoint, finding=finding))
                else:
                    results.append(self._result(test_id, tid, technique, vuln_type, PASS, f"'{endpoint.url}': unauthenticated request returned HTTP {status} -- denied", endpoint=endpoint))
            return results
        finally:
            await anon_context.close()

    async def _safe(self, coro) -> list[TestCaseResult]:
        """Run one technique coroutine, converting any unexpected bug in
        it into a log line rather than aborting every other technique --
        the same resilience `run()` already gives KeyError specifically,
        widened to any exception since a per-technique bug here must
        never cost the rest of the scan its results."""
        try:
            return await coro
        except Exception as exc:
            _log.warning(f"technique run failed: {exc}")
            return []

    def _reused_result(self, test_id: str, technique_id: str, technique: str, default_vuln_type: str,
                        default_status: str, default_role: str | None, matching_findings: list[Finding],
                        base_error: str | None = None) -> list[TestCaseResult]:
        """Wrap Finding(s) already produced by `run()`'s original three
        methods as `TestCaseResult`(s) for a technique that IS one of
        those methods, without re-running the underlying probe.

        `base_error` is the failure string recorded in
        `_base_test_errors` for whichever base test feeds this technique.
        When it's set and there are no findings, the honest answer is
        ERROR ("this test could not complete") -- reporting the usual
        PASS there would claim the target resisted an attack that was
        never actually sent."""
        if matching_findings:
            return [
                self._result(test_id, technique_id, technique, f.vuln_type, FAIL, f.description, role=f.user_role, endpoint=f.endpoint, finding=f)
                for f in matching_findings
            ]
        if base_error is not None:
            return [self._result(test_id, technique_id, technique, default_vuln_type, ERROR,
                                  f"could not complete this test (transient failure during its base run): {base_error}", role=default_role)]
        return [self._result(test_id, technique_id, technique, default_vuln_type, default_status,
                              f"no elevated/cross-object access was accepted (role='{default_role}')", role=default_role)]

    async def _techniques_tc053(self, endpoints, session_manager, session_pool, target_url, evidence, base_findings: list[Finding]) -> list[TestCaseResult]:
        results: list[TestCaseResult] = []
        results.extend(await self._safe(self._technique_idor_path_param(endpoints, session_manager, session_pool, target_url, evidence)))

        query_object_ref_endpoints = _object_ref_endpoints(endpoints)
        idor_query_findings = [f for f in base_findings if f.vuln_type.startswith("Insecure Direct Object Reference")]
        if not query_object_ref_endpoints:
            results.append(self._result("TC-053", "TC-053.2", "Query-parameter ID substitution", "Insecure Direct Object Reference (IDOR)", SKIPPED, "no GET endpoint with a single object-reference query parameter discovered"))
        else:
            results.extend(self._reused_result("TC-053", "TC-053.2", "Query-parameter ID substitution", "Insecure Direct Object Reference (IDOR)", PASS, self.high_priv_role, idor_query_findings,
                                                base_error=self._base_test_errors.get("horizontal_idor")))

        results.extend(await self._safe(self._technique_idor_body_field(endpoints, session_manager, session_pool, target_url, evidence)))

        seen_bodies = [f.response_raw for f in base_findings]
        results.extend(await self._safe(self._technique_idor_leaked_ids(endpoints, session_manager, session_pool, target_url, evidence, seen_bodies)))
        results.extend(await self._safe(self._technique_idor_method_override(endpoints, session_manager, session_pool, target_url, evidence)))
        results.extend(self._technique_id_predictability_analysis(endpoints, base_findings))
        return results

    async def _techniques_tc054(self, endpoints, session_manager, session_pool, target_url, evidence) -> list[TestCaseResult]:
        results: list[TestCaseResult] = []
        results.extend(await self._safe(self._technique_bola_write_methods(endpoints, session_manager, session_pool, target_url, evidence, "PUT", "TC-054.2")))
        results.extend(await self._safe(self._technique_bola_write_methods(endpoints, session_manager, session_pool, target_url, evidence, "DELETE", "TC-054.3")))
        results.extend(await self._safe(self._technique_bola_write_methods(endpoints, session_manager, session_pool, target_url, evidence, "PATCH", "TC-054.5")))
        results.extend(await self._safe(self._technique_nested_object_reference(endpoints, session_manager, session_pool, target_url, evidence)))
        return results

    def _reuse_bac_status(self, results_so_far: list[TestCaseResult], source_test_id: str, source_label: str, tid: str, technique: str) -> TestCaseResult:
        """TC-050.1/.2 both reuse another test_id's already-computed
        FAIL/PASS verdict rather than re-probing -- same shape, differing
        only in which source `test_id` they reuse and the human-readable
        `source_label` for it. Extracted so `_techniques_tc050` drops to
        orchestration only."""
        matching_fail = next((r for r in results_so_far if r.status == FAIL and r.test_id == source_test_id), None)
        return self._result(
            "TC-050", tid, technique, "Broken Access Control",
            FAIL if matching_fail else PASS,
            f"at least one {source_test_id} {source_label} technique failed" if matching_fail else f"see {source_test_id} technique results",
            finding=matching_fail.finding if matching_fail else None,
        )

    async def _techniques_tc050(self, endpoints, session_manager, session_pool, target_url, evidence, results_so_far: list[TestCaseResult]) -> list[TestCaseResult]:
        results: list[TestCaseResult] = [
            self._reuse_bac_status(results_so_far, "TC-053", "IDOR", "TC-050.1", "Direct object reference bypass (reuse of TC-053)"),
            self._reuse_bac_status(results_so_far, "TC-055", "BFLA", "TC-050.2", "Missing function-level check (reuse of TC-055)"),
        ]
        results.extend(await self._safe(self._technique_forced_browsing_unauthenticated(endpoints, session_pool, evidence)))
        results.extend(await self._safe(self._technique_client_side_only_access_control(session_manager, session_pool, target_url)))
        return results

    async def _techniques_tc052(self, endpoints, session_manager, session_pool, target_url, evidence, base_findings: list[Finding]) -> list[TestCaseResult]:
        role_tamper_findings = [f for f in base_findings if f.vuln_type == "Role Manipulation via Parameter Tampering"]
        role_param_endpoints = self._role_param_endpoints(endpoints)
        results: list[TestCaseResult] = []
        if not role_param_endpoints:
            results.append(self._result("TC-052", "TC-052.1", "Vertical escalation via role parameter tampering in request", "Privilege Escalation", SKIPPED, "no role-like query parameter discovered"))
        else:
            results.extend(self._reused_result("TC-052", "TC-052.1", "Vertical escalation via role parameter tampering in request", "Privilege Escalation", PASS, self.low_priv_role, role_tamper_findings,
                                                base_error=self._base_test_errors.get("role_tampering")))
        results.append(self._result("TC-052", "TC-052.2", "Vertical escalation via JWT claim tampering", "Privilege Escalation via JWT", SKIPPED, "covered by stof.modules.jwt_tests (TC-057) instead, to avoid duplicating JWT-tampering logic across modules"))
        results.append(self._technique_privilege_escalation_chaining(base_findings))
        results.append(await self._safe_result(self._technique_mass_assignment(endpoints, session_manager, session_pool, target_url, evidence),
                                                 "TC-052", "TC-052.4", "Escalation via mass assignment (inject role/isAdmin on profile update)", "Privilege Escalation via Mass Assignment"))
        return results

    async def run_techniques(
        self,
        endpoints: list["Endpoint"],
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[TestCaseResult]:
        target_url = self.target_url or (endpoints[0].url if endpoints else "")
        # `run()`'s three original methods (query-param IDOR, vertical
        # priv-esc, role-param tampering) are each reused by more than
        # one technique below (e.g. TC-053.2 and TC-050.1 both want the
        # IDOR result) -- called exactly once here rather than once per
        # reuse, so a live target only gets probed once per underlying
        # mechanism regardless of how many technique IDs report on it.
        base_findings = await self._safe(self.run(endpoints, session_manager, session_pool, evidence))

        results: list[TestCaseResult] = []
        results.extend(await self._techniques_tc053(endpoints, session_manager, session_pool, target_url, evidence, base_findings))
        results.extend(await self._techniques_tc054(endpoints, session_manager, session_pool, target_url, evidence))
        results.extend(await self._techniques_tc055(endpoints, session_manager, session_pool, target_url, evidence, base_findings))
        results.extend(await self._techniques_tc050(endpoints, session_manager, session_pool, target_url, evidence, results))
        results.extend(await self._techniques_tc052(endpoints, session_manager, session_pool, target_url, evidence, base_findings))
        results.extend(await self._techniques_tc056(endpoints, session_manager, session_pool, target_url, evidence, base_findings))
        results.extend(await self._techniques_tc131(endpoints, session_manager, session_pool, target_url, evidence))
        return results
