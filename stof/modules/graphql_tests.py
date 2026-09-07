"""Layer 9 — `stof/modules/graphql_tests.py`: GraphQL Authorization
Bypass (TC-116).

Every technique here first needs a GraphQL endpoint at all -- detected
generically (a discovered endpoint whose path contains "graphql", the
near-universal convention `/graphql`/`/api/graphql`/... follows) rather
than assuming any one target's exact route. A target with no GraphQL
surface (this project's own demo target, OWASP Juice Shop, is REST-only)
correctly reports every technique SKIPPED rather than guessing at a URL.

Introspection (`{__schema{...}}`) is used throughout this module as a
means to name real query/mutation fields to probe. It is also TC-114's
own subject in `config/testcases.json` (GraphQL Introspection Enabled,
High severity there); TC-116.5 in this module scores the same signal
this module already gathers internally on every run -- whether the
introspection query it sends succeeds and returns a non-trivial schema
-- as its own Low-severity, non-overclaiming finding (introspection is
expected and harmless in non-production, so this is reported as
"enabled" with that caveat, not an unconditional vulnerability claim).
"""
from __future__ import annotations

import json as json_module
from dataclasses import dataclass
from typing import TYPE_CHECKING

from stof.core.logger import get_logger
from stof.findings.models import Finding

from .base import VulnModule
from .results import FAIL, PASS, SKIPPED, TestCaseResult, extract_findings

if TYPE_CHECKING:
    from stof.crawler.endpoint_store import Endpoint
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.graphql_tests")

_INTROSPECTION_QUERY = """
query {
  __schema {
    queryType { fields { name } }
    mutationType { fields { name } }
  }
}
"""


def find_graphql_endpoint(endpoints: list["Endpoint"]) -> "Endpoint | None":
    return next((e for e in endpoints if "graphql" in e.url.lower() and e.method.upper() in ("GET", "POST")), None)


async def _graphql_request(context, url: str, query: str, variables: dict | None = None) -> tuple[int, dict | None, str]:
    """Returns (status, parsed_body_or_None, raw_text)."""
    try:
        resp = await context.request.post(
            url, data=json_module.dumps({"query": query, "variables": variables or {}}),
            headers={"Content-Type": "application/json"}, max_redirects=0,
        )
        raw = await resp.text()
    except Exception as exc:
        return 0, None, str(exc)
    try:
        return resp.status, json_module.loads(raw), raw
    except json_module.JSONDecodeError:
        return resp.status, None, raw


@dataclass
class GraphQLTestConfig:
    high_priv_role: str = "admin"
    low_priv_role: str = "normal"
    target_url: str | None = None
    test_username: str | None = None
    # TC-116.3 sends real (always wrong-password) login attempts against
    # the test account -- gated behind the same state-changing-probes
    # safety switch every other repeated-auth-attempt technique in this
    # codebase uses (see auth_tests.py), and bounded small so it can't
    # actually lock the test account out for the rest of a scan.
    allow_state_changing_probes: bool = False
    max_sequential_attempts: int = 5


class GraphQLTestsModule(VulnModule):
    module_id = "graphql_tests"
    name = "GraphQL Authorization Bypass Tests"
    phase = 1

    def __init__(self, config: GraphQLTestConfig | None = None) -> None:
        self.config = config or GraphQLTestConfig()

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _result(self, technique_id: str, technique: str, vuln_type: str, status: str, detail: str,
                role: str | None = None, endpoint=None, finding: Finding | None = None,
                severity: str = "Critical") -> TestCaseResult:
        return self._make_result(
            test_id="TC-116", technique_id=technique_id, technique=technique, vuln_type=vuln_type,
            status=status, detail=detail, role=role, endpoint=endpoint, finding=finding, severity=severity,
        )

    async def _context_for(self, role, session_manager, session_pool, target_url):
        page = await (await session_pool.get_context(role)).new_page()
        try:
            session = await session_manager.get_session(role, page)
        finally:
            await page.close()
        return await session_pool.apply_session(session, target_url)

    @staticmethod
    def _schema_field_names(schema: dict, type_key: str) -> list[str]:
        return [f["name"] for f in (schema.get(type_key) or {}).get("fields") or []]

    async def _fetch_field_names(self, context, endpoint_url: str) -> tuple[list[str], list[str]]:
        status, body, _ = await _graphql_request(context, endpoint_url, _INTROSPECTION_QUERY)
        if status != 200 or not body or "data" not in body:
            return [], []
        schema = (body.get("data") or {}).get("__schema") or {}
        return self._schema_field_names(schema, "queryType"), self._schema_field_names(schema, "mutationType")

    async def _technique_field_level_bypass(self, endpoint, session_manager, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-116.1", "Query bypasses field-level authorization"
        vuln_type = "GraphQL Authorization Bypass (field-level)"
        target_url = self.config.target_url or endpoint.url
        try:
            low_context = await self._context_for(self.config.low_priv_role, session_manager, session_pool, target_url)
        except KeyError as exc:
            return self._result(tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}", endpoint=endpoint)

        query_fields, _mutations = await self._fetch_field_names(low_context, endpoint.url)
        if not query_fields:
            return self._result(tid, technique, vuln_type, SKIPPED, "introspection disabled or returned no query fields -- can't enumerate fields to probe", endpoint=endpoint)

        sensitive_fields = [f for f in query_fields if any(h in f.lower() for h in ("user", "admin", "account", "order", "payment", "role"))]
        probe_fields = sensitive_fields or query_fields[:5]
        for field_name in probe_fields:
            finding = await self._check_field_level_bypass_candidate(low_context, vuln_type, evidence, endpoint, field_name)
            if finding is not None:
                return self._result(tid, technique, vuln_type, FAIL, finding.description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding)
        return self._result(tid, technique, vuln_type, PASS, f"{len(probe_fields)} query field(s) probed, none returned data to the low-privileged role", role=self.config.low_priv_role, endpoint=endpoint)

    async def _check_field_level_bypass_candidate(self, low_context, vuln_type: str, evidence, endpoint, field_name: str) -> Finding | None:
        """Per-field probe-and-check body of
        `_technique_field_level_bypass`'s loop, extracted so that method
        drops to setup + orchestration only -- same branches, same
        order, just named and separated."""
        status, body, raw = await _graphql_request(low_context, endpoint.url, f"query {{ {field_name} }}")
        if not (status == 200 and body and "errors" not in body and body.get("data", {}).get(field_name) is not None):
            return None
        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.2,
            endpoint=endpoint, user_role=self.config.low_priv_role,
            request_raw=f"POST {endpoint.url}\n\nquery {{ {field_name} }}",
            response_raw=raw[:300],
            description=f"Query field '{field_name}' returned data to a low-privileged session (role '{self.config.low_priv_role}') with no field-level authorization error.",
            recommendation="Enforce authorization per-field/per-resolver, not only at the transport (endpoint) level.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"graphql-field-{field_name}") if evidence else []
        return finding

    async def _technique_object_level_bypass(self, endpoint, session_manager, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-116.2", "Mutation bypasses object-level authorization (GraphQL BOLA)"
        vuln_type = "GraphQL Authorization Bypass (object-level, mutation)"
        target_url = self.config.target_url or endpoint.url
        try:
            low_context = await self._context_for(self.config.low_priv_role, session_manager, session_pool, target_url)
        except KeyError as exc:
            return self._result(tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}", endpoint=endpoint)

        _queries, mutation_fields = await self._fetch_field_names(low_context, endpoint.url)
        write_mutations = [f for f in mutation_fields if any(h in f.lower() for h in ("delete", "update", "remove", "edit", "set"))]
        if not write_mutations:
            return self._result(tid, technique, vuln_type, SKIPPED, "introspection returned no delete/update-shaped mutation to probe", endpoint=endpoint)

        # Read-only check only: confirms the mutation is *callable* by a
        # low-priv session (a schema-validation error means it's
        # reachable at all; a permission/auth error means it's actually
        # gated) without supplying real arguments that would attempt a
        # real write -- consistent with this project's "never actually
        # execute a destructive call outside an explicit opt-in" rule.
        mutation_name = write_mutations[0]
        finding = await self._check_object_level_bypass_candidate(low_context, vuln_type, evidence, endpoint, mutation_name)
        if finding is not None:
            return self._result(tid, technique, vuln_type, FAIL, finding.description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding)
        return self._result(tid, technique, vuln_type, PASS, f"mutation '{mutation_name}' was rejected with an authorization-shaped error (or a transport error)", role=self.config.low_priv_role, endpoint=endpoint)

    @staticmethod
    def _looks_like_auth_denial(errors: list[dict]) -> bool:
        error_text = " ".join(str(e.get("message", "")) for e in errors).lower()
        return any(w in error_text for w in ("auth", "permission", "forbidden", "denied", "unauthorized"))

    async def _check_object_level_bypass_candidate(self, low_context, vuln_type: str, evidence, endpoint, mutation_name: str) -> Finding | None:
        """Probe-and-check body of `_technique_object_level_bypass`,
        extracted so that method drops to setup + orchestration only --
        same branches, same order, just named and separated."""
        status, body, raw = await _graphql_request(low_context, endpoint.url, f"mutation {{ {mutation_name} }}")
        errors = (body or {}).get("errors") or []
        if not (status == 200 and errors and not self._looks_like_auth_denial(errors)):
            return None
        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
            endpoint=endpoint, user_role=self.config.low_priv_role,
            request_raw=f"POST {endpoint.url}\n\nmutation {{ {mutation_name} }}",
            response_raw=raw[:300],
            description=f"Mutation '{mutation_name}' was reachable by a low-privileged session (role '{self.config.low_priv_role}') and failed only on argument validation, not on an authorization check.",
            recommendation="Check the caller's authorization for a mutation before validating its arguments, so an unauthorized caller sees a permission error, not a schema error.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"graphql-mutation-{mutation_name}") if evidence else []
        return finding

    # Small, high-signal hint list -- same philosophy as every other hint
    # list in this codebase (field-name hints in base.py, sensitive-field
    # hints above, write-verb hints in `_technique_object_level_bypass`).
    _LOGIN_MUTATION_HINTS = ("login", "signin", "authenticate")

    @staticmethod
    def _find_login_mutation(mutation_fields: list[str]) -> str | None:
        """First mutation field name that looks like a login/authenticate
        entry point, or `None` if the schema exposes nothing of the
        sort. Pure helper -- operates only on the field-name list
        `_fetch_field_names` already returns, no re-introspection."""
        return next(
            (f for f in mutation_fields if any(h in f.lower() for h in GraphQLTestsModule._LOGIN_MUTATION_HINTS)),
            None,
        )

    @staticmethod
    def _looks_like_rate_limited(errors: list[dict]) -> bool:
        error_text = " ".join(str(e.get("message", "")) for e in errors).lower()
        return any(phrase in error_text for phrase in ("rate limit", "too many attempts", "locked", "try again later"))

    @staticmethod
    def _login_call(mutation_name: str, username: str, password: str, alias: str | None = None) -> str:
        prefix = f"{alias}: " if alias else ""
        return f'{prefix}{mutation_name}(username: "{username}", password: "{password}")'

    async def _technique_batching_bypass(self, endpoint, session_manager, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-116.3", "Batched query bypasses a per-request auth check"
        vuln_type = "GraphQL Authorization Bypass (batching)"
        if not self.config.allow_state_changing_probes:
            return self._result(tid, technique, vuln_type, SKIPPED,
                                 "requires sending real (wrong-password) login attempts against the test account -- "
                                 "set GraphQLTestConfig.allow_state_changing_probes=True for an authorized engagement window")
        if not self.config.test_username:
            return self._result(tid, technique, vuln_type, SKIPPED, "no test_username configured to attempt logins as")

        target_url = self.config.target_url or endpoint.url
        try:
            low_context = await self._context_for(self.config.low_priv_role, session_manager, session_pool, target_url)
        except KeyError as exc:
            return self._result(tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}", endpoint=endpoint)

        _queries, mutation_fields = await self._fetch_field_names(low_context, endpoint.url)
        mutation_name = self._find_login_mutation(mutation_fields)
        if mutation_name is None:
            return self._result(tid, technique, vuln_type, SKIPPED,
                                 "introspection returned no login/signin/authenticate-shaped mutation to probe", endpoint=endpoint)

        return await self._run_batching_bypass_probe(low_context, vuln_type, evidence, endpoint, mutation_name)

    async def _run_batching_bypass_probe(self, context, vuln_type: str, evidence, endpoint, mutation_name: str) -> TestCaseResult:
        """Sequential baseline followed by (only if the baseline shows a
        lockout) a single aliased-batch request of the same attempt
        count -- extracted from `_technique_batching_bypass` so that
        method drops to setup + orchestration only, same convention as
        every other technique's `_check_*_candidate` split."""
        tid, technique = "TC-116.3", "Batched query bypasses a per-request auth check"
        username = self.config.test_username
        wrong_password = "definitely-Wrong-Pw1!"
        n = self.config.max_sequential_attempts

        locked_at: int | None = None
        for attempt in range(1, n + 1):
            _status, body, _raw = await _graphql_request(context, endpoint.url, f"mutation {{ {self._login_call(mutation_name, username, wrong_password)} }}")
            errors = (body or {}).get("errors") or []
            if self._looks_like_rate_limited(errors):
                locked_at = attempt
                break

        if locked_at is None:
            return self._result(tid, technique, vuln_type, PASS,
                                 f"sequential baseline of {n} wrong-password attempt(s) against mutation '{mutation_name}' never triggered a "
                                 "rate-limit/lockout-shaped error -- inconclusive baseline: this target may have no login attempt limiter at "
                                 "all, which is not itself a vulnerability and is not evidence of a batching bypass",
                                 role=self.config.low_priv_role, endpoint=endpoint)

        batch_query = "mutation { " + " ".join(
            self._login_call(mutation_name, username, wrong_password, alias=f"a{i}") for i in range(n)
        ) + " }"
        _status, batch_body, batch_raw = await _graphql_request(context, endpoint.url, batch_query)
        batch_errors = (batch_body or {}).get("errors") or []

        if self._looks_like_rate_limited(batch_errors):
            return self._result(tid, technique, vuln_type, PASS,
                                 f"sequential baseline locked out at attempt {locked_at}/{n}; the same {n} attempts sent as a single aliased "
                                 f"batch request against mutation '{mutation_name}' still triggered the same lockout-shaped error -- the limiter "
                                 "holds under aliasing",
                                 role=self.config.low_priv_role, endpoint=endpoint)

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
            endpoint=endpoint, user_role=self.config.low_priv_role,
            request_raw=f"POST {endpoint.url}\n\n{batch_query}",
            response_raw=batch_raw[:300],
            description=(
                f"Sequential login attempts against mutation '{mutation_name}' locked out at attempt {locked_at}/{n}, but the same {n} "
                f"attempts sent as a single GraphQL aliased-batch request completed without the same lockout-shaped error appearing -- "
                "the per-request attempt limiter counts HTTP requests, not individual login operations, and can be bypassed by batching."
            ),
            recommendation="Count login attempts per operation (each aliased mutation call), not per HTTP request, when enforcing a login attempt limiter.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"graphql-batch-{mutation_name}") if evidence else []
        return self._result(tid, technique, vuln_type, FAIL, finding.description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding)

    # Same hint-list philosophy as `_technique_field_level_bypass`'s
    # sensitive-field hints -- a small, high-signal set of common
    # relationship-object sub-field names (id/contact/monetary fields),
    # not an attempt to enumerate the real schema type. Introspection
    # here (via `_fetch_field_names`) names *candidate* top-level query
    # fields to descend into; it does not report their return types, so
    # the nested field actually selected is discovered by trying these
    # hints, not by resolving real GraphQL type information.
    _NESTED_SUBFIELD_HINTS = ("id", "email", "total", "amount", "name")

    async def _technique_nested_relationship_bypass(self, endpoint, session_manager, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-116.4", "Query bypasses authorization via nested relationship traversal"
        vuln_type = "GraphQL Authorization Bypass (nested relationship)"
        target_url = self.config.target_url or endpoint.url
        try:
            low_context = await self._context_for(self.config.low_priv_role, session_manager, session_pool, target_url)
        except KeyError as exc:
            return self._result(tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}", endpoint=endpoint)

        query_fields, _mutations = await self._fetch_field_names(low_context, endpoint.url)
        if not query_fields:
            return self._result(tid, technique, vuln_type, SKIPPED, "introspection disabled or returned no query fields -- can't enumerate a relationship path to probe", endpoint=endpoint)

        sensitive_fields = [f for f in query_fields if any(h in f.lower() for h in ("user", "admin", "account", "order", "payment", "role"))]
        probe_fields = sensitive_fields or query_fields[:5]
        for field_name in probe_fields:
            for sub_field in self._NESTED_SUBFIELD_HINTS:
                finding = await self._check_nested_relationship_bypass_candidate(low_context, vuln_type, evidence, endpoint, field_name, sub_field)
                if finding is not None:
                    return self._result(tid, technique, vuln_type, FAIL, finding.description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding)
        return self._result(
            tid, technique, vuln_type, PASS,
            f"{len(probe_fields)} query field(s) probed via one level of nested relationship traversal "
            f"({len(self._NESTED_SUBFIELD_HINTS)} sub-field hint(s) each), none returned nested data to the low-privileged role",
            role=self.config.low_priv_role, endpoint=endpoint,
        )

    async def _check_nested_relationship_bypass_candidate(self, low_context, vuln_type: str, evidence, endpoint, field_name: str, sub_field: str) -> Finding | None:
        """Per-(field, sub-field) probe-and-check body of
        `_technique_nested_relationship_bypass`'s loop, extracted the
        same way `_check_field_level_bypass_candidate` is: a `sub_field`
        that doesn't actually exist on `field_name`'s return type
        produces a GraphQL validation error (in `body["errors"]`), which
        this rejects exactly like `_check_field_level_bypass_candidate`
        rejects an auth-denial error -- the two cases are indistinguishable
        from a black-box probe and both correctly fall through to trying
        the next candidate."""
        query = f"query {{ {field_name} {{ {sub_field} }} }}"
        status, body, raw = await _graphql_request(low_context, endpoint.url, query)
        if not (status == 200 and body and "errors" not in body):
            return None
        parent = (body.get("data") or {}).get(field_name)
        value = parent.get(sub_field) if isinstance(parent, dict) else None
        if value is None:
            return None
        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.1,
            endpoint=endpoint, user_role=self.config.low_priv_role,
            request_raw=f"POST {endpoint.url}\n\n{query}",
            response_raw=raw[:300],
            description=(
                f"Nested field '{field_name} {{ {sub_field} }}' returned data through a relationship traversal to a "
                f"low-privileged session (role '{self.config.low_priv_role}') with no authorization error, even where "
                "top-level field-level (TC-116.1) and object-level mutation (TC-116.2) authorization checks may be "
                "enforced -- authorization was not applied consistently across the object graph's relationship path."
            ),
            recommendation="Enforce authorization on every resolver in the object graph, including nested/relationship fields reached through a parent object, not only on top-level query/mutation entry points.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"graphql-nested-{field_name}-{sub_field}") if evidence else []
        return finding

    async def _technique_introspection_exposed(self, endpoint, session_manager, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-116.5", "GraphQL introspection is enabled and exposes the schema"
        vuln_type = "GraphQL Introspection Enabled"
        target_url = self.config.target_url or endpoint.url
        try:
            low_context = await self._context_for(self.config.low_priv_role, session_manager, session_pool, target_url)
        except KeyError as exc:
            return self._result(tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}", endpoint=endpoint, severity="Low")

        query_fields, mutation_fields = await self._fetch_field_names(low_context, endpoint.url)
        if not query_fields and not mutation_fields:
            return self._result(
                tid, technique, vuln_type, PASS,
                "introspection query returned no usable query/mutation fields -- introspection appears disabled (or the "
                "endpoint returned an empty/errored schema response)",
                role=self.config.low_priv_role, endpoint=endpoint, severity="Low",
            )

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Low", cvss_score=3.1,
            endpoint=endpoint, user_role=self.config.low_priv_role,
            request_raw=f"POST {endpoint.url}\n\n{_INTROSPECTION_QUERY.strip()}",
            response_raw=f"{{queryType_fields: {len(query_fields)}, mutationType_fields: {len(mutation_fields)}}}"[:300],
            description=(
                f"The GraphQL introspection query ({{ __schema {{ ... }} }}) succeeded for a low-privileged session (role "
                f"'{self.config.low_priv_role}') and returned a non-trivial schema -- {len(query_fields)} query field(s) and "
                f"{len(mutation_fields)} mutation field(s), including the field names this module used to build TC-116.1/.2/.4's "
                "own probes. Introspection is expected and harmless on development/staging endpoints; on a production endpoint "
                "it discloses the full query/mutation surface (field and argument names) to any caller, materially easing "
                "reconnaissance. This scan has no reliable way to distinguish a production endpoint from a non-production one, "
                "so this finding should be triaged with that context in mind rather than treated as an unconditional vulnerability."
            ),
            recommendation="Disable introspection on production GraphQL endpoints (or gate it behind authentication), and leave it enabled only where a development/staging environment genuinely needs it.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="graphql-introspection-enabled") if evidence else []
        return self._result(tid, technique, vuln_type, FAIL, finding.description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding, severity="Low")

    async def run_techniques(
        self,
        endpoints: list["Endpoint"],
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[TestCaseResult]:
        endpoint = find_graphql_endpoint(endpoints)
        if endpoint is None:
            reason = "no GraphQL endpoint discovered on this target (no URL containing 'graphql')"
            return [
                self._result("TC-116.1", "Query bypasses field-level authorization", "GraphQL Authorization Bypass (field-level)", SKIPPED, reason),
                self._result("TC-116.2", "Mutation bypasses object-level authorization (GraphQL BOLA)", "GraphQL Authorization Bypass (object-level, mutation)", SKIPPED, reason),
                self._result("TC-116.3", "Batched query bypasses a per-request auth check", "GraphQL Authorization Bypass (batching)", SKIPPED, reason),
                self._result("TC-116.4", "Query bypasses authorization via nested relationship traversal", "GraphQL Authorization Bypass (nested relationship)", SKIPPED, reason),
                self._result("TC-116.5", "GraphQL introspection is enabled and exposes the schema", "GraphQL Introspection Enabled", SKIPPED, reason, severity="Low"),
            ]

        results: list[TestCaseResult] = []
        for coro in (
            self._technique_field_level_bypass(endpoint, session_manager, session_pool, evidence),
            self._technique_object_level_bypass(endpoint, session_manager, session_pool, evidence),
            self._technique_batching_bypass(endpoint, session_manager, session_pool, evidence),
            self._technique_nested_relationship_bypass(endpoint, session_manager, session_pool, evidence),
            self._technique_introspection_exposed(endpoint, session_manager, session_pool, evidence),
        ):
            try:
                results.append(await coro)
            except Exception as exc:
                _log.warning(f"graphql_tests technique failed unexpectedly: {exc}")
        return results
