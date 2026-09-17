"""TC-131 -- Tenant Isolation BOLA, split out of `idor_tests.py` for the
same reason as `bfla_tests.py`/`role_tests.py`/`mass_assignment_tests.py`
(see `bfla_tests.py`'s module docstring for the mixin-vs-separate-module
reasoning: TC-050/TC-052's reuse logic and shared session/evidence/
matrix plumbing depend on same-scan-pass results, and CLAUDE.md's own
rule against cross-module imports between siblings rules out a real
module boundary here).

Grounded in the `tenant_isolation` family of `stof/payloads/
idor_knowledge_base.json` (8.3% of real-world disclosed BOLA reports,
zero prior STOF coverage): an organization/tenant/workspace-scoping
parameter is a DISTINCT attack shape from a per-object identifier --
substituting it tests "can I reach a different ORGANIZATION's data",
not "can I reach a different object owned within my own scope". That's
why `_looks_like_tenant_scope_param` in `_idor_shared.py` is a
deliberately separate function from `_looks_like_object_reference`,
never merged, and why this technique lives in its own file rather than
being folded into `_technique_idor_path_param`/`_technique_idor_leaked_
ids`.

Confirmation reuses the exact same content-differential pattern
`idor_tests.py` already uses for object-id substitution
(`_probe_candidates`/`_content_fingerprint`): if varying the tenant-
scope parameter across `IdorTestConfig.candidate_ids` returns 2+
distinct, substantial response bodies, the server isn't scoping
results to the requester's own organization. GET-based substitution is
the default and always runs; POST-based substitution only runs under
`allow_state_changing_probes`, the same gate every other write-verb
technique in this file family already uses -- no new, ungated write
path is introduced.
"""
from __future__ import annotations

import asyncio

from stof.core.logger import get_logger
from stof.findings.models import Finding

from ._idor_shared import (
    _content_fingerprint,
    _control_fingerprint_body_field,
    _exclude_control_fingerprint,
    _method_request_fn,
    _set_query_param,
    _tenant_scope_endpoints,
)
from .results import FAIL, PASS, SKIPPED, TestCaseResult

_log = get_logger("modules.tenant_tests")


class TenantTechniquesMixin:
    async def _technique_tenant_scope_substitution(self, endpoints, session_manager, session_pool, target_url, evidence) -> list[TestCaseResult]:
        test_id, tid, technique = "TC-131", "TC-131.1", "Tenant/organization-scope parameter substitution (GET/POST)"
        vuln_type = "Tenant Isolation BOLA (organization-scope substitution)"
        candidates = _tenant_scope_endpoints(endpoints, methods=("GET",))
        write_candidates = _tenant_scope_endpoints(endpoints, methods=("POST",))
        if write_candidates and not self.config.allow_state_changing_probes:
            # GET-based substitution still runs below regardless -- only
            # the POST-shaped subset of this technique is gated, exactly
            # like `_technique_idor_body_field`'s own GET-vs-write split
            # in `mass_assignment_tests.py`.
            _log.info(f"{len(write_candidates)} POST tenant-scope endpoint(s) skipped: allow_state_changing_probes is disabled")
            write_candidates = []
        if not candidates and not write_candidates:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                  "no GET/POST endpoint with a single org_id/organization_id/tenant_id/tenantid/company_id/workspace_id-shaped parameter discovered")]
        try:
            session, context = await self._authenticated_context(session_manager, session_pool, self.high_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        return list(await asyncio.gather(*(
            self._check_tenant_scope_candidate(context, session, evidence, endpoint, param)
            for endpoint, param in candidates + write_candidates
        )))

    async def _check_tenant_scope_candidate(self, context, session, evidence, endpoint, param: str) -> TestCaseResult:
        """Per-endpoint probe-and-check body of
        `_technique_tenant_scope_substitution`'s loop, extracted so that
        method drops to setup + orchestration only -- same shape as
        every other technique's own `_check_*_candidate` helper in this
        file family."""
        test_id, tid, technique = "TC-131", "TC-131.1", "Tenant/organization-scope parameter substitution (GET/POST)"
        vuln_type = "Tenant Isolation BOLA (organization-scope substitution)"

        if endpoint.method.upper() == "GET":
            url_for = lambda cid, e=endpoint, p=param: _set_query_param(e.url, p, cid)  # same lambda-closure shape idor_tests.py's own techniques use
            responses, statuses, _control_fp = await self._probe_candidates(context, self.config.candidate_ids, url_for)
        else:
            responses, statuses = await self._probe_tenant_scope_post(context, endpoint, param)

        distinct = {_content_fingerprint(b) for b in responses.values()}
        if not (len(responses) >= 2 and len(distinct) >= 2):
            return self._result(
                test_id, tid, technique, vuln_type, PASS,
                f"'{endpoint.url}': tenant-scope candidate ids for '{param}' returned no distinct organization-scoped content",
                role=self.high_priv_role, endpoint=endpoint,
            )

        sample_ids = list(responses.keys())[:3]
        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.1,
            endpoint=endpoint, user_role=self.high_priv_role,
            request_raw="\n".join(f"{endpoint.method} {endpoint.url} [{param}={cid}]" for cid in sample_ids),
            response_raw="\n".join(f"[{param}={cid}] HTTP {statuses.get(cid)}, {len(responses[cid])} bytes" for cid in sample_ids),
            description=(
                f"A single session (role '{self.high_priv_role}') retrieved {len(responses)} distinct, "
                f"substantially different response bodies from '{endpoint.url}' by varying the "
                f"organization-scope parameter '{param}' across {sample_ids}, with no apparent check "
                f"that the requested tenant/organization matches the requesting session's own "
                f"membership. This is content-differential evidence (distinct response per substituted "
                f"id), the same signal principle `idor_tests.py` already uses for object-id "
                f"substitution -- it does not by itself prove which specific records leaked, only that "
                f"the server's response differs per tenant-scope value with no observed boundary check."
            ),
            recommendation=(
                "Enforce organizational-membership authorization on every request that takes an org/"
                "tenant/workspace id from the client: verify the authenticated user actually belongs to "
                "the specific organization requested, not just that they are authenticated."
            ),
        )
        finding.evidence_refs = await self._capture_evidence(
            evidence, context, session, f"{endpoint.url}", label=f"tenant-scope-{param}-{sample_ids[0]}", finding=finding
        ) if endpoint.method.upper() == "GET" else (
            await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"tenant-scope-{param}-{sample_ids[0]}") if evidence else []
        )
        return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, role=self.high_priv_role, endpoint=endpoint, finding=finding)

    async def _probe_tenant_scope_post(self, context, endpoint, param: str) -> tuple[dict[str, str], dict[str, int]]:
        """POST-shaped counterpart of `_probe_candidates` for this
        technique only: the tenant-scope value is substituted into the
        JSON body rather than a query string, matching how a real
        tenant-scoped POST endpoint (e.g. `POST /bugs.json` with an
        `organization_id` body field, per this project's own knowledge
        base) actually carries the parameter. Filters out any candidate
        indistinguishable from a control/baseline probe
        (`_control_fingerprint_body_field`), the same false-positive
        guard `_probe_candidates` applies for the GET case above."""
        import json as json_module

        method_fn = _method_request_fn(context, endpoint.method.upper())

        async def _probe_one(candidate: str) -> tuple[str, int | None, str | None]:
            payload = {param: candidate}
            try:
                resp = await method_fn(endpoint.url, data=json_module.dumps(payload), headers={"Content-Type": "application/json"}, max_redirects=0)
                body = await resp.text()
            except Exception as exc:
                _log.warning(f"tenant-scope POST probe failed for {endpoint.url}: {exc}")
                return candidate, None, None
            return candidate, resp.status, body

        probed = await asyncio.gather(*(_probe_one(cid) for cid in self.config.candidate_ids))
        responses: dict[str, str] = {}
        statuses: dict[str, int] = {}
        for candidate, status, body in probed:
            if status is None:
                continue
            statuses[candidate] = status
            if status == 200 and len(body) >= self.config.min_content_length:
                responses[candidate] = body
        control_fp = await _control_fingerprint_body_field(method_fn, endpoint.url, param, self.config.min_content_length)
        return _exclude_control_fingerprint(responses, control_fp), statuses

    async def _techniques_tc131(self, endpoints, session_manager, session_pool, target_url, evidence) -> list[TestCaseResult]:
        return await self._safe(self._technique_tenant_scope_substitution(endpoints, session_manager, session_pool, target_url, evidence))
