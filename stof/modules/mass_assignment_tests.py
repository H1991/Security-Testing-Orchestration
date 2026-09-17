"""TC-052.4 (mass assignment) and TC-053.3 (body/JSON field ID
substitution) -- the mass-assignment/body-tampering family, split out
of `idor_tests.py` for the same reason as `bfla_tests.py` (see that
file's module docstring for the mixin-vs-separate-module reasoning).

Neither technique here uses `classify_response()`: both are content-
differential oracles (does the JSON body I get back contain distinct
objects, or an echoed-back privileged field) rather than a binary
ALLOWED/DENIED authorization-boundary decision -- the same distinction
already documented on `idor_tests.py`'s own `_probe_candidates`/
`_test_horizontal_idor`. `classify_response()`'s job is "is this
endpoint reachable"; these two techniques already know it's reachable
(both require `allow_state_changing_probes`) and are instead asking
"what, specifically, did the write do."
"""
from __future__ import annotations

import asyncio
import json as json_module

from stof.core.logger import get_logger
from stof.findings.models import Finding

from ._idor_shared import (
    _content_fingerprint,
    _control_fingerprint_body_field,
    _exclude_control_fingerprint,
    _method_request_fn,
    _object_ref_endpoints,
)
from .base import first_not_none
from .results import FAIL, PASS, SKIPPED, TestCaseResult

_log = get_logger("modules.mass_assignment_tests")


class MassAssignmentTechniquesMixin:
    async def _technique_idor_body_field(self, endpoints, session_manager, session_pool, target_url, evidence) -> list[TestCaseResult]:
        test_id, tid, technique = "TC-053", "TC-053.3", "Body/JSON field ID substitution"
        vuln_type = "Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (body field)"
        if not self.config.allow_state_changing_probes:
            return [self._gated_skip(test_id, tid, technique, vuln_type, "body-field IDOR probing targets write endpoints and is disabled by default")]
        candidates = _object_ref_endpoints(endpoints, methods=("POST", "PUT"))
        if not candidates:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, "no POST/PUT endpoint with a single object-reference body parameter discovered")]
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.high_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        return list(await asyncio.gather(*(
            self._check_body_field_idor_candidate(context, test_id, tid, technique, vuln_type, evidence, endpoint, param)
            for endpoint, param in candidates
        )))

    async def _check_body_field_idor_candidate(self, context, test_id: str, tid: str, technique: str, vuln_type: str, evidence, endpoint, param: str) -> TestCaseResult:
        """Per-endpoint probe-and-check body of
        `_technique_idor_body_field`'s loop, extracted so that method
        drops to setup + orchestration only -- same branches, same
        order, just named and separated."""
        responses: dict[str, str] = {}
        method_fn = _method_request_fn(context, endpoint.method.upper())
        for candidate in self.config.candidate_ids:
            payload = {param: candidate}
            try:
                resp = await method_fn(endpoint.url, data=json_module.dumps(payload), headers={"Content-Type": "application/json"}, max_redirects=0)
                body = await resp.text()
            except Exception as exc:
                _log.warning(f"body-field probe failed for {endpoint.url}: {exc}")
                continue
            if resp.status == 200 and len(body) >= self.config.min_content_length:
                responses[candidate] = body
        # Same false-positive guard idor_tests.py's own _probe_candidates
        # applies: discard any candidate indistinguishable from a
        # control/baseline probe (a soft-error response that echoes the
        # submitted value back, e.g., would otherwise look like 2+ real
        # distinct objects).
        control_fp = await _control_fingerprint_body_field(method_fn, endpoint.url, param, self.config.min_content_length)
        responses = _exclude_control_fingerprint(responses, control_fp)
        distinct = {_content_fingerprint(b) for b in responses.values()}
        if len(responses) >= 2 and len(distinct) >= 2:
            sample_ids = list(responses.keys())[:3]
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.1,
                endpoint=endpoint, user_role=self.high_priv_role,
                request_raw="\n".join(f"{endpoint.method} {endpoint.url}\n{{\"{param}\": \"{cid}\"}}" for cid in sample_ids),
                response_raw="\n".join(f"[{param}={cid}] {len(responses[cid])} bytes" for cid in sample_ids),
                description=f"A single session (role '{self.high_priv_role}') retrieved {len(responses)} distinct objects from '{endpoint.url}' by varying '{param}' in the JSON request body across {sample_ids}.",
                recommendation="Enforce object-level authorization on every request that takes an object id from the request body, not only from query parameters.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"idor-bodyfield-{param}") if evidence else []
            return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, role=self.high_priv_role, endpoint=endpoint, finding=finding)
        return self._result(test_id, tid, technique, vuln_type, PASS, f"'{endpoint.url}': body-field candidate ids returned no distinct objects", role=self.high_priv_role, endpoint=endpoint)

    async def _technique_mass_assignment(self, endpoints, session_manager, session_pool, target_url, evidence) -> TestCaseResult:
        tid, technique = "TC-052.4", "Escalation via mass assignment (inject role/isAdmin on profile update)"
        vuln_type = "Privilege Escalation via Mass Assignment"
        if not self.config.allow_state_changing_probes:
            return self._gated_skip("TC-052", tid, technique, vuln_type, "mass-assignment probing writes to a self-profile endpoint and is disabled by default")
        self_endpoints = [
            e for e in endpoints if e.method.upper() in ("POST", "PUT", "PATCH")
            and any(hint in e.url.lower() for hint in ("profile", "account", "/me", "settings"))
        ]
        if not self_endpoints:
            return self._result("TC-052", tid, technique, vuln_type, SKIPPED, "no self-profile-shaped POST/PUT/PATCH endpoint (profile/account/me/settings) discovered")
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.low_priv_role, target_url)
        except KeyError as exc:
            return self._result("TC-052", tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        findings = await asyncio.gather(*(self._probe_mass_assignment_candidate(context, evidence, endpoint) for endpoint in self_endpoints))
        finding = first_not_none(findings)
        if finding is not None:
            return self._result("TC-052", tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        return self._result("TC-052", tid, technique, vuln_type, PASS, f"{len(self_endpoints)} self-profile endpoint(s) probed with an injected 'role'/'isAdmin' field; none took effect")

    async def _probe_mass_assignment_candidate(self, context, evidence, endpoint) -> Finding | None:
        """Per-endpoint probe body of `_technique_mass_assignment`'s
        loop, extracted so that method drops to setup + orchestration
        only -- same branches, same order, just named and separated."""
        payload = {"role": "admin", "isAdmin": True}
        try:
            resp = await _method_request_fn(context, endpoint.method.upper())(endpoint.url, data=json_module.dumps(payload), headers={"Content-Type": "application/json"}, max_redirects=0)
            body = await resp.text()
        except Exception as exc:
            _log.warning(f"mass-assignment probe failed for {endpoint.url}: {exc}")
            return None
        if resp.status not in (200, 201) or not ('"role":"admin"' in body.replace(" ", "").lower() or '"isadmin":true' in body.replace(" ", "").lower()):
            return None
        finding = Finding(
            module_id=self.module_id, vuln_type="Privilege Escalation via Mass Assignment", severity="High", cvss_score=8.8,
            endpoint=endpoint, user_role=self.low_priv_role,
            request_raw=f"{endpoint.method} {endpoint.url}\nContent-Type: application/json\n\n{json_module.dumps(payload)}",
            response_raw=f"HTTP {resp.status}, {body[:300]}",
            description=f"'{endpoint.url}' accepted extra privileged fields ('role'/'isAdmin') in the request body from a low-privileged session (role '{self.low_priv_role}') and echoed them back as applied.",
            recommendation="Explicitly allow-list which fields a client-facing update endpoint may set; never bind the full request body onto a privileged model.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"mass-assignment-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
        return finding
