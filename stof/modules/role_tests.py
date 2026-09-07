"""TC-056 -- Role Manipulation techniques, split out of `idor_tests.py`
for the same reason as `bfla_tests.py` (see that file's module
docstring for the mixin-vs-separate-module reasoning).

TC-056.1 (query parameter) and TC-056.3/.4 (cookie/header) are GET-
based ALLOWED/DENIED decisions and route through `classify_response()`/
`AuthorizationDecision`, recording into `self.authorization_matrix`.
TC-056.2 (body field) is a write-verb success/failure check
(POST/PUT/PATCH) and stays a direct status-code check for the same
204-No-Content reason documented in `bfla_tests.py`.
"""
from __future__ import annotations

import json as json_module

from stof.authorization.decision import AuthorizationDecision, classify_response
from stof.core.logger import get_logger
from stof.findings.models import Finding

from ._idor_shared import _ELEVATED_ROLE_VALUES, _content_fingerprint, _method_request_fn, _set_query_param
from .results import FAIL, PASS, SKIPPED, TestCaseResult

_log = get_logger("modules.role_tests")


class RoleTechniquesMixin:
    async def _first_role_tamper_escalation(self, context, endpoint, tamper):
        """The baseline-probe + per-elevated-value-tamper-probe +
        escalation-check loop duplicated verbatim between
        `_test_role_parameter_tampering` (query-parameter tamper) and
        `_probe_role_header_tamper` (cookie/header tamper) -- they
        differ only in HOW a candidate probe is built from an elevated
        role value, captured here by `tamper(value) -> (url, headers)`.
        Returns `(elevated_value, tampered_url, tampered_status,
        tampered_body, baseline_status, baseline_body)` for the first
        escalating candidate, or `None` if none escalated (including if
        the baseline probe itself failed)."""
        baseline_probe = await self._probe_get(context, endpoint.url)
        if baseline_probe is None:
            return None
        baseline_status, baseline_body = baseline_probe
        baseline_decision = classify_response(baseline_status, baseline_body, min_content_length=self.config.min_content_length)

        for elevated_value in _ELEVATED_ROLE_VALUES:
            url, headers = tamper(elevated_value)
            tampered_probe = await self._probe_get(context, url, **({"headers": headers} if headers else {}))
            if tampered_probe is None:
                continue
            tampered_status, tampered_body = tampered_probe
            tampered_decision = classify_response(tampered_status, tampered_body, min_content_length=self.config.min_content_length)
            escalated = (
                tampered_decision == AuthorizationDecision.ALLOWED
                and (baseline_decision != AuthorizationDecision.ALLOWED or _content_fingerprint(tampered_body) != _content_fingerprint(baseline_body))
            )
            if escalated:
                return elevated_value, url, tampered_status, tampered_body, baseline_status, baseline_body
        return None

    async def _test_role_parameter_tampering(self, endpoints, session_manager, session_pool, target_url, evidence=None) -> list[Finding]:
        role_endpoints = [
            (e, p)
            for e in endpoints
            if e.method.upper() == "GET"
            for p in e.parameters
            if any(hint in p.lower() for hint in self.config.role_param_hints)
        ]
        if not role_endpoints:
            return []

        session, context = await self._authenticated_context(session_manager, session_pool, self.low_priv_role, target_url)

        findings: list[Finding] = []
        for endpoint, param in role_endpoints:
            result = await self._first_role_tamper_escalation(
                context, endpoint, lambda v, e=endpoint, p=param: (_set_query_param(e.url, p, v), None))
            if result is None:
                continue
            elevated_value, tampered_url, tampered_status, tampered_body, baseline_status, baseline_body = result
            finding = Finding(
                module_id=self.module_id,
                vuln_type="Role Manipulation via Parameter Tampering",
                severity="High",
                cvss_score=8.8,
                endpoint=endpoint,
                user_role=self.low_priv_role,
                request_raw=f"GET {tampered_url}",
                response_raw=(
                    f"HTTP {tampered_status}, {len(tampered_body)} bytes "
                    f"(baseline HTTP {baseline_status}, {len(baseline_body)} bytes)"
                ),
                description=(
                    f"Endpoint '{endpoint.url}' accepts a client-controlled parameter "
                    f"'{param}'; setting it to '{elevated_value}' from a low-privileged "
                    f"session produced a different, successful response than the "
                    f"unmodified baseline request. This suggests role/permission state "
                    f"may be trusted from client input rather than derived server-side."
                ),
                recommendation=(
                    "Never trust a role/permission value supplied by the client. Derive "
                    "the acting user's role/permissions exclusively from server-side "
                    "session state, and re-validate authorization on every request "
                    "regardless of any client-supplied role parameter."
                ),
                # The description above says "suggests" / "may be
                # trusted" -- single-session parameter tampering alone,
                # no cross-identity confirmation that a genuinely
                # different low-priv identity is actually elevated (the
                # same "never report off single-session enumeration
                # alone" principle idor_tests.py's own cross-session
                # confirmation was built for).
                confidence="likely",
            )
            finding.evidence_refs = await self._capture_evidence(
                evidence, context, session, tampered_url, label=f"role-tamper-{param}-{elevated_value}", finding=finding)
            findings.append(finding)
        return findings

    async def _technique_role_body_field(self, endpoints, session_manager, session_pool, target_url, evidence) -> list[TestCaseResult]:
        test_id, tid, technique = "TC-056", "TC-056.2", "Tamper role field in the request body"
        vuln_type = "Role Manipulation via Request Body Tampering"
        if not self.config.allow_state_changing_probes:
            return [self._gated_skip(test_id, tid, technique, vuln_type, "body-field role tampering targets write endpoints and is disabled by default")]
        role_body_endpoints = [
            (e, p) for e in endpoints if e.method.upper() in ("POST", "PUT", "PATCH")
            for p in e.parameters if any(hint in p.lower() for hint in self.config.role_param_hints)
        ]
        if not role_body_endpoints:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, "no POST/PUT/PATCH endpoint with a role-like body field discovered")]
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.low_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        results: list[TestCaseResult] = []
        for endpoint, param in role_body_endpoints:
            finding = await self._check_role_body_field_candidate(context, vuln_type, evidence, endpoint, param)
            if finding is not None:
                results.append(self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, role=self.low_priv_role, endpoint=endpoint, finding=finding))
            else:
                results.append(self._result(test_id, tid, technique, vuln_type, PASS, f"'{endpoint.url}': no elevated body value for '{param}' was accepted", role=self.low_priv_role, endpoint=endpoint))
        return results

    async def _check_role_body_field_candidate(self, context, vuln_type: str, evidence, endpoint, param: str) -> Finding | None:
        """Per-endpoint probe-and-check body of
        `_technique_role_body_field`'s loop (tries every elevated value,
        returns the first that succeeds), extracted so that method drops
        to setup + orchestration only -- same branches, same order, just
        named and separated."""
        for elevated_value in _ELEVATED_ROLE_VALUES:
            payload = {param: elevated_value}
            try:
                resp = await _method_request_fn(context, endpoint.method.upper())(endpoint.url, data=json_module.dumps(payload), headers={"Content-Type": "application/json"}, max_redirects=0)
            except Exception as exc:
                _log.warning(f"body-tamper probe failed for {endpoint.url}: {exc}")
                continue
            if resp.status in (200, 201, 204):
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.8,
                    endpoint=endpoint, user_role=self.low_priv_role,
                    request_raw=f"{endpoint.method} {endpoint.url}\nContent-Type: application/json\n\n{json_module.dumps(payload)}",
                    response_raw=f"HTTP {resp.status}",
                    description=f"'{endpoint.url}' accepted a request body containing '{param}': '{elevated_value}' from a low-privileged session (role '{self.low_priv_role}'), receiving HTTP {resp.status} instead of a rejection.",
                    recommendation="Never trust a role/permission field in a client-supplied request body; derive it exclusively from server-side session state, and explicitly allow-list which fields a client update endpoint may set.",
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"role-body-{param}-{elevated_value}") if evidence else []
                return finding
        return None

    async def _probe_role_header_tamper(self, context, endpoint, via: str, vuln_type: str) -> Finding | None:
        """One endpoint, one `via` ('cookie' | 'header'): try every
        elevated role value against it, return the first `Finding` that
        demonstrates escalation, or `None` if none did (including if
        the baseline probe itself failed -- logged, not reported as a
        result here, since the caller sweeps several endpoints and one
        broken baseline shouldn't end the technique)."""
        def tamper(elevated_value: str) -> tuple[str, dict]:
            header = {"Cookie": f"role={elevated_value}"} if via == "cookie" else {"X-Role": elevated_value}
            return endpoint.url, header

        result = await self._first_role_tamper_escalation(context, endpoint, tamper)
        if result is None:
            return None
        elevated_value, _url, tampered_status, tampered_body, baseline_status, baseline_body = result
        header_desc = f"Cookie: role={elevated_value}" if via == "cookie" else f"X-Role: {elevated_value}"
        return Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.2,
            endpoint=endpoint, user_role=self.low_priv_role,
            request_raw=f"GET {endpoint.url}\n{header_desc}",
            response_raw=f"HTTP {tampered_status}, {len(tampered_body)} bytes (baseline HTTP {baseline_status}, {len(baseline_body)} bytes)",
            description=f"Sending '{header_desc}' from a low-privileged session (role '{self.low_priv_role}') to '{endpoint.url}' produced a different, successful response than the unmodified baseline.",
            recommendation="Never trust a role/permission value supplied via a client-controlled cookie or header; derive it exclusively from server-side session state.",
        )

    async def _technique_role_cookie_or_header(self, endpoints, session_manager, session_pool, target_url, evidence, via: str, test_technique_id: str) -> list[TestCaseResult]:
        test_id, technique = "TC-056", f"Tamper role via a {'cookie value' if via == 'cookie' else 'custom header (X-Role)'}"
        vuln_type = f"Role Manipulation via {'Cookie' if via == 'cookie' else 'Header'} Tampering"
        # Bounded: this is a broad sweep across endpoints, not a
        # per-object comparison like the IDOR techniques above.
        endpoints_to_probe = [e for e in endpoints if e.method.upper() == "GET" and e.auth_required][:5]
        if not endpoints_to_probe:
            return [self._result(test_id, test_technique_id, technique, vuln_type, SKIPPED, "no authenticated GET endpoint discovered")]
        try:
            session, context = await self._authenticated_context(session_manager, session_pool, self.low_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, test_technique_id, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        for endpoint in endpoints_to_probe:
            finding = await self._probe_role_header_tamper(context, endpoint, via, vuln_type)
            if finding is None:
                continue
            finding.evidence_refs = await self._capture_evidence(evidence, context, session, endpoint.url, label=f"role-{via}-{endpoint.url.rsplit('/', 1)[-1]}", finding=finding)
            return [self._result(test_id, test_technique_id, technique, vuln_type, FAIL, finding.description, role=self.low_priv_role, endpoint=endpoint, finding=finding)]

        return [self._result(test_id, test_technique_id, technique, vuln_type, PASS,
                              f"no elevated {via} value was accepted across {len(endpoints_to_probe)} probed endpoint(s)",
                              role=self.low_priv_role)]

    def _role_param_endpoints(self, endpoints) -> list:
        return [
            e for e in endpoints if e.method.upper() == "GET"
            for p in e.parameters if any(hint in p.lower() for hint in self.config.role_param_hints)
        ]

    async def _techniques_tc056(self, endpoints, session_manager, session_pool, target_url, evidence, base_findings: list[Finding]) -> list[TestCaseResult]:
        role_tamper_findings = [f for f in base_findings if f.vuln_type == "Role Manipulation via Parameter Tampering"]
        results: list[TestCaseResult] = []
        if not self._role_param_endpoints(endpoints):
            results.append(self._result("TC-056", "TC-056.1", "Tamper role via a query-string parameter", "Role Manipulation via Parameter Tampering", SKIPPED, "no role-like query parameter discovered"))
        else:
            results.extend(self._reused_result("TC-056", "TC-056.1", "Tamper role via a query-string parameter", "Role Manipulation via Parameter Tampering", PASS, self.low_priv_role, role_tamper_findings,
                                                base_error=self._base_test_errors.get("role_tampering")))
        results.extend(await self._safe(self._technique_role_body_field(endpoints, session_manager, session_pool, target_url, evidence)))
        results.extend(await self._safe(self._technique_role_cookie_or_header(endpoints, session_manager, session_pool, target_url, evidence, "cookie", "TC-056.3")))
        results.extend(await self._safe(self._technique_role_cookie_or_header(endpoints, session_manager, session_pool, target_url, evidence, "header", "TC-056.4")))
        return results
