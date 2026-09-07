"""Layer 9 — `stof/modules/injection_variants_tests.py`: HTTP Parameter
Pollution + CSV/Formula Injection (TC-134).

Grounded in OWASP WSTG-INPV-04 ("Testing for HTTP Parameter Pollution")
as the primary methodology, with PortSwigger's HPP research as
secondary support, and OWASP's CSV Injection guidance (CWE-1236) for
the second technique. Two genuinely different injection-variant shapes
bundled into one small module rather than two, matching this project's
"one module per coherent test-case family" convention (`configuration_
tests.py`'s TC-017 already bundles ten unrelated-but-small techniques
the same way).

**TC-134.1 HTTP Parameter Pollution** -- WSTG-INPV-04. This is a
DIFFERENTIAL check, not a naive "does duplicating a param do anything"
probe: two single-value baselines are taken first (value A alone, then
a second, distinct benign value B alone), establishing what a
"first-value-only" response and a "last-value-only" response actually
look like for this endpoint. Only THEN is the polluted request sent
(`param=A&param=B`, both benign, one already a real discovered
parameter). A finding requires the polluted response to either reflect
BOTH values (proof some layer processed the duplicate unexpectedly) or
differ from BOTH single-value baselines (the WSTG-INPV-04 "inconsistent
handling across the request-processing stack" signal -- e.g. a
WAF/validation layer reading only the first occurrence while the
application logic uses the last, or vice versa). The mere fact that a
duplicated param changes SOME response text is explicitly NOT enough on
its own -- matching either baseline is the expected, unremarkable
outcome and is never flagged. Findings are reported honestly as
"evidence of inconsistent parameter parsing worth manual review", never
as a confirmed exploit -- this technique cannot itself prove which
layer used which value or that anything is actually exploitable.

Gated behind `allow_state_changing_probes`: although the query-string
variant is read-only, the body-based POST variant resubmits a
discovered form with a duplicated field, which is write-adjacent the
same way any other real-POST probe in this codebase is (see
`sqli_tests.py`/`xss_tests.py`'s own plant-phase gating) -- this
project's conservative-by-default convention treats "sends a real POST
to a discovered endpoint" as gate-worthy regardless of payload danger.

**TC-134.2 CSV/Formula Injection** -- CWE-1236 / OWASP's CSV Injection
cheat sheet. Exact plant/verify shape `sqli_tests.py`'s TC-127.6 and
`xss_tests.py`'s TC-128.4 already established for this codebase: plant
a harmless, formula-shaped marker (`=1+1+"stofcsv<marker>"`, never an
actual malicious formula/macro/DDE payload) into a discovered free-text
POST field via a low-priv authenticated context, then check via a
SEPARATE, higher-privileged GET context whether the stored value
survives verbatim -- no leading `'`/quote-escape, no stripped `=`
prefix. STOF has no way to confirm a spreadsheet export actually
exists, so a hit is framed as "this value would survive into a CSV/
Excel export unescaped IF one exists", never as a confirmed CSV
injection. Reuses `_second_order_plant_candidates`/`_second_order_
verify_candidates` from `_injection_shared.py` unchanged -- same field-
name heuristics, same bounded plant x verify sweep.

Gated behind `allow_state_changing_probes`, same as TC-127.6/TC-128.4:
the plant phase is a real POST/write.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from stof.core.logger import get_logger
from stof.findings.models import Finding

from ._injection_shared import (
    _second_order_plant_candidates,
    _second_order_verify_candidates,
    build_params,
    injectable_endpoints,
    placeholder_value,
    response_similarity,
    send_probe,
)
from .base import VulnModule
from .results import FAIL, PASS, SKIPPED, TestCaseResult, extract_findings

if TYPE_CHECKING:
    from stof.crawler.endpoint_store import Endpoint
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.injection_variants_tests")

# A response similarity at/above this ratio to a baseline is treated as
# "same shape" -- matches `sqli_tests.py`'s own boolean-blind SQLi
# threshold philosophy (SequenceMatcher ratio, not exact-hash equality,
# since real pages carry per-request dynamic noise a hash comparison
# would over-flag on).
_SAME_SHAPE_SIMILARITY_THRESHOLD = 0.95


def _csv_formula_survives_unescaped(body: str, payload: str) -> bool:
    """Pure, directly-unit-testable oracle for TC-134.2's verify phase:
    the planted payload appears verbatim in `body` (proving the leading
    `=` was never stripped), AND the character immediately preceding
    it isn't a `'` -- the standard CSV-injection mitigation (Excel/
    Sheets/LibreOffice all treat a leading apostrophe as "force text",
    neutralizing the formula) that would otherwise make a byte-for-byte
    substring match a false positive."""
    idx = body.find(payload)
    if idx == -1:
        return False
    preceding = body[idx - 1] if idx > 0 else ""
    return preceding != "'"


def _hpp_pollution_signal(polluted_body: str, value_a: str, value_b: str, baseline_a_body: str, baseline_b_body: str) -> "str | None":
    """Pure, directly-unit-testable oracle for TC-134.1: returns a short
    reason string when the polluted response is genuinely inconsistent
    with both single-value expectations, `None` on a clean/expected
    result. Two honest triggers only (see module docstring for why):
    both values reflected together, or the polluted response resembling
    NEITHER single-value baseline."""
    if value_a in polluted_body and value_b in polluted_body:
        return "the response reflects BOTH the first and the duplicated value together"
    matches_first = response_similarity(polluted_body, baseline_a_body) >= _SAME_SHAPE_SIMILARITY_THRESHOLD
    matches_last = response_similarity(polluted_body, baseline_b_body) >= _SAME_SHAPE_SIMILARITY_THRESHOLD
    if not matches_first and not matches_last:
        return "the response matches neither a first-value-only nor a last-value-only expectation"
    return None


def _second_hpp_value(name: str) -> str:
    """A second benign placeholder for TC-134.1's duplicate-key probe,
    deliberately DISJOINT (as a literal substring) from `placeholder_
    value(name)`'s own return for every branch -- if `value_b` ever
    contained `value_a` as a substring (e.g. naively appending a
    suffix), the "reflects BOTH values" oracle below would trivially
    trigger on ANY response containing `value_b` alone, since it would
    always also "contain" `value_a`. Same branching shape as
    `placeholder_value` (`_injection_shared.py`) -- just a second,
    unrelated benign value per field-name category, never derived by
    concatenation."""
    lowered = name.lower()
    if "email" in lowered:
        return "stofdup@example.org"
    if "pass" in lowered:
        return "StofDup-9!"
    if any(h in lowered for h in ("id", "num", "amount", "qty", "quantity")):
        return "2"
    return "stofdup-alt-value"


async def _send_duplicated_param(context, endpoint: "Endpoint", other_params: dict, target_param: str, value_a: str, value_b: str, location: str) -> "tuple[int, str] | None":
    """Sends `target_param` TWICE (`value_a` then `value_b`) alongside
    every other of `endpoint.parameters` at its benign placeholder --
    the one shape `_injection_shared.send_probe`'s dict-based `params`
    genuinely cannot express (a `dict` can't hold a duplicate key), so
    this builds the query string / form body directly via `urlencode`
    over an explicit list of pairs instead. Mirrors `send_probe`'s own
    GET-vs-body routing and None-on-failure convention exactly, so
    callers can treat this as a drop-in duplicate-key variant of it."""
    pairs = [(name, other_params[name]) for name in other_params if name != target_param]
    pairs.append((target_param, value_a))
    pairs.append((target_param, value_b))
    query_string = urlencode(pairs)
    try:
        if endpoint.method.upper() == "GET" or location != "body":
            base = endpoint.url.split("?")[0]
            resp = await context.request.get(f"{base}?{query_string}", max_redirects=0)
        else:
            resp = await context.request.post(
                endpoint.url, data=query_string,
                headers={"Content-Type": "application/x-www-form-urlencoded"}, max_redirects=0,
            )
        body = await resp.text()
    except Exception as exc:
        _log.warning(f"HPP probe failed for {endpoint.url}: {exc}")
        return None
    return resp.status, body


@dataclass
class InjectionVariantsTestConfig:
    low_priv_role: str = "normal"
    high_priv_role: str = "admin"
    allow_state_changing_probes: bool = False
    max_hpp_targets: int = 5
    max_second_order_plant_targets: int = 3
    max_second_order_verify_targets: int = 3


class InjectionVariantsTestsModule(VulnModule):
    module_id = "injection_variants_tests"
    name = "Injection Variants Tests (HTTP Parameter Pollution / CSV Formula Injection)"
    phase = 1

    def __init__(self, config: "InjectionVariantsTestConfig | None" = None) -> None:
        self.config = config or InjectionVariantsTestConfig()
        self._marker = secrets.token_hex(4)

    def _payload_for(self, technique_id: str) -> str:
        return {
            # A harmless, formula-shaped marker only -- never an actual
            # malicious formula/macro/DDE payload (WSTG/CWE-1236's own
            # PoC shape is `=1+1`; the appended quoted marker string is
            # this run's own unique tag, same convention every other
            # planted-marker technique in this codebase uses).
            "TC-134.2": f'=1+1+"stofcsv{self._marker}"',
        }[technique_id]

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _result(self, technique_id: str, technique: str, status: str, detail: str, vuln_type: str,
                role: "str | None" = None, endpoint=None, finding: "Finding | None" = None, severity: str = "Medium") -> TestCaseResult:
        return self._make_result(
            test_id="TC-134", technique_id=technique_id, technique=technique,
            vuln_type=vuln_type, status=status, detail=detail, severity=severity,
            role=role, endpoint=endpoint, finding=finding,
        )

    async def _technique_hpp(
        self,
        endpoints: "list[Endpoint]",
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-134.1", "HTTP Parameter Pollution (duplicate parameter, differential baseline check)"
        vuln_type = "HTTP Parameter Pollution"
        if not self.config.allow_state_changing_probes:
            return self._result(tid, technique, SKIPPED, "allow_state_changing_probes is disabled -- the POST variant resubmits a discovered form", vuln_type)

        candidates = injectable_endpoints(endpoints, self.config.max_hpp_targets)
        if not candidates:
            return self._result(tid, technique, SKIPPED, "no discovered endpoint has a known parameter to duplicate", vuln_type)

        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.low_priv_role, candidates[0].url)
        except KeyError as exc:
            return self._result(tid, technique, SKIPPED, f"role '{self.config.low_priv_role}' not configured: {exc}", vuln_type)

        checked = 0
        for endpoint in candidates:
            target_param = endpoint.parameters[0]
            location = endpoint.location_for(target_param)
            value_a = placeholder_value(target_param)
            value_b = _second_hpp_value(target_param)

            baseline_a = await send_probe(context, endpoint, build_params(endpoint, target_param, value_a), location)
            baseline_b = await send_probe(context, endpoint, build_params(endpoint, target_param, value_b), location)
            if baseline_a is None or baseline_b is None:
                continue
            polluted = await _send_duplicated_param(
                context, endpoint, build_params(endpoint, target_param, value_a), target_param, value_a, value_b, location,
            )
            if polluted is None:
                continue
            checked += 1

            _status_a, body_a, *_ = baseline_a
            _status_b, body_b, *_ = baseline_b
            _status_p, body_p = polluted
            reason = _hpp_pollution_signal(body_p, value_a, value_b, body_a, body_b)
            if reason is None:
                continue

            description = (
                f"{endpoint.method} {endpoint.url}: duplicating parameter '{target_param}' "
                f"('{target_param}={value_a}&{target_param}={value_b}') produced a response where {reason}, "
                "compared against separately-taken single-value baselines for each value. This is evidence of "
                "inconsistent parameter parsing across the request-processing stack (a WAF/validation layer "
                "reading a different occurrence than the application logic, per WSTG-INPV-04) worth manual "
                "review -- it does not by itself prove an exploitable filter bypass or access-control gap."
            )
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=4.3,
                endpoint=endpoint, user_role=self.config.low_priv_role,
                request_raw=f"{endpoint.method} {endpoint.url}\n{target_param}={value_a}&{target_param}={value_b}",
                response_raw=body_p[:300],
                description=description,
                recommendation="Ensure every layer in the request path (WAF, load balancer, framework, application code) parses a duplicated parameter identically -- explicitly reject requests with duplicate parameter names where the framework allows it, rather than relying on whichever layer's implicit first/last behavior happens to match.",
                confidence="likely",  # evidence of inconsistent parsing, not by itself proof of an exploitable bypass -- see description
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="hpp-inconsistent-parsing") if evidence else []
            return self._result(tid, technique, FAIL, description, vuln_type, role=self.config.low_priv_role, endpoint=endpoint, finding=finding, severity="Low")

        if checked == 0:
            return self._result(tid, technique, PASS, f"none of {len(candidates)} candidate endpoint(s) could be probed (all baseline/polluted requests failed)", vuln_type)
        return self._result(tid, technique, PASS, f"{checked} endpoint(s) checked with a duplicated parameter; every polluted response matched an expected single-value baseline", vuln_type, role=self.config.low_priv_role)

    async def _technique_csv_formula_injection(
        self,
        endpoints: "list[Endpoint]",
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-134.2", "CSV/Formula Injection (planted marker, cross-endpoint/role verification)"
        vuln_type = "CSV/Formula Injection (Stored, Unverified Export)"
        if not self.config.allow_state_changing_probes:
            return self._result(tid, technique, SKIPPED, "allow_state_changing_probes is disabled -- the plant phase requires a real POST", vuln_type)

        plant_candidates = _second_order_plant_candidates(endpoints, self.config.max_second_order_plant_targets)
        verify_candidates = _second_order_verify_candidates(endpoints, self.config.max_second_order_verify_targets)
        if not plant_candidates:
            return self._result(tid, technique, SKIPPED, "no discovered POST form has a free-text-shaped field (comment/message/feedback/subject/notes/name/body) to plant a payload into", vuln_type)
        if not verify_candidates:
            return self._result(tid, technique, SKIPPED, "no discovered endpoint looks like a privileged display/admin page to verify against", vuln_type)

        payload = self._payload_for(tid)
        try:
            _plant_session, plant_context = await self._authenticated_context(session_manager, session_pool, self.config.low_priv_role, plant_candidates[0][0].url)
        except KeyError as exc:
            return self._result(tid, technique, SKIPPED, f"role '{self.config.low_priv_role}' not configured: {exc}", vuln_type)
        try:
            _verify_session, verify_context = await self._authenticated_context(session_manager, session_pool, self.config.high_priv_role, verify_candidates[0].url)
        except KeyError as exc:
            return self._result(tid, technique, SKIPPED, f"role '{self.config.high_priv_role}' not configured: {exc}", vuln_type)

        for plant_endpoint, plant_field in plant_candidates:
            params = build_params(plant_endpoint, plant_field, payload)
            location = plant_endpoint.location_for(plant_field)
            plant_probe = await send_probe(plant_context, plant_endpoint, params, location)
            if plant_probe is None:
                continue
            for verify_endpoint in verify_candidates:
                verify_probe = await self._probe_get(verify_context, verify_endpoint.url)
                if verify_probe is None:
                    continue
                verify_status, verify_body = verify_probe
                if not _csv_formula_survives_unescaped(verify_body, payload):
                    continue
                description = (
                    f"Planted a harmless, formula-shaped marker payload ('{payload}') into field "
                    f"'{plant_field}' via {plant_endpoint.method} {plant_endpoint.url} (as role "
                    f"'{self.config.low_priv_role}'); a SEPARATE, later GET request to {verify_endpoint.url} "
                    f"(as role '{self.config.high_priv_role}') returned that same value verbatim (HTTP "
                    f"{verify_status}), with no leading-quote/`=`-stripping sanitization applied. STOF cannot "
                    "confirm a CSV/Excel export of this data actually exists -- this only proves the raw value "
                    "would survive into one unescaped IF one exists, which is the precondition CSV/Formula "
                    "injection (CWE-1236) needs, not a confirmed CSV injection."
                )
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.3,
                    endpoint=verify_endpoint, user_role=self.config.high_priv_role,
                    request_raw=(
                        f"PLANT: {plant_endpoint.method} {plant_endpoint.url}\n{plant_field}={payload!r}\n"
                        f"VERIFY: GET {verify_endpoint.url}"
                    ),
                    response_raw=verify_body[:300],
                    description=description,
                    recommendation="Prefix any cell value beginning with =, +, -, or @ with a leading apostrophe (or strip/neutralize the leading character) before it can reach a CSV/Excel export, on every endpoint that displays or exports stored user-supplied content.",
                    confidence="likely",  # proves the precondition (unescaped survival), not a confirmed CSV export -- see description
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="csv-formula-injection") if evidence else []
                return self._result(tid, technique, FAIL, description, vuln_type, role=self.config.high_priv_role, endpoint=verify_endpoint, finding=finding, severity="Medium")
        return self._result(
            tid, technique, PASS,
            f"{len(plant_candidates)} free-text field(s) planted, {len(verify_candidates)} privileged "
            "endpoint(s) checked afterward, no unescaped formula-shaped value observed",
            vuln_type, role=self.config.high_priv_role,
        )

    async def run_techniques(
        self,
        endpoints: "list[Endpoint]",
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[TestCaseResult]:
        results: list[TestCaseResult] = []
        for tid, technique, coro in (
            ("TC-134.1", "HTTP Parameter Pollution (duplicate parameter, differential baseline check)", self._technique_hpp(endpoints, session_manager, session_pool, evidence)),
            ("TC-134.2", "CSV/Formula Injection (planted marker, cross-endpoint/role verification)", self._technique_csv_formula_injection(endpoints, session_manager, session_pool, evidence)),
        ):
            results.append(await self._safe_result(coro, "TC-134", tid, technique, "Injection Variants"))
        return results
