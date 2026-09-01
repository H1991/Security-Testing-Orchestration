"""Layer 9 — `stof/modules/deserialization_tests.py`: Insecure
Deserialization (TC-085).

Deliberately safe by design, not merely by default: unlike the
state-changing probes elsewhere in this project (which are real
attacks gated behind an opt-in flag), TC-085.1 and TC-085.3 aren't
gated here because they're not implemented at all -- an automated
gadget-chain payload is a real RCE attempt with real potential to
damage the target, and a deeply-nested/huge payload is a real DoS
attempt. Neither belongs in a framework that runs against a live
target without a human reviewing the specific payload first. This
module ships real techniques instead: TC-085.2 sends a harmless
polymorphic-type marker and looks for a deserialization-shaped error
in the response -- proving the vulnerability *class* is present
without ever attempting to actually exploit it. TC-085.4 through
TC-085.6 go further still: each is a *zero-exploit-payload* passive
discovery/fingerprinting check -- structural inspection of a page's
own already-fetched body (TC-085.4), a single harmless GET whose
response headers/content-type are inspected without ever naming a
gadget class or sending a serialized blob of any kind (TC-085.5,
TC-085.6). None of these ever cross the line TC-085.1/TC-085.3
deliberately never cross.
"""
from __future__ import annotations

import json as json_module
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from stof.core.logger import get_logger
from stof.findings.models import Finding

from .base import VulnModule
from .results import FAIL, NOT_IMPLEMENTED, PASS, SKIPPED, TestCaseResult, extract_findings

if TYPE_CHECKING:
    from stof.crawler.endpoint_store import Endpoint
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.deserialization_tests")

# Harmless polymorphic-type marker keys real deserialization libraries
# (Jackson, Newtonsoft.Json, fastjson, ...) commonly honor when
# "polymorphic type handling" is misconfigured -- pointing at a benign,
# well-known JDK/.NET class name that exists on virtually any classpath
# is enough to *detect* the misconfiguration (a deserialization-shaped
# error, or a response shape change) without ever naming a real gadget
# class capable of doing anything harmful.
_POLYMORPHIC_MARKERS: tuple[dict, ...] = (
    {"@type": "java.util.HashMap"},
    {"@class": "java.lang.Object"},
    {"$type": "System.Object, mscorlib"},
)

_DESERIALIZATION_ERROR_SIGNATURES: tuple[str, ...] = (
    "deserializ", "objectinputstream", "unmarshall", "classnotfoundexception",
    "invaliddefinitionexception", "jsonmappingexception", "polymorphic", "typefactory",
)


def looks_like_deserialization_error(body: str) -> bool:
    lowered = body.lower()
    return any(sig in lowered for sig in _DESERIALIZATION_ERROR_SIGNATURES)


def _viewstate_mac_disabled(html: str) -> bool:
    """Pure structural check for TC-085.4 -- zero payload, zero
    exploitation. True only when the page's own already-fetched body
    carries a `__VIEWSTATE` hidden field (ASP.NET WebForms in use) with
    no sibling `__VIEWSTATEMAC` field (MAC validation apparently
    disabled) -- the real, documented precondition for the Dec 2019
    machineKey-leak ViewState RCE campaign. Absence of `__VIEWSTATE`
    itself means "not applicable" (non-ASP.NET page), never a hit."""
    if 'name="__VIEWSTATE"' not in html and "name='__VIEWSTATE'" not in html:
        return False
    return 'name="__VIEWSTATEMAC"' not in html and "name='__VIEWSTATEMAC'" not in html


# Content-Type strings that unambiguously mean "a serialized object goes
# over this wire" -- unlike a generic `application/octet-stream`, these
# name the serialization format itself, so a single hit is worth a
# manual-review flag on its own. `application/x-java-serialized-object`
# is the documented Content-Type used by Java RMI-over-HTTP and legacy
# Java web-service endpoints that accept a raw serialized object body
# (PortSwigger's Java deserialization guidance); `application/x-amf` is
# Adobe BlazeDS/Flex AMF, a Java-serialization-adjacent binary format
# with its own documented deserialization CVEs (e.g. CVE-2017-5641).
_SERIALIZATION_CONTENT_TYPES: tuple[str, ...] = (
    "application/x-java-serialized-object",
    "application/x-amf",
)

# Magic-byte fingerprint for a raw Java serialized object (0xAC 0xED
# 0x00 0x05, the fixed `STREAM_MAGIC`/`STREAM_VERSION` header every
# `ObjectOutputStream` writes) -- the exact heuristic Burp's own
# "Java Serialized Object" passive-scan check and the Freddy extension
# use to fingerprint a serialized blob without deserializing it. Hex
# form is the raw 4 bytes lowercased; base64 form is the fixed 5-char
# prefix every base64 encoding of a stream starting with those 4 bytes
# shares, regardless of what follows (verified: encoding `ac ed 00 05`
# + any 5th byte always starts `rO0AB`).
_JAVA_SERIALIZED_HEX_PREFIX = "aced0005"
_JAVA_SERIALIZED_BASE64_PREFIX = "rO0AB"


def _content_type_indicates_serialization_format(content_type: str) -> bool:
    """Pure check for TC-085.5 -- does a Content-Type value (request or
    response) name a serialization format outright? Substring match
    (not equality) so a `; charset=...`-qualified value still matches."""
    lowered = content_type.lower()
    return any(sig in lowered for sig in _SERIALIZATION_CONTENT_TYPES)


def _looks_like_serialized_blob(value: str) -> bool:
    """Pure check for TC-085.5 -- does an already-captured parameter
    value (from the crawler's own `Endpoint.parameter_values`, no new
    request) carry the Java serialization magic-byte fingerprint,
    hex-encoded or base64-encoded? Zero requests, zero payloads --
    this only reads data STOF already has."""
    if not value:
        return False
    stripped = value.strip()
    return stripped.lower().startswith(_JAVA_SERIALIZED_HEX_PREFIX) or stripped.startswith(
        _JAVA_SERIALIZED_BASE64_PREFIX
    )


# Response headers real frameworks use to advertise their own component
# versions -- `X-Powered-By` (PHP/Express/ASP.NET convention),
# `X-AspNet-Version`/`X-AspNetMvc-Version` (classic ASP.NET banners,
# directly relevant to the ViewState deserialization surface TC-085.4
# already checks), and `Server`. Reading these is the same well-known
# "version banner fingerprinting" practice used to spot a known-CVE'd
# library version (e.g. an old Jackson/fastjson release) from metadata
# alone, without ever exercising the CVE.
_VERSION_BANNER_HEADERS: tuple[str, ...] = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "server")

# Known serialization-library names STOF looks for in a version-banner
# header, paired with a version number in the same value -- e.g.
# `X-Powered-By: Jackson-Databind/2.9.8`. A name with no adjacent
# version number is not reported (too weak a signal to be worth a
# finding on its own).
_LIBRARY_VERSION_RE = re.compile(
    r"(Jackson-Databind|Jackson|Newtonsoft\.Json|fastjson|XStream|BinaryFormatter)"
    r"[\s/:_-]*v?(\d+(?:\.\d+){1,3})",
    re.IGNORECASE,
)


def extract_serialization_library_fingerprint(headers: dict[str, str]) -> str | None:
    """Pure check for TC-085.6 -- inspects response HEADERS ONLY (no
    new probe payload, no body/error inspection) for a known
    serialization-library name plus a version number. Returns
    `"Library/version"` on a match, else `None`."""
    for name in _VERSION_BANNER_HEADERS:
        value = headers.get(name)
        if not value:
            continue
        match = _LIBRARY_VERSION_RE.search(value)
        if match:
            return f"{match.group(1)}/{match.group(2)}"
    return None


@dataclass
class DeserializationTestConfig:
    high_priv_role: str = "admin"
    target_url: str | None = None
    max_endpoints_probed: int = 8


class DeserializationTestsModule(VulnModule):
    module_id = "deserialization_tests"
    name = "Insecure Deserialization Tests"
    phase = 1

    def __init__(self, config: DeserializationTestConfig | None = None) -> None:
        self.config = config or DeserializationTestConfig()

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _result(self, technique_id: str, technique: str, status: str, detail: str,
                endpoint=None, finding: Finding | None = None) -> TestCaseResult:
        return self._make_result(
            test_id="TC-085", technique_id=technique_id, technique=technique,
            vuln_type="Insecure Deserialization", status=status, detail=detail,
            role=self.config.high_priv_role, endpoint=endpoint, finding=finding,
        )

    async def _technique_polymorphic_type_confusion(self, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-085.2", "Type-confusion via a crafted polymorphic JSON payload"
        candidates = [e for e in endpoints if e.method.upper() in ("POST", "PUT", "PATCH") and e.endpoint_type == "api"][: self.config.max_endpoints_probed]
        if not candidates:
            return self._result(tid, technique, SKIPPED, "no POST/PUT/PATCH API endpoint discovered to probe")

        target_url = self.config.target_url or candidates[0].url
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.high_priv_role, target_url)
        except KeyError as exc:
            return self._result(tid, technique, SKIPPED, f"role not configured: {exc}")
        for endpoint in candidates:
            for marker in _POLYMORPHIC_MARKERS:
                finding = await self._check_polymorphic_marker(context, evidence, endpoint, marker)
                if finding is not None:
                    return self._result(tid, technique, FAIL, finding.description, endpoint=endpoint, finding=finding)
        return self._result(tid, technique, PASS, f"{len(candidates)} endpoint(s) probed with {len(_POLYMORPHIC_MARKERS)} marker(s) each; no deserialization-shaped error observed")

    async def _check_polymorphic_marker(self, context, evidence, endpoint, marker: dict) -> Finding | None:
        """Per-(endpoint, marker) probe-and-check body of
        `_technique_polymorphic_type_confusion`'s nested loop, extracted
        so that method drops to setup + orchestration only -- same
        branches, same order, just named and separated."""
        try:
            resp = await context.request.post(
                endpoint.url, data=json_module.dumps(marker),
                headers={"Content-Type": "application/json"}, max_redirects=0,
            )
            body = await resp.text()
        except Exception as exc:
            _log.warning(f"deserialization probe failed for {endpoint.url}: {exc}")
            return None
        if not (resp.status >= 500 and looks_like_deserialization_error(body)):
            return None
        finding = Finding(
            module_id=self.module_id, vuln_type="Insecure Deserialization (polymorphic type handling)",
            severity="Critical", cvss_score=8.1, endpoint=endpoint, user_role=self.config.high_priv_role,
            request_raw=f"POST {endpoint.url}\nContent-Type: application/json\n\n{json_module.dumps(marker)}",
            response_raw=f"HTTP {resp.status}, {body[:300]}",
            description=(
                f"'{endpoint.url}' returned a deserialization-shaped error (HTTP {resp.status}) when sent a "
                f"benign polymorphic-type marker ({marker}), suggesting the server attempts to instantiate "
                "a type named by the client -- the underlying mechanism gadget-chain RCE payloads exploit. "
                "This probe used a harmless class name and did not attempt exploitation."
            ),
            recommendation="Disable polymorphic type handling entirely, or restrict it to an explicit allow-list of expected types -- never let client input name the class to instantiate.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"deserialization-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
        return finding

    def _technique_gadget_chain_rce(self) -> TestCaseResult:
        return self._result("TC-085.1", "Tampered serialized object triggers a gadget-chain / RCE", NOT_IMPLEMENTED,
                             "not implemented by design, not just by default -- a real gadget-chain payload is an actual RCE attempt "
                             "(e.g. via ysoserial) and this framework doesn't automate sending one against a live target without a human "
                             "reviewing the specific payload and target first")

    async def _technique_viewstate_mac_disabled(self, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-085.4", "ASP.NET ViewState present without a __VIEWSTATEMAC field (MAC validation disabled)"
        candidates = [e for e in endpoints if e.endpoint_type == "page"][: self.config.max_endpoints_probed]
        if not candidates:
            return self._result(tid, technique, SKIPPED, "no page endpoint discovered to scan")

        target_url = self.config.target_url or candidates[0].url
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.high_priv_role, target_url)
        except KeyError as exc:
            return self._result(tid, technique, SKIPPED, f"role not configured: {exc}")
        for endpoint in candidates:
            finding = await self._check_viewstate_mac_disabled(context, evidence, endpoint)
            if finding is not None:
                return self._result(tid, technique, FAIL, finding.description, endpoint=endpoint, finding=finding)
        return self._result(tid, technique, PASS, f"no __VIEWSTATE-without-__VIEWSTATEMAC signature found across {len(candidates)} scanned page(s)")

    async def _check_viewstate_mac_disabled(self, context, evidence, endpoint) -> Finding | None:
        """Per-endpoint probe-and-check body of
        `_technique_viewstate_mac_disabled`'s loop -- a plain GET of an
        already-discovered page, same request shape as
        `disclosure_tests.py`'s TC-105.6 page-body inspection. Sends no
        payload of any kind; only reads the response body already
        fetched by the GET."""
        probe = await self._probe_get(context, endpoint.url)
        if probe is None:
            return None
        status, body = probe
        if status != 200 or not _viewstate_mac_disabled(body):
            return None
        finding = Finding(
            module_id=self.module_id, vuln_type="Insecure Deserialization (ASP.NET ViewState MAC disabled)",
            severity="Medium", cvss_score=5.3, endpoint=endpoint, user_role=self.config.high_priv_role,
            request_raw=f"GET {endpoint.url}",
            response_raw=f"HTTP {status}, __VIEWSTATE present, __VIEWSTATEMAC absent",
            description=(
                f"'{endpoint.url}' renders a __VIEWSTATE field with no accompanying __VIEWSTATEMAC field. This "
                "confirms the precondition for ViewState deserialization RCE (MAC validation disabled), not a "
                "confirmed RCE -- exploitation would require a real gadget-chain payload (e.g. via ysoserial.net), "
                "which this framework deliberately never sends (see TC-085.1). This probe was a plain GET of an "
                "already-discovered page; no payload was sent."
            ),
            recommendation="Enable ViewState MAC validation (enableViewStateMac=\"true\") and rotate the machineKey "
                           "if there is any possibility it has leaked; never disable MAC validation on internet-facing ASP.NET WebForms pages.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"viewstate-mac-disabled-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
        return finding

    def _technique_dos_via_nested_payload(self) -> TestCaseResult:
        return self._result("TC-085.3", "DoS via a deeply nested or oversized serialized payload", NOT_IMPLEMENTED,
                             "not implemented by design, not just by default -- an automated DoS probe against a live/shared target "
                             "(this project's own demo target is a public OWASP Juice Shop preview instance) is not something this "
                             "framework should decide to run unilaterally")

    def _passive_serialized_blob_hit(self, endpoints) -> tuple["Endpoint", str, str] | None:
        """Zero-request pass over data the crawler already captured --
        `Endpoint.parameter_values` -- looking for a value carrying the
        Java-serialization magic-byte fingerprint. No new request of
        any kind; the strongest possible passive signal since nothing
        is sent to the target at all."""
        for endpoint in endpoints:
            for name, value in endpoint.parameter_values.items():
                if _looks_like_serialized_blob(value):
                    return endpoint, name, value
        return None

    async def _technique_content_type_discovery(self, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-085.5", "Serialized-object content-type / format discovery"
        passive_hit = self._passive_serialized_blob_hit(endpoints)
        if passive_hit is not None:
            endpoint, name, value = passive_hit
            finding = self._informational_finding(
                endpoint,
                vuln_type="Insecure Deserialization (serialized-object content-type/format discovered)",
                request_raw=f"(no request sent -- inspected the crawler's already-captured value of parameter '{name}' on {endpoint.method} {endpoint.url})",
                response_raw=f"parameter '{name}' value (truncated): {value[:60]!r}",
                description=(
                    f"'{endpoint.url}' has a parameter ('{name}') whose already-crawled value begins with the Java "
                    "serialized-object magic-byte signature (0xACED0005), meaning this endpoint appears to accept a "
                    "serialized object already -- worth a manual review. This is a passive fingerprint of data STOF "
                    "already had; no new request or crafted serialized payload was sent."
                ),
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"deserialization-content-type-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
            return self._result(tid, technique, FAIL, finding.description, endpoint=endpoint, finding=finding)

        candidates = [e for e in endpoints if e.endpoint_type in ("page", "api")][: self.config.max_endpoints_probed]
        if not candidates:
            return self._result(tid, technique, SKIPPED, "no page/api endpoint discovered to check")
        target_url = self.config.target_url or candidates[0].url
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.high_priv_role, target_url)
        except KeyError as exc:
            return self._result(tid, technique, SKIPPED, f"role not configured: {exc}")
        for endpoint in candidates:
            finding = await self._check_content_type_discovery(context, evidence, endpoint)
            if finding is not None:
                return self._result(tid, technique, FAIL, finding.description, endpoint=endpoint, finding=finding)
        return self._result(tid, technique, PASS, f"no serialized-object parameter value or response content-type observed across {len(candidates)} endpoint(s)")

    async def _check_content_type_discovery(self, context, evidence, endpoint) -> Finding | None:
        """Single harmless GET of an already-discovered endpoint --
        inspects only its own response Content-Type header. Sends no
        payload of any kind, crafted serialized or otherwise."""
        try:
            resp = await context.request.get(endpoint.url, max_redirects=0)
            content_type = resp.headers.get("content-type", "")
        except Exception as exc:
            _log.warning(f"content-type discovery probe failed for {endpoint.url}: {exc}")
            return None
        if not _content_type_indicates_serialization_format(content_type):
            return None
        finding = self._informational_finding(
            endpoint,
            vuln_type="Insecure Deserialization (serialized-object content-type/format discovered)",
            request_raw=f"GET {endpoint.url}",
            response_raw=f"Content-Type: {content_type}",
            description=(
                f"'{endpoint.url}' responds with Content-Type '{content_type}', which names a serialization "
                "format outright -- this endpoint appears to accept/produce a serialized object, worth a manual "
                "review. This was a single harmless GET of an already-discovered endpoint; no crafted serialized "
                "payload was sent."
            ),
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"deserialization-content-type-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
        return finding

    async def _technique_library_fingerprinting(self, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-085.6", "Serialization library / version fingerprinting from response headers"
        candidates = [e for e in endpoints if e.endpoint_type in ("page", "api")][: self.config.max_endpoints_probed]
        if not candidates:
            return self._result(tid, technique, SKIPPED, "no page/api endpoint discovered to check")
        target_url = self.config.target_url or candidates[0].url
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.high_priv_role, target_url)
        except KeyError as exc:
            return self._result(tid, technique, SKIPPED, f"role not configured: {exc}")
        for endpoint in candidates:
            finding = await self._check_library_fingerprint(context, evidence, endpoint)
            if finding is not None:
                return self._result(tid, technique, FAIL, finding.description, endpoint=endpoint, finding=finding)
        return self._result(tid, technique, PASS, f"no serialization-library version banner observed across {len(candidates)} endpoint(s)")

    async def _check_library_fingerprint(self, context, evidence, endpoint) -> Finding | None:
        """Single harmless GET, HEADERS ONLY inspected -- no body/error
        text is read, no probe payload is sent. This is a deliberately
        separate, non-redundant technique from TC-085.2: it never
        triggers or inspects an error at all, only a normal response's
        own version-banner headers on an already-discovered endpoint."""
        try:
            resp = await context.request.get(endpoint.url, max_redirects=0)
            headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as exc:
            _log.warning(f"library fingerprint probe failed for {endpoint.url}: {exc}")
            return None
        fingerprint = extract_serialization_library_fingerprint(headers)
        if fingerprint is None:
            return None
        finding = self._informational_finding(
            endpoint,
            vuln_type="Insecure Deserialization (serialization library version disclosed)",
            request_raw=f"GET {endpoint.url}",
            response_raw=f"version-banner header revealed: {fingerprint}",
            description=(
                f"'{endpoint.url}' discloses '{fingerprint}' via a response header, identifying the serialization "
                "library and version in use -- worth checking that version against known CVEs for it. This was a "
                "single harmless GET of an already-discovered endpoint; only its own response headers were "
                "inspected, no probe payload or CVE exploitation attempt was sent."
            ),
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"deserialization-library-fingerprint-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
        return finding

    def _informational_finding(self, endpoint, *, vuln_type: str, request_raw: str, response_raw: str, description: str) -> Finding:
        """Shared constructor for TC-085.5/.6's informational findings
        -- both report "worth a manual review", never a confirmed
        vulnerability, so both fix `severity="Info"`/`cvss_score=0.0`
        rather than each restating it."""
        return Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Info", cvss_score=0.0,
            endpoint=endpoint, user_role=self.config.high_priv_role,
            request_raw=request_raw, response_raw=response_raw, description=description,
            recommendation="Manually review whether this endpoint's serialization surface is reachable by an "
                           "untrusted client, and whether the identified library/version has known deserialization CVEs.",
        )

    async def run_techniques(
        self,
        endpoints: list["Endpoint"],
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[TestCaseResult]:
        results: list[TestCaseResult] = [self._technique_gadget_chain_rce()]
        try:
            results.append(await self._technique_polymorphic_type_confusion(endpoints, session_manager, session_pool, evidence))
        except Exception as exc:
            _log.warning(f"deserialization_tests TC-085.2 failed unexpectedly: {exc}")
            results.append(self._result("TC-085.2", "Type-confusion via a crafted polymorphic JSON payload", "ERROR", str(exc)))
        results.append(self._technique_dos_via_nested_payload())
        try:
            results.append(await self._technique_viewstate_mac_disabled(endpoints, session_manager, session_pool, evidence))
        except Exception as exc:
            _log.warning(f"deserialization_tests TC-085.4 failed unexpectedly: {exc}")
            results.append(self._result("TC-085.4", "ASP.NET ViewState present without a __VIEWSTATEMAC field (MAC validation disabled)", "ERROR", str(exc)))
        try:
            results.append(await self._technique_content_type_discovery(endpoints, session_manager, session_pool, evidence))
        except Exception as exc:
            _log.warning(f"deserialization_tests TC-085.5 failed unexpectedly: {exc}")
            results.append(self._result("TC-085.5", "Serialized-object content-type / format discovery", "ERROR", str(exc)))
        try:
            results.append(await self._technique_library_fingerprinting(endpoints, session_manager, session_pool, evidence))
        except Exception as exc:
            _log.warning(f"deserialization_tests TC-085.6 failed unexpectedly: {exc}")
            results.append(self._result("TC-085.6", "Serialization library / version fingerprinting from response headers", "ERROR", str(exc)))
        return results
