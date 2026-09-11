"""Layer 9 — `stof/modules/tls_tests.py`: TLS/SSL transport-layer
configuration tests (TC-145 to TC-148), using `sslyze` (nabla-c0d3/sslyze,
BSD-3-Clause, the de-facto standard Python TLS-scanning library) rather
than hand-rolling protocol/cipher-suite negotiation against every
OpenSSL quirk ourselves.

**Deliberately NOT overlapping `configuration_tests.py`'s existing TLS
coverage**, which stays exactly as-is:
  - TC-017.9 checks HSTS presence / plaintext-HTTP reachability for
    sensitive endpoints -- an HTTP-response-header concern.
  - TC-017.15 checks certificate expiry/chain/hostname validity -- a
    certificate concern.
This module is the one missing layer: what protocol versions and
cipher suites the TLS *handshake itself* accepts, and whether the
server is vulnerable to a small set of well-known, named TLS-layer
CVEs. All four techniques below run from ONE `sslyze` scan per target
(a single `Scanner().queue_scans()` call requesting every scan command
up front) rather than one connection per technique -- sslyze's own
scanner already dispatches its probes across worker processes
internally, so batching the *request* here is what actually avoids N
redundant handshakes, not just tidier code.

- **TC-145 Deprecated protocol versions** (SSLv2, SSLv3, TLS 1.0,
  TLS 1.1): PCI-DSS v4.0 requires disabling all of these; SSLv3 has
  POODLE (CVE-2014-3566), TLS 1.0/1.1 have no modern AEAD cipher
  support and known padding/MAC weaknesses (BEAST-class). All four
  browser vendors and every major CA/B Forum member deprecated TLS
  1.0/1.1 by 2020.
- **TC-146 Weak cipher suites**: NULL (no encryption at all), anonymous
  (no server authentication -- trivially MITM'd), EXPORT-grade
  (deliberately weakened for 1990s US export law, breakable in
  seconds today), RC4 (RFC 7465 -- biased-keystream attacks), and
  single/triple-DES (56/112-bit effective strength, Sweet32
  CVE-2016-2183) -- checked across whatever of TLS 1.0/1.1/1.2 the
  server actually accepts a handshake on.
- **TC-147 Heartbleed** (CVE-2014-0160): OpenSSL's `heartbeat`
  extension bug letting a remote, unauthenticated attacker read up to
  64KB of process memory per request -- private keys, session tokens,
  credentials, all recoverable this way in the real 2014 incident.
  sslyze's own dedicated probe (`ScanCommand.HEARTBLEED`) sends the
  real malformed heartbeat request and checks the actual response,
  not just a version/patch-level guess.
- **TC-148 ROBOT** (Return Of Bleichenbacher's Oracle Threat,
  CVE-2017-13099-class, disclosed 2017 -- still found on real targets
  in 2026 because a fix requires a server-side code change, not just a
  config flag): a padding-oracle weakness in RSA key exchange that can
  let a network attacker decrypt captured TLS traffic or forge a
  signature. sslyze reports a WEAK vs. STRONG oracle distinction --
  both are reported here as findings (a weak oracle still leaks a
  usable signal, just needs more attacker-side requests), matching
  this project's own worse-severity-only-when-actually-worse
  philosophy rather than treating "not devastating" as "not a
  finding."

**Candidate-detect, not auto-exploit** (this project's own established
line, see `sqli_tests.py`/`deserialization_tests.py`): every technique
here reports what the TLS layer *accepts* (a protocol downgrade
succeeded, a weak cipher was negotiated, Heartbleed's real probe
returned leaked bytes, ROBOT's oracle behavior was observed) -- none of
them go on to actually decrypt captured traffic, extract a private key,
or otherwise complete an attack. That's the same boundary
`deserialization_tests.py` draws for RCE gadget chains: signal a human
verifies, never destructive confirmation.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from stof.core.logger import get_logger
from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding

from .base import VulnModule
from .results import ERROR, FAIL, PASS, SKIPPED, TestCaseResult

if TYPE_CHECKING:
    from sslyze import AllScanCommandsAttempts, ServerScanResult

_log = get_logger("modules.tls_tests")

_VULN_TYPE = "Weak TLS/SSL Transport Configuration"

# (test_id, technique label, attribute suffix used in _result()) for
# every technique -- shared by the normal per-technique path AND the
# whole-module SKIPPED/ERROR fan-out (target isn't HTTPS at all, or the
# TLS connection itself couldn't be established), so both paths report
# the exact same four technique identities rather than the fan-out
# silently reporting fewer/differently-labeled results than a real run.
_TECHNIQUES = (
    ("TC-145", "Deprecated SSL/TLS protocol version accepted (SSLv2/SSLv3/TLS 1.0/TLS 1.1)"),
    ("TC-146", "Weak cipher suite accepted (NULL/anonymous/EXPORT/RC4/DES)"),
    ("TC-147", "Heartbleed (CVE-2014-0160)"),
    ("TC-148", "ROBOT -- Bleichenbacher RSA padding oracle"),
)

_DEPRECATED_PROTOCOL_ATTRS = (
    ("ssl_2_0_cipher_suites", "SSLv2"),
    ("ssl_3_0_cipher_suites", "SSLv3"),
    ("tls_1_0_cipher_suites", "TLS 1.0"),
    ("tls_1_1_cipher_suites", "TLS 1.1"),
)
_CIPHER_SWEEP_ATTRS = (
    ("tls_1_0_cipher_suites", "TLS 1.0"),
    ("tls_1_1_cipher_suites", "TLS 1.1"),
    ("tls_1_2_cipher_suites", "TLS 1.2"),
    # TLS 1.3 deliberately excluded -- the protocol spec itself only
    # defines strong AEAD cipher suites for it, there is no weak-cipher
    # question to ask.
)
# Substrings of a cipher suite's IANA name that mark it as weak --
# matches the well-known categories RFC 7465 (RC4), Sweet32
# CVE-2016-2183 (DES/3DES), and plain "provides no real protection"
# (NULL, anonymous/no server auth, EXPORT-grade) all fall into.
_WEAK_CIPHER_MARKERS = ("NULL", "EXPORT", "RC4", "_DES_", "3DES", "ANON")


def _is_weak_cipher_name(name: str) -> bool:
    upper = name.upper()
    return any(marker in upper for marker in _WEAK_CIPHER_MARKERS)


def _synthetic_endpoint(url: str) -> Endpoint:
    return Endpoint(url=url, method="GET", endpoint_type="api", auth_required=False)


def _run_sslyze_scan(hostname: str, port: int) -> "ServerScanResult":
    """Blocking (sslyze dispatches real TLS handshakes across its own
    worker processes internally) -- run via `run_in_executor`, same
    pattern `configuration_tests.py`'s `_fetch_tls_certificate` already
    uses for its own blocking TLS I/O. Imported lazily so importing
    this module (which happens at `modules/registry.py` import time,
    i.e. on every STOF process start) never pays `sslyze`'s own
    (heavier, C-extension-backed) import cost for a scan that isn't
    using this module."""
    from sslyze import ScanCommand, Scanner, ServerNetworkLocation, ServerScanRequest

    scanner = Scanner()
    scanner.queue_scans([ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=hostname, port=port),
        scan_commands={
            ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES, ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.HEARTBLEED, ScanCommand.ROBOT,
        },
    )])
    return next(iter(scanner.get_results()))


@dataclass
class TlsTestConfig:
    # Same "target-specific, filled in by main.py from config.target.
    # base_url, falls back to the crawler's first discovered endpoint
    # otherwise" convention `ConfigurationTestConfig`/`CacheTestConfig`
    # already use.
    base_url: str = ""


class TlsTestsModule(VulnModule):
    module_id = "tls_tests"
    name = "TLS/SSL Configuration Tests"
    phase = 1

    def __init__(self, config: TlsTestConfig | None = None) -> None:
        self.config = config or TlsTestConfig()

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        from .results import extract_findings

        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _result(self, technique_id: str, technique: str, status: str, detail: str, finding: Finding | None = None) -> TestCaseResult:
        return self._make_result(
            test_id=technique_id, technique_id=technique_id, technique=technique, vuln_type=_VULN_TYPE,
            status=status, detail=detail, role="unauthenticated", finding=finding,
        )

    def _target_host_port(self, endpoints: list[Endpoint]) -> tuple[str, int] | None:
        url = self.config.base_url or (endpoints[0].url if endpoints else "")
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            return None
        return parts.hostname, parts.port or 443

    def _fanout(self, status: str, detail: str) -> list[TestCaseResult]:
        return [self._result(tid, technique, status, detail) for tid, technique in _TECHNIQUES]

    async def run_techniques(self, endpoints, session_manager, session_pool, evidence=None) -> list[TestCaseResult]:
        target = self._target_host_port(endpoints)
        if target is None:
            return self._fanout(SKIPPED, "target is not HTTPS -- nothing to test at the TLS/protocol layer")
        hostname, port = target

        loop = asyncio.get_event_loop()
        try:
            scan_result = await loop.run_in_executor(None, _run_sslyze_scan, hostname, port)
        except Exception as exc:
            _log.warning(f"sslyze scan of '{hostname}:{port}' failed to run: {exc}")
            return self._fanout(ERROR, f"TLS scan of '{hostname}:{port}' could not run: {exc}")
        if scan_result.connectivity_error_trace is not None:
            return self._fanout(ERROR, f"could not establish a TLS connection to '{hostname}:{port}': {scan_result.connectivity_error_trace}")

        attempts = scan_result.scan_result
        return [
            await self._technique_deprecated_protocols(hostname, port, attempts, evidence),
            await self._technique_weak_ciphers(hostname, port, attempts, evidence),
            await self._technique_heartbleed(hostname, port, attempts, evidence),
            await self._technique_robot(hostname, port, attempts, evidence),
        ]

    async def _technique_deprecated_protocols(self, hostname: str, port: int, attempts: "AllScanCommandsAttempts", evidence) -> TestCaseResult:
        from sslyze import ScanCommandAttemptStatusEnum

        tid, technique = _TECHNIQUES[0]
        accepted: list[str] = []
        unchecked: list[str] = []
        for attr, label in _DEPRECATED_PROTOCOL_ATTRS:
            attempt = getattr(attempts, attr)
            if attempt.status != ScanCommandAttemptStatusEnum.COMPLETED or attempt.result is None:
                unchecked.append(label)
                continue
            if attempt.result.accepted_cipher_suites:
                accepted.append(label)

        if not accepted:
            note = f" ({', '.join(unchecked)} could not be tested)" if unchecked else ""
            return self._result(tid, technique, PASS, f"'{hostname}:{port}' rejected every deprecated protocol version tested{note}")

        endpoint_url = f"https://{hostname}:{port}"
        finding = Finding(
            module_id=self.module_id, vuln_type=_VULN_TYPE, severity="Medium", cvss_score=5.9,
            endpoint=_synthetic_endpoint(endpoint_url), user_role="unauthenticated",
            request_raw=f"TLS ClientHello to {hostname}:{port} offering {', '.join(accepted)}",
            response_raw=f"Server completed a full TLS handshake using: {', '.join(accepted)}",
            description=(
                f"'{hostname}:{port}' still completes a TLS handshake using {', '.join(accepted)} -- protocol "
                "version(s) with known, unfixable weaknesses (POODLE for SSLv3, no modern AEAD cipher support "
                "and known padding/MAC weaknesses for TLS 1.0/1.1) that every major browser vendor and PCI-DSS "
                "v4.0 have already deprecated. A client (or an attacker forcing a protocol downgrade) can still "
                "negotiate one of these instead of TLS 1.2/1.3."
            ),
            recommendation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 at the server/load-balancer -- support TLS 1.2 and TLS 1.3 only.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="tls-deprecated-protocol") if evidence else []
        return self._result(tid, technique, FAIL, finding.description, finding=finding)

    @staticmethod
    def _collect_weak_ciphers(attempts: "AllScanCommandsAttempts") -> tuple[dict[str, list[str]], list[str]]:
        """Per-protocol-version accepted weak cipher names, plus the
        list of protocol versions sslyze couldn't complete a scan
        attempt for -- pulled out of `_technique_weak_ciphers` purely
        to keep that method's own branching at collect-then-decide,
        under this project's complexity gate (CLAUDE.md's own quality
        standard)."""
        from sslyze import ScanCommandAttemptStatusEnum

        weak_by_protocol: dict[str, list[str]] = {}
        unchecked: list[str] = []
        for attr, label in _CIPHER_SWEEP_ATTRS:
            attempt = getattr(attempts, attr)
            if attempt.status != ScanCommandAttemptStatusEnum.COMPLETED or attempt.result is None:
                unchecked.append(label)
                continue
            weak = sorted({c.cipher_suite.name for c in attempt.result.accepted_cipher_suites if _is_weak_cipher_name(c.cipher_suite.name)})
            if weak:
                weak_by_protocol[label] = weak
        return weak_by_protocol, unchecked

    @staticmethod
    def _weak_cipher_severity(weak_by_protocol: dict[str, list[str]]) -> tuple[str, float, bool]:
        """NULL/anonymous ciphers provide literally no confidentiality or
        server authentication at all -- a strictly worse outcome than a
        merely-outdated-but-real cipher (RC4/DES/EXPORT), so this is the
        one place severity varies by what was actually found rather
        than a fixed value, matching this project's "severity reflects
        what was actually confirmed" convention. Returns
        `(severity, cvss_score, worst_is_no_encryption)`."""
        all_weak = {c for ciphers in weak_by_protocol.values() for c in ciphers}
        worst_is_no_encryption = any(marker in cipher.upper() for cipher in all_weak for marker in ("NULL", "ANON"))
        return ("Critical", 9.1, True) if worst_is_no_encryption else ("High", 7.4, False)

    async def _technique_weak_ciphers(self, hostname: str, port: int, attempts: "AllScanCommandsAttempts", evidence) -> TestCaseResult:
        tid, technique = _TECHNIQUES[1]
        weak_by_protocol, unchecked = self._collect_weak_ciphers(attempts)

        if not weak_by_protocol:
            note = f" ({', '.join(unchecked)} could not be tested)" if unchecked else ""
            return self._result(tid, technique, PASS, f"'{hostname}:{port}' accepted no NULL/anonymous/EXPORT/RC4/DES cipher suite on any protocol version tested{note}")

        summary = "; ".join(f"{proto}: {', '.join(ciphers)}" for proto, ciphers in weak_by_protocol.items())
        severity, cvss, worst_is_no_encryption = self._weak_cipher_severity(weak_by_protocol)
        no_encryption_note = "NULL/anonymous suites provide no real encryption or server authentication at all. " if worst_is_no_encryption else ""

        endpoint_url = f"https://{hostname}:{port}"
        finding = Finding(
            module_id=self.module_id, vuln_type=_VULN_TYPE, severity=severity, cvss_score=cvss,
            endpoint=_synthetic_endpoint(endpoint_url), user_role="unauthenticated",
            request_raw=f"TLS ClientHello to {hostname}:{port} offering weak cipher suites",
            response_raw=f"Server accepted: {summary}",
            description=(
                f"'{hostname}:{port}' accepts at least one weak cipher suite: {summary}. {no_encryption_note}"
                "RC4 has known biased-keystream attacks (RFC 7465), single/triple-DES has practical "
                "birthday-bound collision attacks against 64-bit block ciphers (Sweet32, CVE-2016-2183), and "
                "EXPORT-grade suites were deliberately weakened for 1990s US export law and are broken in "
                "seconds with modern hardware."
            ),
            recommendation="Remove NULL, anonymous, EXPORT, RC4, and DES/3DES cipher suites from the server's TLS configuration -- keep only modern AEAD suites (AES-GCM, ChaCha20-Poly1305).",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="tls-weak-cipher") if evidence else []
        return self._result(tid, technique, FAIL, finding.description, finding=finding)

    async def _technique_heartbleed(self, hostname: str, port: int, attempts: "AllScanCommandsAttempts", evidence) -> TestCaseResult:
        from sslyze import ScanCommandAttemptStatusEnum

        tid, technique = _TECHNIQUES[2]
        attempt = attempts.heartbleed
        if attempt.status != ScanCommandAttemptStatusEnum.COMPLETED or attempt.result is None:
            return self._result(tid, technique, ERROR, f"Heartbleed probe against '{hostname}:{port}' did not complete: {attempt.error_reason}")
        if not attempt.result.is_vulnerable_to_heartbleed:
            return self._result(tid, technique, PASS, f"'{hostname}:{port}' did not respond to a malformed TLS heartbeat request -- not vulnerable to Heartbleed")

        endpoint_url = f"https://{hostname}:{port}"
        finding = Finding(
            module_id=self.module_id, vuln_type=_VULN_TYPE, severity="High", cvss_score=7.5,
            endpoint=_synthetic_endpoint(endpoint_url), user_role="unauthenticated",
            request_raw=f"Malformed TLS heartbeat request to {hostname}:{port} (oversized payload-length field)",
            response_raw="Server responded with heartbeat data beyond what was actually sent -- confirmed memory over-read",
            description=(
                f"'{hostname}:{port}' is vulnerable to Heartbleed (CVE-2014-0160): a malformed TLS heartbeat "
                "request causes the server to leak up to 64KB of its own process memory per request, with no "
                "authentication required. In the original 2014 incident this recovered private keys, session "
                "cookies, and credentials directly from affected servers' memory."
            ),
            recommendation="Upgrade OpenSSL to a patched version (1.0.1g or later) immediately and rotate every TLS private key and session/credential that may have been exposed.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="tls-heartbleed") if evidence else []
        return self._result(tid, technique, FAIL, finding.description, finding=finding)

    async def _technique_robot(self, hostname: str, port: int, attempts: "AllScanCommandsAttempts", evidence) -> TestCaseResult:
        from sslyze import RobotScanResultEnum, ScanCommandAttemptStatusEnum

        tid, technique = _TECHNIQUES[3]
        attempt = attempts.robot
        if attempt.status != ScanCommandAttemptStatusEnum.COMPLETED or attempt.result is None:
            return self._result(tid, technique, ERROR, f"ROBOT probe against '{hostname}:{port}' did not complete: {attempt.error_reason}")

        outcome = attempt.result.robot_result
        if outcome in (RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE, RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED):
            return self._result(tid, technique, PASS, f"'{hostname}:{port}' is not vulnerable to ROBOT ({outcome.value})")
        if outcome == RobotScanResultEnum.UNKNOWN_INCONSISTENT_RESULTS:
            return self._result(tid, technique, ERROR, f"ROBOT probe against '{hostname}:{port}' returned inconsistent results -- inconclusive, not a clean PASS")

        # VULNERABLE_WEAK_ORACLE or VULNERABLE_STRONG_ORACLE -- a strong
        # oracle needs meaningfully fewer attacker requests to become
        # practically exploitable, so it's flagged more severely, same
        # "severity reflects what was actually confirmed" rule the
        # weak-cipher technique above applies.
        is_strong_oracle = outcome == RobotScanResultEnum.VULNERABLE_STRONG_ORACLE
        severity, cvss = ("Critical", 9.1) if is_strong_oracle else ("High", 7.4)
        endpoint_url = f"https://{hostname}:{port}"
        finding = Finding(
            module_id=self.module_id, vuln_type=_VULN_TYPE, severity=severity, cvss_score=cvss,
            endpoint=_synthetic_endpoint(endpoint_url), user_role="unauthenticated",
            request_raw=f"Series of malformed RSA ciphertexts sent to {hostname}:{port} during the TLS handshake (Bleichenbacher oracle probe)",
            response_raw=f"Server's responses to valid vs. invalid PKCS#1 padding were distinguishable ({outcome.value})",
            description=(
                f"'{hostname}:{port}' is vulnerable to ROBOT (Return Of Bleichenbacher's Oracle Threat) with a "
                f"{'strong' if is_strong_oracle else 'weak'} oracle: the server's TLS RSA key exchange handling "
                "reveals whether a ciphertext's PKCS#1 v1.5 padding is valid, letting a network attacker "
                "eventually decrypt captured TLS traffic that used RSA key exchange, or forge a signature for "
                "that key -- the same class of padding-oracle weakness first published against SSL in 1998, "
                "still recurring because the fix requires server-side code changes, not just a config flag."
            ),
            recommendation="Patch the TLS stack to a version with ROBOT fixed, and disable RSA key exchange cipher suites in favor of (EC)DHE (forward-secret) key exchange.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="tls-robot") if evidence else []
        return self._result(tid, technique, FAIL, finding.description, finding=finding)
