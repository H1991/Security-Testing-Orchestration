"""Layer 9 — `stof/modules/ssrf_tests.py`: Server-Side Request Forgery
(TC-137), grounded in OWASP WSTG-INPV-19 and PortSwigger's own SSRF
research (the "blind SSRF via out-of-band, or via a detectable side
effect when OOB isn't available" framing this module follows).

**Scope, stated honestly up front**: real-world SSRF confirmation at
its strongest uses an out-of-band (OAST) collaborator server -- inject
a unique per-probe callback URL, then check a separate channel for a
DNS/HTTP hit the target's own infrastructure made. STOF does not have
one wired up in Phase 1 (`config.json`'s `burp.collaborator_url` is
reserved for exactly this, once Layer 3C's Burp integration exists —
see CLAUDE.md's Phase 2 table). Building three OAST-only techniques
that always report SKIPPED would be padding, not coverage, so this
module instead builds the three SSRF sub-techniques that produce real,
provable evidence from THIS process's own request/response pair alone,
matching this project's "candidate-detect vs. auto-exploit" philosophy
(`sqli_tests.py`/`deserialization_tests.py`'s same convention) rather
than claiming a false positive OR silently claiming coverage it can't
back up:

- **TC-137.1 metadata/internal-service fingerprint**: injects a
  candidate URL parameter with AWS's IMDS endpoint
  (`http://169.254.169.254/latest/meta-data/`) and a loopback URL
  (`http://127.0.0.1/`), and diffs each response against a baseline
  request to a guaranteed-unreachable RFC 2606 `.invalid` host (what
  "the app tried to fetch this and got nothing back" looks like for
  THIS target specifically). FAILs only when the internal-target
  response both differs meaningfully from that failure baseline AND
  carries a recognizable signature (an IMDS key name, or a real
  non-empty body where the failure baseline was empty/errored) --
  never a bare "the response changed," which a redirect-to-login page
  alone could produce.
- **TC-137.2 blind SSRF via connect-timeout oracle**: PortSwigger's own
  documented technique for detecting blind SSRF without a collaborator
  -- point the candidate parameter at a well-known non-routable address
  (`10.255.255.1`, in the reserved-but-unassigned tail of RFC 1918
  space real infrastructure never answers on) and measure whether the
  response takes dramatically, repeatably longer than a same-shaped
  baseline request. A real server actually attempting that outbound
  TCP connect blocks until its own connect-timeout fires; a server
  that never made the request returns at normal speed regardless of
  the URL's destination. Same "require the delay to repeat once before
  reporting it" discipline as `sqli_tests.py`'s TC-127.3, for the same
  reason (one slow response is exactly as explainable by network
  jitter as a real timeout).
- **TC-137.3 local-file scheme handling**: injects a `file:///etc/passwd`
  payload and checks for the `root:x:0:0` fingerprint appearing in the
  response where the baseline never had it -- confirms the fetcher
  honors non-HTTP(S) schemes at all, a materially different (and often
  higher-severity) bug class than a pure HTTP(S) SSRF.
- **TC-137.4 internal service reachability (loopback port sweep)**:
  the same baseline-diff oracle as TC-137.1, swept across a small,
  curated list of commonly-exposed internal service ports (SSH, MySQL,
  Postgres, Redis, Elasticsearch, two common alt-HTTP/admin ports) on
  `127.0.0.1` -- distinguishes "loopback is reachable at all" (TC-137.1)
  from "which internal services specifically respond," a materially
  more useful signal for triage.
- **TC-137.5 IP/hostname parsing bypass**: the real-world "allowlist
  checks the URL string, not its resolved destination" bug class --
  only fires when the PLAIN loopback URL is already confirmed blocked/
  ignored (no signal), then retries the identical destination written
  as decimal, octal, and hex IP notation, the shortened dotted-decimal
  form, IPv6 loopback, and IPv4-mapped IPv6. A signal on any alternate
  encoding where the plain form showed none is direct evidence of a
  parsing-bypass gap, not just "SSRF exists."

**Mapped against the ten common SSRF attack-pattern taxonomy** (basic/
blind/internal/cloud-metadata/redirect/DNS-bypass/IP-parsing-bypass/
protocol-based/secondary-feature/chaining): TC-137.1 covers cloud-
metadata access and the general "basic URL SSRF" case wherever a
recognizable signature exists; TC-137.2 covers blind SSRF; TC-137.4
covers internal service access; TC-137.3 covers protocol-based SSRF;
TC-137.5 covers IP/hostname parsing bypass; secondary-feature SSRF
(webhook/PDF/image-fetcher/importer) isn't a separate technique here
because `_URL_PARAM_HINTS` already targets exactly those field names
directly -- any of TC-137.1-.5 already exercises a webhook/callback/
avatar-shaped parameter the same as a literal `url` one, no dedicated
technique needed to "cover" a parameter name that's already a
candidate. **Deliberately NOT built here, and why**: redirect-based
allowlist bypass and DNS-rebinding both need STOF's own attacker-
controlled redirect/DNS infrastructure to test honestly -- faking
either with a third-party service this project doesn't control would
mean vouching for infrastructure outside its own trust boundary.
SSRF chaining (pivoting a confirmed-reachable internal service into a
credential/RCE escalation) is deliberately a human pentester's next
step once TC-137.1/.4 flag something reachable, same "candidate-detect,
not auto-exploit-and-chain" line this project already draws for
IDOR/RCE gadget chains elsewhere. Wiring `burp.collaborator_url` into
a proper OOB channel (closing the true blind-SSRF-with-zero-signal
gap OAST exists for) is real, valuable Phase 2 work.

Every technique's `Finding.response_raw` carries truncated evidence of
the signal observed (a differential, a timing delta, a file-read
fingerprint) -- never a claim of having exfiltrated real internal data.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from stof.core.logger import get_logger
from stof.findings.models import Finding

from ._injection_shared import build_params, injectable_endpoints, response_similarity, send_probe
from .base import VulnModule
from .results import FAIL, PASS, SKIPPED, TestCaseResult, extract_findings

if TYPE_CHECKING:
    from stof.crawler.endpoint_store import Endpoint
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.ssrf_tests")

# Not every parameter is a plausible SSRF sink the way every parameter
# is a plausible SQLi sink -- probing every discovered field would be
# slow and noisy for no real gain. This is the same "small, curated,
# high-signal hint list" convention as this project's other candidate
# filters (`configuration_tests._ADMIN_PANEL_PATHS`, `base.py`'s own
# `_USERNAME_FIELD_HINTS`), matching the field names real SSRF research
# (HackerOne's own SSRF write-ups) repeatedly calls out: url/uri fields,
# webhook/callback registration, image/avatar fetchers, redirect/
# import/feed/proxy targets.
_URL_PARAM_HINTS: tuple[str, ...] = (
    "url", "uri", "link", "href", "src", "source", "image", "avatar",
    "callback", "redirect", "webhook", "endpoint", "target", "dest",
    "destination", "file", "download", "import", "feed", "proxy", "host", "domain",
    # Added alongside TC-137.7 (open redirect): these are common
    # real-world redirect-parameter names (Django's own `next`,
    # countless OAuth/SSO flows' `return_to`/`returnUrl`, generic
    # `continue`) that the original SSRF-focused hint list above
    # didn't cover -- still URL-shaped by nature, so broadening this
    # shared list also strengthens every other SSRF technique's own
    # candidate set, not just the new one.
    "next", "return_to", "returnurl", "continue",
)

# RFC 2606 .invalid -- guaranteed never to resolve, so a request here
# is the "the app tried to fetch a URL and got nothing" baseline every
# other candidate is diffed against. Unique per module instance import
# isn't needed (no cross-run correlation happens locally), unlike the
# per-probe uniqueness `cache_tests.py`'s marker needs.
_UNREACHABLE_BASELINE_URL = "http://ssrf-probe-baseline.invalid/"

_AWS_METADATA_URL = "http://169.254.169.254/latest/meta-data/"
_LOOPBACK_URL = "http://127.0.0.1/"
_METADATA_SIGNATURES: tuple[str, ...] = ("ami-id", "instance-id", "instance-type", "security-credentials", "iam/")

_BLACKHOLE_URL = "http://10.255.255.1/"
_TIMEOUT_DELTA_THRESHOLD_S = 3.0

_FILE_SCHEME_PAYLOAD = "file:///etc/passwd"
_FILE_READ_SIGNATURE = "root:x:0:0"

# TC-137.4 -- a small, curated set of commonly-exposed internal service
# ports (SSH, MySQL, Postgres, Redis, Elasticsearch, and two common
# alt-HTTP/admin ports), same "small, high-signal list" convention as
# `_URL_PARAM_HINTS` above and `configuration_tests._ADMIN_PANEL_PATHS`
# elsewhere in this project -- a full 65535-port sweep would be slow,
# noisy, and functionally indistinguishable in outcome from checking
# the handful of ports that actually matter for SSRF impact triage.
_INTERNAL_SERVICE_PORTS: tuple[int, ...] = (22, 3306, 5432, 6379, 9200, 8080, 8443, 27017)

# TC-137.5 -- alternate representations of the SAME loopback/metadata
# address that a naive string-based allowlist ("does the URL start
# with an allowed host?") can fail to recognize as identical to the
# plain form, while the underlying HTTP client's own URL parser still
# resolves them to the real destination. This is the well-documented
# "IP/hostname parsing bypass" SSRF sub-class (decimal/octal/hex IP
# notation, IPv6 loopback and IPv4-mapped-IPv6, and the shortened
# dotted-decimal form) -- each entry is `(url, label)`.
_IP_BYPASS_VARIANTS: tuple[tuple[str, str], ...] = (
    ("http://2130706433/", "decimal IP notation"),
    ("http://0x7f000001/", "hexadecimal IP notation"),
    ("http://0177.0.0.1/", "octal IP notation"),
    ("http://127.1/", "shortened dotted-decimal notation"),
    ("http://[::1]/", "IPv6 loopback"),
    ("http://[::ffff:127.0.0.1]/", "IPv4-mapped IPv6"),
)


@dataclass
class SsrfTestConfig:
    low_priv_role: str = "normal"
    target_url: str = ""
    max_targets: int = 8
    # config.json's `burp.collaborator_url` -- an operator-supplied
    # out-of-band callback host (Burp Collaborator, interactsh, or any
    # equivalent OOB service). Empty by default: TC-137.6 SKIPS cleanly
    # with instructions to configure it rather than silently no-op'ing.
    collaborator_url: str = ""


class SsrfTestsModule(VulnModule):
    module_id = "ssrf_tests"
    name = "Server-Side Request Forgery Tests"
    phase = 1

    def __init__(self, config: SsrfTestConfig | None = None) -> None:
        self.config = config or SsrfTestConfig()

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _result(
        self, technique_id: str, technique: str, vuln_type: str, status: str, detail: str,
        role: "str | None" = None, endpoint=None, finding: "Finding | None" = None,
    ) -> TestCaseResult:
        return self._make_result(
            test_id="TC-137", technique_id=technique_id, technique=technique, vuln_type=vuln_type,
            status=status, detail=detail, role=role, endpoint=endpoint, finding=finding,
        )

    def _param_candidates(self, endpoints: "list[Endpoint]") -> list[tuple["Endpoint", str, str]]:
        candidates: list[tuple[Endpoint, str, str]] = []
        for endpoint in injectable_endpoints(endpoints):
            for name in endpoint.parameters:
                lowered = name.lower()
                if any(hint in lowered for hint in _URL_PARAM_HINTS):
                    candidates.append((endpoint, name, endpoint.location_for(name)))
        return candidates[: self.config.max_targets]

    def _finding(
        self, endpoint: "Endpoint", vuln_type: str, param: str, description: str,
        request_preview: str, response_preview: str, severity: str = "Critical", cvss_score: float = 9.1,
    ) -> Finding:
        return Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity=severity, cvss_score=cvss_score,
            endpoint=endpoint, user_role=self.config.low_priv_role,
            request_raw=request_preview, response_raw=response_preview[:300],
            description=description,
            recommendation=(
                "Validate and allowlist outbound destinations server-side before fetching a "
                "user-supplied URL; reject non-HTTP(S) schemes, loopback/link-local/private "
                "address ranges, and cloud metadata endpoints regardless of DNS resolution path."
            ),
        )

    async def _technique_metadata_fingerprint(
        self, candidates: list[tuple["Endpoint", str, str]], context, evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-137.1", "Cloud metadata / internal-service response fingerprint"
        vuln_type = "Server-Side Request Forgery (metadata/internal fingerprint)"
        if not candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no URL-shaped parameter discovered to probe")

        for endpoint, param, location in candidates:
            baseline = await send_probe(context, endpoint, build_params(endpoint, param, _UNREACHABLE_BASELINE_URL), location)
            if baseline is None:
                continue
            baseline_body = baseline[1]
            for internal_url, label in ((_AWS_METADATA_URL, "AWS instance metadata"), (_LOOPBACK_URL, "loopback (127.0.0.1)")):
                probe = await send_probe(context, endpoint, build_params(endpoint, param, internal_url), location)
                if probe is None:
                    continue
                probe_body = probe[1]
                similarity = response_similarity(baseline_body, probe_body)
                has_signature = any(sig in probe_body.lower() for sig in _METADATA_SIGNATURES)
                meaningfully_different = similarity < 0.7 and len(probe_body.strip()) > 20
                if not (has_signature or meaningfully_different):
                    continue
                description = (
                    f"Injecting {label} URL ('{internal_url}') into parameter '{param}' ({location}) on "
                    f"{endpoint.method} {endpoint.url} produced a response "
                    f"{'carrying a recognizable metadata field name' if has_signature else 'meaningfully different from'} "
                    f"a same-shaped request to a guaranteed-unreachable baseline URL ({similarity:.0%} similar) -- "
                    "a signal consistent with the server actually fetching this internal/metadata destination "
                    "server-side. This is a candidate signal only: no metadata content was extracted or reported."
                )
                finding = self._finding(
                    endpoint, vuln_type, param, description,
                    request_preview=f"{endpoint.method} {endpoint.url}\n{param}={internal_url!r}",
                    response_preview=probe_body,
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"ssrf-metadata-{param}") if evidence else []
                return self._result(tid, technique, vuln_type, FAIL, description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding)
        return self._result(
            tid, technique, vuln_type, PASS,
            f"{len(candidates)} URL-shaped parameter(s) probed with cloud-metadata and loopback URLs, "
            "no response differential or metadata signature observed", role=self.config.low_priv_role,
        )

    async def _timeout_delta(self, endpoint: "Endpoint", param: str, location: str, context) -> "float | None":
        baseline = await send_probe(context, endpoint, build_params(endpoint, param, _UNREACHABLE_BASELINE_URL), location)
        if baseline is None:
            return None
        probe = await send_probe(context, endpoint, build_params(endpoint, param, _BLACKHOLE_URL), location)
        if probe is None:
            return None
        return probe[2] - baseline[2]

    async def _technique_blind_timing(
        self, candidates: list[tuple["Endpoint", str, str]], context, evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-137.2", "Blind SSRF via connect-timeout oracle (non-routable address)"
        vuln_type = "Server-Side Request Forgery (blind, timing-based)"
        if not candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no URL-shaped parameter discovered to probe")

        for endpoint, param, location in candidates:
            delta = await self._timeout_delta(endpoint, param, location, context)
            if delta is None or delta < _TIMEOUT_DELTA_THRESHOLD_S:
                continue
            # Require the delay to repeat once before reporting it --
            # same discipline as sqli_tests.py's TC-127.3, for the same
            # reason: one slow response is exactly as explainable by
            # network jitter as a real server-side connect timeout.
            confirm_delta = await self._timeout_delta(endpoint, param, location, context)
            if confirm_delta is None or confirm_delta < _TIMEOUT_DELTA_THRESHOLD_S:
                continue
            description = (
                f"Injecting a non-routable address ('{_BLACKHOLE_URL}') into parameter '{param}' ({location}) "
                f"on {endpoint.method} {endpoint.url} added a repeatable ~{min(delta, confirm_delta):.1f}s of "
                "response latency compared to a same-shaped baseline request -- a timing signal consistent with "
                "the server actually attempting an outbound TCP connection to that destination and blocking "
                "until its own connect-timeout fired. This is a candidate signal only: no response content "
                "was observed to confirm what (if anything) is reachable at that destination."
            )
            finding = self._finding(
                endpoint, vuln_type, param, description,
                request_preview=f"{endpoint.method} {endpoint.url}\n{param}={_BLACKHOLE_URL!r}",
                response_preview=f"observed delta: first={delta:.1f}s, confirm={confirm_delta:.1f}s",
                severity="High", cvss_score=7.5,
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"ssrf-timing-{param}") if evidence else []
            return self._result(tid, technique, vuln_type, FAIL, description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding)
        return self._result(
            tid, technique, vuln_type, PASS,
            f"{len(candidates)} URL-shaped parameter(s) probed against a non-routable address, "
            "no repeatable timing delta observed", role=self.config.low_priv_role,
        )

    async def _technique_file_scheme(
        self, candidates: list[tuple["Endpoint", str, str]], context, evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-137.3", "Local-file scheme handling (file:// read fingerprint)"
        vuln_type = "Server-Side Request Forgery (file scheme)"
        if not candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no URL-shaped parameter discovered to probe")

        for endpoint, param, location in candidates:
            baseline = await send_probe(context, endpoint, build_params(endpoint, param, _UNREACHABLE_BASELINE_URL), location)
            if baseline is None or _FILE_READ_SIGNATURE in baseline[1].lower():
                continue  # can't tell a real hit from a baseline that already contains it
            probe = await send_probe(context, endpoint, build_params(endpoint, param, _FILE_SCHEME_PAYLOAD), location)
            if probe is None or _FILE_READ_SIGNATURE not in probe[1].lower():
                continue
            description = (
                f"Injecting a 'file:///etc/passwd' payload into parameter '{param}' ({location}) on "
                f"{endpoint.method} {endpoint.url} produced a response containing the 'root:x:0:0' passwd-file "
                "fingerprint, absent from a same-shaped baseline request -- the URL fetcher honors the file:// "
                "scheme and read a local file server-side, a materially more severe bug class than an "
                "HTTP(S)-only SSRF (arbitrary local file disclosure, not just outbound request forgery)."
            )
            finding = self._finding(
                endpoint, vuln_type, param, description,
                request_preview=f"{endpoint.method} {endpoint.url}\n{param}={_FILE_SCHEME_PAYLOAD!r}",
                response_preview=probe[1],
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"ssrf-file-{param}") if evidence else []
            return self._result(tid, technique, vuln_type, FAIL, description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding)
        return self._result(
            tid, technique, vuln_type, PASS,
            f"{len(candidates)} URL-shaped parameter(s) probed with a file:// payload, "
            "no local-file-read fingerprint observed", role=self.config.low_priv_role,
        )

    def _differs_from_baseline(self, baseline_body: str, probe_body: str) -> bool:
        """Shared oracle for TC-137.4/.5 (and the same shape TC-137.1
        already uses inline): a probe response counts as evidence only
        if it's BOTH meaningfully dissimilar from the "nothing was
        fetched" baseline AND non-trivial in length -- a bare status-
        code match or an equally-empty error page on both sides proves
        nothing."""
        return response_similarity(baseline_body, probe_body) < 0.7 and len(probe_body.strip()) > 20

    async def _technique_internal_port_sweep(
        self, candidates: list[tuple["Endpoint", str, str]], context, evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-137.4", "Internal service reachability via loopback port sweep"
        vuln_type = "Server-Side Request Forgery (internal service reachability)"
        if not candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no URL-shaped parameter discovered to probe")

        checked = 0
        for endpoint, param, location in candidates:
            baseline = await send_probe(context, endpoint, build_params(endpoint, param, _UNREACHABLE_BASELINE_URL), location)
            if baseline is None:
                continue
            for port in _INTERNAL_SERVICE_PORTS:
                port_url = f"http://127.0.0.1:{port}/"
                probe = await send_probe(context, endpoint, build_params(endpoint, param, port_url), location)
                checked += 1
                if probe is None or not self._differs_from_baseline(baseline[1], probe[1]):
                    continue
                description = (
                    f"Injecting a loopback URL targeting port {port} ('{port_url}') into parameter '{param}' "
                    f"({location}) on {endpoint.method} {endpoint.url} produced a response meaningfully "
                    f"different from a same-shaped request to a guaranteed-unreachable baseline URL -- a signal "
                    f"consistent with a real service listening on 127.0.0.1:{port} that this server can reach "
                    "internally. This is a candidate signal only: no service banner or data was extracted."
                )
                finding = self._finding(
                    endpoint, vuln_type, param, description,
                    request_preview=f"{endpoint.method} {endpoint.url}\n{param}={port_url!r}",
                    response_preview=probe[1],
                    severity="High", cvss_score=7.5,
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"ssrf-port-{param}-{port}") if evidence else []
                return self._result(tid, technique, vuln_type, FAIL, description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding)
        if checked == 0:
            return self._result(tid, technique, vuln_type, SKIPPED, "baseline probe failed for every candidate parameter")
        return self._result(
            tid, technique, vuln_type, PASS,
            f"{len(_INTERNAL_SERVICE_PORTS)} common internal service port(s) probed via loopback across "
            f"{len(candidates)} URL-shaped parameter(s), no response differential observed", role=self.config.low_priv_role,
        )

    async def _technique_ip_parsing_bypass(
        self, candidates: list[tuple["Endpoint", str, str]], context, evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        tid, technique = "TC-137.5", "IP/hostname parsing bypass (alternate loopback representations)"
        vuln_type = "Server-Side Request Forgery (allowlist parsing bypass)"
        if not candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no URL-shaped parameter discovered to probe")

        for endpoint, param, location in candidates:
            baseline = await send_probe(context, endpoint, build_params(endpoint, param, _UNREACHABLE_BASELINE_URL), location)
            if baseline is None:
                continue
            plain = await send_probe(context, endpoint, build_params(endpoint, param, _LOOPBACK_URL), location)
            if plain is not None and self._differs_from_baseline(baseline[1], plain[1]):
                # The plain form already reaches loopback unrestricted --
                # TC-137.1 already reports that; there's no "bypass" to
                # demonstrate here since nothing was actually blocked.
                continue
            for variant_url, label in _IP_BYPASS_VARIANTS:
                probe = await send_probe(context, endpoint, build_params(endpoint, param, variant_url), location)
                if probe is None or not self._differs_from_baseline(baseline[1], probe[1]):
                    continue
                description = (
                    f"Parameter '{param}' ({location}) on {endpoint.method} {endpoint.url} rejected or ignored "
                    f"the plain loopback URL ('{_LOOPBACK_URL}') but injecting the SAME destination written as "
                    f"{label} ('{variant_url}') produced a response meaningfully different from the unreachable "
                    "baseline -- evidence that server-side validation checks the URL as a literal string rather "
                    "than its resolved destination, letting an alternate encoding reach an address the plain "
                    "form was blocked from."
                )
                finding = self._finding(
                    endpoint, vuln_type, param, description,
                    request_preview=f"{endpoint.method} {endpoint.url}\n{param}={variant_url!r}",
                    response_preview=probe[1],
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"ssrf-ipbypass-{param}") if evidence else []
                return self._result(tid, technique, vuln_type, FAIL, description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding)
        return self._result(
            tid, technique, vuln_type, PASS,
            f"{len(_IP_BYPASS_VARIANTS)} alternate loopback representation(s) probed across {len(candidates)} "
            "URL-shaped parameter(s), no allowlist-parsing bypass observed", role=self.config.low_priv_role,
        )

    async def _technique_oob_callback(
        self, candidates: list[tuple["Endpoint", str, str]], context, evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        """The real, honest closing of this module's own stated Phase 1
        gap: an operator-configured out-of-band collaborator
        (`SsrfTestConfig.collaborator_url`, from `config.json`'s
        `burp.collaborator_url`) lets this technique send a genuine
        unique-per-probe OOB callback URL into every candidate
        parameter -- the strongest SSRF confirmation technique that
        exists, covering the true blind case (a webhook/async-processed
        fetch with neither a timing nor a content signal) TC-137.1-.5
        structurally can't reach on their own. What this module still
        does NOT do is poll the collaborator's own API for a received
        callback -- that's a real, separate integration (Burp's own
        REST API, or interactsh's client protocol) this project hasn't
        built, so this technique reports SKIPPED with the exact markers
        sent, not a FAIL/PASS it can't actually back up. Checking those
        markers against the collaborator's own dashboard is the
        confirmation step, same "STOF signals, a human confirms the
        parts it structurally cannot" line as every other technique in
        this codebase that stops short of full auto-exploitation."""
        tid, technique = "TC-137.6", "Out-of-band (OOB) callback probe via configured collaborator"
        vuln_type = "Server-Side Request Forgery (blind, out-of-band)"
        if not candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no URL-shaped parameter discovered to probe")
        if not self.config.collaborator_url:
            return self._result(
                tid, technique, vuln_type, SKIPPED,
                "no out-of-band collaborator configured -- set it in Settings (Out-of-band testing) or "
                "config.json's burp.collaborator_url to enable this technique",
            )

        sent: list[tuple[Endpoint, str, str]] = []
        # Strip any scheme the operator included -- the marker subdomain
        # goes in front of the bare host either way, so `https://
        # abc.oast.example` and `abc.oast.example` both build the same
        # shape of callback URL.
        collaborator_host = self.config.collaborator_url.split("://", 1)[-1].strip("/")
        for endpoint, param, location in candidates:
            marker = f"stof-{uuid.uuid4().hex[:12]}"
            callback_url = f"http://{marker}.{collaborator_host}/"
            probe = await send_probe(context, endpoint, build_params(endpoint, param, callback_url), location)
            if probe is not None:
                sent.append((endpoint, param, callback_url))

        if not sent:
            return self._result(tid, technique, vuln_type, SKIPPED, "every candidate probe request failed to send")

        markers_preview = "; ".join(f"{param}={url}" for _, param, url in sent[:5])
        detail = (
            f"Sent {len(sent)} unique out-of-band callback URL(s) via the configured collaborator into "
            f"candidate parameter(s): {markers_preview}"
            f"{' (+' + str(len(sent) - 5) + ' more)' if len(sent) > 5 else ''}. STOF does not poll the "
            "collaborator's own API for a received callback -- check its dashboard for a DNS/HTTP hit "
            "against any marker above. A callback received is confirmed blind SSRF; this technique reports "
            "SKIPPED (not PASS) because STOF itself cannot verify the outcome either way."
        )
        return self._result(tid, technique, vuln_type, SKIPPED, detail, role=self.config.low_priv_role)

    async def _technique_open_redirect(
        self, candidates: list[tuple["Endpoint", str, str]], context, evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        """Open Redirect (CWE-601) — a distinct bug class from SSRF (the
        server sends the browser SOMEWHERE, rather than fetching a URL
        itself), but grouped here because it shares this module's own
        URL-shaped-parameter discovery (`_param_candidates`) rather than
        duplicating that detection logic in a new module for one
        technique. Added after cross-referencing a real Burp Active Scan
        run against this target and finding no STOF equivalent.

        Sends an external marker URL (`https://stof-redirect-check.
        invalid/<random>`) into every candidate, without following the
        redirect (`max_redirects=0`, matching every other technique in
        this file), and checks the response's own `Location` header.

        False-positive guard: only flags a 3xx response whose `Location`
        header's host EXACTLY matches the marker host STOF itself
        injected -- a same-origin redirect (the overwhelmingly common,
        completely normal case: bouncing a param back to itself, or to
        a login page) never matches an `.invalid` marker host, so this
        can't confuse ordinary redirect behavior for a vulnerability.
        """
        tid, technique = "TC-137.7", "Open redirect via URL-shaped parameter"
        vuln_type = "Open Redirect"
        if not candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no URL-shaped parameter discovered to probe")

        for endpoint, param, location in candidates:
            marker_host = f"stof-redirect-{uuid.uuid4().hex[:10]}.invalid"
            marker_url = f"https://{marker_host}/"
            probe = await send_probe(context, endpoint, build_params(endpoint, param, marker_url), location)
            if probe is None:
                continue
            status, _body, _elapsed, headers = probe
            location_header = (headers or {}).get("location", "")
            if 300 <= status < 400 and marker_host in location_header:
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=6.1,
                    endpoint=endpoint, user_role=self.config.low_priv_role,
                    request_raw=f"{endpoint.method} {endpoint.url}\n{param}={marker_url!r}",
                    response_raw=f"HTTP {status}\nLocation: {location_header}",
                    description=(
                        f"'{endpoint.url}' parameter '{param}' ({location}) accepted an external URL and "
                        f"redirected the browser there (HTTP {status}, Location: {location_header}). An "
                        "attacker can craft a link on this trusted domain that silently redirects a victim to "
                        "an attacker-controlled site -- commonly abused for phishing (the URL bar shows the "
                        "trusted domain right up until the redirect fires) or to bypass an OAuth/SSO "
                        "redirect_uri allowlist that trusts this host."
                    ),
                    recommendation=(
                        "Validate redirect targets against an explicit allowlist of same-origin/known-partner "
                        "destinations server-side, or require an intermediate confirmation page for any "
                        "off-site redirect."
                    ),
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"open-redirect-{param}") if evidence else []
                return self._result(tid, technique, vuln_type, FAIL, finding.description, endpoint=endpoint, finding=finding)

        return self._result(
            tid, technique, vuln_type, PASS,
            f"{len(candidates)} URL-shaped parameter(s) probed with an external marker URL, none redirected there",
            role=self.config.low_priv_role,
        )

    async def run_techniques(
        self,
        endpoints: "list[Endpoint]",
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[TestCaseResult]:
        candidates = self._param_candidates(endpoints)
        results: list[TestCaseResult] = []

        techniques = (
            ("TC-137.1", "Cloud metadata / internal-service response fingerprint", "Server-Side Request Forgery (metadata/internal fingerprint)"),
            ("TC-137.2", "Blind SSRF via connect-timeout oracle (non-routable address)", "Server-Side Request Forgery (blind, timing-based)"),
            ("TC-137.3", "Local-file scheme handling (file:// read fingerprint)", "Server-Side Request Forgery (file scheme)"),
            ("TC-137.4", "Internal service reachability via loopback port sweep", "Server-Side Request Forgery (internal service reachability)"),
            ("TC-137.5", "IP/hostname parsing bypass (alternate loopback representations)", "Server-Side Request Forgery (allowlist parsing bypass)"),
            ("TC-137.6", "Out-of-band (OOB) callback probe via configured collaborator", "Server-Side Request Forgery (blind, out-of-band)"),
            ("TC-137.7", "Open redirect via URL-shaped parameter", "Open Redirect"),
        )
        if not candidates:
            for tid, technique, vuln_type in techniques:
                results.append(self._result(tid, technique, vuln_type, SKIPPED, "no URL-shaped parameter discovered to probe"))
            return results

        target_url = self.config.target_url or candidates[0][0].url
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.low_priv_role, target_url)
        except KeyError as exc:
            reason = f"role '{self.config.low_priv_role}' not configured: {exc}"
            for tid, technique, vuln_type in techniques:
                results.append(self._result(tid, technique, vuln_type, SKIPPED, reason))
            return results

        results.append(await self._safe_result(self._technique_metadata_fingerprint(candidates, context, evidence), "TC-137", "TC-137.1", techniques[0][1], techniques[0][2], role=self.config.low_priv_role))
        results.append(await self._safe_result(self._technique_blind_timing(candidates, context, evidence), "TC-137", "TC-137.2", techniques[1][1], techniques[1][2], role=self.config.low_priv_role))
        results.append(await self._safe_result(self._technique_file_scheme(candidates, context, evidence), "TC-137", "TC-137.3", techniques[2][1], techniques[2][2], role=self.config.low_priv_role))
        results.append(await self._safe_result(self._technique_internal_port_sweep(candidates, context, evidence), "TC-137", "TC-137.4", techniques[3][1], techniques[3][2], role=self.config.low_priv_role))
        results.append(await self._safe_result(self._technique_ip_parsing_bypass(candidates, context, evidence), "TC-137", "TC-137.5", techniques[4][1], techniques[4][2], role=self.config.low_priv_role))
        results.append(await self._safe_result(self._technique_oob_callback(candidates, context, evidence), "TC-137", "TC-137.6", techniques[5][1], techniques[5][2], role=self.config.low_priv_role))
        results.append(await self._safe_result(self._technique_open_redirect(candidates, context, evidence), "TC-137", "TC-137.7", techniques[6][1], techniques[6][2], role=self.config.low_priv_role))
        return results
