"""Layer 9 — `stof/modules/configuration_tests.py`: Default
Configuration Check (TC-017).

All techniques are read-only GET probes against small, curated path
lists or single-response header inspection (the same "known-patterns"
approach `config/testcases.json` itself notes Burp's own Scanner uses
for this category -- "Burp Scanner checks default files and endpoints;
limited to known patterns") -- no gating needed, nothing here writes
or deletes anything on the target.

TC-017.7 (CSP analysis) is a single anonymous-context GET plus a pure
header check, same shape as TC-017.5 (version disclosure) -- no
wordlist sweep, no state change.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from stof.core.logger import get_logger
from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding

from .base import VulnModule, _is_transient_error
from .results import FAIL, PASS, TestCaseResult, extract_findings

if TYPE_CHECKING:
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.configuration_tests")

_ADMIN_PANEL_PATHS: tuple[str, ...] = (
    "/admin", "/administrator", "/admin/login", "/manage", "/management",
    "/console", "/manager/html", "/wp-admin", "/phpmyadmin", "/adminer.php",
)

_LISTABLE_DIR_PATHS: tuple[str, ...] = (
    "/", "/images/", "/assets/", "/uploads/", "/backup/", "/files/", "/static/", "/logs/",
)
_DIRECTORY_LISTING_SIGNATURES: tuple[str, ...] = ("Index of /", "<title>Index of", "Directory Listing For", "[To Parent Directory]")

_STACK_TRACE_SIGNATURES: tuple[str, ...] = (
    "Traceback (most recent call last)", "at java.", "at org.springframework",
    "System.Exception", "Microsoft.AspNet", "Fatal error:", "Warning: include(",
    "django.core.exceptions", "org.hibernate", "PG::Error", "ORA-0",
)

_SAMPLE_FILE_PATHS: tuple[str, ...] = (
    "/install.php", "/test.php", "/phpinfo.php", "/info.php", "/.git/config",
    "/.env", "/web.config", "/server-status", "/.DS_Store", "/backup.sql", "/dump.sql",
)

_VERSION_DISCLOSURE_HEADERS: tuple[str, ...] = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")
# A bare product name with no version number is normal; a version number
# after it is the actual disclosure (e.g. "Apache/2.4.41" vs "Apache").
_VERSION_NUMBER_RE = re.compile(r"\d+\.\d+")

# A clearly fake, non-allowlisted origin -- won't collide with any real
# allowlist entry, so any reflection of it back is necessarily dynamic.
_SYNTHETIC_CORS_ORIGIN = "https://stof-cors-probe.invalid"

# A nonce/hash source alongside 'unsafe-inline' in the same directive is
# a deliberate, still-strict-for-modern-browsers backward-compat pattern
# (PortSwigger's CSP advisory, Google's Strict CSP methodology) -- legacy
# browsers that don't understand nonce-/hash- sources fall back to
# 'unsafe-inline', while every modern browser ignores 'unsafe-inline'
# once a nonce/hash source is present. Must NOT be flagged.
_NONCE_OR_HASH_SOURCE_RE = re.compile(r"^'(nonce-|sha256-|sha384-|sha512-)")
# A bare wildcard, `data:`, or bare `https:` scheme source lets script
# load from effectively anywhere -- PortSwigger's "CSP allows untrusted
# script execution" advisory's own overly-broad-source category.
_OVERLY_BROAD_CSP_SOURCES = ("*", "data:", "https:")


def _csp_missing_or_weak(content_type: str, csp_header: str | None) -> str | None:
    """Pure, directly-unit-testable CSP evidence check -- same "small and
    high-signal" philosophy as `_is_cors_misconfigured`. Returns a short
    reason string on a hit, `None` on a clean/strict policy or a
    non-HTML response. A small split-on-';'/whitespace directive parse
    is enough here (no full CSP grammar needed): only `script-src`
    (falling back to `default-src` when `script-src` is absent, per the
    CSP spec's own fallback behavior) is inspected, since that's the
    directive that actually governs script execution.

    False-positive guards encoded literally, per the research (PortSwigger's
    CSP advisory, Google's Strict CSP methodology):
    - Never runs against a non-`text/html` response (a missing CSP on a
      JSON/API/static-asset response is normal, not a finding).
    - `'unsafe-inline'` is NOT flagged if a `nonce-`/`hash-` source is
      ALSO present in the same directive.
    - A strict `default-src 'self'` policy with no `unsafe-*`/wildcard
      keywords is never flagged just for being short.
    """
    if "text/html" not in (content_type or "").lower():
        return None
    if not csp_header or not csp_header.strip():
        return "no CSP header present"

    directives: dict[str, list[str]] = {}
    for raw_directive in csp_header.split(";"):
        tokens = raw_directive.strip().split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]

    sources = directives.get("script-src", directives.get("default-src"))
    if sources is None:
        return None  # neither directive present -- nothing to inspect, not enough signal to flag

    if "'unsafe-inline'" in sources and not any(_NONCE_OR_HASH_SOURCE_RE.match(s) for s in sources):
        return "allows unsafe-inline script execution"
    if "'unsafe-eval'" in sources:
        return "allows unsafe-eval"
    if any(source in _OVERLY_BROAD_CSP_SOURCES for source in sources):
        return "allows script execution from an overly broad source"
    return None


# OWASP Secure Headers Project "core" set, narrowed to the three that are
# genuinely security-relevant (not stylistic) and safely checkable from a
# single response: HSTS is TC-017.9's job (transport-security technique),
# so this list stays clickjacking + MIME-sniffing only.
_FRAME_ANCESTORS_RE = re.compile(r"frame-ancestors\s+[^;]+")


def _missing_security_headers(content_type: str, headers: dict[str, str]) -> list[str]:
    """Pure, directly-unit-testable header-hygiene check -- same shape as
    `_csp_missing_or_weak`. Only runs against `text/html` responses (a
    missing clickjacking/MIME-sniffing header on a JSON/API response is
    normal, not a finding -- those headers only matter for a browser
    rendering HTML). Returns the list of missing header names (empty if
    none), so the caller can name exactly which ones in the finding.

    False-positive guard (OWASP Secure Headers Project / MDN): CSP's
    `frame-ancestors` directive supersedes `X-Frame-Options` in every
    browser that supports it, so `X-Frame-Options` is NOT flagged missing
    when `frame-ancestors` is present in the response's CSP header --
    flagging both would double-count the same clickjacking control.
    """
    if "text/html" not in (content_type or "").lower():
        return []
    missing = []
    if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        missing.append("X-Content-Type-Options")
    csp = headers.get("content-security-policy", "")
    has_frame_ancestors = bool(_FRAME_ANCESTORS_RE.search(csp))
    if not headers.get("x-frame-options") and not has_frame_ancestors:
        missing.append("X-Frame-Options")
    return missing


# Endpoint-path keywords that mark a page as handling credentials/session
# tokens/payment data -- the narrow set that makes plaintext HTTP transport
# an actual, evidence-backed finding rather than a stylistic complaint.
_SENSITIVE_PATH_KEYWORDS: tuple[str, ...] = (
    "login", "signin", "sign-in", "auth", "password", "account",
    "session", "checkout", "payment", "billing", "token",
)


def _is_sensitive_path(url: str) -> bool:
    lowered = url.lower()
    return any(keyword in lowered for keyword in _SENSITIVE_PATH_KEYWORDS)


# Cloud object-storage URL shapes -- small and high-signal, same
# philosophy as this file's other hint lists (_ADMIN_PANEL_PATHS etc).
_CLOUD_STORAGE_URL_RE = re.compile(
    r"https?://(?:[a-z0-9.\-]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com"
    r"|s3\.amazonaws\.com/[a-z0-9.\-]+"
    r"|[a-z0-9.\-]+\.blob\.core\.windows\.net"
    r"|storage\.googleapis\.com/[a-z0-9._\-]+"
    r"|[a-z0-9.\-]+\.storage\.googleapis\.com)"
    r"[^\s\"'<>]*",
    re.IGNORECASE,
)
# Root-element/response signatures for a genuine object listing -- an
# access-denied/not-found error response uses a different root element
# entirely (S3/GCS XML API: <Error>...<Code>AccessDenied; Azure:
# <Error><Code>ContainerNotFound / PublicAccessNotPermitted), so checking
# for the *listing* signature specifically (never status-code alone)
# can't confuse a locked-down bucket with an open one.
_BUCKET_LISTING_SIGNATURES: tuple[str, ...] = ("<ListBucketResult", "<EnumerationResults")


def _find_cloud_storage_urls(body: str) -> list[str]:
    """Pure helper: dedup, capped candidate cloud-storage URLs referenced
    in a page's HTML/JS body. Ordering preserved, first-seen kept."""
    seen: list[str] = []
    for match in _CLOUD_STORAGE_URL_RE.finditer(body or ""):
        url = match.group(0)
        if url not in seen:
            seen.append(url)
        if len(seen) >= 5:
            break
    return seen


def _is_bucket_listing(body: str) -> bool:
    return any(sig in (body or "") for sig in _BUCKET_LISTING_SIGNATURES)


def _synthetic_endpoint(url: str) -> Endpoint:
    return Endpoint(url=url, method="GET", endpoint_type="api", auth_required=False)


@dataclass
class ConfigurationTestConfig:
    base_url: str = ""
    admin_panel_paths: tuple[str, ...] = field(default_factory=lambda: _ADMIN_PANEL_PATHS)
    listable_dir_paths: tuple[str, ...] = field(default_factory=lambda: _LISTABLE_DIR_PATHS)
    sample_file_paths: tuple[str, ...] = field(default_factory=lambda: _SAMPLE_FILE_PATHS)
    min_content_length: int = 100
    cors_synthetic_origin: str = _SYNTHETIC_CORS_ORIGIN


class ConfigurationTestsModule(VulnModule):
    module_id = "configuration_tests"
    name = "Default Configuration Check Tests"
    phase = 1

    def __init__(self, config: ConfigurationTestConfig | None = None) -> None:
        self.config = config or ConfigurationTestConfig()

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _result(self, technique_id: str, technique: str, status: str, detail: str,
                endpoint=None, finding: Finding | None = None) -> TestCaseResult:
        return self._make_result(
            test_id="TC-017", technique_id=technique_id, technique=technique,
            vuln_type="Default Configuration Check", status=status, detail=detail,
            role="unauthenticated", endpoint=endpoint, finding=finding,
        )

    def _target_url(self, endpoints: list[Endpoint]) -> str:
        return self.config.base_url or (endpoints[0].url if endpoints else "")

    @staticmethod
    def _fingerprint(status: int, body: str) -> tuple[int, str]:
        return status, hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()

    async def _control_fingerprint(self, context, origin: str) -> tuple[int, str] | None:
        """Probe a random, definitely-nonexistent path so real hits can be
        told apart from a client-side-routed SPA's catch-all response.
        A target like an Angular app that serves the same index.html shell
        (HTTP 200, identical bytes) for ANY unmatched path would otherwise
        make every wordlist path in _probe_paths look "found".

        Not routed through `_probe_get`: a transient network error here
        must propagate (not silently return `None`), the same
        transient-error-not-a-false-PASS fix applied to
        `idor_tests.py`'s `_authenticated_context` -- swallowing it would
        let `_probe_paths` below run its whole wordlist sweep against a
        target it can't actually reach and report a clean "nothing
        found" PASS instead of the honest ERROR."""
        url = f"{origin}/stof-control-{secrets.token_hex(8)}"
        try:
            resp = await context.request.get(url, max_redirects=0)
            body = await resp.text()
        except Exception as exc:
            if _is_transient_error(exc):
                raise
            _log.warning(f"control probe failed for {url}: {exc}")
            return None
        return self._fingerprint(resp.status, body)

    async def _probe_paths(self, context, base_url: str, paths: tuple[str, ...]) -> list[tuple[str, int, str]]:
        """Returns [(url, status, body), ...] for every path whose response
        is distinct from the baseline control probe -- base_url + path
        built via simple string join since these are always origin-relative
        probe paths, not endpoint URLs with existing query strings to
        preserve. Same transient-error propagation as `_control_
        fingerprint` above, for the same reason: a network blip mid-sweep
        must not be swallowed into "this path wasn't reachable" and end
        up reported as a clean PASS."""
        origin = base_url.split("/#/")[0].rstrip("/")
        baseline = await self._control_fingerprint(context, origin)
        results = []
        for path in paths:
            url = f"{origin}{path}"
            try:
                resp = await context.request.get(url, max_redirects=0)
                body = await resp.text()
            except Exception as exc:
                if _is_transient_error(exc):
                    raise
                _log.warning(f"configuration probe failed for {url}: {exc}")
                continue
            if baseline is not None and self._fingerprint(resp.status, body) == baseline:
                continue
            results.append((url, resp.status, body))
        return results

    async def _technique_admin_panel(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-017.1", "Default admin panel / management console exposed"
        vuln_type = "Default Configuration -- Admin Panel Exposed"
        context = await session_pool.new_anonymous_context()
        try:
            hits = await self._probe_paths(context, self._target_url(endpoints), self.config.admin_panel_paths)
        finally:
            await context.close()
        for url, status, body in hits:
            if status == 200 and len(body) >= self.config.min_content_length:
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=7.5,
                    endpoint=_synthetic_endpoint(url), user_role="unauthenticated",
                    request_raw=f"GET {url}", response_raw=f"HTTP {status}, {len(body)} bytes",
                    description=f"An admin/management panel at '{url}' is reachable without authentication (HTTP {status}, {len(body)} bytes).",
                    recommendation="Restrict admin/management interfaces to an internal network or VPN, and require authentication before returning any content.",
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"config-admin-{url.rsplit('/', 1)[-1]}") if evidence else []
                return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(url), finding=finding)
        return self._result(tid, technique, PASS, f"none of {len(self.config.admin_panel_paths)} common admin-panel paths were reachable")

    async def _technique_directory_listing(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-017.2", "Directory listing enabled on web root or asset paths"
        vuln_type = "Default Configuration -- Directory Listing Enabled"
        context = await session_pool.new_anonymous_context()
        try:
            hits = await self._probe_paths(context, self._target_url(endpoints), self.config.listable_dir_paths)
        finally:
            await context.close()
        for url, status, body in hits:
            if status == 200 and any(sig in body for sig in _DIRECTORY_LISTING_SIGNATURES):
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=5.3,
                    endpoint=_synthetic_endpoint(url), user_role="unauthenticated",
                    request_raw=f"GET {url}", response_raw=f"HTTP {status}, directory listing markup present",
                    description=f"'{url}' returns an auto-generated directory listing, exposing every file in that directory to any visitor.",
                    recommendation="Disable directory listing (autoindex off / Options -Indexes) on every web-served directory.",
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"config-dirlist-{url.rsplit('/', 1)[-1] or 'root'}") if evidence else []
                return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(url), finding=finding)
        return self._result(tid, technique, PASS, f"none of {len(self.config.listable_dir_paths)} probed directories returned a listing")

    async def _technique_debug_mode(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-017.3", "Debug mode / verbose stack traces on error"
        vuln_type = "Default Configuration -- Debug Mode / Stack Trace Disclosure"
        candidates = [e for e in endpoints if e.method.upper() == "GET"][:10]
        if not candidates:
            return self._result(tid, technique, PASS, "no endpoint discovered to probe for verbose errors")
        context = await session_pool.new_anonymous_context()
        try:
            for endpoint in candidates:
                probe_url = endpoint.url + ("&" if "?" in endpoint.url else "?") + "__stof_probe=%00%27%22<>"
                probe = await self._probe_get(context, probe_url)
                if probe is None:
                    continue
                status, body = probe
                if status >= 500 and any(sig in body for sig in _STACK_TRACE_SIGNATURES):
                    finding = Finding(
                        module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=5.3,
                        endpoint=endpoint, user_role="unauthenticated",
                        request_raw=f"GET {probe_url}", response_raw=f"HTTP {status}, stack-trace signature present",
                        description=f"'{endpoint.url}' returned a raw stack trace (HTTP {status}) when sent a malformed parameter, revealing internal framework/file/path details.",
                        recommendation="Disable debug/development mode in production and return a generic error page for unhandled exceptions.",
                    )
                    finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"config-debug-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
                    return self._result(tid, technique, FAIL, finding.description, endpoint=endpoint, finding=finding)
            return self._result(tid, technique, PASS, f"{len(candidates)} endpoint(s) probed with a malformed parameter; no stack trace observed")
        finally:
            await context.close()

    async def _technique_sample_files(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-017.4", "Default sample, install, or test files present"
        vuln_type = "Default Configuration -- Sample/Install File Exposed"
        context = await session_pool.new_anonymous_context()
        try:
            hits = await self._probe_paths(context, self._target_url(endpoints), self.config.sample_file_paths)
        finally:
            await context.close()
        for url, status, body in hits:
            if status == 200 and len(body) >= 10:
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=6.5,
                    endpoint=_synthetic_endpoint(url), user_role="unauthenticated",
                    request_raw=f"GET {url}", response_raw=f"HTTP {status}, {len(body)} bytes",
                    description=f"A default/sample/install file at '{url}' is publicly reachable (HTTP {status}, {len(body)} bytes).",
                    recommendation="Remove installer, sample, and debug files from the production deployment; block dotfiles (.git, .env) at the web server level.",
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"config-samplefile-{url.rsplit('/', 1)[-1]}") if evidence else []
                return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(url), finding=finding)
        return self._result(tid, technique, PASS, f"none of {len(self.config.sample_file_paths)} common sample/install file paths were reachable")

    async def _technique_version_disclosure(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-017.5", "Default server banner / version disclosure"
        vuln_type = "Default Configuration -- Server Version Disclosure"
        context = await session_pool.new_anonymous_context()
        try:
            try:
                resp = await context.request.get(self._target_url(endpoints), max_redirects=0)
            except Exception as exc:
                return self._result(tid, technique, "ERROR", f"probe failed: {exc}")
            headers = {k.lower(): v for k, v in resp.headers.items()}
        finally:
            await context.close()

        for header_name in _VERSION_DISCLOSURE_HEADERS:
            value = headers.get(header_name)
            if value and _VERSION_NUMBER_RE.search(value):
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=4.3,
                    endpoint=_synthetic_endpoint(self._target_url(endpoints)), user_role="unauthenticated",
                    request_raw=f"GET {self._target_url(endpoints)}", response_raw=f"{header_name}: {value}",
                    description=f"The response includes a versioned '{header_name}' header ('{value}'), disclosing the exact server/framework version to any visitor.",
                    recommendation="Suppress or generalize version-revealing response headers (Server, X-Powered-By, ...) at the web server/framework config level.",
                )
                return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(self._target_url(endpoints)), finding=finding)
        return self._result(tid, technique, PASS, f"no versioned value found across {len(_VERSION_DISCLOSURE_HEADERS)} commonly-checked response headers")

    @staticmethod
    def _is_cors_misconfigured(sent_origin: str, acao: str | None, acac: str | None) -> bool:
        """Pure evidence check, unit-testable without an HTTP mock.

        FAIL only when BOTH hold: `Access-Control-Allow-Origin` exactly
        echoes the attacker-supplied Origin we sent (proving dynamic
        reflection, not a static allowlist entry or wildcard) AND
        `Access-Control-Allow-Credentials` is present and literally
        "true" (case-insensitive). A static `*` -- with or without
        credentials -- and reflection without credentials=true are both
        explicitly NOT hits; this is the documented false-positive trap
        for this technique."""
        if acao != sent_origin:
            return False
        return bool(acac) and acac.strip().lower() == "true"

    def _cors_candidate_url(self, endpoints: list["Endpoint"]) -> str:
        for endpoint in endpoints:
            if endpoint.endpoint_type == "api":
                return endpoint.url
        return self._target_url(endpoints)

    async def _technique_cors_misconfiguration(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-017.6", "CORS misconfiguration -- reflected Origin with credentials allowed"
        vuln_type = "Default Configuration -- CORS Reflected Origin with Credentials"
        url = self._cors_candidate_url(endpoints)
        sent_origin = self.config.cors_synthetic_origin
        context = await session_pool.new_anonymous_context()
        try:
            try:
                resp = await context.request.get(url, max_redirects=0, headers={"Origin": sent_origin})
            except Exception as exc:
                return self._result(tid, technique, "ERROR", f"probe failed: {exc}")
            headers = {k.lower(): v for k, v in resp.headers.items()}
        finally:
            await context.close()

        acao = headers.get("access-control-allow-origin")
        acac = headers.get("access-control-allow-credentials")
        if self._is_cors_misconfigured(sent_origin, acao, acac):
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=8.1,
                endpoint=_synthetic_endpoint(url), user_role="unauthenticated",
                request_raw=f"GET {url}\nOrigin: {sent_origin}",
                response_raw=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                description=(
                    f"'{url}' dynamically reflects an attacker-supplied Origin ('{sent_origin}') back in "
                    f"Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: {acac}, "
                    "letting any attacker-controlled site read authenticated cross-origin responses from a victim's browser."
                ),
                recommendation="Validate Origin against a strict server-side allowlist before echoing it into Access-Control-Allow-Origin, and never combine a reflected/wildcard origin with Access-Control-Allow-Credentials: true.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="config-cors-reflected-origin") if evidence else []
            return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(url), finding=finding)
        return self._result(tid, technique, PASS, f"'{url}' did not reflect the synthetic Origin with Access-Control-Allow-Credentials: true (ACAO={acao!r}, ACAC={acac!r})")

    async def _technique_csp_weakness(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-017.7", "Content-Security-Policy missing or weak on HTML responses"
        vuln_type = "Default Configuration -- Missing or Weak Content-Security-Policy"
        url = self._target_url(endpoints)
        context = await session_pool.new_anonymous_context()
        try:
            try:
                resp = await context.request.get(url, max_redirects=0)
            except Exception as exc:
                return self._result(tid, technique, "ERROR", f"probe failed: {exc}")
            headers = {k.lower(): v for k, v in resp.headers.items()}
        finally:
            await context.close()

        content_type = headers.get("content-type", "")
        csp_header = headers.get("content-security-policy")
        issue = _csp_missing_or_weak(content_type, csp_header)
        if issue is not None:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.4,
                endpoint=_synthetic_endpoint(url), user_role="unauthenticated",
                request_raw=f"GET {url}",
                response_raw=f"Content-Type: {content_type}\nContent-Security-Policy: {csp_header}",
                description=(
                    f"'{url}' {issue} (Content-Type: {content_type or 'unknown'}). This is a defense-in-depth "
                    "gap, not a confirmed exploit path on its own -- it only matters if the application also has "
                    "an injection point (e.g. reflected/DOM XSS) for a CSP to have blocked, consistent with real "
                    "disclosed reports of this class (HackerOne #225833) being low-severity precisely because "
                    "they lacked an actual XSS to chain with."
                ),
                recommendation="Deploy a strict Content-Security-Policy on every HTML response (e.g. script-src 'self' plus nonces/hashes for any required inline scripts) with no unsafe-inline/unsafe-eval/wildcard sources.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="config-csp-weakness") if evidence else []
            return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(url), finding=finding)
        return self._result(tid, technique, PASS, f"'{url}' (Content-Type: {content_type or 'unknown'}) has no CSP weakness this technique checks for")

    async def _technique_missing_security_headers(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-017.8", "Missing clickjacking / MIME-sniffing security headers"
        vuln_type = "Default Configuration -- Missing Security Headers"
        url = self._target_url(endpoints)
        context = await session_pool.new_anonymous_context()
        try:
            try:
                resp = await context.request.get(url, max_redirects=0)
            except Exception as exc:
                return self._result(tid, technique, "ERROR", f"probe failed: {exc}")
            headers = {k.lower(): v for k, v in resp.headers.items()}
        finally:
            await context.close()

        content_type = headers.get("content-type", "")
        missing = _missing_security_headers(content_type, headers)
        if missing:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=4.3,
                endpoint=_synthetic_endpoint(url), user_role="unauthenticated",
                request_raw=f"GET {url}",
                response_raw=f"Content-Type: {content_type}\n" + "\n".join(f"{h}: <absent>" for h in missing),
                description=(
                    f"'{url}' is missing the following security header(s): {', '.join(missing)} "
                    f"(Content-Type: {content_type or 'unknown'}). This weakens the browser's built-in "
                    "defenses against clickjacking and MIME-type confusion attacks."
                ),
                recommendation="Set X-Content-Type-Options: nosniff and either X-Frame-Options (DENY/SAMEORIGIN) or a CSP frame-ancestors directive on every HTML response.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="config-missing-headers") if evidence else []
            return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(url), finding=finding)
        return self._result(tid, technique, PASS, f"'{url}' (Content-Type: {content_type or 'unknown'}) carries X-Content-Type-Options and an X-Frame-Options/frame-ancestors clickjacking control")

    def _sensitive_http_endpoints(self, endpoints: list["Endpoint"]) -> list[str]:
        return [e.url for e in endpoints if e.url.lower().startswith("http://") and _is_sensitive_path(e.url)]

    async def _technique_tls_configuration(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-017.9", "TLS/transport -- sensitive endpoint over plaintext HTTP or HTTPS without HSTS"
        vuln_type = "Default Configuration -- Weak TLS/Transport Configuration"
        target = self._target_url(endpoints)
        context = await session_pool.new_anonymous_context()
        try:
            for plaintext_url in self._sensitive_http_endpoints(endpoints):
                probe = await self._probe_get(context, plaintext_url)
                if probe is None:
                    continue
                status, _body = probe
                if status < 400:
                    finding = Finding(
                        module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=7.4,
                        endpoint=_synthetic_endpoint(plaintext_url), user_role="unauthenticated",
                        request_raw=f"GET {plaintext_url}", response_raw=f"HTTP {status} over plaintext http://",
                        description=f"A sensitive endpoint ('{plaintext_url}') is reachable over plaintext HTTP (HTTP {status}), letting credentials/session tokens be intercepted by any network-position attacker.",
                        recommendation="Serve every authentication/session/payment endpoint exclusively over HTTPS and redirect http:// requests to https://.",
                    )
                    finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="config-tls-plaintext-sensitive") if evidence else []
                    return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(plaintext_url), finding=finding)

            if not target.lower().startswith("https://"):
                return self._result(tid, technique, PASS, f"'{target}' is not HTTPS and no discovered sensitive endpoint was reachable over plaintext HTTP either")

            try:
                resp = await context.request.get(target, max_redirects=0)
            except Exception as exc:
                return self._result(tid, technique, "ERROR", f"probe failed: {exc}")
            headers = {k.lower(): v for k, v in resp.headers.items()}
        finally:
            await context.close()

        hsts = headers.get("strict-transport-security")
        if not hsts or not hsts.strip():
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Low", cvss_score=3.1,
                endpoint=_synthetic_endpoint(target), user_role="unauthenticated",
                request_raw=f"GET {target}", response_raw="Strict-Transport-Security: <absent>",
                description=f"'{target}' is served over HTTPS but does not send Strict-Transport-Security, leaving users vulnerable to SSL-stripping downgrade on a subsequent plaintext visit (e.g. a bookmarked http:// link or typed-URL navigation).",
                recommendation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains to every HTTPS response, and consider HSTS preload list submission.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="config-tls-no-hsts") if evidence else []
            return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(target), finding=finding)
        return self._result(tid, technique, PASS, f"'{target}' is HTTPS with Strict-Transport-Security present, and no discovered sensitive endpoint was reachable over plaintext HTTP")

    async def _technique_cloud_storage_exposure(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-017.10", "Publicly-listable cloud storage bucket/container referenced by the target"
        vuln_type = "Default Configuration -- Public Cloud Storage Exposure"
        url = self._target_url(endpoints)
        context = await session_pool.new_anonymous_context()
        try:
            try:
                resp = await context.request.get(url, max_redirects=0)
                body = await resp.text()
            except Exception as exc:
                return self._result(tid, technique, "ERROR", f"probe failed: {exc}")

            candidates = _find_cloud_storage_urls(body)
            if not candidates:
                return self._result(tid, technique, PASS, f"'{url}' referenced no S3/Azure Blob/GCS-shaped URLs to check")

            for storage_url in candidates:
                probe = await self._probe_get(context, storage_url)
                if probe is None:
                    continue
                status, storage_body = probe
                if status == 200 and _is_bucket_listing(storage_body):
                    finding = Finding(
                        module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
                        endpoint=_synthetic_endpoint(storage_url), user_role="unauthenticated",
                        request_raw=f"GET {storage_url}", response_raw=f"HTTP {status}, object-listing XML present",
                        description=f"The cloud storage location '{storage_url}', referenced by '{url}', returns a public directory/object listing, exposing every object it contains to any visitor.",
                        recommendation="Disable public listing on the bucket/container (block public ACLs, apply a private bucket policy) and audit its contents for sensitive data.",
                    )
                    finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="config-cloud-storage-listing") if evidence else []
                    return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(storage_url), finding=finding)
            return self._result(tid, technique, PASS, f"{len(candidates)} referenced cloud-storage URL(s) checked; none returned a public object listing")
        finally:
            await context.close()

    async def run_techniques(
        self,
        endpoints: list["Endpoint"],
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[TestCaseResult]:
        results: list[TestCaseResult] = []
        for tid, technique, coro in (
            ("TC-017.1", "Default admin panel / management console exposed", self._technique_admin_panel(endpoints, session_pool, evidence)),
            ("TC-017.2", "Directory listing enabled on web root or asset paths", self._technique_directory_listing(endpoints, session_pool, evidence)),
            ("TC-017.3", "Debug mode / verbose stack traces on error", self._technique_debug_mode(endpoints, session_pool, evidence)),
            ("TC-017.4", "Default sample, install, or test files present", self._technique_sample_files(endpoints, session_pool, evidence)),
            ("TC-017.5", "Default server banner / version disclosure", self._technique_version_disclosure(endpoints, session_pool, evidence)),
            ("TC-017.6", "CORS misconfiguration -- reflected Origin with credentials allowed", self._technique_cors_misconfiguration(endpoints, session_pool, evidence)),
            ("TC-017.7", "Content-Security-Policy missing or weak on HTML responses", self._technique_csp_weakness(endpoints, session_pool, evidence)),
            ("TC-017.8", "Missing clickjacking / MIME-sniffing security headers", self._technique_missing_security_headers(endpoints, session_pool, evidence)),
            ("TC-017.9", "TLS/transport -- sensitive endpoint over plaintext HTTP or HTTPS without HSTS", self._technique_tls_configuration(endpoints, session_pool, evidence)),
            ("TC-017.10", "Publicly-listable cloud storage bucket/container referenced by the target", self._technique_cloud_storage_exposure(endpoints, session_pool, evidence)),
        ):
            # `_safe_result` (not a bare try/except that only logs) so a
            # technique that couldn't complete -- e.g. `_probe_paths`
            # propagating a transient network error -- still produces an
            # ERROR `TestCaseResult` instead of silently vanishing from
            # `results` entirely, which is what a bare log-and-drop would do.
            results.append(await self._safe_result(coro, "TC-017", tid, technique, "Default Configuration Check", role="unauthenticated"))
        return results
