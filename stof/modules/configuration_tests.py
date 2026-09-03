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

import asyncio
import hashlib
import re
import secrets
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from stof.core.logger import get_logger
from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding

from .base import VulnModule, _is_transient_error
from .results import FAIL, PASS, SKIPPED, TestCaseResult, extract_findings

if TYPE_CHECKING:
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.recon.target_profile import TargetProfile
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.configuration_tests")

_ADMIN_PANEL_PATHS: tuple[str, ...] = (
    "/admin", "/administrator", "/admin/login", "/manage", "/management",
    "/console", "/manager/html", "/wp-admin", "/phpmyadmin", "/adminer.php",
)
# Context-aware narrowing (Phase 1): which stack family each path is
# ONLY relevant to, per stof.recon.target_profile.TargetProfile.
# stack_family -- None means "generic, relevant regardless of stack"
# and is never narrowed away. Framework-specific paths (Tomcat's own
# /manager/html, WordPress's /wp-admin, PHP's own admin tools) are
# guaranteed-dead requests against a target confirmed to run a
# different stack -- verified live: demo.testfire.net fingerprints as
# Apache-Coyote/1.1 (Java/Tomcat) via stof/recon/target_profile.py,
# so /wp-admin, /phpmyadmin, /adminer.php are wasted probes there
# every single scan today.
_ADMIN_PANEL_PATH_STACK: dict[str, str | None] = {
    "/admin": None, "/administrator": None, "/admin/login": None,
    "/manage": None, "/management": None, "/console": None,
    "/manager/html": "java",
    "/wp-admin": "php", "/phpmyadmin": "php", "/adminer.php": "php",
}

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
# Same context-aware narrowing convention as _ADMIN_PANEL_PATH_STACK.
_SAMPLE_FILE_PATH_STACK: dict[str, str | None] = {
    "/install.php": "php", "/test.php": "php", "/phpinfo.php": "php", "/info.php": "php",
    "/.git/config": None, "/.env": None,
    "/web.config": "dotnet",
    "/server-status": None, "/.DS_Store": None, "/backup.sql": None, "/dump.sql": None,
}


def _narrow_paths_for_stack(paths: tuple[str, ...], path_stack: dict[str, "str | None"], stack_family: str) -> list[str]:
    """Pure, directly-unit-testable narrowing helper. `stack_family ==
    'unknown'` (recon skipped, or the evidence was genuinely ambiguous
    -- see target_profile.py's own tie-breaking docstring) returns
    every path unchanged: narrowing on absent/ambiguous evidence would
    silently drop real coverage, which this project's own precedent
    (`main.py`'s `_apply_application_profile`) explicitly treats as a
    worse failure than a few wasted probes. A path with no stack entry
    at all (shouldn't happen, but paths always win, never dropped) is
    also kept, same fail-open bias."""
    if stack_family == "unknown":
        return list(paths)
    return [p for p in paths if path_stack.get(p) in (None, stack_family)]

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


# Gap closed after cross-referencing a real Burp Suite Active Scan run
# against this target: Burp flagged "Cross-domain Referer leakage",
# "Mixed content", and "Password field with autocomplete enabled" --
# none of which had a STOF equivalent. Same "text/html only, narrow
# false-positive guard" discipline as every other passive header check
# in this file.

# Only flag the ONE Referrer-Policy value that unconditionally leaks the
# full URL (including query string) to every cross-origin destination a
# link/resource on the page points to. Every other value -- including no
# header at all, which falls back to the browser's own default of
# `strict-origin-when-cross-origin` in every current browser -- already
# behaves reasonably, so flagging "missing" outright would just be noise
# on the overwhelming majority of sites that rely on that safe default.
def _referrer_policy_gap(content_type: str, headers: dict[str, str]) -> str | None:
    if "text/html" not in (content_type or "").lower():
        return None
    value = headers.get("referrer-policy", "").strip().lower()
    if value == "unsafe-url":
        return "Referrer-Policy is explicitly set to 'unsafe-url', which leaks the full URL (including any query string) to every cross-origin link and sub-resource this page loads"
    return None


_HTTP_RESOURCE_RE = re.compile(
    r'<(?:script|img|link|iframe)\b[^>]*\b(?:src|href)\s*=\s*["\']http://([^"\'/]+)[^"\']*["\']', re.IGNORECASE,
)


def _mixed_content_hosts(page_url: str, content_type: str, body: str) -> list[str]:
    """Only meaningful when the page itself is HTTPS -- an HTTP page
    referencing HTTP sub-resources isn't mixed content, it's just... a
    plain HTTP page (already covered by TC-017.9). Matches `src=`/`href=`
    on script/img/link/iframe tags specifically, not any bare "http://"
    text on the page (a visible link's label, a code sample, a citation)
    -- the same "only what a browser would actually treat as a resource
    load" narrowing Burp's own check makes."""
    if not page_url.lower().startswith("https://") or "text/html" not in (content_type or "").lower():
        return []
    hosts = {m.group(1) for m in _HTTP_RESOURCE_RE.finditer(body or "")}
    return sorted(hosts)


_PASSWORD_INPUT_RE = re.compile(r'<input\b[^>]*\btype\s*=\s*["\']password["\'][^>]*>', re.IGNORECASE)
_AUTOCOMPLETE_OFF_RE = re.compile(r'\bautocomplete\s*=\s*["\'](?:off|new-password)["\']', re.IGNORECASE)


def _password_autocomplete_gap(content_type: str, body: str) -> int:
    """Returns the count of <input type="password"> fields that don't
    disable autofill (no autocomplete="off"/"new-password"). Informational
    by design (matches Burp's own severity for this exact check) -- a
    password manager filling a login field is normal, wanted behavior for
    most sites; this is a compliance/defense-in-depth note for contexts
    (shared/kiosk machines) where that's a real concern, never framed as
    a confirmed vulnerability on its own."""
    if "text/html" not in (content_type or "").lower():
        return 0
    fields = _PASSWORD_INPUT_RE.findall(body or "")
    return sum(1 for field in fields if not _AUTOCOMPLETE_OFF_RE.search(field))


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


# Path-Relative StyleSheet Import (PRSSI): a <link rel="stylesheet">
# whose href is relative to the CURRENT page's path (not the site root)
# lets an attacker who can make the browser render this page at an
# unexpected/crafted path (e.g. an app that reflects part of the path
# into a 404 page, or a path-based router) redirect that stylesheet
# request somewhere they control -- attacker CSS injected into a
# trusted origin can exfiltrate page content via CSS selectors/
# attribute readers. Matches Burp's own check: only a *relative* href
# is interesting (no leading "/", scheme, "//", or "data:") -- an
# absolute or root-relative stylesheet path can't be redirected this
# way regardless of what path the page itself is served at.
_STYLESHEET_LINK_RE = re.compile(
    r'<link\b[^>]*\brel\s*=\s*["\']stylesheet["\'][^>]*\bhref\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE,
)


def _path_relative_stylesheet_hrefs(content_type: str, body: str) -> list[str]:
    if "text/html" not in (content_type or "").lower():
        return []
    hrefs = []
    for href in _STYLESHEET_LINK_RE.findall(body or ""):
        if href.startswith(("/", "http://", "https://", "//", "data:")):
            continue
        hrefs.append(href)
    return hrefs


# Days-until-expiry threshold for flagging a certificate as "expiring
# soon" rather than only catching one that's already dead -- 14 days
# gives an operator real lead time to renew, without flagging every
# perfectly healthy 90-day Let's Encrypt cert on day 1.
_CERT_EXPIRY_WARNING_DAYS = 14


def _fetch_tls_certificate(hostname: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Blocking (real TLS handshake via `ssl`/`socket`, no Playwright
    equivalent exists for reading certificate metadata) -- callers run
    this via `run_in_executor`, same pattern `stof/ui/server.py`'s Burp
    connection check already uses for its own blocking I/O. Uses a
    real, verifying `ssl.create_default_context()` (not
    `CERT_NONE`) specifically so a chain/hostname validation failure
    surfaces as the exception this function raises, not silently
    ignored -- that failure IS the finding for TC-017.14."""
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock, ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
        cert = tls_sock.getpeercert()
    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days_remaining = (not_after - datetime.now(timezone.utc)).days
    return {"not_after": not_after, "days_remaining": days_remaining}


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
    # Phase 1 of context-aware testing (see stof/recon/target_profile.py):
    # set by main.py from the same scan's own recon phase. None (the
    # default) behaves exactly like before this existed -- every path
    # probed, nothing narrowed. Only TC-017.1/.4's candidate path lists
    # currently consume this; every other technique in this module is
    # unconditional response/header inspection with nothing stack-
    # specific to narrow.
    target_profile: "TargetProfile | None" = None


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
        stack_family = self.config.target_profile.stack_family if self.config.target_profile else "unknown"
        candidate_paths = _narrow_paths_for_stack(self.config.admin_panel_paths, _ADMIN_PANEL_PATH_STACK, stack_family)
        context = await session_pool.new_anonymous_context()
        try:
            hits = await self._probe_paths(context, self._target_url(endpoints), tuple(candidate_paths))
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
        narrowed_note = (
            f" (narrowed from {len(self.config.admin_panel_paths)} for detected stack '{stack_family}')"
            if len(candidate_paths) < len(self.config.admin_panel_paths) else ""
        )
        return self._result(tid, technique, PASS, f"none of {len(candidate_paths)} common admin-panel paths were reachable{narrowed_note}")

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
        stack_family = self.config.target_profile.stack_family if self.config.target_profile else "unknown"
        candidate_paths = _narrow_paths_for_stack(self.config.sample_file_paths, _SAMPLE_FILE_PATH_STACK, stack_family)
        context = await session_pool.new_anonymous_context()
        try:
            hits = await self._probe_paths(context, self._target_url(endpoints), tuple(candidate_paths))
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
        narrowed_note = (
            f" (narrowed from {len(self.config.sample_file_paths)} for detected stack '{stack_family}')"
            if len(candidate_paths) < len(self.config.sample_file_paths) else ""
        )
        return self._result(tid, technique, PASS, f"none of {len(candidate_paths)} common sample/install file paths were reachable{narrowed_note}")

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

    async def _technique_referrer_policy(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-017.11", "Referrer-Policy leaks full URL to cross-origin destinations"
        vuln_type = "Default Configuration -- Cross-Domain Referer Leakage"
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
        gap = _referrer_policy_gap(content_type, headers)
        if gap:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Low", cvss_score=3.1,
                endpoint=_synthetic_endpoint(url), user_role="unauthenticated",
                request_raw=f"GET {url}", response_raw=f"Referrer-Policy: {headers.get('referrer-policy', '')}",
                description=f"'{url}': {gap}. Any link a user follows off this page, or any cross-origin resource it loads, receives the referring URL verbatim.",
                recommendation="Set Referrer-Policy to 'strict-origin-when-cross-origin' (or stricter) so cross-origin destinations only ever see the origin, not the full URL/query string.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="config-referrer-policy") if evidence else []
            return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(url), finding=finding)
        return self._result(tid, technique, PASS, f"'{url}' does not set Referrer-Policy to 'unsafe-url'")

    async def _technique_mixed_content(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-017.12", "HTTPS page loads sub-resources over plaintext HTTP (mixed content)"
        vuln_type = "Default Configuration -- Mixed Content"
        url = self._target_url(endpoints)
        context = await session_pool.new_anonymous_context()
        try:
            try:
                resp = await context.request.get(url, max_redirects=0)
                body = await resp.text()
            except Exception as exc:
                return self._result(tid, technique, "ERROR", f"probe failed: {exc}")
            headers = {k.lower(): v for k, v in resp.headers.items()}
        finally:
            await context.close()

        content_type = headers.get("content-type", "")
        hosts = _mixed_content_hosts(url, content_type, body)
        if hosts:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=4.8,
                endpoint=_synthetic_endpoint(url), user_role="unauthenticated",
                request_raw=f"GET {url}", response_raw=f"http:// sub-resource host(s) referenced: {', '.join(hosts)}",
                description=(
                    f"'{url}' is served over HTTPS but loads script/img/link/iframe sub-resource(s) over plaintext "
                    f"HTTP from: {', '.join(hosts)}. A network attacker can tamper with those plaintext requests "
                    "even though the page itself is on HTTPS."
                ),
                recommendation="Serve every sub-resource over HTTPS (or a protocol-relative/relative URL); browsers already block or warn on active mixed content by default.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="config-mixed-content") if evidence else []
            return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(url), finding=finding)
        return self._result(tid, technique, PASS, f"'{url}' loads no script/img/link/iframe sub-resource over plaintext HTTP")

    async def _technique_password_autocomplete(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-017.13", "Password field does not disable browser autocomplete"
        vuln_type = "Default Configuration -- Password Autocomplete Enabled"
        # This module's own config only carries base_url (see
        # ConfigurationTestConfig) -- same target every other technique
        # in this file probes. A password field specifically on the
        # login page would be a stronger check, but that URL isn't
        # available here without adding a new config field this file
        # doesn't otherwise need; base_url is what's honestly available.
        login_url = self._target_url(endpoints)
        context = await session_pool.new_anonymous_context()
        try:
            try:
                resp = await context.request.get(login_url, max_redirects=0)
                body = await resp.text()
            except Exception as exc:
                return self._result(tid, technique, "ERROR", f"probe failed: {exc}")
            headers = {k.lower(): v for k, v in resp.headers.items()}
        finally:
            await context.close()

        content_type = headers.get("content-type", "")
        count = _password_autocomplete_gap(content_type, body)
        if count:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Info", cvss_score=1.0,
                endpoint=_synthetic_endpoint(login_url), user_role="unauthenticated",
                request_raw=f"GET {login_url}", response_raw=f"{count} <input type=password> field(s) without autocomplete=off/new-password",
                description=(
                    f"'{login_url}' has {count} password field(s) that don't disable browser/password-manager "
                    "autofill. This is informational, not a confirmed vulnerability: autofill is normal, wanted "
                    "behavior on most sites -- relevant mainly on shared/kiosk machines where a filled-in "
                    "password could be read by the next user of that browser profile."
                ),
                recommendation="Consider autocomplete=\"new-password\" only if this target is used on shared/kiosk machines; otherwise this is a defense-in-depth note, not an action item.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="config-password-autocomplete") if evidence else []
            return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(login_url), finding=finding)
        return self._result(tid, technique, PASS, f"'{login_url}' has no password field with autocomplete enabled" if _PASSWORD_INPUT_RE.search(body or "") else f"'{login_url}' has no password field to check")

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

    async def _technique_path_relative_stylesheet(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-017.14", "Path-Relative StyleSheet Import (PRSSI)"
        vuln_type = "Default Configuration -- Path-Relative StyleSheet Import"
        url = self._target_url(endpoints)
        context = await session_pool.new_anonymous_context()
        try:
            try:
                resp = await context.request.get(url, max_redirects=0)
                body = await resp.text()
            except Exception as exc:
                return self._result(tid, technique, "ERROR", f"probe failed: {exc}")
            headers = {k.lower(): v for k, v in resp.headers.items()}
        finally:
            await context.close()

        content_type = headers.get("content-type", "")
        hrefs = _path_relative_stylesheet_hrefs(content_type, body)
        if hrefs:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Low", cvss_score=3.7,
                endpoint=_synthetic_endpoint(url), user_role="unauthenticated",
                request_raw=f"GET {url}", response_raw=f"<link rel=stylesheet> with path-relative href(s): {', '.join(hrefs)}",
                description=(
                    f"'{url}' imports {len(hrefs)} stylesheet(s) using an href relative to the current page's own "
                    f"path rather than the site root: {', '.join(hrefs)}. If this page can ever be rendered at an "
                    "unexpected/attacker-influenced path (a path-based router, a reflected-path error page), the "
                    "browser resolves that relative href against the wrong base and can be made to load an "
                    "attacker-controlled stylesheet from a trusted origin -- a known technique for exfiltrating "
                    "page content via CSS selectors/attribute readers."
                ),
                recommendation="Reference stylesheets with a root-relative ('/css/app.css') or absolute (https://...) href, never one relative to the current page's own path.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="config-prssi") if evidence else []
            return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(url), finding=finding)
        return self._result(tid, technique, PASS, f"'{url}' has no path-relative <link rel=stylesheet> href")

    async def _technique_tls_certificate(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-017.15", "TLS certificate is expired, expiring soon, or fails chain/hostname validation"
        vuln_type = "Default Configuration -- Weak TLS Certificate"
        url = self._target_url(endpoints)
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            return self._result(tid, technique, SKIPPED, f"'{url}' is not HTTPS -- nothing to check a certificate for")

        loop = asyncio.get_event_loop()
        try:
            cert = await loop.run_in_executor(None, _fetch_tls_certificate, parts.hostname, parts.port or 443)
        except Exception as exc:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=6.5,
                endpoint=_synthetic_endpoint(url), user_role="unauthenticated",
                request_raw=f"TLS handshake to {parts.hostname}:{parts.port or 443}", response_raw=f"handshake/validation failed: {exc}",
                description=f"A TLS handshake to '{parts.hostname}:{parts.port or 443}' failed chain or hostname validation: {exc}. Visitors' browsers will show a certificate warning, training users to click through security errors.",
                recommendation="Ensure the certificate is issued by a trusted CA, covers this exact hostname (including any 'www.' variant actually used), and the full chain (including intermediates) is served.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="config-tls-cert-invalid") if evidence else []
            return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(url), finding=finding)

        days = cert["days_remaining"]
        if days < 0:
            severity, cvss, state = "Critical", 7.4, f"expired {-days} day(s) ago"
        elif days <= _CERT_EXPIRY_WARNING_DAYS:
            severity, cvss, state = "Medium", 5.3, f"expires in {days} day(s)"
        else:
            return self._result(tid, technique, PASS, f"'{parts.hostname}' certificate is valid and expires in {days} day(s)")

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity=severity, cvss_score=cvss,
            endpoint=_synthetic_endpoint(url), user_role="unauthenticated",
            request_raw=f"TLS handshake to {parts.hostname}:{parts.port or 443}", response_raw=f"certificate notAfter: {cert['not_after'].isoformat()}",
            description=f"The TLS certificate for '{parts.hostname}' {state} (notAfter: {cert['not_after'].isoformat()}).",
            recommendation="Renew the certificate before expiry, and set up automated renewal (e.g. certbot/ACME) so this can't recur.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="config-tls-cert-expiry") if evidence else []
        return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(url), finding=finding)

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
            ("TC-017.11", "Referrer-Policy leaks full URL to cross-origin destinations", self._technique_referrer_policy(endpoints, session_pool, evidence)),
            ("TC-017.12", "HTTPS page loads sub-resources over plaintext HTTP (mixed content)", self._technique_mixed_content(endpoints, session_pool, evidence)),
            ("TC-017.13", "Password field does not disable browser autocomplete", self._technique_password_autocomplete(endpoints, session_pool, evidence)),
            ("TC-017.14", "Path-Relative StyleSheet Import (PRSSI)", self._technique_path_relative_stylesheet(endpoints, session_pool, evidence)),
            ("TC-017.15", "TLS certificate is expired, expiring soon, or fails chain/hostname validation", self._technique_tls_certificate(endpoints, session_pool, evidence)),
        ):
            # `_safe_result` (not a bare try/except that only logs) so a
            # technique that couldn't complete -- e.g. `_probe_paths`
            # propagating a transient network error -- still produces an
            # ERROR `TestCaseResult` instead of silently vanishing from
            # `results` entirely, which is what a bare log-and-drop would do.
            results.append(await self._safe_result(coro, "TC-017", tid, technique, "Default Configuration Check", role="unauthenticated"))
        return results
