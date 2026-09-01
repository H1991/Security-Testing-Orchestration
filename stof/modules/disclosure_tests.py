"""Layer 9 — `stof/modules/disclosure_tests.py`: PII Exposure via API
(TC-105).

Two of the four `EXPLOIT_COVERAGE.md` techniques for TC-105 are
genuinely read-only and target-agnostic (scan an already-authenticated
API response, and scan discovered URLs' query strings) and are built
here. The other two are explicitly deferred rather than faked:
TC-105.2 (PII in error messages) needs `recon`'s `error_disclosures`
report threaded through, which no `VulnModule.run()` call site
currently passes; TC-105.3 (PII via IDOR chaining) is the same
underlying mechanism `idor_tests.py` already tests, cross-referenced
rather than re-implemented (same precedent as TC-052.2 in
`idor_tests.py`, which cross-references `jwt_tests.py`'s TC-057
instead of duplicating JWT logic).

TC-105.5 (source map / VCS / backup file exposure) and TC-105.6 (PII
or secrets hidden in HTML comments / inline `<script>` blocks) were
added later, from `stof/payloads/disclosure_knowledge_base.json`'s
research into a structurally different class of gap: files and markup
that were never meant to be served at all, rather than PII surfacing
through the app's own normal data flow. Both are pure GET-and-inspect,
same as TC-105.1/.2/.4, and need no `allow_state_changing_probes` gate.

TC-105.7 (PII/secrets left in `localStorage`/`sessionStorage` after
authentication) is structurally different again: `localStorage` and
`sessionStorage` are client-side JS state, never present in any raw
HTTP response body, so `context.request.*`/`page.content()` cannot see
them at all -- this technique navigates a real `Page` and calls
`page.evaluate()` to read them directly out of the browser, the same
"needs a real Page, not just `context.request`" precedent
`xss_tests.py`'s `_technique_dom_xss` (TC-128.5) established for
`location.hash`. Still read-only inspection of state the app itself
already wrote during a normal authenticated navigation -- no
`allow_state_changing_probes` gate needed.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit

from stof.core.logger import get_logger
from stof.findings.models import Finding

from .base import VulnModule
from .results import FAIL, PASS, SKIPPED, TestCaseResult, extract_findings

if TYPE_CHECKING:
    from stof.crawler.endpoint_store import Endpoint
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.disclosure_tests")

# (label, regex) -- high-signal patterns only, same "small and
# high-signal rather than exhaustive" philosophy as recon's
# secrets_scanner.py. Deliberately doesn't match on bare digit runs
# alone for phone/SSN-shaped patterns, to keep false positives low
# against arbitrary JSON (order ids, prices, timestamps, ...).
# "Credit Card Number" is checked separately below with both a Luhn
# digit AND a known issuer prefix -- Luhn alone isn't enough (~10% of
# *any* random same-length digit run happens to be Luhn-valid; live-
# verified against this project's own demo target, where a JS
# millisecond timestamp embedded in an image filename -- "magn(et)
# ificent!-1571814229653.jpg" -- was Luhn-valid and would otherwise
# have been misreported as a credit card number).
_PII_PATTERNS: tuple[tuple[str, str], ...] = (
    ("US Social Security Number", r"\b\d{3}-\d{2}-\d{4}\b"),
    ("US Phone Number", r"\b\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b"),
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Generic mailbox names that name a role/function, not a specific
# person -- an app's own contact address (e.g. "donotreply@example.com"
# in its /rest/admin/application-configuration response) isn't PII the
# way a real user's personal email in an API response would be.
_GENERIC_EMAIL_LOCAL_PARTS = (
    "noreply", "no-reply", "donotreply", "do-not-reply", "support", "admin",
    "info", "contact", "webmaster", "privacy", "security", "abuse", "postmaster", "hello",
)

_CREDIT_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")
# Visa (4...), Mastercard (51-55... or 2221-2720...), Amex (34/37...,
# 15 digits), Discover (6011.../65...) -- real issuer prefixes, not an
# arbitrary length check, so a same-length non-card number (a
# timestamp, a large sequential id) can't match just by chance.
_CARD_PREFIX_RE = re.compile(r"^(4\d{12}(\d{3})?$|5[1-5]\d{14}$|3[47]\d{13}$|6(?:011|5\d{2})\d{12}$)")
_FIELD_NAME_HINTS = ("email", "ssn", "phone", "dob", "birthdate", "address", "creditcard", "card_number", "cardnumber")


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass
class PiiMatch:
    label: str
    preview: str  # truncated -- never logs the full PII value verbatim


def find_pii(text: str) -> list[PiiMatch]:
    """Pure regex scan (mirrors `recon.secrets_scanner.find_secrets()`'s
    shape) -- directly unit-testable without any Playwright dependency."""
    matches: list[PiiMatch] = []
    for label, pattern in _PII_PATTERNS:
        for m in re.finditer(pattern, text):
            value = m.group(0)
            preview = value[:3] + "…" + value[-2:] if len(value) > 6 else "…"
            matches.append(PiiMatch(label=label, preview=preview))

    for m in _EMAIL_RE.finditer(text):
        local_part = m.group(0).split("@", 1)[0].lower()
        if local_part in _GENERIC_EMAIL_LOCAL_PARTS:
            continue
        value = m.group(0)
        matches.append(PiiMatch(label="Email address", preview=value[:3] + "…" + value[-2:] if len(value) > 6 else "…"))

    for m in _CREDIT_CARD_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if _CARD_PREFIX_RE.match(digits) and _luhn_valid(digits):
            matches.append(PiiMatch(label="Credit Card Number", preview=digits[:3] + "…" + digits[-2:]))

    return matches


# -- TC-105.5: source map / VCS / backup exposure -----------------------
#
# Fixed candidate paths checked directly at the site origin root,
# regardless of whether the crawler's discovered endpoint list links
# to them at all -- a `.git` folder or `.env` file left on the
# webserver is never linked from the app itself (see
# `disclosure_knowledge_base.json`'s `source_map_vcs_backup_exposure`
# real_example citations).
_BACKUP_CANDIDATE_PATHS: tuple[str, ...] = (
    "/.git/config", "/.git/HEAD", "/.env", "/.env.bak", "/config.php.bak",
)
_ENV_KEY_RE = re.compile(r"(?im)^[A-Za-z0-9_]*(?:_KEY|_SECRET|_PASSWORD|_TOKEN|DATABASE_URL)\s*=\s*\S+")


def _looks_like_source_map(body: str) -> bool:
    """A bare `json.loads()` success isn't enough -- any `{}` parses.
    A real source map has a non-empty `sources` array of real-looking
    file paths (`webpack://`, a `/src/` segment)."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return False
    if not isinstance(data, dict):
        return False
    sources = data.get("sources")
    if not isinstance(sources, list) or not sources:
        return False
    return any(isinstance(s, str) and ("webpack://" in s or "/src/" in s) for s in sources)


def _looks_like_git_config(body: str) -> bool:
    return "[core]" in body and "repositoryformatversion" in body


def _looks_like_env_file(body: str) -> bool:
    return bool(_ENV_KEY_RE.search(body))


# -- TC-105.6: PII/secrets hidden in HTML comments or inline scripts ----

_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
# Inline (non-`src`) `<script>` blocks only -- a `<script src="...">`
# tag has no body to scan here, and its target is already reachable as
# a normal JS asset (covered separately by TC-105.5's sourcemap path).
_INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)

# Small and high-signal, same philosophy as `_PII_PATTERNS` above.
_SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    ("AWS Access Key ID", r"\bAKIA[0-9A-Z]{16}\b"),
    ("JWT-shaped token", r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    ("API key / secret assignment", r"(?i)(?:api[_-]?key|secret)[\"']?\s*[:=]\s*[\"'][^\"']{8,}[\"']"),
)


def find_hidden_disclosures(html: str) -> list[PiiMatch]:
    """Pure function, directly unit-testable like `find_pii()`. Scans
    ONLY comment and inline-script spans of raw HTML -- a value already
    visible in rendered page text isn't a new disclosure via source
    inspection, it's TC-105.1/.4's existing pattern in a different
    location (see the knowledge base's `evidence_signal` note)."""
    spans = [m.group(1) for m in _HTML_COMMENT_RE.finditer(html)] + [m.group(1) for m in _INLINE_SCRIPT_RE.finditer(html)]
    matches: list[PiiMatch] = []
    for span in spans:
        matches.extend(find_pii(span))
        for label, pattern in _SECRET_PATTERNS:
            for m in re.finditer(pattern, span):
                value = m.group(0)
                preview = value[:3] + "…" + value[-2:] if len(value) > 6 else "…"
                matches.append(PiiMatch(label=label, preview=preview))
    return matches


@dataclass
class DisclosureTestConfig:
    high_priv_role: str = "admin"
    max_endpoints_scanned: int = 15
    min_matches_to_flag: int = 1
    target_url: str | None = None


class DisclosureTestsModule(VulnModule):
    module_id = "disclosure_tests"
    name = "PII Exposure via API Tests"
    phase = 1

    def __init__(self, config: DisclosureTestConfig | None = None) -> None:
        self.config = config or DisclosureTestConfig()

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _result(self, technique_id: str, technique: str, vuln_type: str, status: str, detail: str,
                endpoint=None, finding: Finding | None = None) -> TestCaseResult:
        return self._make_result(
            test_id="TC-105", technique_id=technique_id, technique=technique, vuln_type=vuln_type,
            status=status, detail=detail, role=self.config.high_priv_role, endpoint=endpoint, finding=finding,
        )

    async def _technique_pii_in_api_response(self, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-105.1", "PII present in an API response but not rendered in the UI"
        vuln_type = "PII Exposure via API Response"
        candidates = [e for e in endpoints if e.method.upper() == "GET" and e.endpoint_type == "api"][: self.config.max_endpoints_scanned]
        if not candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no GET API endpoint discovered to scan")

        target_url = self.config.target_url or candidates[0].url
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.high_priv_role, target_url)
        except KeyError as exc:
            return self._result(tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")
        for endpoint in candidates:
            finding = await self._check_pii_in_api_response(context, vuln_type, evidence, endpoint)
            if finding is not None:
                return self._result(tid, technique, vuln_type, FAIL, finding.description, endpoint=endpoint, finding=finding)
        return self._result(tid, technique, vuln_type, PASS, f"no PII patterns matched across {len(candidates)} scanned API response(s)")

    async def _check_pii_in_api_response(self, context, vuln_type: str, evidence, endpoint) -> Finding | None:
        """Per-endpoint probe-and-check body of
        `_technique_pii_in_api_response`'s loop, extracted so that
        method drops to setup + orchestration only -- same branches,
        same order, just named and separated."""
        probe = await self._probe_get(context, endpoint.url)
        if probe is None:
            return None
        status, body = probe
        if status != 200:
            return None
        matches = find_pii(body)
        if len(matches) < self.config.min_matches_to_flag:
            return None
        labels = sorted({m.label for m in matches})
        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=6.5,
            endpoint=endpoint, user_role=self.config.high_priv_role,
            request_raw=f"GET {endpoint.url}",
            response_raw=f"HTTP {status}, {len(matches)} PII match(es): {', '.join(labels)}",
            description=f"'{endpoint.url}' returned {len(matches)} apparent PII value(s) ({', '.join(labels)}) in its raw API response.",
            recommendation="Apply field-level output filtering server-side so an API response never includes more than the calling UI actually needs to render.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"pii-api-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
        return finding

    async def _technique_pii_in_errors(self, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-105.2", "PII leaked via error messages / stack traces"
        vuln_type = "PII Exposure via Error Message"
        candidates = [e for e in endpoints if e.method.upper() == "GET" and e.endpoint_type == "api"][: self.config.max_endpoints_scanned]
        if not candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no GET API endpoint discovered to trigger an error against")

        target_url = self.config.target_url or candidates[0].url
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.high_priv_role, target_url)
        except KeyError as exc:
            return self._result(tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")
        for endpoint in candidates:
            finding = await self._check_pii_in_error_response(context, vuln_type, evidence, endpoint)
            if finding is not None:
                return self._result(tid, technique, vuln_type, FAIL, finding.description, endpoint=endpoint, finding=finding)
        return self._result(tid, technique, vuln_type, PASS, f"{len(candidates)} endpoint(s) probed with a malformed parameter; no PII found in any error response")

    async def _check_pii_in_error_response(self, context, vuln_type: str, evidence, endpoint) -> Finding | None:
        """Per-endpoint probe-and-check body of
        `_technique_pii_in_errors`'s loop, extracted so that method
        drops to setup + orchestration only -- same branches, same
        order, just named and separated."""
        probe_url = endpoint.url + ("&" if "?" in endpoint.url else "?") + "__stof_probe=%00%27%22{{7*7}}"
        probe = await self._probe_get(context, probe_url)
        if probe is None:
            return None
        status, body = probe
        if status < 400:
            return None
        matches = find_pii(body)
        if not matches:
            return None
        labels = sorted({m.label for m in matches})
        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=6.5,
            endpoint=endpoint, user_role=self.config.high_priv_role,
            request_raw=f"GET {probe_url}",
            response_raw=f"HTTP {status}, {len(matches)} PII match(es) in error response: {', '.join(labels)}",
            description=f"'{endpoint.url}' leaked apparent PII ({', '.join(labels)}) in its own error response (HTTP {status}) when sent a malformed parameter.",
            recommendation="Return a generic error message for malformed input; never let internal state (including other users' data) leak into an error/exception response.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"pii-error-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
        return finding

    def _technique_pii_via_idor(self) -> TestCaseResult:
        return self._result("TC-105.3", "PII exposed by chaining an IDOR to another user's record", "PII Exposure via IDOR", SKIPPED,
                             "covered by stof.modules.idor_tests (TC-053/TC-054) instead -- this module doesn't duplicate IDOR probing, only checks PII content of a response already fetched")

    def _technique_pii_in_urls(self, endpoints) -> TestCaseResult:
        tid, technique = "TC-105.4", "PII present in URLs or server logs via query params"
        vuln_type = "PII Exposure via URL/Query Parameter"
        flagged: list[tuple["Endpoint", list[PiiMatch]]] = []
        for endpoint in endpoints:
            matches = find_pii(endpoint.url)
            name_hint_matches = [p for p in endpoint.parameters if any(h in p.lower() for h in _FIELD_NAME_HINTS)]
            if matches or name_hint_matches:
                flagged.append((endpoint, matches))
        if not flagged:
            return self._result(tid, technique, vuln_type, PASS, f"no PII-shaped values or PII-named parameters found across {len(endpoints)} discovered endpoint(s)")

        endpoint, matches = flagged[0]
        labels = sorted({m.label for m in matches}) or ["PII-named parameter"]
        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=5.3,
            endpoint=endpoint, user_role=self.config.high_priv_role,
            request_raw=f"{endpoint.method} {endpoint.url}",
            response_raw=f"{len(flagged)} discovered URL(s) contain apparent PII: {', '.join(labels)}",
            description=f"'{endpoint.url}' carries an apparent PII value or PII-named parameter directly in its URL, which typically ends up in server access logs, browser history, and Referer headers.",
            recommendation="Move PII out of URLs (query strings and path segments) and into the request body, and scrub existing access logs that already captured it.",
        )
        return self._result(tid, technique, vuln_type, FAIL, finding.description, endpoint=endpoint, finding=finding)

    def _origin_from_endpoints(self, endpoints) -> str | None:
        """Bare `scheme://host` -- same "scope to the origin, not the
        full URL" precedent as `main.py`'s `_burp_scope_prefix`,
        implemented locally rather than imported (no cross-module
        import between siblings)."""
        base = self.config.target_url or next((e.url for e in endpoints if e.url.startswith(("http://", "https://"))), None)
        if not base:
            return None
        parts = urlsplit(base)
        if not parts.scheme or not parts.netloc:
            return None
        return f"{parts.scheme}://{parts.netloc}"

    async def _technique_source_map_and_backup_exposure(self, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-105.5", "Source map / VCS / backup file left exposed on the webserver"
        vuln_type = "Source Map / VCS / Backup File Exposure"
        origin = self._origin_from_endpoints(endpoints)
        js_assets = [e for e in endpoints if e.url.split("?", 1)[0].endswith(".js")][: self.config.max_endpoints_scanned]
        if origin is None and not js_assets:
            return self._result(tid, technique, vuln_type, SKIPPED, "no origin or JS asset discovered to derive candidate paths from")

        target_url = self.config.target_url or (js_assets[0].url if js_assets else endpoints[0].url)
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.high_priv_role, target_url)
        except KeyError as exc:
            return self._result(tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        checked = 0
        if origin is not None:
            for path in _BACKUP_CANDIDATE_PATHS:
                checked += 1
                finding = await self._check_backup_path(context, vuln_type, evidence, origin + path)
                if finding is not None:
                    return self._result(tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        for asset in js_assets:
            checked += 1
            finding = await self._check_js_source_map(context, vuln_type, evidence, asset)
            if finding is not None:
                return self._result(tid, technique, vuln_type, FAIL, finding.description, endpoint=asset, finding=finding)
        return self._result(tid, technique, vuln_type, PASS, f"no source map / VCS / backup file found across {checked} candidate path(s) checked")

    async def _check_backup_path(self, context, vuln_type: str, evidence, url: str) -> Finding | None:
        """Per-candidate probe-and-check body of the VCS/env/backup
        half of `_technique_source_map_and_backup_exposure`'s loop --
        never trusts status code alone (a SPA catch-all route returns
        200+index.html for any path), body checked with the matching
        `_looks_like_*` helper for that file type."""
        probe = await self._probe_get(context, url)
        if probe is None:
            return None
        status, body = probe
        if status != 200:
            return None
        if _looks_like_git_config(body):
            evidence_desc = "response body contains `[core]` and `repositoryformatversion`"
        elif _looks_like_env_file(body):
            evidence_desc = "response body contains a `KEY=VALUE` line whose key matches a secret-shaped name (_KEY/_SECRET/_PASSWORD/_TOKEN/DATABASE_URL)"
        else:
            return None
        return self._make_backup_finding(vuln_type, url, status, evidence_desc)

    async def _check_js_source_map(self, context, vuln_type: str, evidence, asset) -> Finding | None:
        """Follows a JS asset's trailing `//# sourceMappingURL=...`
        comment if present, else falls back to `<script-src>.map`
        once. Body checked against `_looks_like_source_map` -- never
        status code alone."""
        js_probe = await self._probe_get(context, asset.url)
        if js_probe is None:
            return None
        js_status, js_body = js_probe
        if js_status != 200:
            return None
        map_match = re.search(r"//#\s*sourceMappingURL=(\S+)\s*$", js_body.rstrip())
        map_url = urljoin(asset.url, map_match.group(1)) if map_match else asset.url + ".map"
        probe = await self._probe_get(context, map_url)
        if probe is None:
            return None
        status, body = probe
        if status != 200 or not _looks_like_source_map(body):
            return None
        evidence_desc = f"'{map_url}' is a valid source map with a non-empty `sources` array of real file paths"
        return self._make_backup_finding(vuln_type, map_url, status, evidence_desc)

    def _make_backup_finding(self, vuln_type: str, url: str, status: int, evidence_desc: str) -> Finding:
        return Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
            endpoint=None, user_role=self.config.high_priv_role,
            request_raw=f"GET {url}",
            response_raw=f"HTTP {status}: {evidence_desc}",
            description=f"'{url}' is publicly accessible and {evidence_desc}.",
            recommendation="Remove build artifacts, VCS metadata, and backup files from the webserver's document root; deploy only the compiled, production-intended output.",
        )

    async def _technique_pii_in_html_source(self, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-105.6", "PII or secrets hidden in HTML comments or inline scripts"
        vuln_type = "PII/Secret Exposure via HTML Source"
        candidates = [e for e in endpoints if e.endpoint_type == "page"][: self.config.max_endpoints_scanned]
        if not candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no page endpoint discovered to scan")

        target_url = self.config.target_url or candidates[0].url
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.high_priv_role, target_url)
        except KeyError as exc:
            return self._result(tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")
        for endpoint in candidates:
            finding = await self._check_pii_in_html_source(context, vuln_type, evidence, endpoint)
            if finding is not None:
                return self._result(tid, technique, vuln_type, FAIL, finding.description, endpoint=endpoint, finding=finding)
        return self._result(tid, technique, vuln_type, PASS, f"no PII/secrets found hidden in HTML comments or inline scripts across {len(candidates)} scanned page(s)")

    async def _check_pii_in_html_source(self, context, vuln_type: str, evidence, endpoint) -> Finding | None:
        """Per-endpoint probe-and-check body of
        `_technique_pii_in_html_source`'s loop -- scoped strictly to
        `find_hidden_disclosures()`'s comment/inline-script spans, not
        the whole page body, so PII already visible in rendered page
        text is never misreported as a NEW source-inspection finding."""
        probe = await self._probe_get(context, endpoint.url)
        if probe is None:
            return None
        status, body = probe
        if status != 200:
            return None
        matches = find_hidden_disclosures(body)
        if not matches:
            return None
        labels = sorted({m.label for m in matches})
        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=6.5,
            endpoint=endpoint, user_role=self.config.high_priv_role,
            request_raw=f"GET {endpoint.url}",
            response_raw=f"HTTP {status}, {len(matches)} match(es) hidden in HTML comment/inline-script: {', '.join(labels)}",
            description=f"'{endpoint.url}' contains {len(matches)} apparent PII/secret value(s) ({', '.join(labels)}) hidden in an HTML comment or inline <script> block, invisible in the rendered page but present in raw response source.",
            recommendation="Strip debug comments and hardcoded secrets from HTML/JS before deployment; never leave sensitive values in markup a normal user's browser never renders but a raw HTTP response still carries.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"pii-html-source-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
        return finding

    async def _technique_pii_in_client_storage(self, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-105.7", "PII/secrets left in localStorage or sessionStorage after authentication"
        vuln_type = "PII Exposure via Client-Side Storage"
        candidates = [e for e in endpoints if e.endpoint_type == "page"][: self.config.max_endpoints_scanned]
        if not candidates:
            return self._result(tid, technique, vuln_type, SKIPPED, "no page endpoint discovered to navigate to")

        target_url = self.config.target_url or candidates[0].url
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.high_priv_role, target_url)
        except KeyError as exc:
            return self._result(tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        page = await context.new_page()
        try:
            for endpoint in candidates:
                finding = await self._check_pii_in_client_storage(page, vuln_type, evidence, endpoint)
                if finding is not None:
                    return self._result(tid, technique, vuln_type, FAIL, finding.description, endpoint=endpoint, finding=finding)
        finally:
            await page.close()
        return self._result(tid, technique, vuln_type, PASS, f"no PII/secrets found in localStorage/sessionStorage across {len(candidates)} scanned page(s)")

    async def _check_pii_in_client_storage(self, page, vuln_type: str, evidence, endpoint) -> Finding | None:
        """Per-endpoint navigate-and-check body of
        `_technique_pii_in_client_storage`'s loop -- navigates a REAL
        browser `Page` (this technique's whole reason for existing:
        `localStorage`/`sessionStorage` are client-side JS state that
        never appears in any raw HTTP response body, unlike every
        other technique in this file) and reads both storages back via
        `page.evaluate()`. A navigation/evaluate failure (e.g. an
        opaque-origin `about:blank`, or the page just being
        unreachable) is treated the same as `_probe_get`'s own
        failure case -- skip this endpoint, not a hard error, since
        `run_techniques()`'s own try/except around the whole technique
        already covers a genuinely unexpected failure."""
        try:
            await page.goto(endpoint.url, timeout=15000)
            storage = await page.evaluate(
                "() => ({local: Object.entries(localStorage), session: Object.entries(sessionStorage)})"
            )
        except Exception as exc:
            _log.warning(f"client-storage probe failed for {endpoint.url}: {exc}")
            return None
        if not storage:
            return None

        entries = [(f"localStorage.{k}", v) for k, v in storage.get("local") or []]
        entries += [(f"sessionStorage.{k}", v) for k, v in storage.get("session") or []]
        hits: list[tuple[str, PiiMatch]] = [
            (key, match) for key, value in entries if isinstance(value, str) for match in find_pii(value)
        ]
        if not hits:
            return None
        labels = sorted({m.label for _key, m in hits})
        keys = sorted({key for key, _m in hits})
        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=6.5,
            endpoint=endpoint, user_role=self.config.high_priv_role,
            request_raw=f"GET {endpoint.url} (page.evaluate: Object.entries(localStorage)/Object.entries(sessionStorage))",
            response_raw=f"{len(hits)} PII match(es) in client storage key(s) {', '.join(keys)}: {', '.join(labels)}",
            description=(
                f"'{endpoint.url}' leaves {len(hits)} apparent PII value(s) ({', '.join(labels)}) in browser "
                f"localStorage/sessionStorage key(s) ({', '.join(keys)}) after authentication -- any XSS on this "
                "page, or physical/malware access to the browser, can trivially read this data since it persists "
                "outside any httpOnly protection."
            ),
            recommendation="Never cache PII (email, profile fields, tokens) in localStorage/sessionStorage 'for convenience' -- keep it server-side and fetch on demand, or store only a non-identifying reference; use httpOnly, SameSite cookies for session tokens instead.",
        )
        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"pii-client-storage-{endpoint.url.rsplit('/', 1)[-1]}") if evidence else []
        return finding

    async def run_techniques(
        self,
        endpoints: list["Endpoint"],
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[TestCaseResult]:
        results: list[TestCaseResult] = []
        try:
            results.append(await self._technique_pii_in_api_response(endpoints, session_manager, session_pool, evidence))
        except Exception as exc:
            _log.warning(f"disclosure_tests TC-105.1 failed unexpectedly: {exc}")
            results.append(self._result("TC-105.1", "PII present in an API response but not rendered in the UI", "PII Exposure via API Response", "ERROR", str(exc)))
        try:
            results.append(await self._technique_pii_in_errors(endpoints, session_manager, session_pool, evidence))
        except Exception as exc:
            _log.warning(f"disclosure_tests TC-105.2 failed unexpectedly: {exc}")
            results.append(self._result("TC-105.2", "PII leaked via error messages / stack traces", "PII Exposure via Error Message", "ERROR", str(exc)))
        results.append(self._technique_pii_via_idor())
        results.append(self._technique_pii_in_urls(endpoints))
        try:
            results.append(await self._technique_source_map_and_backup_exposure(endpoints, session_manager, session_pool, evidence))
        except Exception as exc:
            _log.warning(f"disclosure_tests TC-105.5 failed unexpectedly: {exc}")
            results.append(self._result("TC-105.5", "Source map / VCS / backup file left exposed on the webserver", "Source Map / VCS / Backup File Exposure", "ERROR", str(exc)))
        try:
            results.append(await self._technique_pii_in_html_source(endpoints, session_manager, session_pool, evidence))
        except Exception as exc:
            _log.warning(f"disclosure_tests TC-105.6 failed unexpectedly: {exc}")
            results.append(self._result("TC-105.6", "PII or secrets hidden in HTML comments or inline scripts", "PII/Secret Exposure via HTML Source", "ERROR", str(exc)))
        try:
            results.append(await self._technique_pii_in_client_storage(endpoints, session_manager, session_pool, evidence))
        except Exception as exc:
            _log.warning(f"disclosure_tests TC-105.7 failed unexpectedly: {exc}")
            results.append(self._result("TC-105.7", "PII/secrets left in localStorage or sessionStorage after authentication", "PII Exposure via Client-Side Storage", "ERROR", str(exc)))
        return results
