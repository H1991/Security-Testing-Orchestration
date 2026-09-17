"""Layer 9 — `stof/modules/auth_tests.py`: Default Credentials (TC-022),
Weak Password Policy (TC-025), Weak Password Change/Reset (TC-027),
Weak Security Question/Answer (TC-132, WSTG-AUTHN-09), Authentication
Schema Bypass (TC-133, WSTG-AUTHN-04).

Named exactly as CLAUDE.md's own Layer 9 file list anticipated
("session fixation, brute, lockout") -- this build covers the Critical
sprint-1 subset (default creds / password policy / password reset)
specifically, not session fixation/lockout, which stay for a later pass.

Every probe here is either read-only (a login attempt, a reset-request
comparison) or explicitly gated behind `AuthTestConfig.
allow_state_changing_probes`, off by default, for the same reason
`idor_tests.py`'s write-method techniques are gated: a successful
weak-password-change probe actually changes the target's real account
password. Every gated technique reverts the password back to its
original value in a `finally` block regardless of outcome -- a failed
revert is logged loudly (`_log.error`, not `.warning`) since it leaves
the configured test account in a broken state for every other module.

Target-agnostic by construction: every URL this module calls
(`login_json_endpoint`, `change_password_url`, `reset_password_request_
url`) is optional config, not a hardcoded shape -- a target that hasn't
configured one just gets that technique reported SKIPPED, exactly like
`jwt_tests.py` does for a role with no JWT auth_type configured.
"""
from __future__ import annotations

import asyncio
import json as json_module
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from stof.cleanup import REVERT_FAILED, REVERTED
from stof.core.logger import get_logger
from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding

from ._injection_shared import looks_json_authenticated, placeholder_value, send_probe
from ._probe_shared import control_fingerprint, sweep_paths
from .base import _PASSWORD_FIELD_HINTS, _USERNAME_FIELD_HINTS, VulnModule, _is_transient_error, find_login_endpoint, first_not_none
from .results import FAIL, NOT_IMPLEMENTED, PASS, SKIPPED, TestCaseResult, extract_findings
from .session_weakness_tests import SessionWeaknessTechniquesMixin

if TYPE_CHECKING:
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.auth_tests")

# Small, well-known default-credential pairs -- the same category of
# list SecLists' own default-creds wordlists cover, kept short and
# high-signal rather than an exhaustive copy (a real engagement would
# point this at a vendor-specific list via `AuthTestConfig.
# credential_pairs` instead).
_DEFAULT_CREDENTIAL_PAIRS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "changeme"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("guest", "guest"),
    ("demo", "demo"),
)

_SHORT_PASSWORDS: tuple[str, ...] = ("abc12", "pw123", "a1b2c")
_COMMON_BREACHED_PASSWORDS: tuple[str, ...] = ("password123", "qwerty123", "letmein123", "welcome123")
# A password with no digits/symbols/uppercase at all -- specifically
# probes for the *absence* of a character-class requirement, distinct
# from TC-025.1's "too short" and TC-025.2's "too common" signals.
_NO_COMPLEXITY_PASSWORD = "alllowercasenospecialchars"

_ADMIN_PANEL_LOGIN_PATHS: tuple[str, ...] = ("/admin", "/administrator", "/admin/login", "/manage", "/manager/html")

# (fingerprint keyword found in headers/body, vendor-specific default
# credential pairs to try if that fingerprint matches) -- a small,
# well-known table (Tomcat/Jenkins/Grafana/phpMyAdmin/JBoss/WebLogic),
# not an exhaustive vendor-defaults database.
_VENDOR_DEFAULT_CREDENTIALS: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    ("tomcat", (("tomcat", "tomcat"), ("tomcat", "s3cret"))),
    ("jenkins", (("admin", "admin"),)),
    ("grafana", (("admin", "admin"),)),
    ("phpmyadmin", (("root", ""), ("root", "root"))),
    ("jboss", (("admin", "admin"),)),
    ("weblogic", (("weblogic", "weblogic1"),)),
)

# Small, high-signal API-key-shaped patterns -- same "small and
# high-signal" philosophy as recon's secrets_scanner.py, reimplemented
# here rather than imported (Layer 9 modules stay independent of each
# other's internals; a little duplication is the accepted tradeoff).
_API_KEY_PATTERNS: tuple[str, ...] = (
    r"AKIA[0-9A-Z]{16}",  # AWS access key
    r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
    r"(?i)(secret|token)['\"]?\s*[:=]\s*['\"][^'\"\s]{12,}['\"]",
)
_CONFIG_EXPOSURE_PATHS: tuple[str, ...] = ("/.env", "/config.json", "/api/config", "/.well-known/config", "/settings.json")

# Common reset-token/OTP field names an API might echo back in its own
# JSON response -- opportunistic: most real targets email the token
# privately, in which case none of these ever match and the technique
# correctly reports SKIPPED rather than guessing.
_TOKEN_FIELD_NAMES: tuple[str, ...] = ("token", "resetToken", "code", "otp", "resetCode")

# TC-027.7's own small, curated guess-list for a client-supplied
# target-user identifier field on a password-change endpoint -- same
# "try a short, plausible list of real-world field names, harmless if
# the target ignores the extra field" philosophy as `_change_password`'s
# two request-shape attempts above.
_TARGET_USER_FIELD_CANDIDATES: tuple[str, ...] = (
    "userId", "user_id", "accountId", "account_id", "id", "targetUserId", "email", "username",
)

# TC-132.1 (WSTG-AUTHN-09, "Testing for Weak Security Question/Answer):
# field-name hints a discovered form/page uses for a security-question
# account-recovery flow. Small and high-signal, same philosophy as
# `_USERNAME_FIELD_HINTS`/`_PASSWORD_FIELD_HINTS` above -- most real
# targets have NO such flow at all (email/SMS OTP has mostly replaced
# it), so the honest, expected outcome of this technique on most
# targets is a clean SKIP, not a forced finding.
_SECURITY_QUESTION_FIELD_HINTS: tuple[str, ...] = (
    "securityquestion", "security_question", "secretquestion", "secret_question",
    "securityanswer", "security_answer", "secretanswer", "secret_answer",
    "recoveryquestion", "recovery_question", "kbaquestion", "kba_question", "secquestion",
)

# Real, WSTG-cited example questions with a small, guessable answer
# space (WSTG's own AUTHN-09 write-up lists "mother's maiden name",
# "first pet", "favorite color" as the canonical low-entropy examples;
# PortSwigger's forgot-password documentation makes the same point).
# Matching one of THESE against a discovered question's visible text is
# the classification step -- the guess itself is never attempted, only
# the question's shape is judged.
_WEAK_SECURITY_QUESTION_PATTERNS: tuple[str, ...] = (
    "mother's maiden name", "mothers maiden name", "maiden name",
    "first pet", "pet's name", "pets name", "name of your pet",
    "favorite color", "favourite color",
    "first car", "make of your first car",
    "high school", "first school",
    "city were you born", "city you were born", "city of birth", "born",
    "childhood best friend", "best friend",
    "favorite food", "favourite food",
    "street you grew up", "street did you grow up",
    "favorite teacher", "favourite teacher",
)

# TC-133.1 (WSTG-AUTHN-04, "Testing for Bypassing Authentication
# Schema"): same "small and high-signal" philosophy -- a bounded set of
# request-SHAPE variants (not identity/role variants, which is what
# `idor_tests.py`/`bfla_tests.py` already cover), tried unauthenticated
# against a URL that already correctly denies an anonymous baseline.
_MAX_SCHEMA_BYPASS_CANDIDATES = 5
_SCHEMA_BYPASS_DENIED_MARKERS: tuple[str, ...] = ("login", "sign in", "log in", "unauthorized", "access denied", "please log in", "authentication required")


def _confidence_from_relogin(confirmed: bool | None) -> str:
    """Shared by every password-change technique in this file that
    confirms its own accepted-at-the-HTTP-layer finding via re-login
    (`_confirm_password_works`/`_confirm_password_works_for`). `confirmed`
    is never `False` at any call site -- each one already returns early
    on that outcome (a re-login failure means the change didn't really
    happen, so there's no Finding to build confidence for at all).
    `True` means STOF independently verified the change by logging in
    with the resulting credential; `None` means no login endpoint was
    configured to check, so the change-password endpoint's own accept/
    reject response is the only signal STOF has."""
    return "confirmed" if confirmed is True else "likely"


def _extract_token(body: dict) -> str | None:
    """Same field-name-agnostic response walk as `jwt_auth.py`'s own
    `_extract_token()` -- reimplemented here rather than imported,
    since Layer 9 modules never import Layer 4 internals (CLAUDE.md's
    forbidden-imports rule)."""
    for path in (("token",), ("access_token",), ("authentication", "token"), ("data", "token")):
        value: object = body
        for key in path:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                value = None
                break
        if isinstance(value, str) and value:
            return value
    return None


async def _try_json_login(context, endpoint_url: str, username: str, password: str) -> tuple[bool, int, str]:
    """Returns (succeeded, status, body_preview).

    A transient network/browser error here used to be indistinguishable
    from "the target rejected these credentials" -- both fell into the
    `except Exception` below and returned `succeeded=False`, so a caller
    sweeping several credential pairs would report a clean PASS ("none
    accepted") even when every single probe actually never reached the
    target. Re-raising a transient error instead lets it propagate up to
    `run_techniques()`'s `_safe_result` wrapper, which reports the whole
    technique as ERROR ("couldn't test") -- the same fix already applied
    to `idor_tests.py`'s `_authenticated_context`."""
    try:
        resp = await context.request.post(
            endpoint_url,
            data=json_module.dumps({"username": username, "email": username, "password": password}),
            headers={"Content-Type": "application/json"},
        )
        body_text = await resp.text()
    except Exception as exc:
        if _is_transient_error(exc):
            raise
        return False, 0, str(exc)
    if resp.status >= 400:
        return False, resp.status, body_text[:200]
    try:
        body = json_module.loads(body_text)
    except json_module.JSONDecodeError:
        return False, resp.status, body_text[:200]
    return (_extract_token(body) is not None), resp.status, body_text[:200]


async def _login_attempt_raw(context, endpoint_url: str, username: str, password: str) -> tuple[int, str]:
    """Like `_try_json_login`, but returns the FULL (untruncated) status
    and body rather than a 200-char preview and a success flag --
    TC-022.5's differential comparison needs the real body length, which
    `_try_json_login`'s `body_text[:200]` preview would silently mask."""
    try:
        resp = await context.request.post(
            endpoint_url,
            data=json_module.dumps({"username": username, "email": username, "password": password}),
            headers={"Content-Type": "application/json"},
        )
        return resp.status, await resp.text()
    except Exception as exc:
        if _is_transient_error(exc):
            raise
        return 0, str(exc)


def _form_login_fields(endpoint: Endpoint) -> tuple[str, str] | None:
    """The (username_param, password_param) pair on a discovered HTML
    login form -- `find_login_endpoint()` (`base.py`) already guarantees
    an endpoint it returns has both, but this is kept defensive/reusable
    rather than assuming that invariant at every call site."""
    username_param = next((p for p in endpoint.parameters if any(h in p.lower() for h in _USERNAME_FIELD_HINTS)), None)
    password_param = next((p for p in endpoint.parameters if any(h in p.lower() for h in _PASSWORD_FIELD_HINTS)), None)
    if username_param is None or password_param is None:
        return None
    return username_param, password_param


_FORM_AUTH_SUCCESS_MARKERS = ("logout", "log out", "sign out", "signout", "welcome", "my account", "dashboard", "account summary")


def _looks_form_authenticated(status: int, headers: dict, body: str, baseline_status: int, baseline_headers: dict, baseline_body: str) -> bool:
    """Same heuristic shape as `sqli_tests.py`'s own `looks_authenticated`
    (a login form commonly answers both a correct and an incorrect
    submission with HTTP 200, re-rendering the same page) -- the
    HTML-page-shaped part is reimplemented here rather than imported,
    since `auth_tests.py` and `sqli_tests.py` are sibling modules and
    CLAUDE.md forbids importing between them; the JSON-API-shaped part
    (`looks_json_authenticated`) is genuinely shared via `_injection_shared.py`,
    the same established pattern `placeholder_value`/`send_probe` already use."""
    location = (headers or {}).get("location", "")
    baseline_location = (baseline_headers or {}).get("location", "")
    redirected_to_new_place = (
        300 <= status < 400
        and bool(location)
        and "log" not in location.lower().rsplit("/", 1)[-1]
        and location != baseline_location
    )
    body_lower, baseline_lower = body.lower(), baseline_body.lower()
    new_success_marker = any(m in body_lower and m not in baseline_lower for m in _FORM_AUTH_SUCCESS_MARKERS)
    return bool(redirected_to_new_place) or new_success_marker or looks_json_authenticated(body, baseline_body)


async def _form_login_baseline(context, endpoint: Endpoint, username_param: str, password_param: str) -> tuple[int, str, dict] | None:
    """A single definitely-wrong-credentials probe against a discovered
    HTML login form, used as the "what does a rejected login look like"
    reference point for `_looks_form_authenticated()`. Returns `None` on
    a request failure."""
    params = {n: placeholder_value(n) for n in endpoint.parameters}
    params[username_param] = "stof-nonexistent-user"
    params[password_param] = "definitely-Wrong-Pw1!"
    probe = await send_probe(context, endpoint, params, endpoint.location_for(username_param))
    if probe is None:
        return None
    status, body, _elapsed, headers = probe
    return status, body, headers


async def _try_form_login(
    context, endpoint: Endpoint, username_param: str, password_param: str, username: str, password: str,
    baseline_status: int, baseline_body: str, baseline_headers: dict,
) -> tuple[bool, int, str]:
    """Form-encoded counterpart to `_try_json_login()`, for a discovered
    HTML login form rather than a configured JSON API -- submits with
    the form's own real field names (from `endpoint.parameters`), not an
    assumed `username`/`password` JSON shape. Models
    `sqli_tests.py`'s `_technique_login_bypass()`'s own HTML-form POST."""
    params = {n: placeholder_value(n) for n in endpoint.parameters}
    params[username_param] = username
    params[password_param] = password
    probe = await send_probe(context, endpoint, params, endpoint.location_for(username_param))
    if probe is None:
        return False, 0, "probe failed"
    status, body, _elapsed, headers = probe
    succeeded = _looks_form_authenticated(status, headers, body, baseline_status, baseline_headers, baseline_body)
    return succeeded, status, body[:200]


def _case_flip_last_path_segment(url: str) -> str | None:
    """`/admin` -> `/Admin`-shaped variant: swap case of the last
    non-empty path segment only, not the whole URL (flipping the host
    would just change the domain, and flipping the whole path is more
    likely to 404 outright on a case-sensitive filesystem router than a
    single-segment flip is). Returns `None` when there's no path or the
    swap is a no-op (an all-non-alpha segment, e.g. `/123`)."""
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url)
    path = parts.path
    if not path or path == "/":
        return None
    trailing_slash = path.endswith("/") and path != "/"
    segments = path.rstrip("/").split("/")
    last = segments[-1]
    flipped = last.swapcase()
    if flipped == last:
        return None
    segments[-1] = flipped
    new_path = "/".join(segments) + ("/" if trailing_slash else "")
    return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))


def _schema_bypass_variants(url: str) -> list[tuple[str, str]]:
    """Returns `[(label, variant_url), ...]` -- a small, bounded list of
    WSTG-AUTHN-04-style request-SHAPE variants of `url`: case-variation
    in the path, a trailing-slash/dot variant, and two common
    auth-check-bypass suffix strings (`;jsessionid=...`, a URL-encoded
    null byte) that some legacy path-parameter-aware routers strip
    before their auth check but a case-insensitive front-end/back-end
    router pair disagrees on. Deliberately NOT identity/role variation
    -- that's `idor_tests.py`/`bfla_tests.py`'s job, not this
    technique's."""
    variants: list[tuple[str, str]] = []
    flipped = _case_flip_last_path_segment(url)
    if flipped:
        variants.append(("case-flipped path segment", flipped))
    if not url.endswith("/"):
        variants.append(("trailing slash", url + "/"))
    variants.append(("trailing dot", url.rstrip("/") + "."))
    variants.append(("jsessionid path-parameter suffix", url.rstrip("/") + ";jsessionid=STOF00000000000000000000000000"))
    variants.append(("URL-encoded null-byte suffix", url.rstrip("/") + "%00"))
    return variants


def _looks_anonymously_denied(status: int, body: str) -> bool:
    """The baseline half of TC-133.1: does an UNMODIFIED auth-gated URL
    correctly deny an anonymous request? A redirect (to a login page)
    or a 401/403 is an unambiguous deny; a 200 whose body itself reads
    like a login/access-denied page (a soft-403) also counts -- same
    "don't gate on raw status alone" principle `classify_response()`
    encodes for the authorization family, reimplemented narrowly here
    rather than imported (`auth_tests.py` never imports
    `authorization.decision` -- that module's ALLOWED branch requires a
    substantial body, tuned for role-differential IDOR/BFLA checks, not
    this technique's simpler binary denied/not-denied question)."""
    if 300 <= status < 400:
        return True
    if status in (401, 403):
        return True
    body_lower = body.lower()
    return any(marker in body_lower for marker in _SCHEMA_BYPASS_DENIED_MARKERS)


def _looks_anonymously_bypassed(status: int, body: str) -> bool:
    """The variant half of TC-133.1: does a request-shape VARIANT of
    that same URL, still with no session at all, return real
    authenticated-looking content? Reuses `_FORM_AUTH_SUCCESS_MARKERS`
    (the same "logout / dashboard / welcome / my account" vocabulary
    `_looks_form_authenticated` already uses for a login-form success
    signal) rather than inventing a second marker list."""
    if status != 200:
        return False
    body_lower = body.lower()
    return any(marker in body_lower for marker in _FORM_AUTH_SUCCESS_MARKERS)


@dataclass
class AuthTestConfig:
    login_json_endpoint: str | None = None  # e.g. config.target.jwt_token_url
    change_password_url: str | None = None  # e.g. config.target.change_password_url
    reset_password_request_url: str | None = None  # e.g. config.target.reset_password_request_url
    reset_password_complete_url: str | None = None  # e.g. config.target.reset_password_complete_url -- takes a token param
    credential_pairs: tuple[tuple[str, str], ...] = field(default_factory=lambda: _DEFAULT_CREDENTIAL_PAIRS)
    short_passwords: tuple[str, ...] = field(default_factory=lambda: _SHORT_PASSWORDS)
    common_breached_passwords: tuple[str, ...] = field(default_factory=lambda: _COMMON_BREACHED_PASSWORDS)
    # The authenticated role/credential whose password-change/reset
    # surface gets probed -- filled in by the caller (main.py) from
    # already-loaded `UserConfig`, the same way `IdorTestsModule` is
    # told which roles are high/low priv rather than guessing.
    test_role: str | None = None
    test_username: str | None = None
    test_current_password: str | None = None
    victim_email: str | None = None  # a second, different user's email/username, for TC-027.5 / TC-027.7
    # TC-027.7 needs this SECOND account's own ORIGINAL password too --
    # unlike every other gated technique in this file (which changes
    # only the attacker's OWN, already-known password and can always
    # revert it), a successful TC-027.7 bypass changes a DIFFERENT
    # account's password. Without this, STOF cannot safely revert that
    # change, so TC-027.7 SKIPs cleanly rather than run at all -- see
    # its own docstring.
    victim_current_password: str | None = None
    allow_state_changing_probes: bool = False
    # TC-129.2 (session valid after logout): optional target-specific
    # logout URL, same "explicit override, generic fallback" philosophy
    # as every other selector/URL in this file. Unset means the
    # technique falls back to a generic logout-link/button click on the
    # target page instead (see `session_weakness_tests.py`).
    logout_url: str | None = None


def _synthetic_endpoint(url: str, method: str) -> Endpoint:
    """A `Finding`/evidence needs an `Endpoint`, but `login_json_endpoint`
    etc. are config URLs, not necessarily ones the crawler discovered."""
    return Endpoint(url=url, method=method, endpoint_type="api", auth_required=False)


class AuthTestsModule(VulnModule, SessionWeaknessTechniquesMixin):
    module_id = "auth_tests"
    name = "Authentication Weakness Tests"
    phase = 1

    def __init__(self, config: AuthTestConfig | None = None) -> None:
        self.config = config or AuthTestConfig()

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _result(self, test_id: str, technique_id: str, technique: str, vuln_type: str,
                status: str, detail: str, finding: Finding | None = None) -> TestCaseResult:
        return self._make_result(
            test_id=test_id, technique_id=technique_id, technique=technique, vuln_type=vuln_type,
            status=status, detail=detail, role=self.config.test_role, finding=finding,
        )

    async def _capture(self, evidence, finding: Finding) -> list[str]:
        if evidence is None:
            return []
        return await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"auth-{finding.finding_id}")

    # --- TC-022 Default Credentials -------------------------------------

    async def _technique_default_credentials(self, endpoints, session_pool, evidence) -> TestCaseResult:
        test_id, tid = "TC-022", "TC-022.1"
        technique, vuln_type = "Common default-credential pairs (admin/admin, admin/password, ...)", "Default Credentials Accepted"

        login_endpoint = None
        if not self.config.login_json_endpoint:
            # No JSON-API login endpoint configured -- fall back to the
            # crawler's own discovered HTML login form (`find_login_endpoint`,
            # `base.py`) instead of SKIPping outright, closing the recurring
            # JSON-login-only gap `auth_knowledge_base.json` documents for
            # this technique against a classic form-login target.
            login_endpoint = find_login_endpoint(endpoints)
            if login_endpoint is None:
                return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                     "no JSON login endpoint configured (target.jwt_token_url), and no discovered "
                                     "HTML login form (a POST endpoint with both a username- and password-shaped "
                                     "field) to fall back to")

        anon_context = await session_pool.new_anonymous_context()
        try:
            if login_endpoint is not None:
                return await self._default_credentials_via_form(anon_context, login_endpoint, evidence, test_id, tid, technique, vuln_type)
            async def _try_pair(username: str, password: str) -> "Finding | None":
                succeeded, status, preview = await _try_json_login(anon_context, self.config.login_json_endpoint, username, password)
                if not succeeded:
                    return None
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.8,
                    endpoint=_synthetic_endpoint(self.config.login_json_endpoint, "POST"), user_role="unauthenticated",
                    # Real, unmasked value here on purpose: `password`
                    # comes from `_DEFAULT_CREDENTIAL_PAIRS`, a fully
                    # public, hardcoded wordlist ("admin"/"admin",
                    # "demo"/"demo", ...) -- it's not a secret, it's the
                    # finding itself, and masking it broke evidence
                    # integrity (see `git log` around this line): the
                    # masked `***` string was what the Burp evidence-
                    # capture replay actually sent, producing a
                    # legitimate 401 that contradicted this finding's
                    # own real 200 -- one finding showing two
                    # disagreeing outcomes to whoever reviewed it. A
                    # real, operator-configured secret (e.g.
                    # `test_current_password` elsewhere in this file)
                    # must still never be written here -- only a value
                    # already drawn from a public wordlist is safe to
                    # persist and replay verbatim.
                    request_raw=f'POST {self.config.login_json_endpoint}\nContent-Type: application/json\n\n{{"username": "{username}", "password": "{password}"}}',
                    response_raw=f"HTTP {status}, {preview}",
                    description=f"The default/common credential pair '{username}'/'{password}' was accepted by '{self.config.login_json_endpoint}'.",
                    recommendation="Remove every default/sample account before deployment, and enforce a password policy that rejects common passwords.",
                )
                finding.evidence_refs = await self._capture(evidence, finding)
                return finding

            attempts = await asyncio.gather(*(_try_pair(u, p) for u, p in self.config.credential_pairs))
            finding = first_not_none(attempts)
            if finding is not None:
                return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)
            return self._result(test_id, tid, technique, vuln_type, PASS, f"none of {len(self.config.credential_pairs)} common credential pairs were accepted")
        finally:
            await anon_context.close()

    async def _default_credentials_via_form(self, anon_context, login_endpoint: Endpoint, evidence, test_id, tid, technique, vuln_type) -> TestCaseResult:
        """Fallback branch of TC-022.1: sweeps `credential_pairs` against
        a discovered HTML login form using the form's own real field
        names, rather than the JSON `login_json_endpoint` shape."""
        fields = _form_login_fields(login_endpoint)
        if fields is None:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "discovered login form is missing an expected username/password field")
        username_param, password_param = fields
        baseline = await _form_login_baseline(anon_context, login_endpoint, username_param, password_param)
        if baseline is None:
            return self._result(test_id, tid, technique, vuln_type, "ERROR", "baseline login probe against the discovered HTML form failed")
        baseline_status, baseline_body, baseline_headers = baseline

        async def _try_pair(username: str, password: str) -> "Finding | None":
            succeeded, status, preview = await _try_form_login(
                anon_context, login_endpoint, username_param, password_param, username, password,
                baseline_status, baseline_body, baseline_headers,
            )
            if not succeeded:
                return None
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.8,
                endpoint=login_endpoint, user_role="unauthenticated",
                # Unmasked on purpose -- see the sibling JSON-login
                # branch above for why: `password` is drawn from the
                # public `credential_pairs` wordlist, not a secret, and
                # masking it here is what broke the Burp evidence-
                # capture replay (`stof/engine/burp_capture.py` parses
                # this exact string to rebuild the request it resends;
                # a literal "***" replayed as the actual password
                # correctly gets rejected, contradicting this finding's
                # own real accepted-login result).
                request_raw=f"POST {login_endpoint.url}\n{username_param}={username}&{password_param}={password}",
                response_raw=f"HTTP {status}, {preview}",
                description=f"The default/common credential pair '{username}'/'{password}' was accepted by the discovered HTML login form at '{login_endpoint.url}'.",
                recommendation="Remove every default/sample account before deployment, and enforce a password policy that rejects common passwords.",
            )
            finding.evidence_refs = await self._capture(evidence, finding)
            return finding

        attempts = await asyncio.gather(*(_try_pair(u, p) for u, p in self.config.credential_pairs))
        finding = first_not_none(attempts)
        if finding is not None:
            return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        return self._result(test_id, tid, technique, vuln_type, PASS,
                             f"none of {len(self.config.credential_pairs)} common credential pairs were accepted by the discovered HTML login form")

    async def _technique_vendor_defaults(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-022.2", "Vendor/product-specific defaults from a known-defaults list"
        vuln_type = "Default Credentials Accepted (vendor-specific)"
        base_url = endpoints[0].url if endpoints else self.config.login_json_endpoint
        if not base_url:
            return self._result("TC-022", tid, technique, vuln_type, SKIPPED, "no endpoint/base URL available to fingerprint")

        anon_context = await session_pool.new_anonymous_context()
        try:
            # Not routed through `_probe_get`: unlike every other GET-probe
            # call site, this fingerprint needs the response HEADERS too
            # (vendor names commonly show up in `Server`/`X-Powered-By`,
            # not just the body) -- `_probe_get`'s `(status, body)` contract
            # deliberately stays narrow for its ~20 other call sites rather
            # than growing a header return value only this one needs.
            try:
                resp = await anon_context.request.get(base_url, max_redirects=0)
                body = (await resp.text())[:2000]
                headers_text = " ".join(f"{k}:{v}" for k, v in resp.headers.items())
            except Exception as exc:
                return self._result("TC-022", tid, technique, vuln_type, "ERROR", f"fingerprint probe failed: {exc}")
            fingerprint_text = (body + " " + headers_text).lower()

            matched_pairs: list[tuple[str, str]] = []
            matched_vendor = None
            for vendor, pairs in _VENDOR_DEFAULT_CREDENTIALS:
                if vendor in fingerprint_text:
                    matched_vendor, matched_pairs = vendor, list(pairs)
                    break
            if not matched_vendor:
                return self._result("TC-022", tid, technique, vuln_type, PASS, f"no known vendor fingerprint matched in headers/body across {len(_VENDOR_DEFAULT_CREDENTIALS)} known products")
            if not self.config.login_json_endpoint:
                return self._result("TC-022", tid, technique, vuln_type, SKIPPED, f"fingerprinted '{matched_vendor}' but no login_json_endpoint configured to try its defaults against")

            async def _try_pair(username: str, password: str) -> "Finding | None":
                succeeded, status, preview = await _try_json_login(anon_context, self.config.login_json_endpoint, username, password)
                if not succeeded:
                    return None
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.8,
                    endpoint=_synthetic_endpoint(self.config.login_json_endpoint, "POST"), user_role="unauthenticated",
                    # Unmasked -- `password` is drawn from
                    # `_VENDOR_DEFAULT_CREDENTIALS`, a public,
                    # documented wordlist, same reasoning as
                    # `_technique_default_credentials` above.
                    request_raw=f'POST {self.config.login_json_endpoint}\nContent-Type: application/json\n\n{{"username": "{username}", "password": "{password}"}} (fingerprinted: {matched_vendor})',
                    response_raw=f"HTTP {status}, {preview}",
                    description=f"The target fingerprints as '{matched_vendor}', and its documented default credential pair '{username}'/'{password}' was accepted.",
                    recommendation=f"Change '{matched_vendor}'s default credentials immediately, or disable the default account entirely.",
                )
                finding.evidence_refs = await self._capture(evidence, finding)
                return finding

            attempts = await asyncio.gather(*(_try_pair(u, p) for u, p in matched_pairs))
            finding = first_not_none(attempts)
            if finding is not None:
                return self._result("TC-022", tid, technique, vuln_type, FAIL, finding.description, finding=finding)
            return self._result("TC-022", tid, technique, vuln_type, PASS, f"fingerprinted '{matched_vendor}' but none of its {len(matched_pairs)} known default credential pair(s) were accepted")
        finally:
            await anon_context.close()

    async def _technique_admin_interface_defaults(self, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-022.3", "Default creds on exposed admin/management interfaces"
        vuln_type = "Default Credentials Accepted (admin interface)"
        base = (self.config.login_json_endpoint or "").rsplit("/", 2)[0] if self.config.login_json_endpoint else None
        if not base:
            return self._result("TC-022", tid, technique, vuln_type, SKIPPED, "no login_json_endpoint configured to derive an origin from")

        anon_context = await session_pool.new_anonymous_context()
        try:
            origin = base.split("/rest/")[0].split("/api/")[0].rstrip("/")

            # SPA-catch-all-aware wordlist sweep (baseline-control-probe
            # pattern shared with `configuration_tests.py`'s TC-017
            # techniques and `bfla_tests.py`'s TC-055.4) -- see
            # `_probe_shared.py` for why.
            baseline = await control_fingerprint(anon_context, origin)
            hits = await sweep_paths(anon_context, origin, _ADMIN_PANEL_LOGIN_PATHS, baseline)
            reachable_admin_paths = [url for url, status, _body in hits if status == 200]
            if not reachable_admin_paths:
                return self._result("TC-022", tid, technique, vuln_type, PASS, f"none of {len(_ADMIN_PANEL_LOGIN_PATHS)} common admin paths were reachable to test credentials against")

            async def _check_admin_url(admin_url: str) -> "Finding | None":
                """One admin URL's own credential-pair sweep -- kept
                sequential internally (early-exit-on-first-match, same
                as before) while different admin URLs run concurrently
                below."""
                login_url = admin_url.rstrip("/") + "/login"
                for username, password in self.config.credential_pairs:
                    succeeded, status, preview = await _try_json_login(anon_context, login_url, username, password)
                    if not succeeded:
                        continue
                    finding = Finding(
                        module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.1,
                        endpoint=_synthetic_endpoint(login_url, "POST"), user_role="unauthenticated",
                        # Unmasked -- `password` is drawn from the
                        # public `credential_pairs` wordlist, same
                        # reasoning as `_technique_default_credentials`.
                        request_raw=f'POST {login_url}\nContent-Type: application/json\n\n{{"username": "{username}", "password": "{password}"}}',
                        response_raw=f"HTTP {status}, {preview}",
                        description=f"The admin interface at '{admin_url}' accepted the default credential pair '{username}'/'{password}'.",
                        recommendation="Remove default admin accounts and restrict admin interfaces to a trusted network.",
                    )
                    finding.evidence_refs = await self._capture(evidence, finding)
                    return finding
                return None

            findings = await asyncio.gather(*(_check_admin_url(url) for url in reachable_admin_paths))
            finding = first_not_none(findings)
            if finding is not None:
                return self._result("TC-022", tid, technique, vuln_type, FAIL, finding.description, finding=finding)
            return self._result("TC-022", tid, technique, vuln_type, PASS, f"{len(reachable_admin_paths)} reachable admin path(s) found, but no default credential pair was accepted")
        finally:
            await anon_context.close()

    async def _technique_default_api_keys(self, endpoints, session_pool) -> TestCaseResult:
        tid, technique = "TC-022.4", "Default API keys or service tokens left unrotated"
        vuln_type = "Default API Key/Token in Use"
        base_url = endpoints[0].url if endpoints else None
        if not base_url:
            return self._result("TC-022", tid, technique, vuln_type, SKIPPED, "no endpoint/base URL available to probe")
        origin = base_url.split("/#/")[0].rstrip("/")

        anon_context = await session_pool.new_anonymous_context()
        try:
            async def _check_config_path(path: str) -> "Finding | None":
                url = f"{origin}{path}"
                probe = await self._probe_get(anon_context, url)
                if probe is None:
                    return None
                status, body = probe
                if status != 200:
                    return None
                for pattern in _API_KEY_PATTERNS:
                    if re.search(pattern, body):
                        return Finding(
                            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
                            endpoint=_synthetic_endpoint(url, "GET"), user_role="unauthenticated",
                            request_raw=f"GET {url}", response_raw=f"HTTP {status}, API-key-shaped value found in response body",
                            description=f"'{url}' is publicly reachable and its response contains what looks like a live API key or secret.",
                            recommendation="Remove exposed config files from the web root, and rotate any credential that was ever publicly reachable.",
                        )
                return None

            findings = await asyncio.gather(*(_check_config_path(path) for path in _CONFIG_EXPOSURE_PATHS))
            finding = first_not_none(findings)
            if finding is not None:
                return self._result("TC-022", tid, technique, vuln_type, FAIL, finding.description, finding=finding)
            return self._result("TC-022", tid, technique, vuln_type, PASS, f"none of {len(_CONFIG_EXPOSURE_PATHS)} common config-exposure paths leaked an API-key-shaped value")
        finally:
            await anon_context.close()

    async def _technique_login_enumeration(self, endpoints, session_pool, evidence) -> TestCaseResult:
        """TC-022.5 -- login-endpoint username enumeration
        (`login_username_enumeration` in `auth_knowledge_base.json`):
        PortSwigger/bug-bounty methodology guides agree the LOGIN
        endpoint's own response differential is the single most common
        disclosed enumeration location, more common than the
        reset-endpoint variant TC-027.5 already covers. Submits (a) a
        known-valid username (`AuthTestConfig.test_username`) with a
        deliberately wrong password, and (b) a definitely-invalid
        username with the same wrong password, then compares status,
        body content/length, and timing between the two. Read-only (two
        failed login attempts, neither succeeds) -- no
        `allow_state_changing_probes` gate needed, same as
        `_technique_reset_enumeration`'s own precedent for the identical
        reason. Never overclaims: a finding names the specific differing
        signal and states only that enumeration "is possible", never
        that a specific credential was confirmed valid."""
        test_id, tid = "TC-022", "TC-022.5"
        technique = "Username enumeration via the login endpoint's own response differential"
        vuln_type = "Login Endpoint Account Enumeration"
        if not self.config.test_username:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no test_username configured to use as a known-valid username")

        login_endpoint = None
        login_url = self.config.login_json_endpoint
        if not login_url:
            login_endpoint = find_login_endpoint(endpoints)
            if login_endpoint is None:
                return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                     "no JSON login endpoint configured (target.jwt_token_url), and no discovered "
                                     "HTML login form to fall back to")

        fake_username = "stof-nonexistent-user-9f3a@example.invalid"
        wrong_password = "definitely-Wrong-Pw1!"

        anon_context = await session_pool.new_anonymous_context()
        try:
            if login_endpoint is not None:
                probed = await self._login_enumeration_via_form(anon_context, login_endpoint, fake_username, wrong_password)
                probed_url, probed_endpoint = login_endpoint.url, login_endpoint
            else:
                probed = await self._login_enumeration_via_json(anon_context, login_url, fake_username, wrong_password)
                probed_url, probed_endpoint = login_url, _synthetic_endpoint(login_url, "POST")
        finally:
            await anon_context.close()

        if probed is None:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "discovered login form is missing an expected username/password field")
        if probed == "ERROR":
            return self._result(test_id, tid, technique, vuln_type, "ERROR", "one of the two login probes failed (network/request error) -- could not test")

        (valid_status, valid_body, valid_elapsed), (invalid_status, invalid_body, invalid_elapsed) = probed

        differences: list[str] = []
        if valid_status != invalid_status:
            differences.append(f"HTTP status differs ({valid_status} for the known-valid username vs. {invalid_status} for a nonexistent one)")
        if len(valid_body) != len(invalid_body):
            differences.append(f"response body length differs ({len(valid_body)} bytes vs. {len(invalid_body)} bytes)")
        timing_delta = abs(valid_elapsed - invalid_elapsed)
        if timing_delta >= 1.0:
            differences.append(f"response timing differs by ~{timing_delta:.2f}s ({valid_elapsed:.2f}s vs. {invalid_elapsed:.2f}s)")

        if not differences:
            return self._result(test_id, tid, technique, vuln_type, PASS,
                                 f"a known-valid username with a wrong password and a nonexistent username produced "
                                 f"indistinguishable responses from the login endpoint (both HTTP {valid_status}, "
                                 "same body length, no repeatable timing delta)")

        signal = "; ".join(differences)
        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.3,
            endpoint=probed_endpoint, user_role="unauthenticated",
            request_raw=f"2x POST {probed_url} (known-valid username + wrong password, vs. a nonexistent username + the same wrong password)",
            response_raw=(
                f"valid-username attempt: HTTP {valid_status}, {len(valid_body)} bytes, {valid_elapsed:.2f}s | "
                f"invalid-username attempt: HTTP {invalid_status}, {len(invalid_body)} bytes, {invalid_elapsed:.2f}s"
            ),
            description=(
                f"The login endpoint's own response differs between a known-valid username with a wrong password "
                f"and a nonexistent username: {signal}. This differential signal suggests username enumeration is "
                "possible via the login endpoint; it does not confirm any specific credential as valid."
            ),
            recommendation="Return an identical response (status, body content/length, and timing) for a failed login regardless of whether the submitted username exists.",
            # The description above says so explicitly: this is a
            # behavioral-differential SIGNAL that enumeration is
            # possible, not a confirmed enumeration of any real
            # username -- same confidence-correctness bug class found
            # and fixed across idor_tests.py/xss_tests.py this session.
            confidence="likely",
        )
        finding.evidence_refs = await self._capture(evidence, finding)
        return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)

    async def _login_enumeration_via_form(self, context, endpoint: Endpoint, fake_username: str, wrong_password: str):
        fields = _form_login_fields(endpoint)
        if fields is None:
            return None
        username_param, password_param = fields
        t0 = time.monotonic()
        valid_probe = await send_probe(
            context, endpoint,
            {**{n: placeholder_value(n) for n in endpoint.parameters}, username_param: self.config.test_username, password_param: wrong_password},
            endpoint.location_for(username_param),
        )
        t1 = time.monotonic()
        invalid_probe = await send_probe(
            context, endpoint,
            {**{n: placeholder_value(n) for n in endpoint.parameters}, username_param: fake_username, password_param: wrong_password},
            endpoint.location_for(username_param),
        )
        t2 = time.monotonic()
        if valid_probe is None or invalid_probe is None:
            return "ERROR"
        return (valid_probe[0], valid_probe[1], t1 - t0), (invalid_probe[0], invalid_probe[1], t2 - t1)

    async def _login_enumeration_via_json(self, context, login_url: str, fake_username: str, wrong_password: str):
        t0 = time.monotonic()
        valid_status, valid_body = await _login_attempt_raw(context, login_url, self.config.test_username, wrong_password)
        t1 = time.monotonic()
        invalid_status, invalid_body = await _login_attempt_raw(context, login_url, fake_username, wrong_password)
        t2 = time.monotonic()
        return (valid_status, valid_body, t1 - t0), (invalid_status, invalid_body, t2 - t1)

    # --- TC-025 Weak Password Policy (via authenticated change-password) ---

    async def _try_weak_password_change(self, session_manager, session_pool, evidence, candidate: str,
                                         test_id: str, tid: str, technique: str) -> TestCaseResult:
        vuln_type = "Weak Password Policy"
        if not self.config.allow_state_changing_probes:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "changes the test account's real password and is disabled by default -- "
                                 "set AuthTestConfig.allow_state_changing_probes=True for an authorized engagement window")
        if not (self.config.change_password_url and self.config.test_role and self.config.test_current_password):
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "no change_password_url / test_role / test_current_password configured for this target")

        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.test_role, self.config.change_password_url)
        except KeyError as exc:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        accepted, status = await self._change_password(context, candidate, self.config.test_current_password)
        if not accepted:
            return self._result(test_id, tid, technique, vuln_type, PASS, f"'{candidate}' was rejected by the password-change endpoint (HTTP {status})")

        # A real password change just happened -- track it before
        # anything else runs, so even a crash between here and the
        # revert in `finally` below still leaves an accurate ledger
        # entry (the whole point of persisting at write-time, not
        # batching at scan end).
        cleanup_entry_id = self._register_cleanup(
            tid, kind="password_change", identifier=self.config.test_role or "unknown",
            endpoint_url=self.config.change_password_url, role=self.config.test_role,
            metadata={"probe": "weak_password_policy"},
        )

        # Accepted a weak password -- this IS the finding, PROVIDED the
        # acceptance is real. Revert immediately regardless of what
        # happens next, so the account doesn't stay on a weak password
        # for other modules/runs.
        try:
            confirmed = await self._confirm_password_works(context, candidate)
            if confirmed is False:
                # The same class of false positive TC-053.5 was fixed
                # for: a non-error status here doesn't guarantee the
                # underlying state actually changed. Confirmed here by
                # trying to log in with the candidate password --
                # since that failed, the change-password response was
                # a soft-success wrapper around a rejection, not a
                # real policy bypass.
                return self._result(test_id, tid, technique, vuln_type, PASS,
                                     f"'{candidate}' change-password request returned HTTP {status}, but logging in with "
                                     "it failed -- not a real policy bypass")
            confirmation_note = (
                "CONFIRMED: logging in with the new password succeeded. " if confirmed is True else
                "Unconfirmed via re-login (no login_json_endpoint/test_username configured to verify the change actually "
                "took effect, so this is the change-password endpoint's response alone): "
            )
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
                endpoint=_synthetic_endpoint(self.config.change_password_url, "GET"), user_role=self.config.test_role,
                request_raw=f"(change-password request to {self.config.change_password_url})",
                response_raw=f"HTTP {status} -- new password '{candidate}' accepted",
                description=f"{confirmation_note}The password-change endpoint accepted the weak candidate password '{candidate}' with no apparent policy check.",
                recommendation="Enforce a minimum length/complexity policy, and reject passwords from a common-password list, server-side on every password-set operation.",
                confidence=_confidence_from_relogin(confirmed),
            )
            finding.evidence_refs = await self._capture(evidence, finding)
            return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        finally:
            reverted, revert_status = await self._change_password(context, self.config.test_current_password, candidate)
            if not reverted:
                _log.error(
                    f"COULD NOT REVERT test account '{self.config.test_username}' password after weak-password-policy "
                    f"probe (HTTP {revert_status}) -- it may now be set to '{candidate}'. Manual intervention required."
                )
                self._mark_cleanup_result(cleanup_entry_id, REVERT_FAILED, f"revert POST returned HTTP {revert_status} -- account may still be on the probe password")
            else:
                self._mark_cleanup_result(cleanup_entry_id, REVERTED, "password reverted to its original configured value")

    async def _change_password(self, context, new_password: str, current_password: str) -> tuple[bool, int]:
        """Two request shapes attempted, since REST APIs disagree on
        this one (query-param GET, e.g. Juice Shop's own `/rest/user/
        change-password?current=...&new=...`, vs a JSON POST body) --
        same "try both common shapes, harmless if the target ignores
        one" philosophy as `jwt_auth.py`'s login field names."""
        url = self.config.change_password_url
        try:
            resp = await context.request.get(url, params={"current": current_password, "new": new_password, "repeat": new_password}, max_redirects=0)
            if resp.status < 400:
                return True, resp.status
        except Exception as exc:
            _log.warning(f"GET-style change-password probe failed: {exc}")

        try:
            resp = await context.request.post(
                url, data=json_module.dumps({"currentPassword": current_password, "newPassword": new_password}),
                headers={"Content-Type": "application/json"}, max_redirects=0,
            )
            return resp.status < 400, resp.status
        except Exception as exc:
            _log.warning(f"POST-style change-password probe failed: {exc}")
            return False, 0

    async def _confirm_password_works(self, context, password: str) -> bool | None:
        """Re-authenticate with `password` to confirm a change-password
        endpoint's non-error status reflects a REAL change, not a
        soft-success response wrapping a rejection -- `_change_password`'s
        `resp.status < 400` check alone can't tell those apart, the same
        class of gap TC-053.5 was fixed for. Returns `None` (not `False`)
        when confirmation isn't possible at all -- no login endpoint or
        test username configured -- so callers can tell "confirmed the
        change didn't really happen" apart from "couldn't check"."""
        if not self.config.test_username:
            return None
        return await self._confirm_password_works_for(context, self.config.test_username, password)

    async def _confirm_password_works_for(self, context, username: str, password: str) -> bool | None:
        """Same confirmation as `_confirm_password_works`, generalised to
        an explicit `username` -- TC-027.7 needs to confirm a change
        against the VICTIM account, not `self.config.test_username`."""
        if not self.config.login_json_endpoint:
            return None
        succeeded, _status, _preview = await _try_json_login(context, self.config.login_json_endpoint, username, password)
        return succeeded

    async def _change_password_for_target(self, context, new_password: str, current_password: str, target_field: str, target_value: str) -> tuple[bool, int]:
        """Same two request shapes as `_change_password` (GET query-param
        and JSON POST), with one extra field naming WHOSE account the
        change applies to -- TC-027.7's probe for whether the endpoint
        honors a client-supplied target-user identifier instead of
        always applying the change to the session's own account."""
        url = self.config.change_password_url
        try:
            resp = await context.request.get(
                url, params={"current": current_password, "new": new_password, "repeat": new_password, target_field: target_value},
                max_redirects=0,
            )
            if resp.status < 400:
                return True, resp.status
        except Exception as exc:
            _log.warning(f"GET-style targeted change-password probe failed: {exc}")

        try:
            resp = await context.request.post(
                url, data=json_module.dumps({"currentPassword": current_password, "newPassword": new_password, target_field: target_value}),
                headers={"Content-Type": "application/json"}, max_redirects=0,
            )
            return resp.status < 400, resp.status
        except Exception as exc:
            _log.warning(f"POST-style targeted change-password probe failed: {exc}")
            return False, 0

    async def _technique_no_previous_password_check(self, session_manager, session_pool, evidence) -> TestCaseResult:
        test_id, tid = "TC-025", "TC-025.5"
        technique, vuln_type = "No check against previous passwords on change", "Weak Password Policy (previous-password reuse)"
        if not self.config.allow_state_changing_probes:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "changes the test account's real password and is disabled by default -- "
                                 "set AuthTestConfig.allow_state_changing_probes=True for an authorized engagement window")
        if not (self.config.change_password_url and self.config.test_role and self.config.test_current_password):
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "no change_password_url / test_role / test_current_password configured for this target")

        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.test_role, self.config.change_password_url)
        except KeyError as exc:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        original = self.config.test_current_password
        probe = "TempReuseProbe!99"
        # Must exist before `try` -- `finally` below references it on
        # EVERY exit path, including the one where step1 itself fails
        # and nothing was ever actually planted/changed yet.
        cleanup_entry_id = None
        try:
            # original -> probe -> original -> probe again (should be
            # rejected as an immediately-previous password if the
            # target enforces reuse prevention).
            step1, _ = await self._change_password(context, probe, original)
            if not step1:
                return self._result(test_id, tid, technique, vuln_type, "ERROR", "setup step (original -> probe) itself failed -- can't test reuse prevention")
            # Real state change just happened -- track it before the
            # rest of this multi-step dance runs, so a crash anywhere
            # in the remaining steps still leaves an accurate ledger
            # entry covering the whole sequence's final `finally` revert.
            cleanup_entry_id = self._register_cleanup(
                tid, kind="password_change", identifier=self.config.test_role or "unknown",
                endpoint_url=self.config.change_password_url, role=self.config.test_role,
                metadata={"probe": "previous_password_reuse"},
            )
            step2, _ = await self._change_password(context, original, probe)
            if not step2:
                _log.error(f"COULD NOT REVERT test account '{self.config.test_username}' after reuse-check setup -- it may now be '{probe}'. Manual intervention required.")
                return self._result(test_id, tid, technique, vuln_type, "ERROR", "setup step (probe -> original) failed; account may be left on the probe password")

            reused, reuse_status = await self._change_password(context, probe, original)
            if not reused:
                return self._result(test_id, tid, technique, vuln_type, PASS, f"reusing the immediately-previous password was rejected (HTTP {reuse_status})")

            confirmed = await self._confirm_password_works(context, probe)
            if confirmed is False:
                return self._result(test_id, tid, technique, vuln_type, PASS,
                                     f"reuse request returned HTTP {reuse_status}, but logging in with '{probe}' failed -- "
                                     "not a real reuse-prevention bypass")
            confirmation_note = (
                "CONFIRMED: logging in with the reused password succeeded. " if confirmed is True else
                "Unconfirmed via re-login (no login_json_endpoint/test_username configured): "
            )
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=4.3,
                endpoint=_synthetic_endpoint(self.config.change_password_url, "GET"), user_role=self.config.test_role,
                request_raw=f"(sequential change-password calls: original -> '{probe}' -> original -> '{probe}' again)",
                response_raw=f"HTTP {reuse_status} -- immediately-previous password accepted again",
                description=f"{confirmation_note}The password-change endpoint accepted a password identical to the one just changed away from, with no reuse-prevention check.",
                recommendation="Track a history of recent password hashes and reject a new password that matches any of them.",
                confidence=_confidence_from_relogin(confirmed),
            )
            finding.evidence_refs = await self._capture(evidence, finding)
            return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        finally:
            reverted, revert_status = await self._change_password(context, original, probe)
            if not reverted:
                _log.error(
                    f"COULD NOT REVERT test account '{self.config.test_username}' password after the "
                    f"previous-password-reuse probe (HTTP {revert_status}) -- it may now be '{probe}'. Manual intervention required."
                )
                self._mark_cleanup_result(cleanup_entry_id, REVERT_FAILED, f"final revert POST returned HTTP {revert_status} -- account may still be on the probe password")
            else:
                self._mark_cleanup_result(cleanup_entry_id, REVERTED, "password reverted to its original configured value")

    # --- TC-027 Weak Password Change/Reset --------------------------------

    async def _technique_change_without_current_password(self, session_manager, session_pool, evidence) -> TestCaseResult:
        test_id, tid = "TC-027", "TC-027.4"
        technique, vuln_type = "Change-password doesn't require current password", "Weak Password Change Functionality"
        if not self.config.allow_state_changing_probes:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "changes the test account's real password and is disabled by default -- "
                                 "set AuthTestConfig.allow_state_changing_probes=True for an authorized engagement window")
        if not (self.config.change_password_url and self.config.test_role and self.config.test_current_password):
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "no change_password_url / test_role / test_current_password configured for this target")

        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.test_role, self.config.change_password_url)
        except KeyError as exc:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        probe_password = "TempProbe!2468"
        try:
            resp = await context.request.get(self.config.change_password_url, params={"new": probe_password, "repeat": probe_password}, max_redirects=0)
            accepted, status = resp.status < 400, resp.status
        except Exception as exc:
            return self._result(test_id, tid, technique, vuln_type, "ERROR", f"probe failed: {exc}")

        if not accepted:
            return self._result(test_id, tid, technique, vuln_type, PASS, f"change request without a 'current' password was rejected (HTTP {status})")

        # A real password change just happened -- track it before
        # anything else runs.
        cleanup_entry_id = self._register_cleanup(
            tid, kind="password_change", identifier=self.config.test_role or "unknown",
            endpoint_url=self.config.change_password_url, role=self.config.test_role,
            metadata={"probe": "change_without_current_password"},
        )

        try:
            confirmed = await self._confirm_password_works(context, probe_password)
            if confirmed is False:
                return self._result(test_id, tid, technique, vuln_type, PASS,
                                     f"request returned HTTP {status}, but logging in with '{probe_password}' failed -- "
                                     "not a real bypass")
            confirmation_note = (
                "CONFIRMED: logging in with the new password succeeded. " if confirmed is True else
                "Unconfirmed via re-login (no login_json_endpoint/test_username configured): "
            )
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.1,
                endpoint=_synthetic_endpoint(self.config.change_password_url, "GET"), user_role=self.config.test_role,
                # Unmasked -- `probe_password` is STOF's own hardcoded
                # literal ("TempProbe!2468"), not a secret; it's already
                # printed unmasked in this technique's own PASS-path
                # detail text above, so masking it only here was
                # inconsistent, not protective.
                request_raw=f"GET {self.config.change_password_url}?new={probe_password}&repeat={probe_password} (no 'current' password param)",
                response_raw=f"HTTP {status} -- accepted",
                description=f"{confirmation_note}The password-change endpoint accepted a new password with no current-password parameter supplied at all, letting a hijacked session lock the real owner out permanently.",
                recommendation="Always require and verify the current password (or a freshly-issued step-up credential) before accepting a new one.",
                confidence=_confidence_from_relogin(confirmed),
            )
            finding.evidence_refs = await self._capture(evidence, finding)
            return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        finally:
            reverted, revert_status = await self._change_password(context, self.config.test_current_password, probe_password)
            if not reverted:
                _log.error(
                    f"COULD NOT REVERT test account '{self.config.test_username}' password after the "
                    f"no-current-password-required probe (HTTP {revert_status}) -- it may now be '{probe_password}'. Manual intervention required."
                )
                self._mark_cleanup_result(cleanup_entry_id, REVERT_FAILED, f"revert POST returned HTTP {revert_status} -- account may still be on the probe password")
            else:
                self._mark_cleanup_result(cleanup_entry_id, REVERTED, "password reverted to its original configured value")

    async def _technique_reset_enumeration(self, endpoints, session_pool, evidence) -> TestCaseResult:
        test_id, tid = "TC-027", "TC-027.5"
        technique, vuln_type = "IDOR on the reset endpoint (account enumeration via reset flow)", "Password Reset Account Enumeration"
        if not self.config.victim_email:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no second configured user's email available to compare against")

        login_endpoint = None
        if not self.config.reset_password_request_url:
            # No dedicated JSON reset endpoint configured -- the crawler
            # has no separate "reset form" discovery, so fall back to the
            # discovered HTML LOGIN form itself as the enumeration
            # surface (same differential shape, applied to the closest
            # real surface this target actually exposes) rather than
            # SKIPping outright.
            login_endpoint = find_login_endpoint(endpoints)
            if login_endpoint is None:
                return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                     "no reset_password_request_url configured for this target, and no discovered "
                                     "HTML login form to fall back to")

        anon_context = await session_pool.new_anonymous_context()
        try:
            if login_endpoint is not None:
                fields = _form_login_fields(login_endpoint)
                if fields is None:
                    return self._result(test_id, tid, technique, vuln_type, SKIPPED, "discovered login form is missing an expected username/password field")
                username_param, password_param = fields
                real_status, real_body = await self._request_reset_via_form(anon_context, login_endpoint, username_param, password_param, self.config.victim_email)
                fake_status, fake_body = await self._request_reset_via_form(anon_context, login_endpoint, username_param, password_param, "definitely-not-a-real-user-9f3a@example.invalid")
                probed_url, probed_endpoint = login_endpoint.url, login_endpoint
                surface_note = " (via the discovered HTML login form, since no dedicated reset endpoint is configured for this target)"
            else:
                real_status, real_body = await self._request_reset(anon_context, self.config.victim_email)
                fake_status, fake_body = await self._request_reset(anon_context, "definitely-not-a-real-user-9f3a@example.invalid")
                probed_url = self.config.reset_password_request_url
                probed_endpoint = _synthetic_endpoint(probed_url, "POST")
                surface_note = ""
        finally:
            await anon_context.close()

        if real_status == fake_status and len(real_body) == len(fake_body):
            return self._result(test_id, tid, technique, vuln_type, PASS,
                                 f"reset-request responses for a real vs. a fake email were indistinguishable (both HTTP {real_status}){surface_note}")

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.3,
            endpoint=probed_endpoint, user_role="unauthenticated",
            request_raw=f"2x POST {probed_url} (email/username={self.config.victim_email!r} vs. a nonexistent email){surface_note}",
            response_raw=f"real: HTTP {real_status}, {len(real_body)} bytes | fake: HTTP {fake_status}, {len(fake_body)} bytes",
            description=f"The password-reset request surface{surface_note} responds differently for a real account's email than for a nonexistent one, letting an attacker enumerate valid accounts.",
            recommendation="Return an identical response (status, body, and timing) for the reset-request step regardless of whether the supplied email/username exists.",
        )
        finding.evidence_refs = await self._capture(evidence, finding)
        return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)

    async def _request_reset_via_form(self, context, endpoint: Endpoint, username_param: str, password_param: str, identifier: str) -> tuple[int, str]:
        """Reset-enumeration probe via the discovered login form: submits
        `identifier` as the username with a fixed wrong password, and
        returns the FULL (status, body) -- the differential comparison
        needs the real body length, so this doesn't reuse `_try_form_login`'s
        200-char preview."""
        params = {n: placeholder_value(n) for n in endpoint.parameters}
        params[username_param] = identifier
        params[password_param] = "definitely-Wrong-Pw1!"
        probe = await send_probe(context, endpoint, params, endpoint.location_for(username_param))
        if probe is None:
            return 0, ""
        status, body, _elapsed, _headers = probe
        return status, body

    async def _request_reset(self, context, email: str) -> tuple[int, str]:
        try:
            resp = await context.request.post(
                self.config.reset_password_request_url,
                data=json_module.dumps({"email": email}), headers={"Content-Type": "application/json"}, max_redirects=0,
            )
            return resp.status, await resp.text()
        except Exception as exc:
            return 0, str(exc)

    def _extract_token_field(self, body_text: str) -> str | None:
        try:
            body = json_module.loads(body_text)
        except json_module.JSONDecodeError:
            return None
        if not isinstance(body, dict):
            return None
        for name in _TOKEN_FIELD_NAMES:
            value = body.get(name)
            if isinstance(value, str) and value:
                return value
        return None

    async def _technique_token_predictable(self, session_pool) -> TestCaseResult:
        tid, technique = "TC-027.1", "Reset token is predictable or sequential"
        vuln_type = "Weak Password Reset (predictable token)"
        if not self.config.reset_password_request_url or not self.config.victim_email:
            return self._result("TC-027", tid, technique, vuln_type, SKIPPED, "no reset_password_request_url / victim_email configured for this target")

        anon_context = await session_pool.new_anonymous_context()
        try:
            _status1, body1 = await self._request_reset(anon_context, self.config.victim_email)
            token1 = self._extract_token_field(body1)
            if token1 is None:
                return self._result("TC-027", tid, technique, vuln_type, SKIPPED,
                                     "reset-request response doesn't echo a token/code field -- this target emails the token privately, which this technique can't observe")
            _status2, body2 = await self._request_reset(anon_context, self.config.victim_email)
            token2 = self._extract_token_field(body2)
        finally:
            await anon_context.close()

        if token2 is None:
            return self._result("TC-027", tid, technique, vuln_type, "ERROR", "first request echoed a token but the second one did not")

        predictable = token1 == token2 or (token1.isdigit() and token2.isdigit() and abs(int(token2) - int(token1)) <= 2) or len(token1) < 6
        if predictable:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.1,
                endpoint=_synthetic_endpoint(self.config.reset_password_request_url, "POST"), user_role="unauthenticated",
                request_raw=f"2x POST {self.config.reset_password_request_url} (email={self.config.victim_email!r})",
                response_raw=f"token 1: {token1[:2]}... | token 2: {token2[:2]}...",
                description="Two consecutive reset-token requests for the same account produced identical, sequential, or very short (low-entropy) tokens.",
                recommendation="Generate reset tokens with a cryptographically secure random generator, at least 128 bits of entropy.",
            )
            return self._result("TC-027", tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        return self._result("TC-027", tid, technique, vuln_type, PASS, "two consecutive reset tokens for the same account were distinct and not sequential/short")

    async def _technique_token_not_invalidated(self, session_pool) -> TestCaseResult:
        tid, technique = "TC-027.2", "Reset token isn't invalidated after first use / doesn't expire"
        vuln_type = "Weak Password Reset (token not invalidated)"
        if not (self.config.reset_password_request_url and self.config.reset_password_complete_url and self.config.victim_email):
            return self._result("TC-027", tid, technique, vuln_type, SKIPPED,
                                 "no reset_password_request_url / reset_password_complete_url / victim_email configured for this target")

        anon_context = await session_pool.new_anonymous_context()
        try:
            _status, body = await self._request_reset(anon_context, self.config.victim_email)
            token = self._extract_token_field(body)
            if token is None:
                return self._result("TC-027", tid, technique, vuln_type, SKIPPED, "reset-request response doesn't echo a token/code field to test reuse with")

            probe_password = "TempTokenReuse!42"
            try:
                first_resp = await anon_context.request.post(
                    self.config.reset_password_complete_url,
                    data=json_module.dumps({"token": token, "email": self.config.victim_email, "newPassword": probe_password}),
                    headers={"Content-Type": "application/json"}, max_redirects=0,
                )
                first_status = first_resp.status
                second_resp = await anon_context.request.post(
                    self.config.reset_password_complete_url,
                    data=json_module.dumps({"token": token, "email": self.config.victim_email, "newPassword": probe_password}),
                    headers={"Content-Type": "application/json"}, max_redirects=0,
                )
                second_status = second_resp.status
            except Exception as exc:
                return self._result("TC-027", tid, technique, vuln_type, "ERROR", f"reset-completion probe failed: {exc}")
        finally:
            await anon_context.close()

        if first_status < 400 and second_status < 400:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=6.5,
                endpoint=_synthetic_endpoint(self.config.reset_password_complete_url, "POST"), user_role="unauthenticated",
                request_raw=f"2x POST {self.config.reset_password_complete_url} (same token)",
                response_raw=f"first use: HTTP {first_status} | second use: HTTP {second_status}",
                description="The same password-reset token was accepted twice in a row -- it isn't invalidated after first use.",
                recommendation="Invalidate a reset token the instant it's successfully used, and give it a short absolute expiry regardless of use.",
            )
            return self._result("TC-027", tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        return self._result("TC-027", tid, technique, vuln_type, PASS, f"second use of the same token was rejected (HTTP {second_status})")

    async def _technique_token_referer_leak(self) -> TestCaseResult:
        return self._result("TC-027", "TC-027.3", "Reset token leaks via the Referer header to a third party", "Weak Password Reset", NOT_IMPLEMENTED,
                             "not yet implemented -- needs a real inbox to receive the reset link and click through from a page that sends a Referer header, outside this framework's current scope")

    async def _technique_host_header_injection(self, session_pool) -> TestCaseResult:
        tid, technique = "TC-027.6", "Host-header injection poisons the generated reset link"
        vuln_type = "Weak Password Reset (Host header injection)"
        if not self.config.reset_password_request_url:
            return self._result("TC-027", tid, technique, vuln_type, SKIPPED, "no reset_password_request_url configured for this target")

        victim = self.config.victim_email or "probe@example.com"
        injected_host = "attacker-controlled.invalid"
        anon_context = await session_pool.new_anonymous_context()
        try:
            resp_status, body = None, ""
            try:
                resp = await anon_context.request.post(
                    self.config.reset_password_request_url,
                    data=json_module.dumps({"email": victim}),
                    headers={"Content-Type": "application/json", "X-Forwarded-Host": injected_host, "Host": injected_host},
                    max_redirects=0,
                )
                resp_status = resp.status
                body = await resp.text()
            except Exception as exc:
                return self._result("TC-027", tid, technique, vuln_type, "ERROR", f"probe failed: {exc}")
        finally:
            await anon_context.close()

        if injected_host in body:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
                endpoint=_synthetic_endpoint(self.config.reset_password_request_url, "POST"), user_role="unauthenticated",
                request_raw=f"POST {self.config.reset_password_request_url}\nX-Forwarded-Host: {injected_host}\nHost: {injected_host}",
                response_raw=body[:300],
                description=f"The reset-request response reflects the attacker-controlled Host/X-Forwarded-Host header ('{injected_host}') directly, meaning a generated reset link would point at an attacker's domain.",
                recommendation="Never derive a reset link's domain from a client-supplied Host/X-Forwarded-Host header; use a fixed, server-side-configured base URL.",
            )
            return self._result("TC-027", tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        return self._result("TC-027", tid, technique, vuln_type, PASS,
                             f"HTTP {resp_status} response doesn't reflect an injected Host header -- note this only checks the API response itself, not the eventual emailed link, which this framework can't observe")

    async def _technique_horizontal_password_change(self, session_manager, session_pool, evidence) -> TestCaseResult:
        """TC-027.7 -- distinct from both TC-027.4 (does changing MY OWN
        password require MY OWN current password?) and TC-027.5 (does
        the UNAUTHENTICATED reset-REQUEST step leak whether an email is
        registered?): this asks whether an AUTHENTICATED session can
        redirect a password change onto a DIFFERENT account by supplying
        a target-user identifier the endpoint shouldn't honor at all --
        the real, reported vulnerability shape ("Account Takeover via
        Unauthorized Password Modification") this project's own
        cross-referenced pentest report flagged that neither existing
        TC-027 technique covers.

        The attacker's own `current` field is always filled with
        `test_current_password` (a real, valid value) -- this technique
        deliberately holds "does the endpoint require a valid current
        password" CONSTANT and varies ONLY the target-identifier field,
        so a FAIL here is unambiguously the IDOR-via-target-field class,
        never a re-detection of TC-027.4's separate gap.

        Requires a SECOND, fully STOF-controlled test account (`victim_
        email` + `victim_current_password`, its own real, known
        password) before running at all -- a successful bypass changes
        THAT account's real password, and unlike every other technique
        in this file, STOF cannot revert a change on an account it
        wasn't already authenticated as, unless it already knows that
        account's own original password to log in and change it back."""
        test_id, tid = "TC-027", "TC-027.7"
        technique = "Password-change endpoint honors a client-supplied target-user identifier (horizontal account takeover)"
        vuln_type = "Account Takeover via Unauthorized Password Modification"
        if not self.config.allow_state_changing_probes:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "changes a second, victim test account's real password and is disabled by default -- "
                                 "set AuthTestConfig.allow_state_changing_probes=True for an authorized engagement window")
        if not (self.config.change_password_url and self.config.test_role and self.config.test_current_password):
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "no change_password_url / test_role / test_current_password configured for this target")
        if not (self.config.victim_email and self.config.victim_current_password):
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "no victim_email / victim_current_password configured -- this technique needs a second, fully "
                                 "STOF-controlled test account whose own original password is known, so a successful bypass "
                                 "can be safely reverted")

        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.test_role, self.config.change_password_url)
        except KeyError as exc:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        probe_password = "TargetProbe!3579"
        tried: list[str] = []
        for target_field in _TARGET_USER_FIELD_CANDIDATES:
            tried.append(target_field)
            result = await self._probe_horizontal_password_change_candidate(
                context, evidence, test_id, tid, technique, vuln_type, target_field, probe_password)
            if result is not None:
                return result
        return self._result(test_id, tid, technique, vuln_type, PASS,
                             f"tried {len(tried)} candidate target-identifier field name(s) ({', '.join(tried)}) on the "
                             "password-change endpoint; none redirected the change onto the victim account")

    async def _probe_horizontal_password_change_candidate(
        self, context, evidence, test_id: str, tid: str, technique: str, vuln_type: str, target_field: str, probe_password: str,
    ) -> TestCaseResult | None:
        """One candidate field name's worth of TC-027.7's loop, extracted
        so that method drops to setup + orchestration only. Returns
        `None` to keep trying the next candidate; returns a FAIL result
        (after reverting) the moment one candidate actually redirects
        the change onto the victim account."""
        accepted, status = await self._change_password_for_target(
            context, probe_password, self.config.test_current_password, target_field, self.config.victim_email)
        if not accepted:
            return None
        confirmed = await self._confirm_password_works_for(context, self.config.victim_email, probe_password)
        if confirmed is False:
            return None  # accepted at the HTTP layer but didn't actually take effect on the victim account

        # A real password change on the VICTIM account just took effect
        # -- track it before anything else runs.
        cleanup_entry_id = self._register_cleanup(
            tid, kind="password_change", identifier=self.config.victim_email,
            endpoint_url=self.config.change_password_url, role=self.config.test_role,
            metadata={"probe": "horizontal_password_change", "target_field": target_field},
        )

        try:
            confirmation_note = (
                "CONFIRMED: logging in as the victim account with the new password succeeded. " if confirmed is True else
                "Unconfirmed via re-login (no login_json_endpoint configured): "
            )
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.8,
                endpoint=_synthetic_endpoint(self.config.change_password_url, "GET"), user_role=self.config.test_role,
                # `current` stays masked -- `test_current_password` is
                # the operator's real configured test-account secret
                # (from users.json), not a public wordlist value, so it
                # must never be persisted to a report per this project's
                # own "credentials never in code/reports" rule. `new` IS
                # unmasked: `probe_password` is STOF's own hardcoded
                # literal ("TargetProbe!3579"), not a secret.
                request_raw=f"GET/POST {self.config.change_password_url} with current=*** (attacker's own), new={probe_password}, {target_field}={self.config.victim_email!r}",
                response_raw=f"HTTP {status} -- accepted",
                description=(
                    f"{confirmation_note}Authenticated as '{self.config.test_role}', supplying a '{target_field}' parameter "
                    f"identifying a different account ({self.config.victim_email}) on the password-change endpoint changed "
                    "that other account's password -- a horizontal-to-account-takeover IDOR on the password-change flow."
                ),
                recommendation=(
                    "Never accept a client-supplied target-user identifier on a password/credential-change endpoint. Derive "
                    "the account being changed exclusively from the authenticated session/token; ignore any request body or "
                    "query parameter naming a different user."
                ),
                confidence=_confidence_from_relogin(confirmed),
            )
            finding.evidence_refs = await self._capture(evidence, finding)
            return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        finally:
            reverted, revert_status = await self._change_password_for_target(
                context, self.config.victim_current_password, self.config.test_current_password, target_field, self.config.victim_email)
            if not reverted:
                _log.error(
                    f"COULD NOT REVERT victim test account '{self.config.victim_email}' password after the "
                    f"horizontal-password-change probe (HTTP {revert_status}) -- it may now be '{probe_password}'. Manual intervention required."
                )
                self._mark_cleanup_result(cleanup_entry_id, REVERT_FAILED, f"revert POST returned HTTP {revert_status} -- victim account may still be on the probe password")
            else:
                self._mark_cleanup_result(cleanup_entry_id, REVERTED, "victim account password reverted to its original configured value")

    # --- TC-132 Weak Security Question/Answer (WSTG-AUTHN-09) -----------

    async def _technique_weak_security_question(self, endpoints, session_pool, evidence) -> TestCaseResult:
        """Discovery-first, per this technique's own scope: does this
        target's account-recovery/verification flow use security
        questions AT ALL? Most real targets don't (email/SMS OTP has
        mostly replaced the pattern), so the honest, expected outcome
        here is SKIPPED -- that is not a bug, it's this technique
        correctly declining to fabricate a finding against a flow that
        doesn't exist. Only when a security-question-shaped field is
        actually found does it go on to classify the QUESTION text
        against WSTG's own cited low-entropy examples; it never
        attempts to guess or submit an answer."""
        test_id, tid = "TC-132", "TC-132.1"
        technique = "Security question/answer recovery flow uses a low-entropy, guessable question (WSTG-AUTHN-09)"
        vuln_type = "Weak Security Question/Answer"

        candidate_endpoint = next(
            (e for e in endpoints if any(hint in p.lower() for p in e.parameters for hint in _SECURITY_QUESTION_FIELD_HINTS)),
            None,
        )
        if candidate_endpoint is None:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "no discovered form/page has a security-question-shaped field -- this target's "
                                 "account-recovery/verification flow doesn't appear to use security questions at all")

        anon_context = await session_pool.new_anonymous_context()
        try:
            probe = await self._probe_get(anon_context, candidate_endpoint.url)
        finally:
            await anon_context.close()
        if probe is None:
            return self._result(test_id, tid, technique, vuln_type, "ERROR",
                                 f"could not fetch '{candidate_endpoint.url}' to inspect the security question's visible text")
        status, body = probe
        matched = [pattern for pattern in _WEAK_SECURITY_QUESTION_PATTERNS if pattern in body.lower()]
        if not matched:
            return self._result(test_id, tid, technique, vuln_type, PASS,
                                 f"a security-question-shaped field was found at '{candidate_endpoint.url}' (HTTP {status}), but its "
                                 f"visible question text didn't match any of {len(_WEAK_SECURITY_QUESTION_PATTERNS)} known low-entropy "
                                 "question patterns -- no answer-guessing was attempted")

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.3,
            endpoint=candidate_endpoint, user_role="unauthenticated",
            request_raw=f"GET {candidate_endpoint.url}",
            response_raw=f"HTTP {status}, matched known-weak question pattern(s): {', '.join(matched)}",
            description=(
                f"The account-recovery/verification flow at '{candidate_endpoint.url}' offers a security question matching "
                f"a known low-entropy pattern ('{matched[0]}'-style). WSTG-AUTHN-09 flags this class of question as "
                "inherently guessable (a small, enumerable, or publicly-researchable answer space) regardless of the "
                "specific answer configured -- this finding is limited to the QUESTION itself being low-entropy; no "
                "answer was guessed or submitted."
            ),
            recommendation=(
                "Retire security-question-based recovery in favor of a verified channel (email/SMS OTP); if a security "
                "question must be kept, require a self-authored question with an effectively unlimited answer space, "
                "and rate-limit/lock out repeated verification attempts the same as a password field."
            ),
        )
        finding.evidence_refs = await self._capture(evidence, finding)
        return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)

    # --- TC-133 Authentication Schema Bypass (WSTG-AUTHN-04) -------------

    async def _technique_auth_schema_bypass(self, endpoints, session_pool, evidence) -> TestCaseResult:
        """Distinct from this project's existing IDOR/BFLA
        forced-browsing techniques: those test whether an
        AUTHENTICATED-but-wrong-role caller can reach a function
        (authoriZation). This tests whether the AUTHENTICATION check
        itself can be dodged by varying the REQUEST's shape alone --
        case, trailing separators, a `;jsessionid=` path parameter, a
        null byte -- with no valid session at all. Takes a small,
        bounded set of already-discovered auth-required endpoints;
        skips any endpoint whose unmodified URL is already anonymously
        reachable (that's a plain forced-browsing gap, not a
        schema-bypass one) rather than counting it as a false PASS."""
        test_id, tid = "TC-133", "TC-133.1"
        technique = "Auth-gated endpoint reachable anonymously via request-shape variation, not identity (WSTG-AUTHN-04)"
        vuln_type = "Authentication Schema Bypass"

        candidates = [e for e in endpoints if e.auth_required and e.method.upper() == "GET"][:_MAX_SCHEMA_BYPASS_CANDIDATES]
        if not candidates:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "no discovered auth-required GET endpoint available to probe")

        anon_context = await session_pool.new_anonymous_context()
        try:
            async def _check_candidate(endpoint) -> "tuple[bool, Finding | None]":
                """One endpoint's own baseline + shape-variant sweep --
                split out so different endpoints can run concurrently.
                Returns `(was_checked, finding_or_None)`."""
                baseline = await self._probe_get(anon_context, endpoint.url)
                if baseline is None:
                    return False, None
                baseline_status, baseline_body = baseline
                if not _looks_anonymously_denied(baseline_status, baseline_body):
                    return False, None  # already reachable anonymously as-is -- a forced-browsing/BFLA gap, not this technique's case
                for label, variant_url in _schema_bypass_variants(endpoint.url):
                    variant_probe = await self._probe_get(anon_context, variant_url)
                    if variant_probe is None:
                        continue
                    variant_status, variant_body = variant_probe
                    if not _looks_anonymously_bypassed(variant_status, variant_body):
                        continue
                    finding = Finding(
                        module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.1,
                        endpoint=endpoint, user_role="unauthenticated",
                        request_raw=f"GET {variant_url}  (baseline: GET {endpoint.url} -> HTTP {baseline_status}, correctly denied)",
                        response_raw=f"HTTP {variant_status}, authenticated-looking content returned with no session at all",
                        description=(
                            f"'{endpoint.url}' correctly denies an anonymous request, but its '{label}' request-shape "
                            f"variant ('{variant_url}') returns authenticated-looking content to a completely "
                            "unauthenticated caller. The authentication check itself is bypassed by the request's SHAPE "
                            "alone -- no valid session, credential, or identity was ever presented."
                        ),
                        recommendation=(
                            "Normalize/canonicalize the request path (case, trailing separators, path parameters, "
                            "encoded characters) BEFORE the authentication check runs, so no shape variant of an "
                            "auth-gated URL bypasses it -- ideally by enforcing auth at a layer (reverse proxy/gateway) "
                            "that sees the same canonicalized path the application does."
                        ),
                    )
                    finding.evidence_refs = await self._capture(evidence, finding)
                    return True, finding
                return True, None

            results = await asyncio.gather(*(_check_candidate(endpoint) for endpoint in candidates))
            checked = sum(1 for was_checked, _finding in results if was_checked)
            finding = first_not_none(f for _was_checked, f in results)
            if finding is not None:
                return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)

            if checked == 0:
                return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                     f"none of {len(candidates)} candidate auth-required endpoint(s) correctly denied an anonymous "
                                     "baseline request to compare shape variants against (already reachable anonymously, or the "
                                     "baseline probe itself failed)")
            return self._result(test_id, tid, technique, vuln_type, PASS,
                                 f"checked {checked} auth-required endpoint(s) whose anonymous baseline correctly denies access; "
                                 "none of their request-shape variants (case, trailing slash/dot, jsessionid/null-byte suffix) bypassed it")
        finally:
            await anon_context.close()

    async def run_techniques(
        self,
        endpoints: list["Endpoint"],
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[TestCaseResult]:
        results: list[TestCaseResult] = []
        results.append(await self._safe_result(
            self._technique_default_credentials(endpoints, session_pool, evidence),
            "TC-022", "TC-022.1", "Common default-credential pairs (admin/admin, admin/password, ...)",
            "Authentication Weakness Tests", role=self.config.test_role))
        results.append(await self._safe_result(
            self._technique_vendor_defaults(endpoints, session_pool, evidence),
            "TC-022", "TC-022.2", "Vendor/product-specific defaults from a known-defaults list",
            "Authentication Weakness Tests", role=self.config.test_role))
        results.append(await self._safe_result(
            self._technique_admin_interface_defaults(session_pool, evidence),
            "TC-022", "TC-022.3", "Default creds on exposed admin/management interfaces",
            "Authentication Weakness Tests", role=self.config.test_role))
        results.append(await self._safe_result(
            self._technique_default_api_keys(endpoints, session_pool),
            "TC-022", "TC-022.4", "Default API keys or service tokens left unrotated",
            "Authentication Weakness Tests", role=self.config.test_role))
        results.append(await self._safe_result(
            self._technique_login_enumeration(endpoints, session_pool, evidence),
            "TC-022", "TC-022.5", "Username enumeration via the login endpoint's own response differential",
            "Authentication Weakness Tests", role=self.config.test_role))

        results.append(await self._safe_result(
            self._try_weak_password_change(session_manager, session_pool, evidence, self.config.short_passwords[0], "TC-025", "TC-025.1", "Accepts short passwords (<8 chars)"),
            "TC-025", "TC-025.1", "Accepts short passwords (<8 chars)",
            "Authentication Weakness Tests", role=self.config.test_role))
        results.append(await self._safe_result(
            self._try_weak_password_change(session_manager, session_pool, evidence, self.config.common_breached_passwords[0], "TC-025", "TC-025.2", "Accepts common/breached passwords (rockyou-class list)"),
            "TC-025", "TC-025.2", "Accepts common/breached passwords (rockyou-class list)",
            "Authentication Weakness Tests", role=self.config.test_role))
        username_as_password = self.config.test_username or "testuser"
        results.append(await self._safe_result(
            self._try_weak_password_change(session_manager, session_pool, evidence, username_as_password, "TC-025", "TC-025.3", "Accepts password identical to username/email"),
            "TC-025", "TC-025.3", "Accepts password identical to username/email",
            "Authentication Weakness Tests", role=self.config.test_role))
        results.append(await self._safe_result(
            self._try_weak_password_change(session_manager, session_pool, evidence, _NO_COMPLEXITY_PASSWORD, "TC-025", "TC-025.4", "No complexity requirement enforced"),
            "TC-025", "TC-025.4", "No complexity requirement enforced",
            "Authentication Weakness Tests", role=self.config.test_role))
        results.append(await self._safe_result(
            self._technique_no_previous_password_check(session_manager, session_pool, evidence),
            "TC-025", "TC-025.5", "No check against previous passwords on change",
            "Authentication Weakness Tests", role=self.config.test_role))

        results.append(await self._safe_result(
            self._technique_token_predictable(session_pool),
            "TC-027", "TC-027.1", "Reset token is predictable or sequential",
            "Authentication Weakness Tests", role=self.config.test_role))
        results.append(await self._safe_result(
            self._technique_token_not_invalidated(session_pool),
            "TC-027", "TC-027.2", "Reset token isn't invalidated after first use / doesn't expire",
            "Authentication Weakness Tests", role=self.config.test_role))
        results.append(await self._technique_token_referer_leak())
        results.append(await self._safe_result(
            self._technique_change_without_current_password(session_manager, session_pool, evidence),
            "TC-027", "TC-027.4", "Change-password doesn't require current password",
            "Authentication Weakness Tests", role=self.config.test_role))
        results.append(await self._safe_result(
            self._technique_reset_enumeration(endpoints, session_pool, evidence),
            "TC-027", "TC-027.5", "IDOR on the reset endpoint (account enumeration via reset flow)",
            "Authentication Weakness Tests", role=self.config.test_role))
        results.append(await self._safe_result(
            self._technique_host_header_injection(session_pool),
            "TC-027", "TC-027.6", "Host-header injection poisons the generated reset link",
            "Authentication Weakness Tests", role=self.config.test_role))
        results.append(await self._safe_result(
            self._technique_horizontal_password_change(session_manager, session_pool, evidence),
            "TC-027", "TC-027.7", "Password-change endpoint honors a client-supplied target-user identifier (horizontal account takeover)",
            "Authentication Weakness Tests", role=self.config.test_role))

        results.extend(await self._techniques_tc129(endpoints, session_manager, session_pool, evidence))

        results.append(await self._safe_result(
            self._technique_weak_security_question(endpoints, session_pool, evidence),
            "TC-132", "TC-132.1", "Security question/answer recovery flow uses a low-entropy, guessable question (WSTG-AUTHN-09)",
            "Authentication Weakness Tests", role=self.config.test_role))
        results.append(await self._safe_result(
            self._technique_auth_schema_bypass(endpoints, session_pool, evidence),
            "TC-133", "TC-133.1", "Auth-gated endpoint reachable anonymously via request-shape variation, not identity (WSTG-AUTHN-04)",
            "Authentication Weakness Tests", role=self.config.test_role))
        return results
