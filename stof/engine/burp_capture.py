"""Layer 3C (extension) — best-effort request/response capture via
Burp's intercepting PROXY, for findings STOF's own modules already
confirmed. Separate from `burp_controller.py` (which drives Burp's
REST API to run/poll an Active Scan) — this sends one request through
Burp's proxy listener so:

  1. Burp's own Proxy history gets a real, inspectable/replayable copy
     of the traffic for the operator, and
  2. STOF appends a real captured request/response (full headers, real
     body) onto the finding's own evidence, alongside whatever the
     technique's own request_raw/response_raw preview already said.

**Append, never replace** — a real bug from the first live run against
demo.testfire.net: overwriting `request_raw` outright destroyed the
one thing that actually mattered for a SQLi login-bypass finding (the
exact injection payload used), because the naive replayed request sent
no body at all and got back an ordinary 200 login page instead of
anything resembling the original evidence. Fixed two ways: this module
now parses and resends the real payload (see `_extract_request_parts`),
and even so it appends its capture under a clearly labeled section
rather than ever overwriting the technique's own text again.

**Authenticated replay, not a blind curl.** A real gap found via user
report: the capture used to open a bare, cookie-less
`playwright.request.new_context()` -- for anything gated behind login
(every IDOR/BOLA finding is), that just replays as an anonymous
request and gets back a login page or a 401/403, not the actual
evidenced response. That "capture" told a human reviewer nothing about
whether the finding was real; it was no more trustworthy than pasting
the same URL into `curl` by hand. Fixed by threading the real `Session`
(cookies + headers) STOF actually used for the finding into the
Burp-proxied request context via `storage_state`/`extra_http_headers` —
see `_authenticated_request_context`. For an IDOR/BOLA finding with a
cross-session confirmation (`Finding.confirmed_role` set), BOTH
identities' real, authenticated requests are sent through Burp's proxy
back-to-back (see `_capture_both_identities`) so a human opening Burp's
Proxy history sees two real, side-by-side responses -- the same object,
two different real sessions -- and can judge in seconds whether the
authorization gap is genuine, without needing Burp's own Active
Scanner (which has no cross-identity authorization-differential check
to run in the first place -- see `BurpConfig`'s own docstring on why
`run_active_scan` is a separate, bigger thing).

Honest scope, still true after the payload-sending fix: this sends a
REPRESENTATIVE request to the same endpoint/method/params (parsed from
the finding's own request_raw preview, which every module already
builds as `f"{method} {url}\\n{param}={value!r}..."`) — not a literal
byte-for-byte replay of whatever the technique originally sent over
however many requests it actually took (a technique that compares two
requests, e.g. boolean-blind SQLi's true/false pair, only gets one
representative capture here, not both). Getting byte-for-byte replay
of every technique's exact request sequence would mean refactoring how
every module builds and sends its probes — a much larger change than
what was asked for.

Also why this reads Playwright's own view of the round-trip rather
than querying Burp's REST API for what it captured: Burp Suite
Professional's classic REST API (the one `burp_controller.py` already
integrates) is scan/issue-focused -- it has no general "give me this
proxy-history entry" endpoint to pull a capture back after the fact.
Sending it through Burp's proxy is what gets it into Burp's UI; reading
it here is how STOF gets it into its own Finding.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from stof.core.logger import get_logger

if TYPE_CHECKING:
    from playwright.async_api import Playwright

    from stof.findings.models import Finding
    from stof.session.models import Session
    from stof.session.session_manager import SessionManager

_log = get_logger("engine.burp_capture")

_METHOD_URL_RE = re.compile(r"^([A-Z]+)\s+(\S+)")
_PARAM_TOKEN_RE = re.compile(r"([A-Za-z0-9_\[\].-]+)=('[^']*'|\"[^\"]*\"|\*+|[^&\s]+)")
_SUPPORTED_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_BODY_METHODS = {"post", "put", "patch"}


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _extract_request_parts(request_raw: str) -> tuple[str, str, dict[str, str]] | None:
    """Parses `(method, url, params)` from a finding's own request_raw
    preview. `params` comes from a second line shaped like
    `key=value&key2=value2` (every module that includes one uses this
    convention -- see e.g. sqli_tests.py's `uid={payload!r}&passw=***`)
    -- an empty dict, not a failure, when there's no such line (plenty
    of techniques are single-line GETs with the payload already in the
    URL itself)."""
    lines = (request_raw or "").strip().splitlines()
    if not lines:
        return None
    match = _METHOD_URL_RE.match(lines[0])
    if not match:
        return None
    method, url = match.group(1).upper(), match.group(2)

    params: dict[str, str] = {}
    if len(lines) > 1:
        for token_match in _PARAM_TOKEN_RE.finditer(lines[1]):
            key, value = token_match.group(1), _unquote(token_match.group(2))
            params[key] = value
    return method, url, params


def _browser_like_headers(url: str) -> dict[str, str]:
    """A representative desktop-Chrome header set STOF actually sends
    (not reconstructed after the fact) -- deliberately explicit rather
    than left to Playwright's bare defaults, so what's *displayed*
    matches what was *sent*, byte for byte, unlike the earlier version
    of this module which could only show method+URL because it tried
    to read headers back off a Playwright `APIResponse` (which has no
    such back-reference to its own request)."""
    host = urlsplit(url).netloc
    return {
        "Host": host,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Connection": "close",
    }


def _session_auth_headers(session: "Session | None") -> dict[str, str]:
    """Real auth material to actually SEND, from the same `Session` a
    vulnerability module already authenticated with -- a `Cookie`
    header built from `session.cookies` (the browser-context cookie
    jar every technique's own probe already carried) plus whatever
    `session.headers` holds (e.g. a JWT's `Authorization: Bearer ...`).
    Without this, a Burp-proxied replay of any login-gated finding is
    indistinguishable from an anonymous request -- it captures a login
    page or a 401/403, not the actual evidenced response. Empty dict
    for `session=None`, which callers use for a finding with no known
    session (unauthenticated-by-design findings, or Burp evidence
    capture running without a `SessionManager` at all)."""
    if session is None:
        return {}
    headers: dict[str, str] = {}
    if session.cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
    headers.update(session.headers)
    return headers


async def capture_via_burp(
    playwright: "Playwright",
    proxy_url: str,
    finding: "Finding",
    timeout_s: float = 30.0,
    session: "Session | None" = None,
) -> tuple[str, str] | None:
    """Returns `(request_text, response_text)` captured via Burp's
    proxy, or `None` on any failure -- Burp not running, wrong proxy
    port, network error, or a `request_raw` that doesn't parse. Never
    raises: a missing/unreachable Burp must never block a scan or drop
    a finding.

    `session`, when given, makes this an AUTHENTICATED replay (see
    `_session_auth_headers`) -- the real identity that produced this
    evidence, not a bare anonymous request. Omit it only when no
    session is known for this finding; the capture still runs, just
    without real cookies/auth, same as before this parameter existed."""
    parsed = _extract_request_parts(finding.request_raw)
    if parsed is None:
        _log.warning(f"finding '{finding.finding_id}': could not parse a method/URL from request_raw -- skipping Burp capture")
        return None
    method, url, params = parsed
    method_lower = method.lower()
    if method_lower not in _SUPPORTED_METHODS:
        _log.warning(f"finding '{finding.finding_id}': unsupported method '{method}' for Burp capture -- skipping")
        return None
    # Real bug this guards against: a technique that deliberately masks
    # a genuine secret in `request_raw` (e.g. an operator's real
    # configured test-account password -- never a public wordlist value,
    # those are unmasked on purpose) has that masked placeholder parsed
    # out and sent HERE as the literal, non-functional string -- which
    # then correctly gets rejected by the target, producing a captured
    # "evidence" response that flatly contradicts the finding's own real
    # result. A human reviewer (or an end user replaying the captured
    # request in Burp) has no way to tell "this specific replay used a
    # masked placeholder" from "this finding is a false positive" --
    # eroding trust in a true positive. Skip the replay outright rather
    # than silently produce evidence that lies about the outcome; the
    # technique's own `request_raw`/`response_raw` preview (already
    # appended to the finding) remains the record of what actually
    # happened.
    if any(v.strip("*") == "" and v for v in params.values()):
        _log.warning(
            f"finding '{finding.finding_id}': request_raw contains a masked ('***') credential value -- "
            "skipping Burp capture rather than replaying a non-functional placeholder as if it were real"
        )
        return None

    headers = _browser_like_headers(url)
    headers.update(_session_auth_headers(session))
    call_kwargs: dict[str, Any] = {"headers": headers}
    body_line = ""
    if params and method_lower in _BODY_METHODS:
        call_kwargs["form"] = params
        body_line = "\n" + "&".join(f"{k}={v}" for k, v in params.items())

    try:
        context = await playwright.request.new_context(
            proxy={"server": proxy_url}, ignore_https_errors=True, timeout=timeout_s * 1000,
        )
    except Exception as exc:
        _log.warning(f"could not open a Burp-proxied connection at {proxy_url}: {exc}")
        return None

    try:
        request_fn = getattr(context, method_lower)
        resp = await request_fn(url, **call_kwargs)

        header_block = "\n".join(f"{k}: {v}" for k, v in headers.items())
        identity_note = f" (role '{session.role}')" if session is not None else " (no session -- unauthenticated replay)"
        request_text = f"{method} {url}{identity_note}\n{header_block}{body_line}"

        response_headers = "\n".join(f"{k}: {v}" for k, v in (resp.headers or {}).items())
        body_text = await resp.text()
        response_text = f"HTTP {resp.status}\n{response_headers}\n\n{body_text[:4000]}"

        _log.info(f"finding '{finding.finding_id}': captured via Burp{identity_note} -- {method} {url} -> HTTP {resp.status}")
        return request_text, response_text
    except Exception as exc:
        _log.warning(f"finding '{finding.finding_id}': Burp capture request failed for {method} {url}: {exc}")
        return None
    finally:
        await context.dispose()


def _burp_section_header(role: str | None) -> str:
    label = f" (role: {role}, authenticated)" if role else ""
    return f"\n\n--- Captured via Burp proxy{label} (representative request, see above for the technique's own record) ---\n"


async def _capture_and_append(
    playwright: "Playwright", proxy_url: str, finding: "Finding", session: "Session | None", role: str | None,
) -> bool:
    """One identity's capture-and-append, shared by both the primary
    and (when present) cross-session-confirming identity below --
    same append-never-replace rule as the rest of this module, each
    identity gets its own clearly labeled section rather than
    overwriting the other's."""
    result = await capture_via_burp(playwright, proxy_url, finding, session=session)
    if result is None:
        return False
    burp_request, burp_response = result
    finding.request_raw = finding.request_raw + _burp_section_header(role) + burp_request
    finding.response_raw = finding.response_raw + _burp_section_header(role) + burp_response
    return True


async def capture_findings_via_burp(
    playwright: "Playwright",
    proxy_url: str,
    findings: list["Finding"],
    session_manager: "SessionManager | None" = None,
    click_echo=None,
) -> int:
    """Appends a Burp-captured request/response section onto each
    finding's request_raw/response_raw where capture succeeds -- never
    replaces the technique's own text, so whatever specific evidence
    the technique itself recorded (the exact payload, the exact
    comparison it made) always survives alongside the fuller capture.
    Returns the number of findings enriched.

    `session_manager`, when given, makes every capture an AUTHENTICATED
    replay using that finding's own real `user_role` session (see
    `capture_via_burp`'s `session` parameter) -- `SessionManager.
    peek_session()` reads the already-live, already-authenticated
    session from the scan that just ran, no new auth attempted. When a
    finding also carries `confirmed_role` (an IDOR/BOLA finding that a
    second, genuinely different identity independently confirmed --
    see `idor_tests.py`'s `_confirm_cross_session`), that SECOND
    identity's real authenticated request is captured too and appended
    as its own labeled section: a human opening Burp's Proxy history
    then sees two real, side-by-side, authenticated responses for the
    same object under two different sessions -- the actual "second
    opinion" evidence this was built for, not an automated agree/
    disagree check against Burp's own Active Scanner (which has no
    cross-identity authorization-differential check to run).

    Sequential, not `asyncio.gather()`-parallel -- each capture opens
    its own short-lived Burp-proxied connection, and running all of
    them at once against a single Burp Proxy listener risks tripping
    it up for no real time saving on what's normally a handful of
    findings, not hundreds."""
    enriched = 0
    for finding in findings:
        primary_session = session_manager.peek_session(finding.user_role) if session_manager else None
        captured = await _capture_and_append(playwright, proxy_url, finding, primary_session, finding.user_role if primary_session else None)

        confirm_captured = False
        if finding.confirmed_role and session_manager is not None:
            confirm_session = session_manager.peek_session(finding.confirmed_role)
            if confirm_session is not None:
                confirm_captured = await _capture_and_append(playwright, proxy_url, finding, confirm_session, finding.confirmed_role)

        if captured or confirm_captured:
            enriched += 1
            if click_echo:
                identities = finding.user_role + (f" + {finding.confirmed_role}" if confirm_captured else "")
                click_echo(f"[BURP]  ✓ captured {finding.vuln_type} @ {finding.endpoint.url} (identity: {identities})")
        elif click_echo:
            click_echo(f"[BURP]  ⚠ could not capture {finding.vuln_type} @ {finding.endpoint.url} -- kept original evidence")
    return enriched
