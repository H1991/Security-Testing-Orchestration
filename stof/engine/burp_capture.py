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


async def capture_via_burp(
    playwright: "Playwright",
    proxy_url: str,
    finding: "Finding",
    timeout_s: float = 30.0,
) -> tuple[str, str] | None:
    """Returns `(request_text, response_text)` captured via Burp's
    proxy, or `None` on any failure -- Burp not running, wrong proxy
    port, network error, or a `request_raw` that doesn't parse. Never
    raises: a missing/unreachable Burp must never block a scan or drop
    a finding."""
    parsed = _extract_request_parts(finding.request_raw)
    if parsed is None:
        _log.warning(f"finding '{finding.finding_id}': could not parse a method/URL from request_raw -- skipping Burp capture")
        return None
    method, url, params = parsed
    method_lower = method.lower()
    if method_lower not in _SUPPORTED_METHODS:
        _log.warning(f"finding '{finding.finding_id}': unsupported method '{method}' for Burp capture -- skipping")
        return None

    headers = _browser_like_headers(url)
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
        request_text = f"{method} {url}\n{header_block}{body_line}"

        response_headers = "\n".join(f"{k}: {v}" for k, v in (resp.headers or {}).items())
        body_text = await resp.text()
        response_text = f"HTTP {resp.status}\n{response_headers}\n\n{body_text[:4000]}"

        _log.info(f"finding '{finding.finding_id}': captured via Burp -- {method} {url} -> HTTP {resp.status}")
        return request_text, response_text
    except Exception as exc:
        _log.warning(f"finding '{finding.finding_id}': Burp capture request failed for {method} {url}: {exc}")
        return None
    finally:
        await context.dispose()


_BURP_SECTION_HEADER = "\n\n--- Captured via Burp proxy (representative request, see above for the technique's own record) ---\n"


async def capture_findings_via_burp(
    playwright: "Playwright",
    proxy_url: str,
    findings: list["Finding"],
    click_echo=None,
) -> int:
    """Appends a Burp-captured request/response section onto each
    finding's request_raw/response_raw where capture succeeds -- never
    replaces the technique's own text, so whatever specific evidence
    the technique itself recorded (the exact payload, the exact
    comparison it made) always survives alongside the fuller capture.
    Returns the number of findings enriched.

    Sequential, not `asyncio.gather()`-parallel -- each capture opens
    its own short-lived Burp-proxied connection, and running all of
    them at once against a single Burp Proxy listener risks tripping
    it up for no real time saving on what's normally a handful of
    findings, not hundreds."""
    enriched = 0
    for finding in findings:
        result = await capture_via_burp(playwright, proxy_url, finding)
        if result is not None:
            burp_request, burp_response = result
            finding.request_raw = finding.request_raw + _BURP_SECTION_HEADER + burp_request
            finding.response_raw = finding.response_raw + _BURP_SECTION_HEADER + burp_response
            enriched += 1
            if click_echo:
                click_echo(f"[BURP]  ✓ captured {finding.vuln_type} @ {finding.endpoint.url}")
        elif click_echo:
            click_echo(f"[BURP]  ⚠ could not capture {finding.vuln_type} @ {finding.endpoint.url} -- kept original evidence")
    return enriched
