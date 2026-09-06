"""Recon Engine — secrets in JS/HTML (SecretFinder-equivalent).

Directly answers TC-008 ("Review Webpage Content for Information
Leakage") from the test case catalog, and its own noted Burp gap:
"passively flags JS files with sensitive strings; limited JS analysis
depth." This scans every script (inline + external) and every HTML
comment on a page, not just what a passive proxy happens to see fly by.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from stof.core.logger import get_logger

if TYPE_CHECKING:
    from playwright.async_api import Page

_log = get_logger("recon.secrets_scanner")

# (label, regex) -- kept intentionally small and high-signal rather than
# an exhaustive copy of SecretFinder's rule set.
_SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    ("JWT", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
    ("Generic API Key Assignment", r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
    # Regression: `[^'"\s]{8,}` (the original character class here) only
    # excludes ASCII whitespace -- confirmed live scanning a real i18n
    # bundle, where it matched dozens of translation-dictionary entries
    # like `password: "パスワードを変更する"` (Japanese for "change
    # password") and `password: "รหัสผ่าน"` (Thai for "password")
    # wholesale, since CJK/Thai text has no ASCII spaces to exclude it
    # in the first place. Restricted to characters a real credential
    # value actually uses (`A-Za-z0-9` plus common secret-encoding
    # punctuation) instead of "anything that isn't a quote or a
    # space" -- this excludes non-ASCII text as a side effect (real
    # secrets are practically always ASCII), not by trying to detect
    # "is this a translation string" directly.
    #
    # Still not enough on its own: confirmed live, the SAME bundle also
    # carried the word "password" translated into several ASCII-
    # representable languages -- `password:"Passwort"` (German),
    # `password:"Wachtwoord"` (Dutch), `password:"Salasana"` (Finnish),
    # `password:"Adgangskode"` (Danish) -- which the character-class
    # fix above can't distinguish from a real value. A `(?=\D*\d)`
    # lookahead requiring at least one digit somewhere in the matched
    # value is the actual discriminator: real generated secrets/API
    # keys/tokens virtually always mix in digits, and no human-language
    # dictionary word -- in any language this pattern has hit so far --
    # does. `sk_live_51H8x...` and a real Jira-style API token both
    # still match; every i18n false positive found so far does not.
    ("Generic Secret Assignment", r"(?i)(secret|token|password)['\"]?\s*[:=]\s*['\"](?=[^'\"]*\d)[A-Za-z0-9_\-+/.=]{8,}['\"]"),
    ("Private Key Block", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    ("Internal/Debug Path Hint", r"['\"](?:/internal/|/debug/|/admin/api/|/actuator/)[A-Za-z0-9/_-]*['\"]"),
)

# Route-string patterns mined from JS bundles -- confirmed useful live:
# this app's entire admin surface (category management, workflow
# management) sat behind a collapsed sidebar the crawler's click-
# exploration can only reach one accordion-level at a time; the SPA's
# own router config in its shipped JS bundle names every route
# up front, regardless of whether the UI ever exposes a clickable path
# to it. Deliberately framework-agnostic: covers the common
# `path:"/..."`/`path: '/...'` router-config shape (Vue Router,
# React Router route objects) shared across the major SPA frameworks,
# not any one target's specific route names. A route string alone
# isn't proof an endpoint exists -- callers still same-origin-filter
# and dedupe it like any other discovered URL.
_ROUTE_STRING_PATTERN = re.compile(r"""path\s*:\s*['"](/[a-zA-Z0-9_\-/:.]{1,120})['"]""")
# What doesn't count as a real route worth queuing -- static asset
# extensions a router config's `path:` key never legitimately points
# at, and bare "/" (already the crawl's own start point).
_ROUTE_SKIP_EXTENSIONS = (".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2", ".map")

_EXTRACT_SCRIPTS_AND_COMMENTS_SCRIPT = """
() => {
    const scripts = Array.from(document.querySelectorAll('script'));
    const inline = scripts.filter((s) => !s.src).map((s) => s.textContent || '');
    const external = scripts.filter((s) => s.src).map((s) => s.src);
    const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
    const comments = [];
    let node;
    while ((node = walker.nextNode())) comments.push(node.nodeValue || '');
    return { inline, external, comments };
}
"""


@dataclass
class SecretFinding:
    source_url: str
    label: str
    match_preview: str  # truncated -- never the full secret, avoids logging real credentials verbatim


def find_secrets(text: str, source_url: str) -> list[SecretFinding]:
    """Pure regex scan of one blob of text (pulled out from the
    Playwright-dependent extraction so it's directly unit-testable)."""
    findings: list[SecretFinding] = []
    for label, pattern in _SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            preview = match.group(0)
            # Redact whenever there's enough length to still be a
            # useful preview once masked -- e.g. AWS keys are exactly
            # 20 chars, well under a naive "only mask long ones" cutoff.
            if len(preview) > 12:
                preview = preview[:6] + "..." + preview[-4:]
            findings.append(SecretFinding(source_url=source_url, label=label, match_preview=preview))
    return findings


def find_routes(text: str) -> list[str]:
    """Pure regex scan of one JS blob for router-config route strings
    (`path: "/..."`) -- see `_ROUTE_STRING_PATTERN`'s own comment for
    why this exists. Returns raw path strings, deduplicated, in the
    order first seen; resolving them against the target's origin and
    filtering (same-origin, dedup against already-known endpoints) is
    the caller's job, same as any other discovered URL."""
    seen: dict[str, None] = {}
    for match in _ROUTE_STRING_PATTERN.finditer(text):
        path = match.group(1)
        if path in ("/", ""):
            continue
        if path.lower().split("?", 1)[0].endswith(_ROUTE_SKIP_EXTENSIONS):
            continue
        seen.setdefault(path, None)
    return list(seen.keys())


async def scan_page_for_secrets_and_routes(
    page: "Page", timeout_ms: int = 20000
) -> tuple[list[SecretFinding], list[str]]:
    """Scan the current page's inline scripts, external scripts (fetched
    fresh), and HTML comments for both secret-like patterns and router-
    config route strings -- one pass over each script blob for both,
    rather than fetching every external bundle twice (once per
    concern).

    Default bumped from 8s to 20s: confirmed live against a real
    target whose single main JS bundle was 4.3MB, consistently missing
    the 8s cutoff and silently skipping BOTH the secrets AND the 132
    route strings actually embedded in it -- not a rare case, a modern
    SPA's whole app in one bundle is common."""
    extracted = await page.evaluate(_EXTRACT_SCRIPTS_AND_COMMENTS_SCRIPT)
    secrets: list[SecretFinding] = []
    routes: dict[str, None] = {}

    def _scan_blob(text: str, source_url: str, *, routes_too: bool) -> None:
        secrets.extend(find_secrets(text, source_url))
        if routes_too:
            for path in find_routes(text):
                routes.setdefault(path, None)

    for inline_script in extracted.get("inline", []):
        _scan_blob(inline_script, page.url, routes_too=True)

    for comment in extracted.get("comments", []):
        _scan_blob(comment, page.url, routes_too=False)

    for script_src in extracted.get("external", []):
        absolute_src = urljoin(page.url, script_src)
        try:
            response = await page.context.request.get(absolute_src, timeout=timeout_ms)
            body = await response.text()
        except Exception as exc:
            _log.warning(f"could not fetch script '{absolute_src}': {exc}")
            continue
        _scan_blob(body, absolute_src, routes_too=True)

    return secrets, list(routes.keys())
