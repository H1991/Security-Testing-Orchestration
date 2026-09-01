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
    ("Generic Secret Assignment", r"(?i)(secret|token|password)['\"]?\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"),
    ("Private Key Block", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    ("Internal/Debug Path Hint", r"['\"](?:/internal/|/debug/|/admin/api/|/actuator/)[A-Za-z0-9/_-]*['\"]"),
)

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


async def scan_page_for_secrets(page: "Page", timeout_ms: int = 8000) -> list[SecretFinding]:
    """Scan the current page's inline scripts, external scripts (fetched
    fresh), and HTML comments for secret-like patterns."""
    extracted = await page.evaluate(_EXTRACT_SCRIPTS_AND_COMMENTS_SCRIPT)
    findings: list[SecretFinding] = []

    for inline_script in extracted.get("inline", []):
        findings.extend(find_secrets(inline_script, page.url))

    for comment in extracted.get("comments", []):
        findings.extend(find_secrets(comment, page.url))

    for script_src in extracted.get("external", []):
        absolute_src = urljoin(page.url, script_src)
        try:
            response = await page.context.request.get(absolute_src, timeout=timeout_ms)
            body = await response.text()
        except Exception as exc:
            _log.warning(f"could not fetch script '{absolute_src}': {exc}")
            continue
        findings.extend(find_secrets(body, absolute_src))

    return findings
