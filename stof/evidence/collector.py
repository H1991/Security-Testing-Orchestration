"""Layer 12 — Evidence Collection.

Called by vulnerability modules only when a finding is confirmed --
never speculatively, per CLAUDE.md's own rule for Layer 3B's
`screenshot.py` (reused here for the actual PNG capture): "never called
speculatively during normal replay."

Captures exactly what CLAUDE.md's Layer 12 section lists: "screenshots,
req/resp, session state" -- a full-page screenshot, the page's rendered
HTML at capture time (the closest analogue to a "response" a raw
`APIRequestContext` probe doesn't otherwise leave a visual trail for),
and the session's cookies. Stores under `data/evidence/<scan_id>/
<label>/`, matching CLAUDE.md's documented path shape, and returns the
written paths for the caller to fold into `Finding.evidence_refs` --
exactly the call shape CLAUDE.md's own example shows: `await
evidence.capture(page, session, label="finding-AUTH-001")`.

Session cookies, and any Cookie/Set-Cookie/Authorization header text
embedded in a captured request/response, are REDACTED before they ever
reach disk (see `_redact_secret`/`_redacted_cookies`/
`_redact_sensitive_headers` below) -- they're live bearer credentials
for whichever test account the scan authenticated as, not payload data
a finding needs verbatim to prove its point. Without this,
`data/evidence/` accumulates a standing, unencrypted cache of working
session tokens across every engagement this tool has ever run.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from stof.core.logger import get_logger
from stof.engine import screenshot as screenshot_module

from .request_response_image import render_http_pair_image

if TYPE_CHECKING:
    from playwright.async_api import Page

    from stof.session.models import Session

_log = get_logger("evidence.collector")

DEFAULT_EVIDENCE_DIR = Path("data/evidence")

_UNSAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9_-]+")


def _safe_label(label: str) -> str:
    return _UNSAFE_CHARS_RE.sub("_", label).strip("_") or "evidence"


# `session.cookies` and any Cookie/Set-Cookie/Authorization header
# captured here are live bearer credentials for whichever test account
# (admin, normal, ...) the scan authenticated as -- not payload data,
# not something a finding needs verbatim to prove its point. Written
# raw to disk, they turn `data/evidence/` into a standing cache of
# working session tokens across every engagement this tool has ever
# run, with no expiry and no encryption at rest. Redacting to a
# recognizable-but-unusable shape (first/last few chars) keeps the
# evidence value -- "yes, a session cookie/bearer token was present and
# looked like a real token" -- without keeping the credential itself.
_SENSITIVE_HEADER_RE = re.compile(r"^(cookie|set-cookie|authorization):[ \t]*(.*)$", re.IGNORECASE | re.MULTILINE)


def _redact_secret(value: str, keep: int = 4) -> str:
    value = value.strip()
    if len(value) <= keep * 2:
        return "***redacted***"
    return f"{value[:keep]}…redacted ({len(value) - keep * 2} chars)…{value[-keep:]}"


def _redacted_cookies(cookies: dict[str, str]) -> dict[str, str]:
    return {name: _redact_secret(value) for name, value in cookies.items()}


def _redact_sensitive_headers(text: str) -> str:
    def _sub(m: re.Match) -> str:
        header, value = m.group(1), m.group(2)
        if not value.strip():
            return m.group(0)
        return f"{header}: {_redact_secret(value)}"
    return _SENSITIVE_HEADER_RE.sub(_sub, text)


class EvidenceCollector:
    def __init__(self, scan_id: str, base_dir: str | Path = DEFAULT_EVIDENCE_DIR) -> None:
        self.scan_id = scan_id
        self.base_dir = Path(base_dir)

    async def capture(
        self, page: "Page", session: "Session", label: str = "finding",
        request_raw: str = "", response_raw: str = "",
    ) -> list[str]:
        """Best-effort: a capture failure (e.g. the page already
        navigated away or closed) is logged and simply yields fewer
        evidence_refs on that one Finding -- it must never take down
        the vulnerability module's whole run. `request_raw`, when
        non-empty, also gets a styled Burp-style request/response
        image rendered alongside the live page screenshot."""
        directory = self.base_dir / self.scan_id / _safe_label(label)
        directory.mkdir(parents=True, exist_ok=True)
        paths: list[str] = []

        try:
            screenshot_path = await screenshot_module.capture(page, output_dir=directory, label=label)
            paths.append(str(screenshot_path))
        except Exception as exc:
            _log.warning(f"screenshot capture failed for '{label}': {exc}")

        try:
            content = await page.content()
            content_path = directory / "page_content.html"
            content_path.write_text(content, encoding="utf-8")
            paths.append(str(content_path))
        except Exception as exc:
            _log.warning(f"page content capture failed for '{label}': {exc}")

        try:
            cookies_path = directory / "session_cookies.json"
            cookies_path.write_text(json.dumps(_redacted_cookies(session.cookies), indent=2), encoding="utf-8")
            paths.append(str(cookies_path))
        except Exception as exc:
            _log.warning(f"session cookie capture failed for '{label}': {exc}")

        if request_raw:
            image_path = render_http_pair_image(
                _redact_sensitive_headers(request_raw), _redact_sensitive_headers(response_raw),
                directory / "request_response.png", title=label,
            )
            if image_path.is_file():
                paths.append(str(image_path))

        return paths

    async def capture_raw(self, request_raw: str, response_raw: str, label: str = "finding") -> list[str]:
        """Non-browser variant of `capture()`: persists already-known
        request/response text as evidence files (plus the same styled
        image `capture()` renders) under the same `data/evidence/
        <scan_id>/<label>/` layout, for findings that never had a live
        Playwright `page` to capture from -- e.g. Burp Suite's
        out-of-band Active Scan issues (Layer 11's `findings.
        burp_normalizer`), which decode Burp's own evidence into plain
        request/response text instead."""
        directory = self.base_dir / self.scan_id / _safe_label(label)
        directory.mkdir(parents=True, exist_ok=True)
        paths: list[str] = []
        request_raw = _redact_sensitive_headers(request_raw)
        response_raw = _redact_sensitive_headers(response_raw)

        try:
            request_path = directory / "request.txt"
            request_path.write_text(request_raw, encoding="utf-8")
            paths.append(str(request_path))
        except OSError as exc:
            _log.warning(f"request evidence write failed for '{label}': {exc}")

        try:
            response_path = directory / "response.txt"
            response_path.write_text(response_raw, encoding="utf-8")
            paths.append(str(response_path))
        except OSError as exc:
            _log.warning(f"response evidence write failed for '{label}': {exc}")

        image_path = render_http_pair_image(request_raw, response_raw, directory / "request_response.png", title=label)
        if image_path.is_file():
            paths.append(str(image_path))

        return paths
