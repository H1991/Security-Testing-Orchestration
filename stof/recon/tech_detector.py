"""Recon Engine — tech/fingerprint detection (httpx-equivalent).

Native reimplementation, not a wrapper around the `httpx` CLI tool:
studies the same idea (headers/cookies/body signature matching over a
raw HTTP response, no full page render) and implements it with
Playwright's `APIRequestContext`, which is exactly the "browser-native,
no external dependency" principle this project has followed since
Layer 7's crawler.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from stof.core.logger import get_logger

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext

_log = get_logger("recon.tech_detector")

# name -> regex patterns matched against page body/inline script content.
_BODY_TECH_SIGNATURES: dict[str, tuple[str, ...]] = {
    "React": (r"data-reactroot", r"__REACT_DEVTOOLS_GLOBAL_HOOK__", r"_reactRootContainer"),
    "Angular": (r"ng-version", r"window\.angular", r"ng-app"),
    "Vue.js": (r"__VUE__", r"data-v-[0-9a-f]{6,}", r"Vue\.config"),
    "Next.js": (r"__NEXT_DATA__", r"/_next/static/"),
    "Nuxt.js": (r"__NUXT__",),
    "jQuery": (r"jquery(?:\.min)?\.js", r"jQuery v\d"),
    "Bootstrap": (r"bootstrap(?:\.min)?\.css", r"bootstrap(?:\.min)?\.js"),
    "WordPress": (r"wp-content/", r"wp-includes/"),
    "Angular (legacy AngularJS)": (r"ng-controller", r"angular\.module\("),
}

# cookie name (case-insensitive substring) -> tech it implies.
_COOKIE_TECH_SIGNATURES: dict[str, str] = {
    "jsessionid": "Java (JSP/Servlet)",
    "phpsessid": "PHP",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel",
    "django": "Django",
    "connect.sid": "Express (Node.js)",
}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def detect_tech(headers: dict[str, str], cookie_names: list[str], body: str) -> list[str]:
    """Pure signature-matching, testable without any network access.
    `headers` keys are expected lower-cased (matches Playwright's own
    `response.headers` convention)."""
    found: set[str] = set()

    server = headers.get("server")
    if server:
        found.add(server)
    powered_by = headers.get("x-powered-by")
    if powered_by:
        found.add(powered_by)

    for cookie_name in cookie_names:
        lowered = cookie_name.lower()
        for pattern, tech in _COOKIE_TECH_SIGNATURES.items():
            if pattern in lowered:
                found.add(tech)

    for tech, patterns in _BODY_TECH_SIGNATURES.items():
        if any(re.search(pattern, body, re.IGNORECASE) for pattern in patterns):
            found.add(tech)

    return sorted(found)


def extract_title(body: str) -> str | None:
    match = _TITLE_RE.search(body)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip() or None


@dataclass
class TechProfile:
    url: str
    status_code: int | None = None
    title: str | None = None
    content_type: str | None = None
    redirect_location: str | None = None
    tech: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)


async def analyze_url(context: "BrowserContext", url: str, timeout_ms: int = 10000) -> TechProfile:
    """One URL's httpx-equivalent profile: status, title, tech stack --
    via a raw HTTP GET (context.request), not a rendered page load."""
    try:
        response = await context.request.get(url, timeout=timeout_ms, max_redirects=0)
    except Exception as exc:
        _log.warning(f"tech detection failed for '{url}': {exc}")
        return TechProfile(url=url)

    headers: dict[str, Any] = {k.lower(): v for k, v in response.headers.items()}
    try:
        body = await response.text()
    except Exception:
        body = ""

    cookies = response.headers.get("set-cookie", "")
    cookie_names = [c.split("=", 1)[0].strip() for c in cookies.split(",") if "=" in c]

    return TechProfile(
        url=url,
        status_code=response.status,
        title=extract_title(body),
        content_type=headers.get("content-type"),
        redirect_location=headers.get("location") if response.status in (301, 302, 303, 307, 308) else None,
        tech=detect_tech(headers, cookie_names, body),
        headers=headers,
    )
