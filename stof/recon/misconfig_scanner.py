"""Recon Engine — misconfiguration / exposure scanning (nuclei-equivalent).

Native reimplementation: a small built-in set of exposure checks and
error-disclosure signatures, in the spirit of nuclei's templates, not a
wrapper around the `nuclei` binary or a copy of its template library.
Passive from the target's point of view -- every check here is a GET
request to a URL, never a payload injected into a form/parameter (that
line is `crawler.py`'s `submit_forms_with_test_data`, a separate,
explicitly opt-in concern).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from stof.core.logger import get_logger

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext

_log = get_logger("recon.misconfig_scanner")

_SECURITY_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
)

# Small built-in set of commonly-exposed paths worth checking for. This
# is intentionally short (a handful of high-signal paths), not an
# attempt to reproduce nuclei's thousands of templates.
_EXPOSURE_PROBE_PATHS = (
    "/.git/config",
    "/.env",
    "/.well-known/security.txt",
    "/server-status",
    "/actuator/health",
    "/swagger.json",
    "/swagger-ui.html",
    "/.aws/credentials",
    "/backup.zip",
    "/.DS_Store",
    "/web.config",
    "/WEB-INF/web.xml",
)

# Body content patterns indicating a verbose/leaky error response
# (stack traces, DB errors, framework internals) -- covers TC-084
# ("Sensitive Data Exposure in Error Messages").
_ERROR_DISCLOSURE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"at\s+[\w.$]+\(\w+\.java:\d+\)", "Java stack trace"),
    (r"Exception in thread", "Java exception"),
    (r'File "[^"]+\.py", line \d+', "Python traceback"),
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"Microsoft OLE DB Provider for", "MSSQL/OLE DB error"),
    (r"Warning: mysql_", "PHP MySQL error"),
    (r"ORA-\d{5}", "Oracle DB error"),
    (r"System\.NullReferenceException|System\.Web\.HttpException", ".NET exception"),
    (r"org\.apache\.\w+\.\w+Exception", "Apache/Java framework exception"),
    (r"SQLSTATE\[\d+\]", "SQL error (SQLSTATE)"),
    (r"Whitelabel Error Page", "Spring Boot default error page"),
)


def check_missing_security_headers(headers: dict[str, str]) -> list[str]:
    """Pure function: which of a small standard set of security
    headers are absent from `headers` (expected lower-cased keys)."""
    return [name for name in _SECURITY_HEADERS if name not in headers]


def find_error_disclosure(body: str) -> list[str]:
    """Pure function: which leak signatures appear in a response body."""
    return [label for pattern, label in _ERROR_DISCLOSURE_PATTERNS if re.search(pattern, body)]


@dataclass
class ExposedPath:
    url: str
    status_code: int


@dataclass
class ErrorDisclosure:
    url: str
    status_code: int
    leaked: list[str]


async def scan_exposed_paths(
    context: "BrowserContext", base_url: str, timeout_ms: int = 8000
) -> list[ExposedPath]:
    """Probe the built-in list of commonly-exposed paths. A path
    "exists" if it returns 200 -- callers should sanity-check results
    against the target's normal 404 behaviour (some legacy apps return
    200 for a friendly not-found page)."""
    found: list[ExposedPath] = []
    for path in _EXPOSURE_PROBE_PATHS:
        url = urljoin(base_url, path)
        try:
            response = await context.request.get(url, timeout=timeout_ms)
        except Exception as exc:
            _log.warning(f"exposure probe failed for '{url}': {exc}")
            continue
        if response.status == 200:
            found.append(ExposedPath(url=url, status_code=response.status))
    return found


async def probe_error_disclosure(
    context: "BrowserContext", url: str, timeout_ms: int = 8000
) -> ErrorDisclosure | None:
    """Request a URL expected to trigger an error (caller's
    responsibility to pick one, e.g. an existing endpoint with a
    mangled/missing parameter) and check the response for leak
    signatures."""
    try:
        response = await context.request.get(url, timeout=timeout_ms)
        body = await response.text()
    except Exception as exc:
        _log.warning(f"error-disclosure probe failed for '{url}': {exc}")
        return None

    leaked = find_error_disclosure(body)
    if not leaked:
        return None
    return ErrorDisclosure(url=url, status_code=response.status, leaked=leaked)
