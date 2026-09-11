"""Layer 2 — orchestrator-level traffic guard: scope enforcement plus a
full audit trail, applied uniformly to every real HTTP request any
module sends, independent of the module itself.

Real gap this closes: `rate_limiter.py`'s own `throttled()` already
caps concurrency/pace, but grep-verified only 3 of the 31 files under
`stof/modules/` route their requests through it -- the other 28 call
`context.request.get/post/...` directly, so a wordlist sweep or
candidate-ID loop in one of those modules is completely unthrottled,
and nothing anywhere records the exact request/response actually sent
to the target independent of whether it produced a `Finding` (a
`Finding`'s own `request_raw`/`response_raw` only exists for the ONE
request that confirmed it -- every other probe STOF ever sent, hit or
miss, leaves no trace at all). Both gaps matter for the same reason: a
pentest client's AppSec team, or an internal post-incident review,
needs to be able to answer "what did this scanner actually send, and
did it ever leave the agreed scope" with certainty, not with "whatever
each module happened to log."

This module is deliberately the ONLY new policy surface -- it does not
reimplement rate limiting (still `core.rate_limiter.throttled`, see
`stof.engine.guarded_context` for how the two compose) and it does not
touch any of the 31 module files. It is wired into
`stof.engine.multi_session.SessionPool` (see that module's own
`_maybe_guard`) as the single choke point every module already shares
without knowing it: every module receives its `BrowserContext` from a
`SessionPool`, never launches its own. Wrapping the context THERE means
every existing and future module gets scope enforcement, uniform rate
limiting, and audit logging automatically, with zero code changes to
the module itself.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from stof.core.logger import get_logger

_log = get_logger("core.traffic_guard")

# Header VALUES redacted from the audit log -- the log itself must not
# become a second place credentials leak from (session cookies, bearer
# tokens, API keys). The header NAME is kept so a reviewer can still see
# *that* auth was present on a request, just not read the live secret
# out of the audit trail.
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}
_REDACTED = "[redacted]"

# Keeps one payload-heavy request (a large file upload probe, a huge
# deserialization gadget string) from ballooning the audit log to
# gigabytes over a long scan -- the log's job is proving WHAT was sent
# and WHERE, not archiving every byte of every body forever.
_BODY_TRUNCATE_CHARS = 2000


class OutOfScopeError(Exception):
    """A module (or a bug in one) tried to send a real request outside
    this scan's own allowlisted origin(s). Raised, never silently
    dropped or logged-and-continued -- an out-of-scope request is
    exactly the class of mistake this guard exists to make impossible,
    not just visible after the fact."""


def _origin(url: str) -> str:
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return f"{scheme}://{host}:{port}"


def derive_allowed_origins(base_url: str, extra_urls: tuple[str, ...] = ()) -> set[str]:
    """The scan's own target `base_url` is always in scope; `extra_urls`
    covers a target that legitimately spans more than one origin (e.g.
    a separate API host) -- callers pass any config URLs that name a
    second real host explicitly, never a wildcard."""
    origins = {_origin(base_url)}
    origins.update(_origin(url) for url in extra_urls if url)
    return origins


def _redact_headers(headers: dict[str, str] | None) -> dict[str, str]:
    if not headers:
        return {}
    return {name: (_REDACTED if name.lower() in _SENSITIVE_HEADERS else value) for name, value in headers.items()}


def _truncate(body: str | None) -> str | None:
    if body is None or len(body) <= _BODY_TRUNCATE_CHARS:
        return body
    return body[:_BODY_TRUNCATE_CHARS] + f"...[truncated, {len(body)} chars total]"


@dataclass
class AuditEntry:
    timestamp: str
    method: str
    url: str
    role: str | None
    request_headers: dict[str, str]
    request_body: str | None
    response_status: int | None
    response_headers: dict[str, str]
    response_body_len: int | None
    latency_ms: float
    error: str | None = None

    def to_json_line(self) -> str:
        return json.dumps(asdict(self))


class TrafficGuard:
    """One instance per scan, shared across every `SessionPool`-vended
    context for that scan (see `stof.engine.guarded_context`). Not
    thread-safe-by-design in the concurrency sense -- like
    `rate_limiter.py`'s own module-level state, this only ever needs to
    hold within one scan subprocess's single asyncio event loop, never
    across processes or scans."""

    def __init__(self, allowed_origins: set[str], audit_path: Path | None = None) -> None:
        self.allowed_origins = allowed_origins
        self.audit_path = audit_path
        self.total_requests = 0

    def check_scope(self, url: str) -> None:
        origin = _origin(url)
        if origin not in self.allowed_origins:
            raise OutOfScopeError(
                f"refusing to send a request to '{url}' (origin '{origin}') -- "
                f"outside this scan's allowed origin(s): {sorted(self.allowed_origins)}"
            )

    def build_entry(
        self, method: str, url: str, role: str | None,
        request_headers: dict[str, str] | None, request_body: str | None,
        response_status: int | None, response_headers: dict[str, str] | None,
        response_body_len: int | None, latency_ms: float, error: str | None,
    ) -> AuditEntry:
        return AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            method=method, url=url, role=role,
            request_headers=_redact_headers(request_headers),
            request_body=_truncate(request_body),
            response_status=response_status,
            response_headers=_redact_headers(response_headers),
            response_body_len=response_body_len,
            latency_ms=round(latency_ms, 2),
            error=error,
        )

    def record(self, entry: AuditEntry) -> None:
        self.total_requests += 1
        if self.audit_path is None:
            return
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as f:
                f.write(entry.to_json_line() + "\n")
        except OSError as exc:
            # A broken audit log must never abort the scan itself --
            # same "a probe failure must never take down the whole
            # module" resilience convention this codebase already
            # applies everywhere else, just at the audit-write step.
            _log.warning(f"could not write audit log entry to '{self.audit_path}': {exc}")
