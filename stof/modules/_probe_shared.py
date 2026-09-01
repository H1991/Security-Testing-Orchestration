"""Pure-ish helpers shared by every technique that needs the
baseline-control-probe + wordlist-sweep pattern: probe a random,
definitely-nonexistent path first so a real "found" path can be told
apart from a client-side-routed SPA's catch-all response (an Angular
app serving the same index.html shell -- HTTP 200, identical bytes --
for ANY unmatched path would otherwise make every wordlist candidate
look "found").

Extracted from `configuration_tests.py`'s own `_control_fingerprint`/
`_probe_paths` (the cleanest existing implementation of this pattern)
to stop `bfla_tests.py`'s `_technique_hidden_endpoint_discovery` and
`auth_tests.py`'s `_technique_admin_interface_defaults` each
reimplementing the same loop -- the latter was also re-deriving its own
inline `hashlib.sha256(...)` instead of reusing a shared fingerprint
helper.

Deliberately swallow-always (log + skip on any probe failure), matching
what both of those two call sites already did before this extraction --
NOT the transient-error-propagating version `configuration_tests.py`'s
own `_control_fingerprint`/`_probe_paths` now use after the Batch 3
reliability fix. Those two stayed on their own separate implementation
rather than migrating to this shared one: migrating them would silently
change behavior for consumers that don't participate in Batch 3's fix
(a transient error reaching `bfla_tests.py`'s `_technique_hidden_
endpoint_discovery` today already vanishes that technique's result
under `IdorTestsModule._safe()`'s swallow-to-`[]` contract, same as any
other exception there -- routing it through a raising helper wouldn't
change that outcome, but it also isn't the deliberate, tested fix Batch
3 scoped to `auth_tests.py`/`configuration_tests.py` specifically, so
extending it here would be an undocumented, untested behavior change in
what's supposed to be a pure-refactor batch). Not fully pure (both
issue real HTTP requests via `context.request.get`) but carry no other
side effects/state -- same "shared, leading-underscore file" convention
as `_idor_shared.py` for the IDOR family.
"""
from __future__ import annotations

import hashlib
import secrets

from stof.core.logger import get_logger

_log = get_logger("modules._probe_shared")


def content_fingerprint(status: int, body: str) -> tuple[int, str]:
    return status, hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()


async def control_fingerprint(context, origin: str) -> tuple[int, str] | None:
    """Probe a random, definitely-nonexistent path under `origin` and
    return its `(status, body_hash)` fingerprint, or `None` if the probe
    itself failed (logged, not raised -- callers already treat a failed
    control probe as "no baseline available", not a hard error)."""
    url = f"{origin}/stof-control-{secrets.token_hex(8)}"
    try:
        resp = await context.request.get(url, max_redirects=0)
        body = await resp.text()
    except Exception as exc:
        _log.warning(f"control probe failed for {url}: {exc}")
        return None
    return content_fingerprint(resp.status, body)


async def sweep_paths(context, origin: str, paths: "list[str] | tuple[str, ...]", baseline: "tuple[int, str] | None") -> list[tuple[str, int, str]]:
    """Returns `[(url, status, body), ...]` for every path whose
    response is distinct from `baseline` -- `url` built via a simple
    `origin + path` join since these are always origin-relative probe
    paths, not endpoint URLs with an existing query string to preserve."""
    results: list[tuple[str, int, str]] = []
    for path in paths:
        url = f"{origin}{path}"
        try:
            resp = await context.request.get(url, max_redirects=0)
            body = await resp.text()
        except Exception as exc:
            _log.warning(f"probe failed for {url}: {exc}")
            continue
        if baseline is not None and content_fingerprint(resp.status, body) == baseline:
            continue  # identical to the control response -- SPA catch-all, not a real hit
        results.append((url, resp.status, body))
    return results
