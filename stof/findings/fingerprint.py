"""Stable cross-scan identity for a `Finding` -- the prerequisite for
baseline/diff mode (`stof/findings/baseline.py`) and for the trend
chart already in the console (`stof/ui/server.py`) to mean anything.

Real, previously-unaddressed gap this closes: `Finding.finding_id` is a
fresh random uuid every scan, so two runs against the identical target
finding the identical bug (same endpoint, same technique, same role)
produced two `Finding` objects with nothing in common an operator or a
CI pipeline could match on -- every scan looked like it found N brand
new vulnerabilities, even when N-1 of them were the same open issue
persisting from last time.
"""
from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from .models import Finding


def _normalized_endpoint_key(url: str) -> str:
    """Scheme + host + path, no query string and no fragment -- a
    query string carries the injected payload/candidate-id value a
    technique happened to try THIS run (a different random marker, a
    different candidate id from an id-shaped-parameter sweep), which
    must never make an otherwise-identical finding hash differently
    from one scan to the next. The path itself (which endpoint was
    vulnerable) is exactly the part that should stay stable."""
    split = urlsplit(url)
    return f"{split.scheme}://{split.netloc}{split.path}"


def compute_fingerprint(finding: "Finding") -> str:
    """Deterministic identity from (technique, endpoint method,
    normalized endpoint URL, role) -- deliberately NOT from
    `finding_id` (fresh uuid every run), `discovered_at` (a timestamp),
    or free text in `description`/`response_raw` (can carry a run's own
    random marker). Falls back to `vuln_type` when `technique_id` is
    unset (a `Finding` constructed directly, outside `extract_findings`
    -- e.g. in a unit test) so this never raises on an otherwise-valid
    finding.

    Known, honest limitation: this does not include which specific
    request PARAMETER was vulnerable (`Finding` has no structured field
    for it -- that detail currently lives only in prose inside
    `request_raw`/`description`). Two distinct vulnerable parameters on
    the exact same endpoint/technique/role will collide onto the same
    fingerprint and read as "the same finding" in a baseline diff. This
    is a real, narrower version of the same class of gap fixed here,
    not a silently-ignored one -- worth a follow-up if/when `Finding`
    gains a structured parameter field."""
    identity = "|".join([
        finding.technique_id or finding.vuln_type,
        finding.endpoint.method.upper(),
        _normalized_endpoint_key(finding.endpoint.url),
        finding.user_role,
    ])
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
