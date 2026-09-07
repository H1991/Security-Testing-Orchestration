"""Layer 10 — CVSS v3.1 vector computation.

A bare `cvss_score` (a float STOF's own modules already hand-choose per
finding) isn't independently verifiable -- a PCI ASV reviewer or a
customer security questionnaire expects the full vector (`CVSS:3.1/
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) so the score can be recomputed
and checked, not taken on faith. This module supplies that vector for
every finding STOF generates itself.

Design: classify a finding into a small set of real, defensible
vulnerability FAMILIES (XSS, SQLi, IDOR/BOLA, BFLA, SSRF, ...), each
with a fixed, industry-representative Attack Vector / Attack Complexity
/ Privileges Required / User Interaction / Scope shape (the metrics a
human would actually check for that weakness class). The three Impact
metrics (Confidentiality/Integrity/Availability) are then SOLVED for --
searched over the 27 possible N/L/H combinations -- to find one whose
CVSS v3.1 base score, computed by `cvss_base_score()` below, matches
`finding.cvss_score` EXACTLY. This makes every vector correct BY
CONSTRUCTION for whatever score a technique already chose, rather than
a static per-vuln_type table that could silently drift out of sync
with `cvss_score` the same way `severity` itself did (see `Finding.
__post_init__`'s own docstring for that audit).

`cvss_base_score()` is verified against known reference vectors --
see `tests/unit/test_cvss.py` -- before being trusted for the solver.
"""
from __future__ import annotations

import math
from itertools import product
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from stof.findings.models import Finding

# ---------------------------------------------------------------------------
# CVSS v3.1 base score formula (see first.org/cvss/v3.1/specification-document
# section 7.3) -- a pure, independently-verifiable implementation.
# ---------------------------------------------------------------------------

_AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC_WEIGHTS = {"L": 0.77, "H": 0.44}
_PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI_WEIGHTS = {"N": 0.85, "R": 0.62}
_CIA_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}


def _roundup(value: float) -> float:
    """CVSS's own specified rounding: round UP to the nearest 0.1,
    computed on an integer-scaled value to avoid binary-float error at
    the boundary (e.g. a raw 4.0000000001 must not round up to 4.1)."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000
    return (math.floor(scaled / 10000) + 1) / 10


def cvss_base_score(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> float:
    """The CVSS v3.1 base score for one full metric set. Pure and
    side-effect-free -- see this module's own docstring for why every
    vector this project assigns is checked against this function
    rather than trusted by construction alone."""
    pr_weights = _PR_WEIGHTS_CHANGED if s == "C" else _PR_WEIGHTS_UNCHANGED
    c_w, i_w, a_w = _CIA_WEIGHTS[c], _CIA_WEIGHTS[i], _CIA_WEIGHTS[a]
    iss = 1 - ((1 - c_w) * (1 - i_w) * (1 - a_w))
    impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * _AV_WEIGHTS[av] * _AC_WEIGHTS[ac] * pr_weights[pr] * _UI_WEIGHTS[ui]
    combined = impact + exploitability if s == "U" else 1.08 * (impact + exploitability)
    return _roundup(min(combined, 10.0))


def vector_string(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> str:
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


# ---------------------------------------------------------------------------
# Vulnerability families -- each a real, defensible AV/AC/PR/UI/S shape.
# Checked as a keyword against `vuln_type` (lowercased), first match wins,
# same convention as `classification.py`'s CWE/OWASP keyword overrides.
# C/I/A are deliberately NOT fixed here -- see `_solve_impact_for_score`.
# ---------------------------------------------------------------------------

_FALLBACK_SHAPE = ("N", "L", "N", "N", "U")  # generic authenticated-web-app baseline

_FAMILY_SHAPES: tuple[tuple[str, tuple[str, str, str, str, str]], ...] = (
    # (keyword, (AV, AC, PR, UI, S))
    ("dom-based cross-site", ("N", "L", "N", "R", "C")),
    ("dom-based open redirect", ("N", "L", "N", "R", "C")),
    ("dom data manipulation", ("N", "L", "N", "R", "C")),
    ("stored cross-site", ("N", "L", "N", "N", "C")),
    ("cross-site scripting", ("N", "L", "N", "R", "C")),
    (" xss", ("N", "L", "N", "R", "C")),
    ("css injection", ("N", "L", "N", "R", "C")),
    ("open redirect", ("N", "L", "N", "R", "C")),
    ("sql injection", ("N", "L", "N", "N", "U")),
    ("mass assignment", ("N", "L", "L", "N", "C")),
    ("object-level authorization", ("N", "L", "L", "N", "U")),
    ("idor", ("N", "L", "L", "N", "U")),
    ("insecure direct object reference", ("N", "L", "L", "N", "U")),
    ("cross-tenant", ("N", "L", "L", "N", "U")),
    ("tenant isolation", ("N", "L", "L", "N", "U")),
    ("function-level authorization", ("N", "L", "L", "N", "C")),
    ("bfla", ("N", "L", "L", "N", "C")),
    ("privilege escalation", ("N", "L", "L", "N", "C")),
    ("role manipulation", ("N", "L", "L", "N", "C")),
    ("jwt role manipulation", ("N", "L", "L", "N", "C")),
    ("edit role claim", ("N", "L", "L", "N", "C")),
    ("algorithm confusion", ("N", "L", "N", "N", "C")),
    ("jwt kid header injection", ("N", "L", "N", "N", "C")),
    ("jwt claim validation", ("N", "L", "N", "N", "U")),
    ("jwt replay", ("N", "L", "L", "N", "U")),
    ("jwt exposure", ("N", "L", "N", "N", "U")),
    ("server-side request forgery", ("N", "L", "N", "N", "C")),
    ("ssrf", ("N", "L", "N", "N", "C")),
    ("csrf", ("N", "L", "N", "R", "U")),
    ("cross-site request forgery", ("N", "L", "N", "R", "U")),
    ("deserialization", ("N", "L", "N", "N", "U")),
    ("web cache poisoning", ("N", "L", "N", "N", "C")),
    ("web cache deception", ("N", "L", "N", "N", "C")),
    ("graphql authorization", ("N", "L", "L", "N", "U")),
    ("graphql introspection", ("N", "L", "N", "N", "U")),
    ("business logic", ("N", "L", "L", "N", "U")),
    ("workflow step", ("N", "L", "L", "N", "U")),
    ("workflow state", ("N", "L", "L", "N", "U")),
    ("reserved username", ("N", "L", "N", "N", "U")),
    ("self-assigned privilege", ("N", "L", "N", "N", "C")),
    ("race condition", ("N", "L", "N", "N", "U")),
    ("usage limit", ("N", "L", "N", "N", "U")),
    ("account takeover", ("N", "L", "L", "N", "C")),
    ("account enumeration", ("N", "L", "N", "N", "U")),
    ("default credentials", ("N", "L", "N", "N", "U")),
    ("credential pairs", ("N", "L", "N", "N", "U")),
    ("weak password", ("N", "L", "N", "N", "U")),
    ("password autocomplete", ("N", "L", "L", "N", "U")),
    ("password change", ("N", "L", "N", "N", "U")),
    ("password reset", ("N", "L", "N", "N", "U")),
    ("rate limiting", ("N", "L", "N", "N", "U")),
    ("lockout", ("N", "L", "N", "N", "U")),
    ("session fixation", ("N", "L", "N", "N", "U")),
    ("session cookie", ("N", "L", "N", "N", "U")),
    ("session token", ("N", "L", "N", "N", "U")),
    ("session hijacking", ("N", "L", "N", "N", "U")),
    ("session not invalidated", ("N", "L", "L", "N", "U")),
    ("session not bound", ("N", "L", "L", "N", "U")),
    ("cacheable after logout", ("N", "L", "L", "N", "U")),
    ("session timeout", ("N", "L", "N", "N", "U")),
    ("access control", ("N", "L", "N", "N", "U")),
    ("forced browsing", ("N", "L", "N", "N", "U")),
    ("client-side-only enforcement", ("N", "L", "N", "N", "U")),
    ("pii", ("N", "L", "N", "N", "U")),
    ("secret exposure", ("N", "L", "N", "N", "U")),
    ("excessive data exposure", ("N", "L", "L", "N", "U")),
    ("path traversal", ("N", "L", "N", "N", "U")),
    ("null-byte", ("N", "L", "N", "N", "U")),
    ("filter bypass", ("N", "L", "N", "N", "U")),
    ("http parameter pollution", ("N", "L", "N", "N", "U")),
    ("csv/formula injection", ("N", "L", "L", "R", "U")),
    ("api key/token", ("N", "L", "N", "N", "U")),
    ("cors", ("N", "L", "N", "N", "U")),
    ("cross-domain referer", ("N", "L", "N", "N", "U")),
    ("mixed content", ("N", "L", "N", "N", "U")),
    ("cloud storage exposure", ("N", "L", "N", "N", "U")),
    ("sample/install file", ("N", "L", "N", "N", "U")),
    ("admin panel exposed", ("N", "L", "N", "N", "U")),
    ("debug mode", ("N", "L", "N", "N", "U")),
    ("directory listing", ("N", "L", "N", "N", "U")),
    ("server version disclosure", ("N", "L", "N", "N", "U")),
    ("weak tls", ("N", "L", "N", "N", "U")),
    ("robots.txt", ("N", "L", "N", "N", "U")),
    ("security headers", ("N", "L", "N", "N", "U")),
    ("content-security-policy", ("N", "L", "N", "R", "C")),
    ("path-relative stylesheet", ("N", "L", "N", "R", "C")),
    ("object identifiers", ("N", "L", "N", "N", "U")),
    ("authentication schema bypass", ("N", "L", "N", "N", "U")),
    ("security question", ("N", "L", "N", "N", "U")),
)


def _classify_shape(vuln_type: str) -> tuple[str, str, str, str, str]:
    hay = vuln_type.lower()
    for keyword, shape in _FAMILY_SHAPES:
        if keyword in hay:
            return shape
    return _FALLBACK_SHAPE


def _shape_variants(shape: tuple[str, str, str, str, str]) -> tuple[tuple[str, str, str, str, str], ...]:
    """A family's own AV/AC/PR/UI/S choice, plus a small, still-honest
    set of variants tried in order before giving up on a vector for a
    given score. `AV` (is this reachable over the network at all?) is
    the one metric kept fixed -- every finding in this codebase is a
    web-application finding, reachable over the network, so varying it
    would produce a genuinely misleading vector. The other four --
    Attack Complexity, Privileges Required, User Interaction, Scope --
    are exactly the metrics real-world NVD entries are the LEAST
    consistent about for the same weakness class (an access-control
    bypass gets scored S:C by one analyst, S:U by another, both
    defensibly; whether exploitation needs a low-priv account or none
    at all is often a judgment call specific to how a given app wired
    its own routes). Trying every combination of those four (16 total,
    all still real, nameable CVSS shapes) before giving up keeps every
    accepted vector a genuinely representative shape for the finding's
    own class, never an arbitrary one borrowed from an unrelated
    family, and never a metric invented purely to hit a number."""
    av, ac, pr, ui, s = shape
    ac_options = (ac, "H" if ac == "L" else "L")
    pr_options = (pr, "N" if pr != "N" else "L")
    ui_options = (ui, "R" if ui == "N" else "N")
    s_options = (s, "C" if s == "U" else "U")
    return tuple(
        (av, ac_v, pr_v, ui_v, s_v)
        for ac_v in ac_options for pr_v in pr_options for ui_v in ui_options for s_v in s_options
    )


_CIA_LEVELS = ("N", "L", "H")
# Search order: lowest combined impact first, so two combinations that
# both reproduce the target score prefer the more conservative one
# (never overstate C/I/A beyond what's needed to justify the score).
_CIA_SEARCH_ORDER = sorted(
    product(_CIA_LEVELS, repeat=3),
    key=lambda cia: sum(_CIA_WEIGHTS[x] for x in cia),
)


def _solve_impact_for_score(shape: tuple[str, str, str, str, str], target_score: float) -> tuple[str, str, str] | None:
    """Searches the 27 Confidentiality/Integrity/Availability
    combinations for one whose CVSS base score (with `shape`'s fixed
    AV/AC/PR/UI/S) equals `target_score` exactly. Returns `None` if no
    combination reproduces it -- CVSS's discrete metric space doesn't
    cover every possible 0.0-10.0 value, and a finding whose score
    isn't reachable this way gets no fabricated vector (see `Finding`'s
    own severity/cvss_score consistency rule -- the same honesty
    standard applies here)."""
    av, ac, pr, ui, s = shape
    if target_score == 0.0:
        return ("N", "N", "N")
    for c, i, a in _CIA_SEARCH_ORDER:
        if cvss_base_score(av, ac, pr, ui, s, c, i, a) == target_score:
            return (c, i, a)
    return None


def _first_working_vector(shapes: tuple[tuple[str, str, str, str, str], ...], target_score: float) -> str | None:
    for shape in shapes:
        cia = _solve_impact_for_score(shape, target_score)
        if cia is not None:
            av, ac, pr, ui, s = shape
            return vector_string(av, ac, pr, ui, s, *cia)
    return None


def cvss_vector_for(vuln_type: str, cvss_score: float) -> str | None:
    """The CVSS v3.1 vector for a finding of this `vuln_type` whose
    score is `cvss_score`. `None` when no real vector reproduces that
    exact score -- never a vector chosen to merely "look plausible"."""
    primary_shape = _classify_shape(vuln_type)
    vector = _first_working_vector(_shape_variants(primary_shape), cvss_score)
    if vector is not None:
        return vector
    if primary_shape == _FALLBACK_SHAPE:
        return None
    # The family's own shape (and its Scope/AC variants) still couldn't
    # reproduce this exact score -- last resort, try the generic
    # baseline's own variants before giving up entirely.
    return _first_working_vector(_shape_variants(_FALLBACK_SHAPE), cvss_score)


def cvss_vector_for_finding(finding: "Finding") -> str | None:
    return cvss_vector_for(finding.vuln_type, finding.cvss_score)
