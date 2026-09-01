"""Layer 13 — classifies a confirmed `Finding` into one of the
walkthrough "player" names in `walkthrough_players.py`.

Same "small, high-signal `technique_id`/`vuln_type` prefix matching"
philosophy every hint-list in this codebase already follows (see
`stof/modules/base.py`'s `_USERNAME_FIELD_HINTS`/`_PASSWORD_FIELD_HINTS`,
`configuration_tests.py`'s path hints, etc.) -- small, explicit,
easy-to-audit string checks, not a ML classifier or a big dispatch table.

`Finding` (Layer 10, per CLAUDE.md) has no `technique_id` field of its
own -- only `module_id`/`vuln_type`. `_TC_ID_HINTS` below is a *display*
best-effort id for the walkthrough page header only (never used for
routing/classification, which is `vuln_type`-driven); it intentionally
mirrors the same vuln_type substrings `classify_finding()` matches on so
the two stay in lockstep, falling back to `finding.module_id` when
nothing matches -- never invented from nothing.

Two unconditional fallback players guarantee every FAIL finding gets a
real walkthrough, even one never explicitly categorized here:
`"authenticated_navigation"` (generic fallback #1, IDOR/BFLA-shaped) and
`"annotated_evidence"` (generic fallback #2, the true catch-all).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from stof.findings.models import Finding

LOGIN_FORM_INJECTION = "login_form_injection"
URL_REFLECTION = "url_reflection"
DOM_EXECUTION = "dom_execution"
STORED_PLANT_AND_VIEW = "stored_plant_and_view"
SESSION_AFTER_LOGOUT = "session_after_logout"
NO_RATE_LIMIT = "no_rate_limit"
CSRF_NO_TOKEN = "csrf_no_token"
AUTHENTICATED_NAVIGATION = "authenticated_navigation"
ANNOTATED_EVIDENCE = "annotated_evidence"

# One-off structural techniques matched directly by technique_id-shaped
# substrings embedded in vuln_type/description text where present, since
# Finding itself carries no technique_id. TC-129.2/TC-129.3 are matched
# on their distinctive, effectively-unique vuln_type strings instead
# (see session_weakness_tests.py) -- there is no ambiguity to resolve.
_SESSION_AFTER_LOGOUT_VULN_TYPES = ("Session Not Invalidated",)
_NO_RATE_LIMIT_VULN_TYPES = ("No Rate Limiting", "Rate Limit", "Account Lockout")

_IDOR_HINTS = (
    "IDOR", "Object Reference", "Function-Level", "Forced Browsing",
    "Insecure Direct Object Reference", "Broken Function Level Authorization",
    "Broken Object Level Authorization", "Mass Assignment", "Method Override",
    "Privilege Escalation",
)

# Best-effort display id only -- see module docstring. Ordered so the
# most specific match ("SQL" + "Login"/"Bypass") is checked before the
# more generic "Reflected"/"Stored" ones.
_TC_ID_HINTS: tuple[tuple[str, str], ...] = (
    ("TC-127.4", ("sql", "login")),
    ("TC-127.4", ("sql", "bypass")),
    ("TC-128.5", ("dom",)),
    ("TC-128.4", ("stored",)),
    ("TC-127.6", ("second-order",)),
    ("TC-128.1", ("reflected",)),
    ("TC-129.2", ("session not invalidated",)),
    ("TC-129.3", ("rate limit",)),
    ("TC-129.3", ("account lockout",)),
    ("TC-130.1", ("csrf",)),
    ("TC-130.1", ("cross-site request forgery",)),
    ("TC-053", ("idor",)),
    ("TC-053", ("object reference",)),
    ("TC-054", ("function-level",)),
    ("TC-055", ("forced browsing",)),
)


def _contains_all(haystack: str, needles: tuple[str, ...]) -> bool:
    return all(n in haystack for n in needles)


def _contains_any(haystack: str, needles: tuple[str, ...]) -> bool:
    return any(n.lower() in haystack for n in needles)


def _is_login_form_injection(vuln_type: str, text: str) -> bool:
    return "sql" in text and ("login" in text or "bypass" in text)


def _is_session_after_logout(vuln_type: str, text: str) -> bool:
    return _contains_any(vuln_type, _SESSION_AFTER_LOGOUT_VULN_TYPES)


def _is_no_rate_limit(vuln_type: str, text: str) -> bool:
    return _contains_any(vuln_type, _NO_RATE_LIMIT_VULN_TYPES)


def _is_csrf(vuln_type: str, text: str) -> bool:
    return "csrf" in text or "cross-site request forgery" in text


def _is_dom_execution(vuln_type: str, text: str) -> bool:
    return "dom-based" in vuln_type or ("dom" in vuln_type and "xss" in vuln_type)


def _is_stored_plant_and_view(vuln_type: str, text: str) -> bool:
    return "stored" in vuln_type or "second-order" in vuln_type or "second order" in vuln_type


def _is_url_reflection(vuln_type: str, text: str) -> bool:
    return "reflected" in vuln_type


def _is_authenticated_navigation(vuln_type: str, text: str) -> bool:
    return _contains_any(text, _IDOR_HINTS)


# Ordered most-specific-first; the first matching predicate wins. A
# single small loop keeps this function's own cyclomatic complexity
# flat regardless of how many player categories get added later --
# each predicate carries its own (already-small) branching instead.
_CLASSIFIERS: tuple[tuple[str, "callable"], ...] = (
    (LOGIN_FORM_INJECTION, _is_login_form_injection),
    (SESSION_AFTER_LOGOUT, _is_session_after_logout),
    (NO_RATE_LIMIT, _is_no_rate_limit),
    (CSRF_NO_TOKEN, _is_csrf),
    (DOM_EXECUTION, _is_dom_execution),
    (STORED_PLANT_AND_VIEW, _is_stored_plant_and_view),
    (URL_REFLECTION, _is_url_reflection),
    (AUTHENTICATED_NAVIGATION, _is_authenticated_navigation),
)


def classify_finding(finding: "Finding") -> str:
    """Pure function: `Finding` -> player name. Never raises, never
    returns an unmapped/unknown name -- `ANNOTATED_EVIDENCE` is the
    unconditional default."""
    vuln_type = (finding.vuln_type or "").lower()
    description = (finding.description or "").lower()
    text = f"{vuln_type} {description}"

    for player_name, predicate in _CLASSIFIERS:
        if predicate(vuln_type, text):
            return player_name

    return ANNOTATED_EVIDENCE


def display_tc_id(finding: "Finding") -> str:
    """Best-effort human-readable id for the walkthrough page header
    only (see module docstring) -- falls back to `module_id` when no
    hint matches rather than inventing an id that doesn't exist."""
    vuln_type = (finding.vuln_type or "").lower()
    description = (finding.description or "").lower()
    text = f"{vuln_type} {description}"
    for tc_id, needles in _TC_ID_HINTS:
        if _contains_all(text, needles):
            return tc_id
    return finding.module_id
