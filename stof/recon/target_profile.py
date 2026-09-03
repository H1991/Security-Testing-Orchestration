"""Recon Engine — target stack classification (Phase 1 of context-aware
testing).

`ReconReport.tech_stack` (populated by `tech_detector.py`) is real,
already-working fingerprint data -- but nothing downstream ever reads
it. Every vuln module technique runs the exact same candidate-path/
signature sweep regardless of what recon already learned about the
target. This is the plumbing that closes that gap for the first
consumer (`configuration_tests.py`): a small, honest classifier that
turns the raw per-page tech signature strings into one target-wide
`TargetProfile`, so a module can narrow (never silently skip) a
candidate list to what's actually plausible for this target.

Design constraint carried over from `main.py`'s own
`_apply_application_profile()` precedent (see that function's
docstring): never guess at a richer "app type" to decide relevance
when the signal is genuinely ambiguous -- a wrong guess here would
silently narrow real coverage, which is a worse failure than probing a
handful of paths that turn out irrelevant. `stack_family` defaults to
"unknown" (never NARROWS anything) unless the evidence is unambiguous.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .recon_engine import ReconReport

# Each family maps to the raw tech-signature substrings (case-
# insensitive) that unambiguously imply it -- server banners, X-Powered-By
# values, and file-extension/cookie signatures `tech_detector.py` already
# emits into `ReconReport.tech_stack[*]['tech']`. Deliberately narrow:
# a generic "nginx"/"cloudflare" match implies nothing about the
# application layer running behind it, so it's not included here at all.
_STACK_FAMILY_SIGNATURES: dict[str, tuple[str, ...]] = {
    "php": ("php", "wordpress", "laravel", "x-powered-by: php"),
    "java": ("apache-coyote", "jsessionid", "java (jsp/servlet)", "tomcat", "jetty"),
    "dotnet": ("asp.net", "microsoft-iis", "x-aspnet-version", "x-aspnetmvc-version"),
    "python": ("django", "gunicorn", "werkzeug"),
    "node": ("express", "connect.sid", "next.js", "nuxt.js"),
    "ruby": ("phusion passenger", "ruby on rails", "puma"),
}

# JSP/ASPX/PHP page-extension signals in the crawled URLs themselves --
# a second, independent evidence source alongside header/cookie/body
# signatures, since a target can suppress its Server header entirely
# but can't hide its own file extensions.
_URL_EXTENSION_STACK: dict[str, str] = {
    ".jsp": "java", ".jspx": "java",
    ".aspx": "dotnet", ".asmx": "dotnet",
    ".php": "php",
}


@dataclass
class TargetProfile:
    stack_family: str = "unknown"  # "php" | "java" | "dotnet" | "python" | "node" | "ruby" | "unknown"
    detected_tech: list[str] = field(default_factory=list)
    # "high" -- 2+ independent signals (e.g. a header AND a URL extension)
    # agree; "low" -- exactly one signal; "none" -- stack_family is "unknown".
    confidence: str = "none"


def _collect_evidence(recon_report: "ReconReport") -> tuple[set[str], dict[str, int]]:
    """Single pass over `tech_stack`: collects every raw tech-signature
    string (for `TargetProfile.detected_tech`) and a per-URL-extension
    vote (a `.jsp`/`.aspx`/`.php` extension is its own independent
    stack signal, alongside whatever header/cookie/body tech strings
    `tech_detector.py` already found on that same page)."""
    detected_tech: set[str] = set()
    extension_votes: dict[str, int] = {}
    for page in recon_report.tech_stack:
        detected_tech.update(page.get("tech", []))
        url = page.get("url", "").lower()
        for ext, family in _URL_EXTENSION_STACK.items():
            if url.endswith(ext):
                detected_tech.add(f"url-extension:{ext}")
                extension_votes[family] = extension_votes.get(family, 0) + 1
    return detected_tech, extension_votes


def _family_votes_from_tech(detected_tech: set[str]) -> dict[str, int]:
    # Excludes the synthetic "url-extension:.php"-shaped markers
    # `_collect_evidence` adds to `detected_tech` for reporting -- those
    # already cast their own vote via `extension_votes`; substring-
    # matching them again here would double-count the same signal
    # (".php" appears inside "url-extension:.php" too) and inflate a
    # single real signal into a false "high confidence" pair.
    lowered_tech = {t.lower() for t in detected_tech if not t.startswith("url-extension:")}
    votes: dict[str, int] = {}
    for family, signatures in _STACK_FAMILY_SIGNATURES.items():
        hits = sum(1 for sig in signatures if any(sig in t for t in lowered_tech))
        if hits:
            votes[family] = hits
    return votes


def build_target_profile(recon_report: "ReconReport | None") -> TargetProfile:
    """Pure, directly-unit-testable classifier. Never raises -- a
    missing/empty recon report (recon skipped, or no user configured
    to authenticate it with, both real conditions `main.py` already
    handles) just yields the default "unknown" profile, which every
    consumer must treat as "narrow nothing, probe everything"."""
    if recon_report is None:
        return TargetProfile()

    detected_tech, family_votes = _collect_evidence(recon_report)
    for family, hits in _family_votes_from_tech(detected_tech).items():
        family_votes[family] = family_votes.get(family, 0) + hits

    if not family_votes:
        return TargetProfile(detected_tech=sorted(detected_tech))

    # The family with the most independent corroborating signals wins;
    # a tie (two families each with exactly one signal) is genuinely
    # ambiguous and stays "unknown" rather than guessing between them.
    top_family = max(family_votes, key=lambda f: family_votes[f])
    tied = [f for f, v in family_votes.items() if v == family_votes[top_family]]
    if len(tied) > 1:
        return TargetProfile(detected_tech=sorted(detected_tech))

    confidence = "high" if family_votes[top_family] >= 2 else "low"
    return TargetProfile(stack_family=top_family, detected_tech=sorted(detected_tech), confidence=confidence)
