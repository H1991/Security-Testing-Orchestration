"""Layer 10 — Unified Findings Store: the `Finding` data contract.

(Built ahead of the rest of Layer 10, during Layer 9 — same precedent as
`session/models.py` being built early during Layer 4: CLAUDE.md's own
Layer 9 `VulnModule.run()` spec returns `list[Finding]`, so this had to
exist before a real vulnerability module could be written.)

Field order below matches CLAUDE.md's Layer 10 spec exactly in
`to_dict()`/`from_dict()`. The dataclass field *declaration* order
differs slightly (fields with sensible defaults -- `finding_id`,
`evidence_refs`, `discovered_at`, `scanner_source` -- are grouped after
the required ones) because Python dataclasses require defaulted fields
to come last; `Session` (Layer 5) sets the same precedent for
`session_id`.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from stof.crawler.endpoint_store import Endpoint


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# CVSS v3.1's own qualitative severity rating scale -- the exact mapping
# every compliance framework that references CVSS (PCI DSS, SOC 2,
# ISO 27001) expects, and the single source of truth `Finding.
# __post_init__` below enforces every STOF-generated finding actually
# follows. Before this existed, ~130 `Finding(...)` call sites across
# the vuln modules each hand-typed BOTH a severity string and a
# cvss_score independently, with nothing keeping them in sync -- an
# audit found 54 of them had drifted (the overwhelming majority
# inflated, e.g. a CVSS 4.3 "Server Version Disclosure" labeled
# "Critical"), which is exactly the kind of noise that erodes trust in
# a tool's real Critical/High findings and would fail a compliance
# review that checks severity against the reported CVSS score.
_CVSS_SEVERITY_BANDS: tuple[tuple[float, str], ...] = (
    (9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"),
)


def severity_for_score(cvss_score: float) -> str:
    """CVSS v3.1 qualitative severity rating: 0.0 -> Info, 0.1-3.9 ->
    Low, 4.0-6.9 -> Medium, 7.0-8.9 -> High, 9.0-10.0 -> Critical."""
    for threshold, label in _CVSS_SEVERITY_BANDS:
        if cvss_score >= threshold:
            return label
    return "Info"


@dataclass
class Finding:
    module_id: str
    vuln_type: str
    severity: str  # Critical | High | Medium | Low | Info
    cvss_score: float
    endpoint: "Endpoint"
    user_role: str
    request_raw: str
    response_raw: str
    description: str
    recommendation: str
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    evidence_refs: list[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=_utcnow)
    scanner_source: str = "stof"
    # The originating `TestCaseResult.technique_id` (e.g. "TC-127.4") --
    # NOT set by any of the ~130 `Finding(...)` call sites across the
    # vuln modules (a `Finding` never knew which technique produced it).
    # `stof.modules.results.extract_findings()` is the one place every
    # module's results already funnel through on the way to becoming
    # this project's canonical findings list, so it's the one place
    # that stamps this in -- see its own docstring. `cwe`/`owasp_category`
    # are derived from `technique_id` (falling back to `module_id`/
    # `vuln_type` keyword matching) by `stof.findings.classification`,
    # stamped in at the same point -- a single authoritative source
    # instead of the frontend re-guessing from prose text on every
    # render, which is what this replaces.
    technique_id: str | None = None
    cwe: str | None = None
    owasp_category: str | None = None
    # "confirmed" (default) -- STOF directly observed the technical effect
    # its own description claims (a write actually succeeded, a value was
    # actually echoed back, a real triggered dialog/redirect). "likely" --
    # a genuinely uncertain signal STOF says so about in its own
    # description: a timing-based inference, a response-code differential
    # without content verification, a proven precondition for a
    # vulnerability class STOF can't independently confirm exists (e.g. a
    # CSV/Excel export), or an accepted-but-unconfirmable password change
    # (no login endpoint configured to verify it took effect). Was
    # previously only ever expressed as free-text prose buried inside
    # `description` -- e.g. "CONFIRMED: ..." vs "Unconfirmed via
    # re-login..." -- with no way for a human triager or the report layer
    # to filter on it. Every one of the ~15 call sites across this
    # project's modules that already had this distinction in prose now
    # also sets this field explicitly; every other call site keeps the
    # "confirmed" default unchanged.
    confidence: str = "confirmed"
    # The full CVSS v3.1 vector (`CVSS:3.1/AV:N/AC:L/...`) `cvss_score`
    # was computed from -- stamped centrally by `extract_findings()`
    # (see `stof.findings.cvss.cvss_vector_for_finding`), never set
    # directly at a `Finding(...)` call site. `None` when no real CVSS
    # v3.1 metric combination reproduces this exact `cvss_score` (a
    # genuine, if rare, gap in CVSS's own discrete scoring space -- see
    # that module's docstring) -- never a fabricated vector.
    cvss_vector: str | None = None
    # The role of the SECOND, genuinely different identity that cross-
    # session-confirmed this finding (see `idor_tests.py`'s
    # `_confirm_cross_session`) -- `None` when no such confirmation ran
    # (single-session evidence only, or a vuln class this doesn't apply
    # to). Exists so a downstream consumer that wants to independently
    # verify a finding (Burp evidence capture) knows there's a second,
    # real authenticated identity worth replaying alongside `user_role`,
    # not just the one that first observed the distinct content.
    confirmed_role: str | None = None

    def __post_init__(self) -> None:
        # Only for STOF's own findings -- a Burp-imported finding
        # (`scanner_source == "burp"`, Phase 2) carries Burp's own
        # severity judgment, which legitimately isn't always a pure
        # function of a CVSS score alone (Burp has "Information"-level
        # findings with no CVSS score at all, for instance), and this
        # project has no business overriding another scanner's own
        # classification. For STOF's own findings, though, severity and
        # cvss_score are two views of the exact same, single judgment
        # call this codebase makes at Finding-construction time -- there
        # is no legitimate reason for them to ever disagree, and 54
        # already had before this check existed (see `severity_for_
        # score`'s own docstring). Raising here (not silently
        # normalizing) means a new technique that reintroduces this bug
        # fails its own unit test immediately, not "eventually, in a
        # report a compliance reviewer flags."
        if self.scanner_source == "stof":
            expected = severity_for_score(self.cvss_score)
            if self.severity != expected:
                raise ValueError(
                    f"Finding(vuln_type={self.vuln_type!r}) has severity={self.severity!r} but "
                    f"cvss_score={self.cvss_score} maps to {expected!r} on the CVSS v3.1 scale -- "
                    "these must match for a STOF-generated finding. Fix the severity= argument "
                    "at the Finding(...) call site (see severity_for_score())."
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "module_id": self.module_id,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "endpoint": self.endpoint.to_dict(),
            "user_role": self.user_role,
            "request_raw": self.request_raw,
            "response_raw": self.response_raw,
            "evidence_refs": self.evidence_refs,
            "description": self.description,
            "recommendation": self.recommendation,
            "discovered_at": self.discovered_at.isoformat(),
            "scanner_source": self.scanner_source,
            "technique_id": self.technique_id,
            "cwe": self.cwe,
            "owasp_category": self.owasp_category,
            "confidence": self.confidence,
            "cvss_vector": self.cvss_vector,
            "confirmed_role": self.confirmed_role,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        from stof.crawler.endpoint_store import Endpoint

        return cls(
            finding_id=data["finding_id"],
            module_id=data["module_id"],
            vuln_type=data["vuln_type"],
            severity=data["severity"],
            cvss_score=data["cvss_score"],
            endpoint=Endpoint.from_dict(data["endpoint"]),
            user_role=data["user_role"],
            request_raw=data["request_raw"],
            response_raw=data["response_raw"],
            evidence_refs=data.get("evidence_refs", []),
            description=data["description"],
            recommendation=data["recommendation"],
            discovered_at=datetime.fromisoformat(data["discovered_at"]),
            scanner_source=data.get("scanner_source", "stof"),
            technique_id=data.get("technique_id"),
            cwe=data.get("cwe"),
            owasp_category=data.get("owasp_category"),
            confidence=data.get("confidence", "confirmed"),
            cvss_vector=data.get("cvss_vector"),
            confirmed_role=data.get("confirmed_role"),
        )

    def to_row(self) -> dict[str, Any]:
        """Serialise to a flat dict of SQLite-storable primitives,
        matching `Session.to_row()`'s convention of JSON-encoding
        nested structures."""
        return {
            "finding_id": self.finding_id,
            "module_id": self.module_id,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "endpoint": json.dumps(self.endpoint.to_dict()),
            "user_role": self.user_role,
            "request_raw": self.request_raw,
            "response_raw": self.response_raw,
            "evidence_refs": json.dumps(self.evidence_refs),
            "description": self.description,
            "recommendation": self.recommendation,
            "discovered_at": self.discovered_at.isoformat(),
            "scanner_source": self.scanner_source,
            "technique_id": self.technique_id,
            "cwe": self.cwe,
            "owasp_category": self.owasp_category,
            "confidence": self.confidence,
            "cvss_vector": self.cvss_vector,
            "confirmed_role": self.confirmed_role,
        }

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "Finding":
        from stof.crawler.endpoint_store import Endpoint

        return cls(
            finding_id=row["finding_id"],
            module_id=row["module_id"],
            vuln_type=row["vuln_type"],
            severity=row["severity"],
            cvss_score=row["cvss_score"],
            endpoint=Endpoint.from_dict(json.loads(row["endpoint"])),
            user_role=row["user_role"],
            request_raw=row["request_raw"],
            response_raw=row["response_raw"],
            evidence_refs=json.loads(row["evidence_refs"]),
            description=row["description"],
            recommendation=row["recommendation"],
            discovered_at=datetime.fromisoformat(row["discovered_at"]),
            scanner_source=row["scanner_source"],
            technique_id=row.get("technique_id"),
            cwe=row.get("cwe"),
            owasp_category=row.get("owasp_category"),
            confidence=row.get("confidence") or "confirmed",
            cvss_vector=row.get("cvss_vector"),
            confirmed_role=row.get("confirmed_role"),
        )
