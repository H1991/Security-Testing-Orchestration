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
        )
