"""Layer 13 — machine-readable JSON report.

Distinct from `stof/findings/store.py`'s `write_findings()`: that
writes the bare `list[Finding]` Layer 10 persists internally. This
wraps the same findings with scan metadata and a severity-count summary
-- the shape a management/CI consumer actually wants, not the raw
storage format.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from stof.core.logger import get_logger

if TYPE_CHECKING:
    from stof.findings.models import Finding

_log = get_logger("reporting.json_report")

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")

_SOURCE_LABELS = {"stof": "STOF", "burp": "Burp Suite Pro"}


def _critical_high_confidence_counts(findings: list["Finding"]) -> dict[str, int]:
    """The number a triager actually cares about first for a tool whose
    whole point is not crying wolf on Critical/High: how many of THOSE
    are STOF directly observing the claimed effect (a write that really
    succeeded, a value really echoed back) vs. a genuinely uncertain
    signal (a timing inference, an accepted-but-unconfirmable change, a
    proven precondition for a vuln class STOF can't itself verify
    exists) that STOF is honest about needing manual confirmation for.
    See `Finding.confidence`'s own docstring."""
    critical_high = [f for f in findings if f.severity in ("Critical", "High")]
    counts = Counter(f.confidence for f in critical_high)
    return {
        "confirmed": counts.get("confirmed", 0),
        "likely": counts.get("likely", 0),
        "tentative": counts.get("tentative", 0),
    }


def build_summary(findings: list["Finding"]) -> dict[str, Any]:
    counts = Counter(f.severity for f in findings)
    by_source_raw = Counter(f.scanner_source for f in findings)
    by_source = {
        _SOURCE_LABELS.get(source, source): count for source, count in by_source_raw.items()
    }
    critical_high_confidence = _critical_high_confidence_counts(findings)
    return {
        "total_findings": len(findings),
        "by_severity": {sev: counts.get(sev, 0) for sev in SEVERITY_ORDER},
        "by_source": by_source,
        "critical_high_confirmed": critical_high_confidence["confirmed"],
        "critical_high_likely": critical_high_confidence["likely"],
        "critical_high_tentative": critical_high_confidence["tentative"],
    }


def build_report(
    findings: list["Finding"],
    scan_metadata: dict[str, Any],
    recon_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    report = {
        "scan_id": scan_metadata.get("scan_id"),
        "target": scan_metadata.get("target"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "modules_run": scan_metadata.get("modules_run", []),
        "module_notes": scan_metadata.get("module_notes", []),
        "duration_seconds": scan_metadata.get("duration_seconds"),
        "summary": build_summary(findings),
        "coverage": scan_metadata.get("coverage"),
        "skipped_techniques": scan_metadata.get("skipped_techniques", []),
        "findings": [f.to_dict() for f in findings],
    }
    if recon_report is not None:
        report["recon"] = recon_report
    return report


def write(
    findings: list["Finding"],
    scan_metadata: dict[str, Any],
    output_path: str | Path,
    recon_report: dict[str, Any] | None = None,
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(findings, scan_metadata, recon_report)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    _log.info(f"wrote JSON report ({len(findings)} finding(s)) -> {path}")
    return path
