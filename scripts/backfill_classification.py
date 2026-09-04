#!/usr/bin/env python3
"""One-time backfill: stamp cwe/owasp_category (and technique_id, where
recoverable) onto every Finding already written to disk before
stof.findings.classification / extract_findings()'s stamping existed.

Only module_id/vuln_type/description are needed by classify_cwe()/
classify_owasp() -- every finding ever written has always carried
those, so this is a real, accurate backfill, not a guess filled in
after the fact. technique_id genuinely cannot be recovered for old
data (it was never stored anywhere), so it's left as None/absent
rather than fabricated.

Covers every place a Finding gets serialized to disk:
  - data/reports/scan_*.json           (report envelope: findings: [...])
  - data/benchmarks/results/reports/scan_*.json  (same shape, separate tree)
  - data/findings/scan_*.json          (bare list[Finding])
  - data/findings.json                 (bare list[Finding], "latest" pointer)

Idempotent: a finding that already has a non-null owasp_category is
left untouched, so running this twice (or after new scans have already
started stamping their own findings) is always safe.

Usage:
    python3 scripts/backfill_classification.py [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from stof.findings.classification import classify_cwe, classify_owasp

REPORT_GLOBS = (
    REPO_ROOT / "data" / "reports",
    REPO_ROOT / "data" / "benchmarks" / "results" / "reports",
)
BARE_FINDINGS_GLOBS = (
    REPO_ROOT / "data" / "findings",
)
BARE_FINDINGS_FILES = (
    REPO_ROOT / "data" / "findings.json",
)


def _backfill_finding(finding: dict, force: bool = False) -> bool:
    """Mutates `finding` in place if it's missing cwe/owasp_category
    (or unconditionally, with `force=True` -- needed the one time this
    file's own classification RULES change, e.g. moving from OWASP
    Top 10:2021-only to the tiered API-2023/Web-2025 scheme: findings
    already stamped under the old rules have real, non-null values, so
    the normal "only fill in what's missing" check would otherwise
    leave them on the outdated categories forever). Returns True if
    anything changed."""
    if not force and finding.get("owasp_category") and finding.get("cwe"):
        return False
    module_id = finding.get("module_id", "")
    vuln_type = finding.get("vuln_type", "")
    description = finding.get("description", "")
    finding["cwe"] = classify_cwe(module_id, vuln_type, description)
    finding["owasp_category"] = classify_owasp(module_id, vuln_type, description)
    finding.setdefault("technique_id", None)
    return True


def _backfill_report_file(path: Path, dry_run: bool, force: bool = False) -> int:
    doc = json.loads(path.read_text(encoding="utf-8"))
    findings = doc.get("findings")
    if not isinstance(findings, list):
        return 0
    changed = sum(1 for f in findings if _backfill_finding(f, force=force))
    if changed and not dry_run:
        path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return changed


def _backfill_bare_findings_file(path: Path, dry_run: bool, force: bool = False) -> int:
    findings = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(findings, list):
        return 0
    changed = sum(1 for f in findings if _backfill_finding(f, force=force))
    if changed and not dry_run:
        path.write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    return changed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="report what would change without writing anything")
    parser.add_argument("--force", action="store_true", help="recompute cwe/owasp_category even for findings that already have them (use after a classification RULE change, e.g. a new OWASP edition)")
    args = parser.parse_args()

    total_files = 0
    total_findings = 0

    for reports_dir in REPORT_GLOBS:
        if not reports_dir.is_dir():
            continue
        for path in sorted(reports_dir.glob("scan_*.json")):
            changed = _backfill_report_file(path, args.dry_run, force=args.force)
            if changed:
                total_files += 1
                total_findings += changed
                print(f"{'[dry-run] would update' if args.dry_run else 'updated'} {path} -- {changed} finding(s)")

    for findings_dir in BARE_FINDINGS_GLOBS:
        if not findings_dir.is_dir():
            continue
        for path in sorted(findings_dir.glob("scan_*.json")):
            changed = _backfill_bare_findings_file(path, args.dry_run, force=args.force)
            if changed:
                total_files += 1
                total_findings += changed
                print(f"{'[dry-run] would update' if args.dry_run else 'updated'} {path} -- {changed} finding(s)")

    for path in BARE_FINDINGS_FILES:
        if not path.is_file():
            continue
        changed = _backfill_bare_findings_file(path, args.dry_run, force=args.force)
        if changed:
            total_files += 1
            total_findings += changed
            print(f"{'[dry-run] would update' if args.dry_run else 'updated'} {path} -- {changed} finding(s)")

    verb = "Would backfill" if args.dry_run else "Backfilled"
    print(f"\n{verb} {total_findings} finding(s) across {total_files} file(s).")


if __name__ == "__main__":
    main()
