#!/usr/bin/env python3
"""STOF evaluation harness -- Layer-agnostic script, not part of the
`stof` package itself (deliberately: this drives `stof scan` as a real
subprocess exactly the way the web console does, rather than importing
main.py's internals, so it measures the actual shipped behavior).

Runs a real scan against a ground-truth target, matches the resulting
findings against a curated, honest "here's what STOF should catch"
manifest (data/benchmarks/ground_truth/<target>.json), and reports:

  - recall per category (did STOF find each known, documented issue)
  - which known issues were MISSED (false negatives) -- the actionable
    output
  - which findings weren't matched to anything in the ground-truth list
    (NOT automatically "false positives" -- Juice Shop has far more
    real vulnerabilities than this curated manifest lists; these are
    surfaced for a human to actually look at, never auto-labeled)
  - a regression check against the immediately previous run for the
    same target, so a code change that silently drops detection is
    caught by running this again, not by re-reading a scan log by eye

Usage:
    python3 scripts/benchmark.py juiceshop
    python3 scripts/benchmark.py juiceshop --skip-scan --scan-id <id>   # re-score an existing run
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = REPO_ROOT / "data" / "benchmarks"
CONFIGS_DIR = BENCH_DIR / "configs"
GROUND_TRUTH_DIR = BENCH_DIR / "ground_truth"
RESULTS_DIR = BENCH_DIR / "results"


def _run_scan(target_name: str) -> str:
    """Launches `stof scan` as a real subprocess against the target's
    own benchmark config/users, exactly how a real operator would run
    it -- not a shortcut through main.py's internals. Returns the
    scan_id STOF assigned, found by looking at which `scan_*.json`
    report file appeared in the target's reports_dir after this
    subprocess started (more robust than parsing the console banner's
    own text, which is formatted for a human, not a script, and
    changed shape once already this session)."""
    config_path = CONFIGS_DIR / f"{target_name}_config.json"
    users_path = CONFIGS_DIR / f"{target_name}_users.json"
    if not config_path.exists() or not users_path.exists():
        print(f"No benchmark config for '{target_name}' -- expected {config_path} and {users_path}", file=sys.stderr)
        sys.exit(2)

    config = json.loads(config_path.read_text())
    reports_dir = REPO_ROOT / config["output"]["reports_dir"]
    reports_dir.mkdir(parents=True, exist_ok=True)
    before = {p.name for p in reports_dir.glob("scan_*.json")}

    print(f"[benchmark] launching real scan against '{target_name}' (config: {config_path.name})...")
    proc = subprocess.run(  # noqa: S603 -- fixed argv (sys.executable + literal flags), no untrusted input
        [sys.executable, "-m", "stof.main", "scan", "--config", str(config_path), "--users", str(users_path)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=1800, check=False,
    )
    after = {p for p in reports_dir.glob("scan_*.json") if p.name not in before}
    if not after:
        output = proc.stdout + proc.stderr
        print(f"[benchmark] scan process exited {proc.returncode} but no new report appeared in {reports_dir} -- last 40 lines:", file=sys.stderr)
        print("\n".join(output.splitlines()[-40:]), file=sys.stderr)
        sys.exit(1)
    # Exactly one new report is the expected case; if somehow more than
    # one appeared, the newest by mtime is this run's.
    new_report = max(after, key=lambda p: p.stat().st_mtime)
    scan_id = new_report.stem.removeprefix("scan_")
    print(f"[benchmark] scan complete, scan_id={scan_id} (exit code {proc.returncode})")
    return scan_id


def _load_findings(target_name: str, scan_id: str) -> list[dict]:
    config = json.loads((CONFIGS_DIR / f"{target_name}_config.json").read_text())
    reports_dir = REPO_ROOT / config["output"]["reports_dir"]
    report_path = reports_dir / f"scan_{scan_id}.json"
    if not report_path.exists():
        print(f"[benchmark] expected report at {report_path} but it doesn't exist", file=sys.stderr)
        sys.exit(1)
    doc = json.loads(report_path.read_text())
    return doc.get("findings", [])


def _matches_case(finding: dict, case: dict) -> bool:
    vuln_type = (finding.get("vuln_type") or "").lower()
    endpoint = finding.get("endpoint")
    endpoint_url = (endpoint.get("url") if isinstance(endpoint, dict) else endpoint) or ""
    endpoint_url = endpoint_url.lower()

    vuln_match = any(kw.lower() in vuln_type for kw in case["expects_vuln_type_keywords"])
    if not vuln_match:
        return False
    endpoint_keywords = case.get("expects_endpoint_keywords") or []
    if not endpoint_keywords:
        return True
    return any(kw.lower() in endpoint_url for kw in endpoint_keywords)


def _score(findings: list[dict], ground_truth: dict) -> dict:
    matched_cases, missed_cases = [], []
    matched_finding_indices: set[int] = set()

    for case in ground_truth["cases"]:
        hit = None
        for i, finding in enumerate(findings):
            # Skip a finding already consumed by an earlier case -- one
            # real finding must not be able to satisfy two different
            # ground-truth cases and inflate recall past what actually
            # happened.
            if i in matched_finding_indices:
                continue
            if _matches_case(finding, case):
                hit = finding
                matched_finding_indices.add(i)
                break
        if hit:
            matched_cases.append({"case": case, "matched_finding": {
                "vuln_type": hit.get("vuln_type"), "severity": hit.get("severity"),
                "endpoint": hit.get("endpoint"),
            }})
        else:
            missed_cases.append(case)

    unmatched_findings = [
        {"vuln_type": f.get("vuln_type"), "severity": f.get("severity"), "endpoint": f.get("endpoint")}
        for i, f in enumerate(findings) if i not in matched_finding_indices
    ]
    total = len(ground_truth["cases"])
    recall = len(matched_cases) / total if total else 0.0
    return {
        "recall": recall,
        "matched_count": len(matched_cases),
        "total_cases": total,
        "matched_cases": matched_cases,
        "missed_cases": missed_cases,
        "unmatched_findings_for_human_review": unmatched_findings,
        "total_findings_in_scan": len(findings),
    }


def _print_report(target_name: str, result: dict, previous: dict | None) -> None:
    print()
    print(f"=== Benchmark: {target_name} ===")
    print(f"Recall: {result['matched_count']}/{result['total_cases']} ({result['recall']*100:.0f}%)")
    print(f"Total findings in scan: {result['total_findings_in_scan']}")
    print()
    print("Matched (true positives):")
    for m in result["matched_cases"]:
        c = m["case"]
        print(f"  [OK] {c['id']} ({c['category']}) -- {c['description']}")
    print()
    if result["missed_cases"]:
        print("MISSED (false negatives -- STOF should have caught these):")
        for c in result["missed_cases"]:
            print(f"  [MISS] {c['id']} ({c['category']}) -- {c['description']}")
    else:
        print("No misses -- every ground-truth case was caught.")
    print()
    print(f"Findings not matched to any ground-truth case ({len(result['unmatched_findings_for_human_review'])}) -- "
          "NOT automatically false positives, this target has real vulnerabilities beyond this curated manifest; "
          "review, don't assume noise:")
    for f in result["unmatched_findings_for_human_review"][:15]:
        ep = f.get("endpoint")
        ep_url = ep.get("url") if isinstance(ep, dict) else ep
        print(f"  - {f.get('severity'):8s} {f.get('vuln_type')} @ {ep_url}")
    if len(result["unmatched_findings_for_human_review"]) > 15:
        print(f"  ... and {len(result['unmatched_findings_for_human_review']) - 15} more (see the saved JSON result)")

    if previous is not None:
        print()
        delta = result["recall"] - previous["recall"]
        if delta < -1e-9:
            print(f"⚠ REGRESSION: recall dropped from {previous['recall']*100:.0f}% to {result['recall']*100:.0f}% since the last run")
        elif delta > 1e-9:
            print(f"✓ recall improved from {previous['recall']*100:.0f}% to {result['recall']*100:.0f}% since the last run")
        else:
            print(f"= recall unchanged ({result['recall']*100:.0f}%) since the last run")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", help="benchmark target name, e.g. 'juiceshop' -- must have matching files in data/benchmarks/configs/ and ground_truth/")
    parser.add_argument("--skip-scan", action="store_true", help="re-score an already-completed scan instead of launching a new one")
    parser.add_argument("--scan-id", help="scan_id to re-score, required with --skip-scan")
    args = parser.parse_args()

    ground_truth_path = GROUND_TRUTH_DIR / f"{args.target}.json"
    if not ground_truth_path.exists():
        print(f"No ground-truth manifest at {ground_truth_path}", file=sys.stderr)
        sys.exit(2)
    ground_truth = json.loads(ground_truth_path.read_text())

    if args.skip_scan:
        if not args.scan_id:
            print("--skip-scan requires --scan-id", file=sys.stderr)
            sys.exit(2)
        scan_id = args.scan_id
    else:
        scan_id = _run_scan(args.target)

    findings = _load_findings(args.target, scan_id)
    result = _score(findings, ground_truth)
    result["target"] = args.target
    result["scan_id"] = scan_id
    result["timestamp"] = datetime.now(timezone.utc).isoformat()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    previous = None
    existing = sorted(RESULTS_DIR.glob(f"{args.target}_*.json"))
    if existing:
        previous = json.loads(existing[-1].read_text())

    result_path = RESULTS_DIR / f"{args.target}_{int(time.time())}.json"
    result_path.write_text(json.dumps(result, indent=2))

    _print_report(args.target, result, previous)
    print()
    print(f"[benchmark] result saved to {result_path}")


if __name__ == "__main__":
    main()
