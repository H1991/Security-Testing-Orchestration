"""stof/tools integration demo: runs the REAL ProjectDiscovery httpx +
nuclei binaries against demo.testfire.net and synthesizes the curated
techstack.json shape.

Requires the real `httpx` and `nuclei` (ProjectDiscovery) binaries on
PATH or in one of `extra_dirs` below -- download from
https://github.com/projectdiscovery/httpx/releases and
https://github.com/projectdiscovery/nuclei/releases (no Go toolchain
needed, prebuilt binaries are provided). Not a mock: this is the real
"tool section" of the app, wrapping the real tools via subprocess.

Run directly to produce data/techstack.json:
    python tests/integration/test_tools_techstack_demo.py
"""
from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path

from stof.tools import run_httpx, run_nuclei, synthesize_techstack

TARGET = "https://demo.testfire.net"
HTTPX_OUT_PATH = Path("data/httpx_results.json")
NUCLEI_OUT_PATH = Path("data/nuclei_results.json")
OUT_PATH = Path("data/techstack.json")


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"--- wrote {path} ---")


async def _run(extra_dirs: list[str]) -> None:
    print(f"--- running real httpx against {TARGET} ---")
    httpx_results = await run_httpx([TARGET], extra_dirs=extra_dirs, timeout_s=60)
    for r in httpx_results:
        print(f"  {r.url}  status={r.status_code}  title={r.title!r}  server={r.webserver}  tech={r.tech}")
    _write(HTTPX_OUT_PATH, [asdict(r) for r in httpx_results])

    print(f"--- running real nuclei (tags=tech, safe exclusions) against {TARGET} ---")
    nuclei_findings = await run_nuclei(TARGET, tags=["tech"], extra_dirs=extra_dirs, timeout_s=120)
    for f in nuclei_findings:
        print(f"  [{f.severity}] {f.name} ({f.template_id})")
    _write(NUCLEI_OUT_PATH, [asdict(f) for f in nuclei_findings])

    summary = synthesize_techstack(TARGET, httpx_results=httpx_results, nuclei_findings=nuclei_findings)
    _write(OUT_PATH, summary.to_dict())
    print(json.dumps(summary.to_dict(), indent=2))


if __name__ == "__main__":
    extra_dirs = sys.argv[1:] or []
    asyncio.run(_run(extra_dirs))
