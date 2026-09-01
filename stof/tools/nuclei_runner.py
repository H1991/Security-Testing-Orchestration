"""stof/tools — subprocess wrapper for ProjectDiscovery's `nuclei`.

Wraps the real `nuclei` binary. Important difference from everything
else in `stof/` (including `stof/recon/`, which is deliberately
passive): nuclei is an ACTIVE scanner -- it sends real vulnerability-
check requests (CVE probes, misconfig checks, sometimes exploit-shaped
requests) against the target, not just GETs. Safety defaults here
exclude the "dos"/"fuzz"/"intrusive" tags; running anything more
aggressive is the caller's explicit choice via `extra_args`, the same
opt-in philosophy as `crawler.py`'s `submit_forms_with_test_data`.

Verified against this project's real demo target: found a WAF-detect
match and an Apache version match with the (safe) "tech" tag set in a
few seconds; the full default template set (thousands of templates,
every tag) took over 90s and was not something to run unbounded.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field

from stof.core.logger import get_logger

from .tool_availability import ToolInfo, find_tool

_log = get_logger("tools.nuclei_runner")

BINARY_NAME = "nuclei"
INSTALL_URL = "https://github.com/projectdiscovery/nuclei/releases"
DEFAULT_EXCLUDED_TAGS = ("dos", "fuzz", "intrusive")


@dataclass
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    matched_at: str
    tags: list[str] = field(default_factory=list)
    # The specific matched value (e.g. "Apache-Coyote/1.1"), when the
    # template extracts one -- not every template does (a WAF-detect
    # match is inherently a yes/no signal with nothing to extract).
    # Prefer this over `name` for tech classification: `name` is a
    # human-readable template description ("Apache Detection"), not a
    # precise identifier, and double-counting it alongside httpx's
    # actual tech-detect output is what caused a real, confirmed bug --
    # a generic "Apache HTTP Server" beat out the more specific,
    # doubly-confirmed "Apache Tomcat" on an alphabetical tie-break.
    extracted_results: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


def locate_nuclei(extra_dirs: list[str] | None = None) -> ToolInfo:
    return find_tool(BINARY_NAME, extra_dirs)


def _parse_line(line: str) -> NucleiFinding | None:
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        _log.warning(f"could not parse nuclei output line: {line[:200]}")
        return None
    info = data.get("info", {})
    return NucleiFinding(
        template_id=data.get("template-id", data.get("template_id", "")),
        name=info.get("name", ""),
        severity=info.get("severity", "unknown"),
        matched_at=data.get("matched-at", data.get("matched_at", data.get("host", ""))),
        tags=info.get("tags", []),
        extracted_results=data.get("extracted-results", data.get("extracted_results", [])),
        raw=data,
    )


async def run_nuclei(
    target_url: str,
    tags: list[str] | None = None,
    exclude_tags: tuple[str, ...] = DEFAULT_EXCLUDED_TAGS,
    tool_path: str | None = None,
    extra_dirs: list[str] | None = None,
    timeout_s: int = 300,
    rate_limit: int = 100,
    concurrency: int = 25,
    extra_args: list[str] | None = None,
) -> list[NucleiFinding]:
    """Run the real nuclei binary against `target_url`. `tags`/
    `exclude_tags` scope which templates run -- an empty `tags` list
    means "every template nuclei has except the excluded tags," which
    is thousands of requests; pass e.g. `tags=["tech"]` to keep a scan
    fast and narrow. Raises FileNotFoundError if the binary can't be
    located."""
    if tool_path is None:
        tool = locate_nuclei(extra_dirs)
        if not tool.available or tool.path is None:
            raise FileNotFoundError(
                f"nuclei (ProjectDiscovery) binary not found on PATH. "
                f"Install it from {INSTALL_URL}, or pass tool_path= explicitly."
            )
        tool_path = tool.path

    args = [
        tool_path, "-u", target_url, "-jsonl", "-silent",
        "-rate-limit", str(rate_limit), "-c", str(concurrency),
    ]
    if tags:
        args.extend(["-tags", ",".join(tags)])
    if exclude_tags:
        args.extend(["-etags", ",".join(exclude_tags)])
    args.extend(extra_args or [])

    process = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.wait()
        raise TimeoutError(f"nuclei did not finish within {timeout_s}s for '{target_url}'") from exc

    if stderr:
        stderr_text = stderr.decode(errors="replace").strip()
        if stderr_text:
            _log.warning(f"nuclei stderr: {stderr_text[:500]}")

    findings = [r for line in stdout.decode(errors="replace").splitlines() if (r := _parse_line(line)) is not None]
    _log.info(f"nuclei found {len(findings)} match(es) for '{target_url}'")
    return findings
