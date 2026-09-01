"""stof/tools — subprocess wrapper for ProjectDiscovery's `httpx`.

Wraps the real `httpx` binary (github.com/projectdiscovery/httpx), not
a reimplementation -- see `stof/recon/tech_detector.py` for this
project's dependency-free, Playwright-native equivalent. Use this
module when you specifically want ProjectDiscovery's own detection
engine; use `stof.recon` when you want zero external dependencies.

Verified against this project's real demo target (Altoro Mutual /
demo.testfire.net): correctly identified "Apache Tomcat" and "Java"
that the native tech_detector's signature table doesn't yet know about.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field

from stof.core.logger import get_logger

from .tool_availability import ToolInfo, find_tool

_log = get_logger("tools.httpx_runner")

BINARY_NAME = "httpx"
INSTALL_URL = "https://github.com/projectdiscovery/httpx/releases"


@dataclass
class HttpxResult:
    url: str
    status_code: int | None = None
    title: str | None = None
    webserver: str | None = None
    tech: list[str] = field(default_factory=list)
    content_type: str | None = None
    content_length: int | None = None
    raw: dict = field(default_factory=dict)  # full parsed JSON line -- nothing lost


def locate_httpx(extra_dirs: list[str] | None = None) -> ToolInfo:
    return find_tool(BINARY_NAME, extra_dirs)


def _parse_line(line: str) -> HttpxResult | None:
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        _log.warning(f"could not parse httpx output line: {line[:200]}")
        return None
    return HttpxResult(
        url=data.get("url", ""),
        status_code=data.get("status_code"),
        title=data.get("title"),
        webserver=data.get("webserver"),
        tech=data.get("tech", []),
        content_type=data.get("content_type"),
        content_length=data.get("content_length"),
        raw=data,
    )


async def run_httpx(
    urls: list[str],
    tool_path: str | None = None,
    extra_dirs: list[str] | None = None,
    timeout_s: int = 120,
    extra_args: list[str] | None = None,
) -> list[HttpxResult]:
    """Run the real httpx binary over `urls` (piped via stdin, `-l`
    equivalent), parsing its JSON-lines output. Raises
    FileNotFoundError if the binary can't be located."""
    if tool_path is None:
        tool = locate_httpx(extra_dirs)
        if not tool.available or tool.path is None:
            raise FileNotFoundError(
                f"httpx (ProjectDiscovery) binary not found on PATH. "
                f"Install it from {INSTALL_URL}, or pass tool_path= explicitly."
            )
        tool_path = tool.path

    args = [tool_path, "-tech-detect", "-title", "-status-code", "-server", "-json", "-silent"]
    args.extend(extra_args or [])

    process = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate("\n".join(urls).encode()), timeout=timeout_s
        )
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.wait()
        raise TimeoutError(f"httpx did not finish within {timeout_s}s for {len(urls)} URL(s)") from exc

    if stderr:
        stderr_text = stderr.decode(errors="replace").strip()
        if stderr_text:
            _log.warning(f"httpx stderr: {stderr_text[:500]}")

    results = [r for line in stdout.decode(errors="replace").splitlines() if (r := _parse_line(line)) is not None]
    _log.info(f"httpx analyzed {len(results)}/{len(urls)} URL(s) successfully")
    return results
