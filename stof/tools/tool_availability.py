"""stof/tools — availability checks for external recon binaries.

This package wraps real third-party tools (ProjectDiscovery's `httpx`
and `nuclei`) via subprocess -- a deliberate exception to this
project's otherwise Playwright/Python-native approach (see `stof/recon/`
for the native equivalents built earlier). Done this way at explicit
user request, to sit under a distinct "external tools" section rather
than be folded into the native recon engine.

Naming collision warning: the Python package `httpx` (an async HTTP
client library, itself a dependency of `playwright`) is completely
unrelated to ProjectDiscovery's `httpx` CLI recon tool this package
wraps. Never `import httpx` anywhere in `stof/tools/` -- always invoke
the binary via subprocess by its resolved path.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ToolInfo:
    name: str
    path: str | None
    available: bool


def find_tool(binary_name: str, extra_dirs: list[str] | None = None) -> ToolInfo:
    """Look in `extra_dirs` first (if given), then fall back to PATH.

    `extra_dirs` deliberately takes priority over PATH: `httpx` in
    particular collides with the unrelated Python `httpx` HTTP client
    library, which also installs a console script literally named
    `httpx` -- confirmed the hard way, a plain "PATH first" lookup
    silently ran that one instead of the real ProjectDiscovery binary
    whose location was explicitly passed in. An explicit location
    should always win over that ambiguity.
    """
    for directory in extra_dirs or []:
        candidate = Path(directory) / binary_name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return ToolInfo(name=binary_name, path=str(candidate), available=True)
    path = shutil.which(binary_name)
    return ToolInfo(name=binary_name, path=path, available=path is not None)


def require_tool(binary_name: str, extra_dirs: list[str] | None = None, install_url: str = "") -> str:
    """Same as `find_tool`, but raises a clear, actionable error instead
    of returning an unavailable ToolInfo. Returns the resolved path."""
    tool = find_tool(binary_name, extra_dirs)
    if not tool.available or tool.path is None:
        hint = f" Install it from {install_url}" if install_url else ""
        raise FileNotFoundError(
            f"'{binary_name}' binary not found on PATH.{hint} "
            f"Then either add it to PATH or pass its location explicitly."
        )
    return tool.path
