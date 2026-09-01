"""Unit tests for stof.tools.tool_availability."""
import os
import stat

import pytest

from stof.tools.tool_availability import find_tool, require_tool

# ---------------------------------------------------------------------------
# find_tool
# ---------------------------------------------------------------------------


def test_find_tool_locates_on_path(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/httpx" if name == "httpx" else None)

    tool = find_tool("httpx")

    assert tool.available is True
    assert tool.path == "/usr/bin/httpx"


def test_find_tool_not_found_anywhere(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda name: None)

    tool = find_tool("nuclei", extra_dirs=[str(tmp_path)])

    assert tool.available is False
    assert tool.path is None


def test_find_tool_prefers_extra_dirs_over_path(monkeypatch, tmp_path):
    """Regression: `httpx` collides with the unrelated Python `httpx`
    HTTP client library's own console script of the same name, which
    can be found on PATH first with no way to tell them apart by name
    alone -- confirmed for real, this silently ran the wrong binary
    until extra_dirs was made to take priority."""
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/httpx")  # the "wrong" one, on PATH
    real_binary = tmp_path / "httpx"
    real_binary.write_text("#!/bin/sh\necho real\n")
    real_binary.chmod(real_binary.stat().st_mode | stat.S_IEXEC)

    tool = find_tool("httpx", extra_dirs=[str(tmp_path)])

    assert tool.path == str(real_binary)
    assert tool.path != "/usr/bin/httpx"


def test_find_tool_falls_back_to_extra_dirs(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda name: None)
    fake_binary = tmp_path / "httpx"
    fake_binary.write_text("#!/bin/sh\necho fake\n")
    fake_binary.chmod(fake_binary.stat().st_mode | stat.S_IEXEC)

    tool = find_tool("httpx", extra_dirs=[str(tmp_path)])

    assert tool.available is True
    assert tool.path == str(fake_binary)


def test_find_tool_ignores_non_executable_file_in_extra_dirs(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda name: None)
    non_exec = tmp_path / "httpx"
    non_exec.write_text("not executable")
    os.chmod(non_exec, 0o644)

    tool = find_tool("httpx", extra_dirs=[str(tmp_path)])

    assert tool.available is False


# ---------------------------------------------------------------------------
# require_tool
# ---------------------------------------------------------------------------


def test_require_tool_returns_path_when_available(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nuclei")

    assert require_tool("nuclei") == "/usr/bin/nuclei"


def test_require_tool_raises_clear_error_when_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)

    with pytest.raises(FileNotFoundError, match="nuclei"):
        require_tool("nuclei", install_url="https://example.com/install")
