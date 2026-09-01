"""Unit tests for stof.tools.httpx_runner.

Mocks asyncio.create_subprocess_exec rather than requiring the real
httpx binary -- the real binary was verified manually against
demo.testfire.net (see conversation), which is where the exact JSON
shape parsed here (`_parse_line`) came from.
"""
from __future__ import annotations

import asyncio

import pytest

from stof.tools.httpx_runner import _parse_line, run_httpx
from stof.tools.tool_availability import ToolInfo

REAL_HTTPX_LINE = (
    '{"timestamp":"2026-07-28T11:34:58Z","url":"https://demo.testfire.net","title":"Altoro Mutual",'
    '"webserver":"Apache-Coyote/1.1","content_type":"text/html","tech":["Apache Tomcat","Java"],'
    '"status_code":200,"content_length":9405}'
)


class _FakeProcess:
    def __init__(self, stdout: bytes, stderr: bytes = b""):
        self._stdout = stdout
        self._stderr = stderr
        self.killed = False

    async def communicate(self, input_data: bytes | None = None):
        return self._stdout, self._stderr

    def kill(self):
        self.killed = True

    async def wait(self):
        return None


# ---------------------------------------------------------------------------
# _parse_line -- pure function, uses the real captured JSON shape
# ---------------------------------------------------------------------------


def test_parse_line_extracts_real_httpx_fields():
    result = _parse_line(REAL_HTTPX_LINE)

    assert result.url == "https://demo.testfire.net"
    assert result.title == "Altoro Mutual"
    assert result.webserver == "Apache-Coyote/1.1"
    assert result.tech == ["Apache Tomcat", "Java"]
    assert result.status_code == 200


def test_parse_line_skips_blank_lines():
    assert _parse_line("") is None
    assert _parse_line("   ") is None


def test_parse_line_returns_none_for_malformed_json():
    assert _parse_line("{not valid json") is None


# ---------------------------------------------------------------------------
# run_httpx -- subprocess orchestration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_httpx_parses_multiple_json_lines(monkeypatch):
    stdout = (REAL_HTTPX_LINE + "\n" + REAL_HTTPX_LINE.replace("demo.testfire.net", "other.example.com")).encode()

    async def fake_create_subprocess_exec(*args, **kwargs):
        return _FakeProcess(stdout)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    results = await run_httpx(["https://demo.testfire.net", "https://other.example.com"], tool_path="/fake/httpx")

    assert len(results) == 2
    assert {r.url for r in results} == {"https://demo.testfire.net", "https://other.example.com"}


@pytest.mark.asyncio
async def test_run_httpx_raises_file_not_found_when_binary_missing(monkeypatch):
    monkeypatch.setattr(
        "stof.tools.httpx_runner.locate_httpx",
        lambda extra_dirs=None: ToolInfo(name="httpx", path=None, available=False),
    )

    with pytest.raises(FileNotFoundError, match="httpx"):
        await run_httpx(["https://x/"])


@pytest.mark.asyncio
async def test_run_httpx_kills_process_on_timeout(monkeypatch):
    created: dict[str, _FakeProcess] = {}

    async def fake_create_subprocess_exec(*args, **kwargs):
        process = _FakeProcess(b"")
        created["process"] = process
        return process

    async def fake_wait_for(coro, timeout):
        coro.close()
        raise asyncio.TimeoutError

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(asyncio, "wait_for", fake_wait_for)

    with pytest.raises(TimeoutError):
        await run_httpx(["https://x/"], tool_path="/fake/httpx", timeout_s=1)

    assert created["process"].killed is True
