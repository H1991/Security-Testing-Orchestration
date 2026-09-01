"""Unit tests for stof.tools.nuclei_runner.

Mocks asyncio.create_subprocess_exec rather than requiring the real
nuclei binary -- the real binary was verified manually against
demo.testfire.net (WAF-detect + Apache-detect matches), which is where
the exact JSON shape parsed here (`_parse_line`) came from.
"""
from __future__ import annotations

import asyncio

import pytest

from stof.tools.nuclei_runner import DEFAULT_EXCLUDED_TAGS, _parse_line, run_nuclei
from stof.tools.tool_availability import ToolInfo

REAL_NUCLEI_LINE = (
    '{"template-id":"waf-detect","info":{"name":"WAF Detection","severity":"info",'
    '"tags":["waf","tech","misc","discovery"]},"host":"demo.testfire.net",'
    '"url":"https://demo.testfire.net","matched-at":"https://demo.testfire.net"}'
)

REAL_NUCLEI_LINE_WITH_EXTRACTION = (
    '{"template-id":"apache-detect","info":{"name":"Apache Detection","severity":"info",'
    '"tags":["tech","apache","discovery"]},"host":"demo.testfire.net",'
    '"url":"https://demo.testfire.net","matched-at":"https://demo.testfire.net",'
    '"extracted-results":["Apache-Coyote/1.1"]}'
)


class _FakeProcess:
    def __init__(self, stdout: bytes, stderr: bytes = b""):
        self._stdout = stdout
        self._stderr = stderr
        self.killed = False

    async def communicate(self):
        return self._stdout, self._stderr

    def kill(self):
        self.killed = True

    async def wait(self):
        return None


# ---------------------------------------------------------------------------
# _parse_line -- pure function, uses the real captured JSON shape
# ---------------------------------------------------------------------------


def test_parse_line_extracts_real_nuclei_fields():
    finding = _parse_line(REAL_NUCLEI_LINE)

    assert finding.template_id == "waf-detect"
    assert finding.name == "WAF Detection"
    assert finding.severity == "info"
    assert finding.matched_at == "https://demo.testfire.net"
    assert "waf" in finding.tags


def test_parse_line_extracts_extracted_results_when_present():
    finding = _parse_line(REAL_NUCLEI_LINE_WITH_EXTRACTION)

    assert finding.extracted_results == ["Apache-Coyote/1.1"]


def test_parse_line_extracted_results_defaults_to_empty_list():
    """Not every template extracts a value -- e.g. waf-detect is
    inherently a yes/no signal with nothing to extract."""
    finding = _parse_line(REAL_NUCLEI_LINE)

    assert finding.extracted_results == []


def test_parse_line_skips_blank_lines():
    assert _parse_line("") is None


def test_parse_line_returns_none_for_malformed_json():
    assert _parse_line("{broken") is None


# ---------------------------------------------------------------------------
# run_nuclei -- subprocess orchestration + safety defaults
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_nuclei_parses_findings(monkeypatch):
    async def fake_create_subprocess_exec(*args, **kwargs):
        return _FakeProcess(REAL_NUCLEI_LINE.encode() + b"\n")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    findings = await run_nuclei("https://demo.testfire.net", tool_path="/fake/nuclei")

    assert len(findings) == 1
    assert findings[0].template_id == "waf-detect"


@pytest.mark.asyncio
async def test_run_nuclei_excludes_dangerous_tags_by_default(monkeypatch):
    captured_args: list[str] = []

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured_args.extend(args)
        return _FakeProcess(b"")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    await run_nuclei("https://demo.testfire.net", tool_path="/fake/nuclei")

    assert "-etags" in captured_args
    etags_value = captured_args[captured_args.index("-etags") + 1]
    for tag in DEFAULT_EXCLUDED_TAGS:
        assert tag in etags_value


@pytest.mark.asyncio
async def test_run_nuclei_scopes_to_requested_tags(monkeypatch):
    captured_args: list[str] = []

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured_args.extend(args)
        return _FakeProcess(b"")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    await run_nuclei("https://demo.testfire.net", tags=["tech"], tool_path="/fake/nuclei")

    assert "-tags" in captured_args
    assert captured_args[captured_args.index("-tags") + 1] == "tech"


@pytest.mark.asyncio
async def test_run_nuclei_raises_file_not_found_when_binary_missing(monkeypatch):
    monkeypatch.setattr(
        "stof.tools.nuclei_runner.locate_nuclei",
        lambda extra_dirs=None: ToolInfo(name="nuclei", path=None, available=False),
    )

    with pytest.raises(FileNotFoundError, match="nuclei"):
        await run_nuclei("https://x/")


@pytest.mark.asyncio
async def test_run_nuclei_kills_process_on_timeout(monkeypatch):
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
        await run_nuclei("https://x/", tool_path="/fake/nuclei", timeout_s=1)

    assert created["process"].killed is True
