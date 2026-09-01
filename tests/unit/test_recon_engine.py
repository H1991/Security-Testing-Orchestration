"""Unit tests for Recon Engine — stof.recon.recon_engine."""
import asyncio
import json
from unittest.mock import AsyncMock

import pytest

import stof.recon.recon_engine as recon_engine_module
from stof.crawler.endpoint_store import Endpoint
from stof.recon.recon_engine import ReconReport, run_recon, write_recon_report
from stof.recon.tech_detector import TechProfile


def _fake_context() -> AsyncMock:
    context = AsyncMock()
    probe_page = AsyncMock()
    context.new_page = AsyncMock(return_value=probe_page)
    return context


# ---------------------------------------------------------------------------
# ReconReport / write_recon_report
# ---------------------------------------------------------------------------


def test_recon_report_to_dict_round_trips_through_json():
    report = ReconReport(
        target="https://x/",
        scanned_at="2026-01-01T00:00:00+00:00",
        pages_analyzed=2,
        tech_stack=[{"url": "https://x/", "tech": ["nginx"]}],
    )

    round_tripped = json.loads(json.dumps(report.to_dict()))

    assert round_tripped["target"] == "https://x/"
    assert round_tripped["pages_analyzed"] == 2


def test_write_recon_report_creates_parent_dirs_and_writes_json(tmp_path):
    report = ReconReport(target="https://x/", scanned_at="2026-01-01T00:00:00+00:00", pages_analyzed=0)

    path = write_recon_report(report, tmp_path / "sub" / "recon.json")

    assert path.is_file()
    assert json.loads(path.read_text())["target"] == "https://x/"


# ---------------------------------------------------------------------------
# run_recon — orchestration wiring (submodules monkeypatched)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_recon_assembles_a_complete_report(monkeypatch):
    async def fake_analyze_url(context, url, timeout_ms=10000):
        return TechProfile(url=url, status_code=200, title="Home", tech=["nginx"], headers={"server": "nginx"})

    async def fake_scan_exposed_paths(context, base_url, timeout_ms=8000):
        return []

    async def fake_probe_error_disclosure(context, url, timeout_ms=8000):
        return None

    async def fake_scan_page_for_secrets(page, timeout_ms=8000):
        return []

    monkeypatch.setattr(recon_engine_module.tech_detector, "analyze_url", fake_analyze_url)
    monkeypatch.setattr(recon_engine_module.misconfig_scanner, "scan_exposed_paths", fake_scan_exposed_paths)
    monkeypatch.setattr(recon_engine_module.misconfig_scanner, "probe_error_disclosure", fake_probe_error_disclosure)
    monkeypatch.setattr(recon_engine_module.secrets_scanner, "scan_page_for_secrets", fake_scan_page_for_secrets)

    endpoints = [
        Endpoint(url="https://x/", method="GET", endpoint_type="page"),
        Endpoint(url="https://x/doTransfer", method="POST", endpoint_type="form", parameters=["fromAccount"]),
    ]

    report = await run_recon(endpoints, _fake_context(), "https://x/")

    assert report.target == "https://x/"
    assert report.pages_analyzed == 1
    assert report.tech_stack[0]["tech"] == ["nginx"]
    assert "POST https://x/doTransfer" in report.parameters


@pytest.mark.asyncio
async def test_run_recon_respects_max_tech_pages_limit(monkeypatch):
    calls: list[str] = []

    async def fake_analyze_url(context, url, timeout_ms=10000):
        calls.append(url)
        return TechProfile(url=url)

    async def fake_scan_exposed_paths(context, base_url, timeout_ms=8000):
        return []

    async def fake_probe_error_disclosure(context, url, timeout_ms=8000):
        return None

    async def fake_scan_page_for_secrets(page, timeout_ms=8000):
        return []

    monkeypatch.setattr(recon_engine_module.tech_detector, "analyze_url", fake_analyze_url)
    monkeypatch.setattr(recon_engine_module.misconfig_scanner, "scan_exposed_paths", fake_scan_exposed_paths)
    monkeypatch.setattr(recon_engine_module.misconfig_scanner, "probe_error_disclosure", fake_probe_error_disclosure)
    monkeypatch.setattr(recon_engine_module.secrets_scanner, "scan_page_for_secrets", fake_scan_page_for_secrets)

    endpoints = [Endpoint(url=f"https://x/{i}", method="GET", endpoint_type="page") for i in range(5)]

    await run_recon(endpoints, _fake_context(), "https://x/", max_tech_pages=2)

    assert len(calls) == 2


@pytest.mark.asyncio
async def test_run_recon_records_missing_security_headers(monkeypatch):
    async def fake_analyze_url(context, url, timeout_ms=10000):
        return TechProfile(url=url, status_code=200, headers={})  # no headers -> everything "missing"

    async def fake_scan_exposed_paths(context, base_url, timeout_ms=8000):
        return []

    async def fake_probe_error_disclosure(context, url, timeout_ms=8000):
        return None

    async def fake_scan_page_for_secrets(page, timeout_ms=8000):
        return []

    monkeypatch.setattr(recon_engine_module.tech_detector, "analyze_url", fake_analyze_url)
    monkeypatch.setattr(recon_engine_module.misconfig_scanner, "scan_exposed_paths", fake_scan_exposed_paths)
    monkeypatch.setattr(recon_engine_module.misconfig_scanner, "probe_error_disclosure", fake_probe_error_disclosure)
    monkeypatch.setattr(recon_engine_module.secrets_scanner, "scan_page_for_secrets", fake_scan_page_for_secrets)

    endpoints = [Endpoint(url="https://x/", method="GET", endpoint_type="page")]

    report = await run_recon(endpoints, _fake_context(), "https://x/")

    assert "https://x/" in report.missing_security_headers
    assert "content-security-policy" in report.missing_security_headers["https://x/"]


@pytest.mark.asyncio
async def test_run_recon_secrets_scan_watchdog_recovers_from_a_page_that_never_resolves(monkeypatch):
    """Regression: live-verified against a real target -- a burst of
    net::ERR_NETWORK_CHANGED/interrupted-navigation failures across
    consecutive pages left the secrets-scan loop's `page.goto()` hung
    indefinitely, with its own `timeout=10000` never firing.
    `page_watchdog_s` is the hard backstop, same pattern as
    `crawler.CrawlerConfig.page_watchdog_s`."""
    async def fake_analyze_url(context, url, timeout_ms=10000):
        return TechProfile(url=url)

    async def fake_scan_exposed_paths(context, base_url, timeout_ms=8000):
        return []

    async def fake_probe_error_disclosure(context, url, timeout_ms=8000):
        return None

    async def fake_scan_page_for_secrets(page, timeout_ms=8000):
        return []

    monkeypatch.setattr(recon_engine_module.tech_detector, "analyze_url", fake_analyze_url)
    monkeypatch.setattr(recon_engine_module.misconfig_scanner, "scan_exposed_paths", fake_scan_exposed_paths)
    monkeypatch.setattr(recon_engine_module.misconfig_scanner, "probe_error_disclosure", fake_probe_error_disclosure)
    monkeypatch.setattr(recon_engine_module.secrets_scanner, "scan_page_for_secrets", fake_scan_page_for_secrets)

    context = _fake_context()
    probe_page = await context.new_page()

    async def hanging_goto(url, timeout=None):
        if url == "https://x/wedged":
            await asyncio.Event().wait()  # never resolves on its own

    probe_page.goto = AsyncMock(side_effect=hanging_goto)

    endpoints = [
        Endpoint(url="https://x/wedged", method="GET", endpoint_type="page"),
        Endpoint(url="https://x/ok", method="GET", endpoint_type="page"),
    ]

    report = await asyncio.wait_for(
        run_recon(endpoints, context, "https://x/", page_watchdog_s=0.05),
        timeout=5,
    )

    assert report.pages_analyzed == 2  # tech_detector still saw both -- only the secrets-scan goto hung
