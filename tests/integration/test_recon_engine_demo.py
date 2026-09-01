"""Recon Engine integration demo: runs the native httpx/nuclei/
SecretFinder/Arjun-equivalent scans against demo.testfire.net, using
the endpoints Layer 7's crawler already discovered, and writes one
consolidated data/recon_results.json.

Needs network access and a real Chromium (`playwright install chromium`).

Automated, headless check:
    pytest tests/integration/test_recon_engine_demo.py -v -s

Run directly to produce the real recon_results.json:
    python tests/integration/test_recon_engine_demo.py
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from playwright.async_api import async_playwright

from stof.auth import FormLoginProvider
from stof.config import load_dotenv, load_users
from stof.config.schema import BrowserConfig
from stof.crawler import load as load_endpoints
from stof.engine import SessionPool
from stof.recon import run_recon, write_recon_report

PROJECT_ROOT = Path(__file__).resolve().parents[2]
USERS_PATH = PROJECT_ROOT / "config" / "users.json"
ENDPOINTS_PATH = PROJECT_ROOT / "data" / "endpoints.json"
START_URL = "https://demo.testfire.net/bank/main.jsp"


async def _run(out_path: Path):
    load_dotenv()
    users = load_users(USERS_PATH)
    admin_user = next(u for u in users.users if u.role == "admin")
    endpoints = load_endpoints(ENDPOINTS_PATH)
    if not endpoints:
        raise RuntimeError(f"{ENDPOINTS_PATH} is empty -- run the Layer 7 crawler demo first")

    provider = FormLoginProvider(
        login_url="https://demo.testfire.net/login.jsp",
        username_selector="#uid",
        password_selector="#passw",
        submit_selector=(
            "#login > table:nth-of-type(1) > tbody:nth-of-type(1) > "
            "tr:nth-of-type(3) > td:nth-of-type(2) > input:nth-of-type(1)"
        ),
        success_selector="text=Welcome",
    )

    async with async_playwright() as pw:
        pool = await SessionPool.launch(pw, BrowserConfig(headless=True), ignore_https_errors=True)
        context = await pool.get_context("admin")
        login_page = await context.new_page()
        await provider.authenticate(admin_user, login_page)
        await login_page.close()

        print(f"--- running recon engine over {len(endpoints)} known endpoints ---")
        report = await run_recon(endpoints, context, START_URL, max_tech_pages=25, max_secret_scan_pages=10)

        print(f"pages analyzed: {report.pages_analyzed}")
        print(f"distinct tech signatures: {sorted({t for row in report.tech_stack for t in row['tech']})}")
        print(f"pages missing security headers: {len(report.missing_security_headers)}")
        print(f"exposed paths: {[e['url'] for e in report.exposed_paths]}")
        print(f"error disclosures: {report.error_disclosures}")
        print(f"secrets found: {len(report.secrets)}")
        for s in report.secrets[:10]:
            print(f"    [{s['label']}] {s['match_preview']}  ({s['source_url']})")
        print(f"endpoints with known parameters: {len(report.parameters)}")

        path = write_recon_report(report, out_path)
        print(f"--- wrote {path} ---")

        await pool.shutdown()

    return report


@pytest.mark.asyncio
async def test_recon_engine_produces_a_populated_report(tmp_path):
    report = await _run(tmp_path / "recon_results.json")

    assert report.pages_analyzed > 0
    assert len(report.tech_stack) > 0


if __name__ == "__main__":
    asyncio.run(_run(Path("data/recon_results.json")))
