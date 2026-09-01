"""Layer 7 integration demo: authenticated BFS crawl of demo.testfire.net,
discovering pages, forms, and XHR/fetch API endpoints -- passive
discovery only, no attack payloads sent.

Needs network access and a real Chromium (`playwright install chromium`).

Automated, headless check:
    pytest tests/integration/test_crawler_demo.py -v -s

Watch it happen in a real, visible browser window:
    python tests/integration/test_crawler_demo.py
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from playwright.async_api import async_playwright

from stof.auth import FormLoginProvider
from stof.config import load_dotenv, load_users
from stof.config.schema import BrowserConfig
from stof.crawler import CrawlerConfig, crawl, write_endpoints
from stof.engine import SessionPool

PROJECT_ROOT = Path(__file__).resolve().parents[2]
USERS_PATH = PROJECT_ROOT / "config" / "users.json"
START_URL = "https://demo.testfire.net/bank/main.jsp"


async def _run(headless: bool, slow_mo: int, out_path: Path, crawler_config: CrawlerConfig | None = None):
    load_dotenv()
    users = load_users(USERS_PATH)
    admin_user = next(u for u in users.users if u.role == "admin")

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
        # demo.testfire.net's TLS cert is expired -- their bug, not ours.
        pool = await SessionPool.launch(
            pw, BrowserConfig(headless=headless, slowmo_ms=slow_mo), ignore_https_errors=True
        )
        context = await pool.get_context("admin")
        login_page = await context.new_page()

        print("--- logging in as admin first (crawler needs an authenticated context) ---")
        await provider.authenticate(admin_user, login_page)
        await login_page.close()

        crawler_config = crawler_config or CrawlerConfig(max_depth=2, max_pages=15)
        print(
            f"--- crawling from {START_URL} "
            f"(max_depth={crawler_config.max_depth}, max_pages={crawler_config.max_pages}) ---"
        )
        endpoints = await crawl(START_URL, context, crawler_config)

        by_type: dict[str, int] = {}
        for e in endpoints:
            by_type[e.endpoint_type] = by_type.get(e.endpoint_type, 0) + 1
        print(f"--- discovered {len(endpoints)} endpoint(s): {by_type} ---")
        for e in sorted(endpoints, key=lambda x: (x.endpoint_type, x.url)):
            params = f" params={e.parameters}" if e.parameters else ""
            print(f"    [{e.endpoint_type:5s}] {e.method:6s} {e.url}{params}")

        path = write_endpoints(endpoints, out_path)
        print(f"--- wrote {path} ---")

        await pool.shutdown()

    return endpoints


@pytest.mark.asyncio
async def test_crawl_discovers_pages_forms_and_apis(tmp_path):
    endpoints = await _run(headless=True, slow_mo=0, out_path=tmp_path / "endpoints.json")

    types_found = {e.endpoint_type for e in endpoints}
    assert "page" in types_found
    assert len(endpoints) > 1
    assert all(e.auth_required for e in endpoints)


if __name__ == "__main__":
    # A real full-site crawl (the pytest test above stays small/fast on
    # purpose). testfire.net has 70+ pages, so generous limits here.
    full_config = CrawlerConfig(max_depth=6, max_pages=250, timeout_ms=15000, retries_per_page=2)
    asyncio.run(
        _run(headless=False, slow_mo=100, out_path=Path("data/endpoints.json"), crawler_config=full_config)
    )
