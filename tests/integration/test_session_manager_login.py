"""Layer 4 + Layer 5 integration demo — real login via FormLoginProvider,
managed by SessionManager, against demo.testfire.net.

Needs network access and a real Chromium (`playwright install chromium`).

Automated, headless check:
    pytest tests/integration/test_session_manager_login.py -v -s

Watch it happen in a real, visible browser window (logs in once, reuses
the cached session, then logs in again after being invalidated):
    python tests/integration/test_session_manager_login.py
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from playwright.async_api import async_playwright

from stof.auth import FormLoginProvider
from stof.config import load_dotenv, load_users
from stof.session import SessionManager, SessionStore

LOGIN_URL = "https://demo.testfire.net/login.jsp"
SUBMIT_SELECTOR = (
    "#login > table:nth-of-type(1) > tbody:nth-of-type(1) > "
    "tr:nth-of-type(3) > td:nth-of-type(2) > input:nth-of-type(1)"
)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
USERS_PATH = PROJECT_ROOT / "config" / "users.json"


def _build_manager(db_path: Path) -> SessionManager:
    load_dotenv()
    users = load_users(USERS_PATH)
    users_by_role = {u.role: u for u in users.users}
    provider = FormLoginProvider(
        login_url=LOGIN_URL,
        username_selector="#uid",
        password_selector="#passw",
        submit_selector=SUBMIT_SELECTOR,
        success_selector="text=Welcome",
    )
    store = SessionStore(db_path=db_path)
    return SessionManager(users=users_by_role, providers={"form_login": provider}, store=store)


async def _run(headless: bool, slow_mo: int, db_path: Path):
    db_path.unlink(missing_ok=True)
    manager = _build_manager(db_path)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless, slow_mo=slow_mo)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        print("--- 1. get_session('admin') on an unauthenticated page: real login happens ---")
        first = await manager.get_session("admin", page)
        print(f"    session_id={first.session_id[:8]}  cookies={list(first.cookies.keys())}")

        print("--- 2. get_session('admin') again: cached, no new login ---")
        second = await manager.get_session("admin", page)
        print(f"    same session object reused: {second is first}")

        print("--- 3. invalidate('admin') then get_session(): real login happens again ---")
        manager.invalidate("admin")
        third = await manager.get_session("admin", page)
        print(f"    new session_id={third.session_id[:8]}  (different from step 1: {third.session_id != first.session_id})")

        await browser.close()

    return first, second, third


@pytest.mark.asyncio
async def test_session_manager_reuses_and_reauthenticates(tmp_path):
    first, second, third = await _run(headless=True, slow_mo=0, db_path=tmp_path / "stof.db")

    assert first.cookies  # real cookies were captured on first login
    assert second is first  # cache was reused, no second login
    assert third.session_id != first.session_id  # invalidate() forced a fresh login


if __name__ == "__main__":
    asyncio.run(_run(headless=False, slow_mo=200, db_path=Path("/tmp/stof_session_demo.db")))
