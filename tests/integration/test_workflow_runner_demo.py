"""Layer 6 integration demo: WorkflowRunner replays the real recorded
workflow (data/workflows/test_login.json) against demo.testfire.net,
resolving {{user.username}}/{{user.password}} tokens from a Session's
user_id -- this is the first time in this project's build that token
resolution happens for real, via `runner.run_workflow(workflow_id,
session)` exactly as CLAUDE.md's Layer 6 spec describes, instead of
being manually simulated the way earlier layer demos had to.

The Session starts with no cookies -- the recorded workflow's own
actions ARE the login, so nothing needs to authenticate it beforehand.

Needs network access and a real Chromium (`playwright install chromium`).

Automated, headless check:
    pytest tests/integration/test_workflow_runner_demo.py -v -s

Watch it happen in a real, visible browser window:
    python tests/integration/test_workflow_runner_demo.py
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from playwright.async_api import async_playwright

from stof.config import load_dotenv, load_users
from stof.config.schema import BrowserConfig
from stof.engine import PlaywrightEngine, SessionPool
from stof.session.models import Session
from stof.workflows import WorkflowRepository, WorkflowRunner

PROJECT_ROOT = Path(__file__).resolve().parents[2]
USERS_PATH = PROJECT_ROOT / "config" / "users.json"
WORKFLOWS_DIR = PROJECT_ROOT / "data" / "workflows"
WORKFLOW_ID = "wf-20260722-b8d4d7"  # the recorded login flow


async def _run(headless: bool, slow_mo: int):
    load_dotenv()
    users = load_users(USERS_PATH)
    admin_user = next(u for u in users.users if u.role == "admin")
    repository = WorkflowRepository(workflows_dir=WORKFLOWS_DIR)

    async with async_playwright() as pw:
        # demo.testfire.net's TLS cert is expired -- their bug, not ours.
        pool = await SessionPool.launch(
            pw, BrowserConfig(headless=headless, slowmo_ms=slow_mo), ignore_https_errors=True
        )
        engine = PlaywrightEngine(pool)
        runner = WorkflowRunner(repository=repository, engine=engine, users=users)

        # No cookies yet -- the workflow being replayed IS the login flow.
        session = Session(user_id=admin_user.id, role=admin_user.role, auth_type=admin_user.auth_type)

        print(f"--- WorkflowRunner.run_workflow({WORKFLOW_ID!r}, session) ---")
        print("    (tokens resolved from session.user_id -> UserConfig, not substituted by hand)")
        result = await runner.run_workflow(WORKFLOW_ID, session)
        print(f"    success={result.success}  completed={result.completed_actions}/{result.total_actions}")
        print(f"    final_url={result.final_url}")

        await pool.shutdown()

    return session, result


@pytest.mark.asyncio
async def test_workflow_runner_replays_real_recorded_login():
    session, result = await _run(headless=True, slow_mo=0)

    assert session.user_id  # sanity: we built a real Session
    assert result.success
    assert "main.jsp" in result.final_url


if __name__ == "__main__":
    asyncio.run(_run(headless=False, slow_mo=200))
