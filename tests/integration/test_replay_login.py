"""Layer 3B integration test — replays a real Layer 3A-recorded workflow
against demo.testfire.net and verifies it logs in successfully.

Needs network access, a real Chromium (`playwright install chromium`),
and a recorded workflow at data/workflows/test_login.json (see README.md
-> "Manually testing Layer 3A").

Automated, headless check:
    pytest tests/integration/test_replay_login.py -v

Watch it happen in a real, visible browser window:
    python tests/integration/test_replay_login.py [admin|normal]
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from playwright.async_api import async_playwright

from stof.config import load_dotenv, load_users
from stof.engine import PlaywrightEngine

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = PROJECT_ROOT / "data" / "workflows" / "test_login.json"
USERS_PATH = PROJECT_ROOT / "config" / "users.json"


def _load_workflow_for_role(role: str) -> tuple[dict, object]:
    load_dotenv()
    users = load_users(USERS_PATH)
    user = next(u for u in users.users if u.role == role)

    workflow = json.loads(WORKFLOW_PATH.read_text(encoding="utf-8"))
    # Simulate Layer 6's runner.py token resolution (not built yet):
    # replace {{user.username}}/{{user.password}} with this role's creds.
    for action in workflow["actions"]:
        if action.get("value") == "{{user.username}}":
            action["value"] = user.username
        elif action.get("value") == "{{user.password}}":
            action["value"] = user.password
    return workflow, user


async def _replay(headless: bool, role: str = "admin"):
    if not WORKFLOW_PATH.is_file():
        raise FileNotFoundError(
            f"{WORKFLOW_PATH} not found -- record a login flow first via "
            "`python -m stof.recorder --output data/workflows/test_login.json "
            "--users config/users.json`"
        )

    workflow, user = _load_workflow_for_role(role)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless, slow_mo=150 if not headless else 0)
        # demo.testfire.net's TLS cert is expired -- their bug, not ours.
        context = await browser.new_context(ignore_https_errors=True)

        class _SinglePool:
            async def apply_session(self, session, target_url):
                return context

        engine = PlaywrightEngine(_SinglePool())
        session = SimpleNamespace(role=role, cookies={}, headers={})

        result = await engine.replay(workflow, session)
        await browser.close()
        return result, user


@pytest.mark.asyncio
async def test_replay_logs_into_testfire_as_admin():
    result, _user = await _replay(headless=True, role="admin")
    assert result.success, result.error
    assert "main.jsp" in result.final_url


if __name__ == "__main__":
    role = sys.argv[1] if len(sys.argv) > 1 else "admin"
    result, user = asyncio.run(_replay(headless=False, role=role))
    print(f"role:              {role} ({user.username})")
    print(f"success:           {result.success}")
    print(f"completed_actions: {result.completed_actions}/{result.total_actions}")
    print(f"final_url:         {result.final_url}")
    if result.error:
        print(f"error:             {result.error}")
