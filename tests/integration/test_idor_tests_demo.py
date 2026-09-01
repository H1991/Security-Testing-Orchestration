"""Layer 9 integration demo — runs `IdorTestsModule` + `JwtTestsModule`
for real against demo.testfire.net, using the real, previously
crawled `data/endpoints.json` (Layer 7's output), real `FormLoginProvider`
logins (Layer 4) managed by a real `SessionManager` (Layer 5) and
`SessionPool` (Layer 3B), and writes real `Finding` records to
`data/findings.json` (Layer 10) -- the tangible MVP artifact for the
management demo.

This is a hand-verification-turned-regression-test: the two findings it
expects were confirmed manually against the live target before this
module was written (see `stof/modules/idor_tests.py`'s docstring) --
IDOR on `GET /bank/showAccount?listAccounts=<id>` and vertical
privilege escalation on `GET /admin/admin.jsp`.

Needs network access and a real Chromium (`playwright install
chromium`), plus a `.env` with `ADMIN_PASSWORD`/`USER_PASSWORD` (see
`.env.example` -- demo.testfire.net's own well-known, intentionally
vulnerable demo credentials, not real secrets).

`config/users.json` declares the 'normal' role as `auth_type: "jwt"`,
but demo.testfire.net authenticates everyone via session cookies -- no
JWT endpoint exists on this target. This demo overrides that one field
to `form_login` purely so the real, confirmed vertical-privilege-
escalation finding (which needs an authenticated 'normal' session) can
run against a target that actually supports it; it does not touch
`config/users.json` itself.

Automated, headless check:
    pytest tests/integration/test_idor_tests_demo.py -v -s

Run standalone and print a management-readable summary:
    python tests/integration/test_idor_tests_demo.py
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from playwright.async_api import async_playwright

from stof.auth import FormLoginProvider
from stof.config import load_dotenv, load_users
from stof.crawler.endpoint_store import load as load_endpoints
from stof.engine.multi_session import SessionPool
from stof.findings.store import write_findings
from stof.modules.idor_tests import IdorTestConfig, IdorTestsModule
from stof.session import SessionManager, SessionStore

LOGIN_URL = "https://demo.testfire.net/login.jsp"
SUBMIT_SELECTOR = (
    "#login > table:nth-of-type(1) > tbody:nth-of-type(1) > "
    "tr:nth-of-type(3) > td:nth-of-type(2) > input:nth-of-type(1)"
)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
USERS_PATH = PROJECT_ROOT / "config" / "users.json"
ENDPOINTS_PATH = PROJECT_ROOT / "data" / "endpoints.json"
FINDINGS_PATH = PROJECT_ROOT / "data" / "findings.json"


def _build_session_manager(db_path: Path) -> SessionManager:
    load_dotenv()
    users = load_users(USERS_PATH)
    users_by_role = {u.role: u for u in users.users}
    # See module docstring: this target has no JWT auth surface at all,
    # so 'normal' is run as form_login here for a real, live demo.
    users_by_role["normal"] = users_by_role["normal"].model_copy(update={"auth_type": "form_login"})

    provider = FormLoginProvider(
        login_url=LOGIN_URL,
        username_selector="#uid",
        password_selector="#passw",
        submit_selector=SUBMIT_SELECTOR,
        success_selector="text=Welcome",
    )
    store = SessionStore(db_path=db_path)
    return SessionManager(users=users_by_role, providers={"form_login": provider}, store=store)


async def _run(headless: bool, db_path: Path):
    if not ENDPOINTS_PATH.is_file():
        raise FileNotFoundError(
            f"{ENDPOINTS_PATH} not found -- run the crawler first (`stof crawl` / "
            "tests/integration/test_crawler_demo.py) to discover real endpoints."
        )
    endpoints = load_endpoints(ENDPOINTS_PATH)

    db_path.unlink(missing_ok=True)
    session_manager = _build_session_manager(db_path)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless, slow_mo=150 if not headless else 0)
        # demo.testfire.net's TLS cert is expired -- their bug, not ours.
        session_pool = SessionPool(browser, ignore_https_errors=True)

        module = IdorTestsModule(
            config=IdorTestConfig(candidate_ids=[str(n) for n in range(800000, 800011)]),
            high_priv_role="admin",
            low_priv_role="normal",
            target_url="https://demo.testfire.net",
        )

        findings = await module.run(endpoints, session_manager, session_pool)

        await session_pool.shutdown()

    return findings


def _print_summary(findings) -> None:
    print(f"\n--- IDOR / Privilege Escalation scan: {len(findings)} finding(s) ---")
    for f in findings:
        print(f"[FIND] {f.severity.upper():8s} {f.vuln_type} — {f.endpoint.url} (role={f.user_role})")
        print(f"        {f.description}")


@pytest.mark.asyncio
async def test_idor_module_finds_the_two_confirmed_real_vulnerabilities(tmp_path):
    findings = await _run(headless=True, db_path=tmp_path / "stof.db")

    write_findings(findings, path=FINDINGS_PATH)
    _print_summary(findings)

    vuln_types = {f.vuln_type for f in findings}
    assert any("Insecure Direct Object Reference" in v for v in vuln_types), (
        "expected the confirmed real IDOR on /bank/showAccount to be flagged"
    )
    assert any("Privilege Escalation" in v for v in vuln_types), (
        "expected the confirmed real vertical privesc on /admin/admin.jsp to be flagged"
    )
    assert all(f.severity == "Critical" for f in findings)


if __name__ == "__main__":
    findings = asyncio.run(_run(headless=False, db_path=Path("/tmp/stof_idor_demo.db")))
    write_findings(findings, path=FINDINGS_PATH)
    _print_summary(findings)
    print(f"\nWrote {len(findings)} finding(s) -> {FINDINGS_PATH}")
