"""Layer 2 (CLI entry point) — `stof/main.py`, per CLAUDE.md's CLI
Interface section.

`crawl`, `test`, and `scan` are implemented -- CLAUDE.md's documented
shape almost exactly:

    stof crawl --config config/config.json --output data/endpoints.json
    stof test --module jwt_tests --endpoints data/endpoints.json --output data/reports/
    stof scan --config config/config.json --users config/users.json --output data/reports/

`scan` (added once enough vulnerability modules existed to make "every
implemented module" a meaningful default) is the one-command pipeline:
dependency check, crawl, every implemented module, reports -- it calls
`_run_crawl()` then `_run_test()` in sequence rather than duplicating
either. `record`/`modules list`/`report --last` from CLAUDE.md's CLI
section still aren't built.

Target-agnostic by design: login form selectors, IDOR candidate IDs,
and login role/auth_type all come from `config.json`/`users.json` as
configured, with generic app-agnostic fallbacks (see
`stof.auth.form_login`) when a target doesn't set them explicitly --
this file must never bake in one specific target's DOM or ID scheme,
since the whole point is to point it at a different app and re-run.
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import click
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from stof.auth import AssistedLoginProvider, FormLoginProvider, JWTAuthProvider
from stof.bench import score_false_positives, score_recall
from stof.cleanup import registry as cleanup_registry
from stof.config import ConfigError, load_config, load_dotenv, load_users
from stof.core import rate_limiter
from stof.core.console import DEFAULT_LOG_DIR, ScanConsole, attach_file_logging, detach_file_logging
from stof.core.logger import get_logger
from stof.core.module_registry import VULN_MODULE_NAMES
from stof.core.test_orchestrator import build_test_plan
from stof.crawler.crawler import CrawlerConfig, verify_auth_required
from stof.crawler.crawler import crawl as run_crawler
from stof.crawler.endpoint_store import Endpoint, write_endpoints
from stof.crawler.endpoint_store import load as load_endpoints
from stof.crawler.endpoint_store import merge as merge_endpoints
from stof.engine.burp_capture import capture_findings_via_burp
from stof.engine.burp_controller import BurpApiError, BurpController
from stof.engine.multi_session import SessionPool
from stof.engine.playwright_engine import PlaywrightEngine
from stof.evidence import EvidenceCollector
from stof.findings.baseline import compute_diff, find_baseline_scan_id
from stof.findings.burp_normalizer import normalize_burp_issues
from stof.findings.models import Finding
from stof.findings.store import FindingDB, write_findings
from stof.modules.auth_tests import AuthTestConfig, AuthTestsModule
from stof.modules.business_logic_tests import BusinessLogicTestConfig, BusinessLogicTestsModule
from stof.modules.cache_tests import CacheTestConfig, CacheTestsModule
from stof.modules.configuration_tests import ConfigurationTestConfig, ConfigurationTestsModule
from stof.modules.csrf_tests import CsrfTestConfig, CsrfTestsModule
from stof.modules.deserialization_tests import DeserializationTestConfig, DeserializationTestsModule
from stof.modules.disclosure_tests import DisclosureTestConfig, DisclosureTestsModule
from stof.modules.file_upload_tests import FileUploadTestConfig, FileUploadTestsModule
from stof.modules.graphql_tests import GraphQLTestConfig, GraphQLTestsModule
from stof.modules.idor_tests import IdorTestConfig, IdorTestsModule
from stof.modules.injection_variants_tests import InjectionVariantsTestConfig, InjectionVariantsTestsModule
from stof.modules.jwt_tests import JwtTestConfig, JwtTestsModule
from stof.modules.mfa_tests import MfaTestConfig, MfaTestsModule
from stof.modules.results import ERROR, TestCaseResult, extract_findings, skipped_techniques, summarize
from stof.modules.sqli_tests import SqliTestConfig, SqliTestsModule
from stof.modules.ssrf_tests import SsrfTestConfig, SsrfTestsModule
from stof.modules.xss_tests import XssTestConfig, XssTestsModule
from stof.passive.engine import PassiveEngine
from stof.recon import build_target_profile, run_recon, write_recon_report
from stof.recorder import cdp
from stof.reporting import generate_reports
from stof.reporting.walkthrough_runner import build_walkthroughs
from stof.session import SessionManager, SessionStore
from stof.workflows.repository import WorkflowRepository
from stof.workflows.runner import WorkflowRunner

_log = get_logger("core.main")

# Generic, app-agnostic default: most simple apps' own object IDs are
# small sequential integers. A target with a different ID scheme (e.g.
# a specific known-valid range) should set `target.idor_candidate_ids`
# in config.json instead of this file hardcoding any one app's range.
_GENERIC_IDOR_CANDIDATE_IDS = [str(i) for i in range(1, 21)]


# Derived from ModulesConfig via module_registry.py, not hand-copied --
# see that module's docstring for the real bug a second hand-maintained
# list like this one already caused once.
_KNOWN_MODULES = VULN_MODULE_NAMES


def _jwt_roles(users_by_role: dict) -> list[str]:
    # jwt_tests only has real surface against roles actually configured
    # as `auth_type: "jwt"` -- a target with none (e.g. a purely
    # cookie-based app) legitimately yields an empty role list rather
    # than probing a role that was never JWT-authenticated to begin with.
    return [role for role, user in users_by_role.items() if user.auth_type == "jwt"]


def _resolve_module_names(explicit: list[str] | None, config) -> list[str]:
    """`--module` always wins when passed explicitly. Otherwise the
    modules actually enabled under config.json's own "modules" block
    are the default -- config-driven selective execution via Layer 8's
    `build_test_plan()`, instead of a second, disconnected "run every
    implemented module" default that ignored config.json entirely (the
    bug that made toggling "idor_tests": false in config.json silently
    do nothing)."""
    if explicit:
        unknown = [m for m in explicit if m not in _KNOWN_MODULES]
        if unknown:
            raise click.ClickException(f"Unknown module(s): {', '.join(unknown)}. Available: {', '.join(_KNOWN_MODULES)}")
        return explicit

    plan = build_test_plan(config)
    resolved = [m for m in plan.enabled_modules if m in _KNOWN_MODULES]
    if not resolved:
        raise click.ClickException(
            "No vulnerability modules are enabled. Set at least one to `true` under "
            "\"modules\" in your config.json, or pass --module explicitly."
        )
    return resolved


def _apply_application_profile(
    module_names: list[str], endpoints: list, jwt_roles: list[str]
) -> tuple[list[str], list[str]]:
    """Post-crawl "what kind of application is this" pass, applied on
    top of whatever `_resolve_module_names()` already selected -- not a
    replacement for it. Deliberately narrow: only skips a module when
    its required surface is *provably absent* from what was actually
    discovered (no role configured with `auth_type: "jwt"` at all, no
    URL containing "graphql" anywhere in the crawl), the exact same
    standard each of these modules' own techniques already use
    internally to report SKIPPED one-by-one -- this just decides it
    once, before the module runs at all, instead of after every
    technique individually reaches the same conclusion. Never guesses
    at richer "app type" categories (SPA vs. server-rendered, REST vs.
    traditional) to decide relevance for modules like idor_tests/
    auth_tests/configuration_tests -- those apply to virtually any HTTP
    application, and a wrong guess there would silently skip real
    coverage, which is a worse failure than a handful of SKIP lines."""
    skips: list[str] = []
    filtered = list(module_names)
    if "jwt_tests" in filtered and not jwt_roles:
        filtered.remove("jwt_tests")
        skips.append('jwt_tests (no role configured with auth_type: "jwt")')
    if "graphql_tests" in filtered and not any("graphql" in e.url.lower() for e in endpoints):
        filtered.remove("graphql_tests")
        skips.append("graphql_tests (no GraphQL endpoint discovered)")
    return filtered, skips


def _build_module_builders(config, jwt_roles: list[str], users_by_role: dict, target_profile=None, shared_candidate_ids: list[str] | None = None) -> dict:
    # `shared_candidate_ids`, when given, is the SAME mutable list object
    # `_run_all_vuln_modules()` keeps growing as earlier modules in this
    # scan discover new id-shaped values (leaked in a PII/disclosure
    # finding, an IDOR response, ...) -- see that function's own comment.
    # Every `idor_tests` lambda below reads it by reference at CALL time
    # (Python closures are late-binding), so a module that runs later in
    # `module_names` sees ids an earlier module already surfaced, not
    # just the ones configured before the scan even started.
    idor_ids = shared_candidate_ids if shared_candidate_ids is not None else list(config.target.idor_candidate_ids or _GENERIC_IDOR_CANDIDATE_IDS)
    jwt_config_kwargs = {}
    if config.target.jwt_role_claim is not None:
        jwt_config_kwargs["role_claim"] = config.target.jwt_role_claim

    # Same generic "admin"/"normal" convention `IdorTestsModule` itself
    # defaults to -- a target using different role names overrides these
    # by naming its own roles that way in users.json (the modules take
    # whatever roles are actually configured, not literal string matches).
    high_priv_role = "admin" if "admin" in users_by_role else next(iter(users_by_role), None)
    low_priv_role = "normal" if "normal" in users_by_role else next(
        (r for r in users_by_role if r != high_priv_role), high_priv_role
    )
    test_user = users_by_role.get(low_priv_role)
    victim_user = users_by_role.get(high_priv_role)

    allow_state_changing_probes = config.testing.allow_state_changing_probes

    auth_config = AuthTestConfig(
        login_json_endpoint=config.target.jwt_token_url,
        change_password_url=config.target.change_password_url,
        reset_password_request_url=config.target.reset_password_request_url,
        reset_password_complete_url=config.target.reset_password_complete_url,
        logout_url=config.target.logout_url,
        test_role=low_priv_role,
        test_username=test_user.username if test_user else None,
        test_current_password=test_user.password if test_user else None,
        victim_email=victim_user.username if victim_user else None,
        allow_state_changing_probes=allow_state_changing_probes,
    )

    # MFA testing needs the login page itself (not a JSON-API endpoint)
    # -- the OTP field it looks for only ever appears on the real login
    # form, same reason `_build_form_login_provider` always uses
    # `config.target.login_url` rather than `jwt_token_url`.
    mfa_config = MfaTestConfig(
        login_url=config.target.login_url,
        test_role=low_priv_role,
        test_username=test_user.username if test_user else None,
        test_password=test_user.password if test_user else None,
        totp_secret=test_user.totp_secret if test_user else None,
    )

    csrf_config = CsrfTestConfig(
        test_role=low_priv_role,
        role_auth_type=test_user.auth_type if test_user else None,
        victim_role=high_priv_role,
        victim_role_auth_type=victim_user.auth_type if victim_user else None,
        allow_state_changing_probes=allow_state_changing_probes,
    )

    return {
        "idor_tests": lambda: IdorTestsModule(config=IdorTestConfig(candidate_ids=idor_ids, allow_state_changing_probes=allow_state_changing_probes)),
        "jwt_tests": lambda: JwtTestsModule(roles=jwt_roles, config=JwtTestConfig(**jwt_config_kwargs)),
        "auth_tests": lambda: AuthTestsModule(config=auth_config),
        "mfa_tests": lambda: MfaTestsModule(config=mfa_config),
        "csrf_tests": lambda: CsrfTestsModule(config=csrf_config),
        "configuration_tests": lambda: ConfigurationTestsModule(config=ConfigurationTestConfig(base_url=config.target.base_url, target_profile=target_profile)),
        "disclosure_tests": lambda: DisclosureTestsModule(config=DisclosureTestConfig(high_priv_role=high_priv_role or "admin")),
        "graphql_tests": lambda: GraphQLTestsModule(config=GraphQLTestConfig(
            high_priv_role=high_priv_role or "admin", low_priv_role=low_priv_role or "normal",
            test_username=test_user.username if test_user else None,
            allow_state_changing_probes=allow_state_changing_probes,
        )),
        "deserialization_tests": lambda: DeserializationTestsModule(config=DeserializationTestConfig(high_priv_role=high_priv_role or "admin")),
        "sqli_tests": lambda: SqliTestsModule(config=SqliTestConfig(
            low_priv_role=low_priv_role or "normal", high_priv_role=high_priv_role or "admin",
            allow_state_changing_probes=allow_state_changing_probes,
        )),
        "xss_tests": lambda: XssTestsModule(config=XssTestConfig(
            low_priv_role=low_priv_role or "normal", high_priv_role=high_priv_role or "admin",
            allow_state_changing_probes=allow_state_changing_probes,
            collaborator_url=config.burp.collaborator_url,
        )),
        "ssrf_tests": lambda: SsrfTestsModule(config=SsrfTestConfig(
            low_priv_role=low_priv_role or "normal", collaborator_url=config.burp.collaborator_url,
        )),
        "injection_variants_tests": lambda: InjectionVariantsTestsModule(config=InjectionVariantsTestConfig(
            low_priv_role=low_priv_role or "normal", high_priv_role=high_priv_role or "admin",
            allow_state_changing_probes=allow_state_changing_probes,
        )),
        "cache_tests": lambda: CacheTestsModule(config=CacheTestConfig(
            base_url=config.target.base_url, test_role=low_priv_role or "normal",
            allow_state_changing_probes=allow_state_changing_probes,
        )),
        "business_logic_tests": lambda: BusinessLogicTestsModule(config=BusinessLogicTestConfig(
            allow_state_changing_probes=allow_state_changing_probes, test_role=low_priv_role or "normal",
        )),
        "file_upload_tests": lambda: FileUploadTestsModule(config=FileUploadTestConfig(
            allow_state_changing_probes=allow_state_changing_probes,
        )),
    }


def _build_form_login_provider(config) -> FormLoginProvider:
    kwargs = {}
    for field in ("username_selector", "password_selector", "submit_selector", "success_selector"):
        value = getattr(config.target, field)
        if value is not None:
            kwargs[field] = value
    return FormLoginProvider(login_url=config.target.login_url, **kwargs)


def _build_login_provider(config) -> "FormLoginProvider | AssistedLoginProvider":
    """`TargetConfig.requires_assisted_login` swaps the WHOLE target's
    "form_login" provider slot from the normal automated
    `FormLoginProvider` to `AssistedLoginProvider` -- every form-login
    role on a target behind a bot-challenge needs the assisted path,
    not just one specific user, so this is a target-level switch rather
    than a second, separate auth_type users.json would need to declare
    per role. See `stof/auth/assisted_login.py`'s own module docstring
    for why a captured cookie alone can't just be handed to the normal
    provider instead."""
    if config.target.requires_assisted_login:
        kwargs = {}
        if config.target.success_selector is not None:
            kwargs["success_selector"] = config.target.success_selector
        return AssistedLoginProvider(login_url=config.target.login_url, **kwargs)
    return _build_form_login_provider(config)


async def _attach_assisted_login_contexts(
    pw, config, session_pool, session_manager, login_provider, users_by_role: dict, echo
) -> None:
    """When `config.target.requires_assisted_login` is set, connects
    over CDP to the server-side assisted-login browser (`stof/ui/
    server.py`'s `AssistedLoginBrowserSession`, started from the
    Settings UI -- NOT the operator's own local Chrome; that design
    was replaced once it became clear a remote end user's own laptop
    has no reachable path back to a cloud-hosted STOF server. The
    server-side browser is live-streamed to whoever completes the
    login via CDP screencast + input relay, but the browser itself
    always lives on this same machine, at a fixed localhost-only
    endpoint -- see `stof/recorder/cdp.py`'s `assisted_login_cdp_
    endpoint()`) and hands each form-login role's traffic off to that
    REAL, human-cleared browser context for the rest of this process's
    run, instead of ever attempting the normal automated login flow
    that would just hit the same bot-challenge wall again.

    Called identically from both `_run_crawl()` and `_run_test()` --
    they're genuinely separate browser launches/processes (see
    `_run_scan()`'s own docstring), so each independently reconnects
    over CDP; CDP supports multiple concurrent client connections to
    one browser, so this is safe.

    A no-op (returns immediately) for every target that doesn't set
    the flag -- zero behavior change for a normal target."""
    if not config.target.requires_assisted_login:
        return
    form_login_roles = sorted(role for role, u in users_by_role.items() if u.auth_type == "form_login")
    if not form_login_roles:
        return

    endpoint = cdp.assisted_login_cdp_endpoint()
    try:
        external_browser = await pw.chromium.connect_over_cdp(endpoint)
    except Exception as exc:
        raise click.ClickException(
            f"Assisted login is enabled for this target, but no assisted-login browser session was found at "
            f"{endpoint}. Go to Settings -> Assisted Login, start a session, and complete login for role(s) "
            f"{', '.join(form_login_roles)}, then re-run. Original error: {exc}"
        ) from exc

    contexts = external_browser.contexts
    if len(contexts) < len(form_login_roles):
        raise click.ClickException(
            f"Assisted login needs one confirmed browser context per form-login role -- found "
            f"{len(contexts)}, but {len(form_login_roles)} role(s) need one ({', '.join(form_login_roles)}). "
            "Complete assisted login for each role in Settings, then re-run."
        )

    for role, context in zip(form_login_roles, contexts, strict=False):
        page = context.pages[0] if context.pages else await context.new_page()
        user = users_by_role[role]
        session = await login_provider.authenticate(user, page)
        session_manager.seed_session(session)
        await session_pool.attach_external_context(role, context)
        echo(f"[AUTH]  ✓ Assisted login confirmed for role '{role}' via operator browser at {endpoint}")


def _existing_json(path: Path) -> dict:
    """Tolerant read for `configure`'s "merge over what's already
    there" behavior -- a missing or unparseable file just means "start
    from nothing" rather than a hard failure, since `configure` is the
    command that's supposed to get someone UNSTUCK from a bad config."""
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_dotenv_value(path: Path, key: str, value: str) -> None:
    """Upserts one `KEY=VALUE` line in a `.env` file, preserving every
    other line untouched (comments, unrelated vars, ordering) -- the
    writer-side counterpart to `load_dotenv()`'s reader."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    prefix = f"{key}="
    for i, line in enumerate(lines):
        if line.strip().startswith(prefix):
            lines[i] = f"{key}={value}"
            break
    else:
        lines.append(f"{key}={value}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@click.group()
def cli() -> None:
    """STOF — Security Testing Orchestration Framework."""


def _prompt_optional_totp_secret(role_label: str) -> str | None:
    """Optional TOTP/2FA secret prompt for one role -- extracted out of
    `configure()` itself (asked once per role, admin and normal-user)
    both to avoid duplicating the prompt logic and because inlining it
    twice pushed `configure()`'s own complexity past this project's own
    ~15 threshold. Returns `None` when the operator says the account
    has no MFA step, matching `UserConfig.totp_secret`'s own `None`
    default -- `configure()` only writes a totp_secret entry at all
    when this returns a real value."""
    if not click.confirm(f"Does the {role_label} account require an authenticator-app code (TOTP/2FA) to log in?", default=False):
        return None
    click.echo("  Get this from the account's 2FA enrollment QR code -- scan it with any generic QR reader")
    click.echo("  (not an authenticator app) to read the raw otpauth://totp/...?secret=XXXX data, and paste")
    click.echo("  just the secret= value below.")
    return click.prompt(f"  {role_label.capitalize()} TOTP secret", hide_input=True)


@cli.command()
@click.option("--config", "config_path", default="config/config.json", show_default=True, type=click.Path())
@click.option("--users", "users_path", default="config/users.json", show_default=True, type=click.Path())
@click.option("--env-file", "env_path", default=".env", show_default=True, type=click.Path())
def configure(config_path: str, users_path: str, env_path: str) -> None:
    """Interactive setup wizard for a target and its credentials.

    Replaces hand-editing config.json + users.json + a matching .env in
    three separate files with matching `{{env:VAR}}` token names -- the
    thing that made first-time setup (and re-pointing at a different
    target) fiddly and error-prone. Prompts for the target URL(s),
    admin/normal credentials, and which vulnerability modules to run by
    default, then writes all three files and validates the result
    immediately (same `load_config`/`load_users` this project's own
    commands use, so a mistake is caught here, not mid-scan).

    Passwords are written ONLY to `.env` -- config.json/users.json only
    ever get a `{{env:VAR}}` token, never a literal password, matching
    this project's existing credential-handling rule. Re-run any time
    to repoint at a different target or rotate credentials; existing
    browser/output/burp settings in config.json are preserved as-is."""
    config_path, users_path, env_path = Path(config_path), Path(users_path), Path(env_path)
    existing_config = _existing_json(config_path)
    existing_target = existing_config.get("target", {})

    click.echo("STOF target & credential setup")
    click.echo("-" * 40)

    base_url = click.prompt("Target base URL", default=existing_target.get("base_url") or None).strip()
    parts = urlsplit(base_url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise click.ClickException(f"'{base_url}' doesn't look like a valid http(s) URL (expected e.g. https://example.com)")
    origin = f"{parts.scheme}://{parts.netloc}"

    login_url = click.prompt("Login page URL", default=existing_target.get("login_url") or f"{origin}/login").strip()

    wants_jwt = click.confirm("Does this target also expose a JWT/API token login endpoint?", default=bool(existing_target.get("jwt_token_url")))
    jwt_token_url = None
    if wants_jwt:
        jwt_token_url = click.prompt("JWT token endpoint URL", default=existing_target.get("jwt_token_url") or f"{origin}/api/login").strip()

    click.echo()
    click.echo("Credentials (passwords go to .env only -- never written to config.json/users.json)")
    admin_username = click.prompt("Admin (high-privilege) username/email")
    admin_password = click.prompt("Admin password", hide_input=True)
    admin_totp_secret = _prompt_optional_totp_secret("admin")
    normal_username = click.prompt("Normal (low-privilege) username/email")
    normal_password = click.prompt("Normal password", hide_input=True)
    normal_totp_secret = _prompt_optional_totp_secret("normal-user")
    wants_jwt_role = wants_jwt and click.confirm("Also authenticate the normal user via JWT (for jwt_tests)?", default=True)

    click.echo()
    click.echo("Vulnerability modules to run by default (used when `stof scan`/`stof test` run without --module):")
    existing_modules = existing_config.get("modules", {})
    module_flags = {name: click.confirm(f"  enable {name}?", default=existing_modules.get(name, True)) for name in _KNOWN_MODULES}

    _write_dotenv_value(env_path, "ADMIN_PASSWORD", admin_password)
    _write_dotenv_value(env_path, "USER_PASSWORD", normal_password)

    admin_user = {"id": "admin-01", "role": "admin", "username": admin_username, "password": "{{env:ADMIN_PASSWORD}}", "auth_type": "form_login"}
    normal_user = {"id": "user-01", "role": "normal", "username": normal_username, "password": "{{env:USER_PASSWORD}}", "auth_type": "form_login"}
    # Same {{env:VAR}} token convention as password -- never a literal
    # secret in users.json. Omitted entirely (not written as null) when
    # not configured, matching `UserConfig.totp_secret`'s own `None`
    # default so an existing users.json with no MFA stays byte-for-byte
    # unaffected by this feature existing.
    if admin_totp_secret:
        _write_dotenv_value(env_path, "ADMIN_TOTP_SECRET", admin_totp_secret)
        admin_user["totp_secret"] = "{{env:ADMIN_TOTP_SECRET}}"
    if normal_totp_secret:
        _write_dotenv_value(env_path, "USER_TOTP_SECRET", normal_totp_secret)
        normal_user["totp_secret"] = "{{env:USER_TOTP_SECRET}}"

    users_doc = {"users": [admin_user, normal_user]}
    if wants_jwt_role:
        users_doc["users"].append({"id": "user-01-jwt", "role": "jwt_user", "username": normal_username, "password": "{{env:USER_PASSWORD}}", "auth_type": "jwt"})
    users_path.parent.mkdir(parents=True, exist_ok=True)
    users_path.write_text(json.dumps(users_doc, indent=2) + "\n", encoding="utf-8")

    target_block = dict(existing_target)
    target_block["base_url"] = base_url
    target_block["login_url"] = login_url
    if jwt_token_url:
        target_block["jwt_token_url"] = jwt_token_url
    else:
        target_block.pop("jwt_token_url", None)

    modules_block = dict(existing_modules)
    modules_block["crawler"] = True
    modules_block.update(module_flags)

    config_doc = {
        "target": target_block,
        "browser": existing_config.get("browser") or {"headless": True, "slowmo_ms": 0, "proxy": None},
        "modules": modules_block,
        "output": existing_config.get("output") or {"reports_dir": "data/reports", "evidence_dir": "data/evidence"},
        # api_key ships as "" (not a {{env:...}} token) so validation
        # never demands BURP_API_KEY be set for a target that isn't
        # using Burp integration -- set it (and burp.enabled) by hand
        # in config.json if/when you turn that on.
        "burp": existing_config.get("burp") or {"enabled": False, "run_active_scan": False, "api_url": "http://127.0.0.1:1337", "proxy_url": "http://127.0.0.1:8080", "api_key": "", "scan_timeout_s": 1800, "poll_interval_s": 5},
    }
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config_doc, indent=2) + "\n", encoding="utf-8")

    click.echo()
    load_dotenv(env_path)
    try:
        load_config(config_path)
        load_users(users_path)
    except ConfigError as exc:
        raise click.ClickException(f"wrote {config_path} and {users_path}, but validation failed: {exc}") from exc

    click.echo(f"Wrote {config_path}, {users_path}, {env_path} -- configuration is valid.")
    click.echo(f"Next: stof scan --config {config_path} --users {users_path}")


@cli.command()
@click.option("--module", default=None, help=f"Comma-separated module name(s). Defaults to whatever is enabled under config.json's \"modules\" block. Available: {', '.join(_KNOWN_MODULES)}.")
@click.option("--endpoints", default="data/endpoints.json", show_default=True, type=click.Path())
@click.option("--config", "config_path", default="config/config.json", show_default=True, type=click.Path())
@click.option("--users", "users_path", default="config/users.json", show_default=True, type=click.Path())
@click.option("--output", default=None, help="Reports output dir. Defaults to config.output.reports_dir.")
@click.option("--log-dir", default=str(DEFAULT_LOG_DIR), show_default=True, type=click.Path(), help="Per-scan log file directory.")
@click.option("--headless/--headed", default=None, help="Overrides config.browser.headless.")
def test(module: str | None, endpoints: str, config_path: str, users_path: str, output: str | None, log_dir: str, headless: bool | None) -> None:
    """Run one or more vulnerability modules against already-discovered
    endpoints and produce HTML/JSON/Excel reports -- the single command
    for this project's IDOR/Privilege-Escalation MVP demo."""
    module_names = [m.strip() for m in module.split(",") if m.strip()] if module else None
    exit_code = asyncio.run(_run_test(module_names, endpoints, config_path, users_path, output, headless, log_dir=log_dir))
    raise SystemExit(exit_code)


@cli.command()
@click.option("--config", "config_path", default="config/config.json", show_default=True, type=click.Path())
@click.option("--users", "users_path", default="config/users.json", show_default=True, type=click.Path())
@click.option("--role", default=None, help="Configured user role to crawl as. Defaults to crawling as EVERY configured role and merging the results (single-role targets crawl once, unchanged).")
@click.option("--output", "output_path", default="data/endpoints.json", show_default=True, type=click.Path())
@click.option("--max-depth", default=3, show_default=True)
@click.option("--max-pages", default=100, show_default=True)
@click.option("--headless/--headed", default=None, help="Overrides config.browser.headless.")
def crawl(config_path: str, users_path: str, role: str | None, output_path: str, max_depth: int, max_pages: int, headless: bool | None) -> None:
    """Authenticated BFS crawl of `config.json`'s configured target --
    writes a fresh `endpoints.json` for `stof test` to run against.
    Re-run this whenever the target changes to a different app; `test`
    never crawls on its own, it only reads whatever this last wrote."""
    exit_code = asyncio.run(_run_crawl(config_path, users_path, role, output_path, max_depth, max_pages, headless))
    raise SystemExit(exit_code)


@cli.command()
@click.option("--report", "report_path", required=True, type=click.Path(exists=True), help="JSON report from a scan of the KNOWN-VULNERABLE benchmark target (data/reports/scan_<id>.json).")
@click.option("--manifest", "manifest_path", required=True, type=click.Path(exists=True), help="Ground-truth manifest (see benchmarks/README.md) naming what SHOULD be found.")
@click.option("--clean-report", "clean_report_path", default=None, type=click.Path(exists=True), help="Optional JSON report from a scan of a KNOWN-CLEAN target (same vuln classes, none of them real) -- every finding in it is a false positive.")
def bench(report_path: str, manifest_path: str, clean_report_path: str | None) -> None:
    """Scores a scan's report against a benchmark manifest -- recall
    (of the vulnerabilities the manifest says are really there, how
    many did STOF catch) and, with --clean-report, false-positive rate
    (of what STOF claimed to find against a target known to have none
    of them, how many were wrong). See `stof/bench/score.py`'s own
    docstring for why these are two separate numbers, not one."""
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))

    recall_score = score_recall(report, manifest)
    click.echo(f"[BENCH] {recall_score.manifest_name} ({recall_score.target})")
    click.echo(f"[BENCH] Recall: {len(recall_score.detected)}/{recall_score.expected_total} ({recall_score.recall:.0%})")
    for item in recall_score.missed:
        click.echo(f"[BENCH]   MISSED: {item['technique_id']} @ {item['endpoint_pattern']} -- {item.get('description', '')}")

    if clean_report_path:
        clean_report = json.loads(Path(clean_report_path).read_text(encoding="utf-8"))
        fp_score = score_false_positives(clean_report)
        click.echo(f"[BENCH] False positives against clean target ({fp_score.target}): {fp_score.false_positive_count}")
        for fp in fp_score.false_positives:
            click.echo(f"[BENCH]   FALSE POSITIVE: {fp['technique_id']} ({fp['vuln_type']}) @ {fp['endpoint_url']}")


def _chromium_installed() -> bool:
    cache_dir = Path.home() / ".cache" / "ms-playwright"
    return cache_dir.is_dir() and any(cache_dir.glob("chromium-*"))


def _ensure_dependencies_installed() -> None:
    """`scan` is meant to be the one command a fresh checkout runs --
    if this project's own declared dependencies (Pillow in particular,
    added for evidence-image rendering) aren't installed yet, install
    them now rather than failing deep inside a module with an
    ImportError. Deliberately narrow: only `pip install -e .[dev]` of
    *this* project's own pyproject.toml, never anything network-wide
    or version-changing -- and skipped entirely once satisfied, so a
    normal run pays no extra cost.

    Playwright's browser binary (a real, ~150-300MB one-time download)
    IS auto-installed too, at explicit user request -- but always with
    a visible `[SCAN]` message first, never silently, so a slow first
    run is explained rather than just... slow."""
    try:
        import PIL.Image  # noqa: F401
        import playwright  # noqa: F401
        import pydantic  # noqa: F401
    except ImportError as exc:
        click.echo("[SCAN] Installing missing Python dependencies (pip install -e \".[dev]\")...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-e", ".[dev]", "-q"],
            cwd=Path(__file__).resolve().parent.parent, check=False,
        )
        if result.returncode != 0:
            raise click.ClickException("dependency install failed -- run `pip install -e \".[dev]\"` manually and retry") from exc
        click.echo("[SCAN] Python dependencies installed.")

    if not _chromium_installed():
        click.echo("[SCAN] Installing Playwright's Chromium browser (one-time, ~150-300MB download)...")
        result = subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=False)
        if result.returncode != 0:
            raise click.ClickException("Chromium install failed -- run `python3 -m playwright install chromium` manually and retry")
        click.echo("[SCAN] Chromium installed.")


@cli.command()
@click.option("--config", "config_path", default="config/config.json", show_default=True, type=click.Path())
@click.option("--users", "users_path", default="config/users.json", show_default=True, type=click.Path())
@click.option("--role", default=None, help="Configured user role to crawl as. Defaults to crawling as EVERY configured role and merging the results (single-role targets crawl once, unchanged).")
@click.option("--endpoints", "endpoints_path", default="data/endpoints.json", show_default=True, type=click.Path())
@click.option("--max-depth", default=3, show_default=True)
@click.option("--max-pages", default=100, show_default=True)
@click.option("--module", default=None, help=f"Comma-separated module name(s). Defaults to whatever is enabled under config.json's \"modules\" block. Available: {', '.join(_KNOWN_MODULES)}.")
@click.option("--output", default=None, help="Reports output dir. Defaults to config.output.reports_dir.")
@click.option("--log-dir", default=str(DEFAULT_LOG_DIR), show_default=True, type=click.Path(), help="Per-scan log file directory.")
@click.option("--headless/--headed", default=None, help="Overrides config.browser.headless.")
@click.option("--recrawl/--no-recrawl", default=True, show_default=True, help="Re-crawl before testing (default), or reuse the existing --endpoints file as-is.")
@click.option("--scan-id", "scan_id", default=None, help="Override the auto-generated scan id (used by stof/ui's backend to correlate a launched process with its log/report files before either exists on disk).")
@click.option("--workflow", default=None, help="Comma-separated recorded workflow id(s) (see `stof record` / data/workflows/) to replay once each, early in the scan, before vulnerability testing starts. Extends reachable attack surface past what the crawler alone finds (a checkout flow, a signup wizard, ...) -- not yet fed into any module's own detection logic beyond that, see the REPLAYING RECORDED WORKFLOWS phase's own log output for exactly what happened.")
def scan(config_path: str, users_path: str, role: str | None, endpoints_path: str, max_depth: int, max_pages: int,
         module: str | None, output: str | None, log_dir: str, headless: bool | None, recrawl: bool, scan_id: str | None,
         workflow: str | None) -> None:
    """The one-command full pipeline: install missing dependencies,
    launch a browser and authenticate against the target (crawl +
    endpoint discovery), then run every vulnerability module enabled in
    config.json -- printing `[TEST] PASS/FAIL/SKIP/N/A` for every
    technique -- and generate the HTML/JSON/Excel reports plus a
    persistent per-scan log file. This is CLAUDE.md's own documented
    `stof scan` command."""
    _ensure_dependencies_installed()
    module_names = [m.strip() for m in module.split(",") if m.strip()] if module else None
    workflow_ids = [w.strip() for w in workflow.split(",") if w.strip()] if workflow else None

    exit_code = asyncio.run(_run_scan(config_path, users_path, role, endpoints_path, max_depth, max_pages, module_names, output, headless, recrawl, log_dir=log_dir, scan_id=scan_id, workflow_ids=workflow_ids))
    raise SystemExit(exit_code)


# Confirmed live: a Playwright driver connection dying mid-scan
# (`Browser.new_context: Connection closed while reading from the
# driver`) does NOT raise up through `vm.run_techniques()` -- each
# technique's own per-technique isolation (`base.py`'s `_safe_result`)
# already catches it and turns it into an ERROR TestCaseResult, same as
# any other technique failure. That's correct behavior for an ordinary
# probe failure, but it means `_with_retry`'s exception-based retry
# never fires for THIS failure class, and every module after the one
# where the driver died silently inherits the same dead browser/
# session_pool and fails the same way -- confirmed by a real scan where
# a driver death partway through produced a cascade of near-identical
# ERROR results across every remaining module. The fix has to look at
# the RESULTS a module actually returned, not just whether an exception
# was raised.
_DRIVER_DEAD_SIGNATURES = (
    "connection closed while reading from the driver",
    "target page, context or browser has been closed",
    "browser has been closed",
    "target closed",
)


def _looks_like_driver_dead(detail: str) -> bool:
    lowered = (detail or "").lower()
    return any(sig in lowered for sig in _DRIVER_DEAD_SIGNATURES)


def _module_hit_dead_driver(results: list) -> bool:
    return any(r.status == ERROR and _looks_like_driver_dead(r.detail) for r in results)


async def _with_retry(coro_fn, attempts: int = 3):
    """This sandbox's connection to demo.testfire.net has repeatedly
    shown transient `net::ERR_NETWORK_CHANGED` failures during page
    navigation throughout this project's development (see
    tests/integration/*_demo.py, which needed manual retries for the
    same reason) -- not a code bug, but real enough to make the one
    command unreliable for a live demo without handling it here.
    `coro_fn` is a zero-arg callable returning an awaitable, so each
    retry attempt gets a fresh coroutine rather than re-awaiting a
    already-consumed one."""
    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return await coro_fn()
        except PlaywrightError as exc:
            last_exc = exc
            click.echo(f"[STOF]  transient network error on attempt {attempt}/{attempts}: {exc}. Retrying...")
            await asyncio.sleep(2)
    raise last_exc


_JWT_NOTE_NO_ROLE_CONFIGURED = (
    "Not applicable -- no configured user in users.json has auth_type: \"jwt\", "
    "so there was no JWT-authenticated role to test. This does not mean the "
    "target has no JWT auth surface -- only that no role is currently configured "
    "to authenticate as one. Set a role's auth_type to \"jwt\" (with a token_url "
    "if the token comes from a login call) to actually exercise this module."
)


def _jwt_tests_note(jwt_roles: list[str]) -> str:
    if not jwt_roles:
        return _JWT_NOTE_NO_ROLE_CONFIGURED
    return (
        f"Ran against JWT-authenticated role(s) {', '.join(jwt_roles)} but found no "
        "role-claim tampering issue. This can mean the target correctly verifies the "
        "token's signature, its JWT has no matching role claim to tamper with, or the "
        "probed endpoint doesn't enforce auth at all and the module safely skipped to "
        "avoid a misleading finding -- check the scan log for which case applied."
    )


def _revert_state_changing_probes_flag(config_path: str) -> None:
    """`testing.allow_state_changing_probes` is a manually-armed safety
    gate (config/config.json) a tester flips on before a scan that needs
    real write-verb probes, then should flip back off afterward -- but
    it's been left `true` on disk after validation runs repeatedly during
    this project's development. Auto-disarming it here, unconditionally
    after every `stof scan`/`stof test` run (success, failure, or crash,
    since this lives in the caller's `finally`), removes the need to
    remember the manual revert at all."""
    path = Path(config_path)
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return
    if raw.get("testing", {}).get("allow_state_changing_probes") is True:
        raw["testing"]["allow_state_changing_probes"] = False
        path.write_text(json.dumps(raw, indent=2) + "\n")


def _burp_seed_urls(endpoint_list, base_url: str) -> list[str]:
    """Filters Layer 7's discovered endpoints down to absolute http(s)
    URLs Burp can actually scan.

    The crawler's endpoint list can include non-HTTP hrefs it saw on a
    page (e.g. `javascript:checkSiteStatus('AltoroMutual')` from a real
    demo.testfire.net link) -- Burp's REST API validates its whole
    `urls` array and returns 400 ClientError for the entire request if
    even one entry isn't a real URL, so a single bad entry would
    otherwise silently kill the scan for every other endpoint too.
    Falls back to `base_url` alone if nothing valid was discovered."""
    seed_urls = sorted({e.url for e in endpoint_list if e.url.startswith(("http://", "https://"))})
    return seed_urls or [base_url]


def _burp_scope_prefix(base_url: str) -> str:
    """Burp's scope-include rule is matched against the real HTTP
    traffic it observes (e.g. `/rest/...`, `/api/...`), which never
    carries a client-side SPA route fragment (`#/...`). Using
    `base_url` verbatim as the scope prefix would silently exclude
    every real request for a hash-routed single-page app -- scoping to
    the bare origin instead is correct for any target, SPA or not."""
    parts = urlsplit(base_url)
    return f"{parts.scheme}://{parts.netloc}"


async def _run_burp_scan(pw, config, endpoint_list, evidence, click_echo=click.echo) -> list:
    """Runs a real Burp Suite Professional Active Scan against the
    target and returns normalized `Finding`s (`scanner_source="burp"`).
    Never raises out to the caller -- a Burp connectivity/API problem
    is reported and the rest of the scan (stof's own modules) proceeds
    regardless, matching this command's existing resilience pattern for
    recon and individual vuln modules.

    Seeds Burp with the URLs Layer 7's crawler already discovered
    instead of just the bare base_url, so Burp can audit known
    endpoints directly rather than blind-crawling the whole site from
    scratch -- the same endpoint map every other module here already
    reads from `endpoints.json`."""
    seed_urls = _burp_seed_urls(endpoint_list, config.target.base_url)
    click_echo(
        f"[BURP]  Starting Burp Suite Active Scan against {len(seed_urls)} known endpoint(s) "
        f"of {config.target.base_url} via {config.burp.api_url}..."
    )
    controller = None
    try:
        controller = await BurpController.create(
            pw, config.burp.api_url, config.burp.api_key,
            poll_interval_s=config.burp.poll_interval_s, timeout_s=config.burp.scan_timeout_s,
        )
        issues = await controller.run_active_scan(
            seed_urls, scope_prefixes=[_burp_scope_prefix(config.target.base_url)]
        )
        findings = normalize_burp_issues(issues)
        for f in findings:
            f.evidence_refs = await evidence.capture_raw(
                f.request_raw, f.response_raw, label=f"burp-{f.finding_id}"
            )
        click_echo(f"[BURP]  Active Scan complete: {len(findings)} issue(s) reported by Burp")
        return findings
    except (BurpApiError, TimeoutError, PlaywrightError) as exc:
        click_echo(f"[BURP]  scan failed or Burp was unreachable ({config.burp.api_url}): {exc}")
        return []
    finally:
        if controller is not None:
            await controller.close()


def _grow_shared_candidate_ids(shared_ids: list[str], new_findings: list[Finding], module_name: str, console, cap: int = 60) -> None:
    """Cross-module identifier sharing: an id-shaped value leaked in
    ANY module's own finding this scan (a PII-exposed account id from
    `disclosure_tests`, a leaked order id from an `idor_tests` response,
    ...) is fed into `shared_ids` -- the SAME mutable list every
    `IdorTestConfig(candidate_ids=...)` this scan holds a reference to
    -- so a module running LATER in `module_names` gets to try ids a
    module that ran EARLIER already proved are real, live object
    references on this target, not just this project's own generic
    `1`-`20` placeholder range. Reuses `idor_tests.py`'s own leaked-id
    extraction (`_extract_leaked_ids`) rather than duplicating its
    regex -- the exact same "2-10 digit run or UUID" shape already
    proven against real targets. Capped so an unusually chatty module
    can't grow the pool large enough to slow down every later module's
    own candidate-id probe loop."""
    from stof.modules._idor_shared import _extract_leaked_ids

    if len(shared_ids) >= cap or not new_findings:
        return
    texts = [f"{f.request_raw}\n{f.response_raw}" for f in new_findings]
    room = cap - len(shared_ids)
    newly_found = _extract_leaked_ids(texts, known=set(shared_ids), limit=room)
    shared_ids.extend(newly_found)
    if newly_found:
        console.info(f"{len(newly_found)} new object id candidate(s) discovered by {module_name}, now shared with the remaining modules this scan")


def _endpoints_from_discovered_routes(recon_report, base_url: str) -> list[Endpoint]:
    """Resolves `ReconReport.discovered_routes` (raw path strings mined
    from JS bundles, see `secrets_scanner.find_routes()`) against
    `base_url` into real `Endpoint`s the SAME scan's vuln modules can
    test -- a route string alone found this run but only written to a
    recon report file would sit unused until some future re-crawl
    happened to pick it up, if ever. Same-origin only, same rule every
    other discovered URL in this codebase follows (see `crawler.py`'s
    own `_same_origin` check) -- a route string is just a path, so it's
    always resolved against `base_url`'s own origin, never able to
    point anywhere else."""
    if recon_report is None or not recon_report.discovered_routes:
        return []
    endpoints = []
    for route in recon_report.discovered_routes:
        path = route.get("path")
        if not path:
            continue
        endpoints.append(Endpoint(url=urljoin(base_url, path), method="GET", endpoint_type="page"))
    return endpoints


def _severity_summary(all_findings: list[Finding]) -> tuple[dict[str, int], int]:
    """`(severity_counts, critical_high_likely)` for the end-of-scan
    console summary -- pulled out of `_run_test` itself purely to keep
    that function's own cyclomatic complexity from growing further; no
    behavior difference from the inline version."""
    severity_counts: dict[str, int] = {}
    critical_high_likely = 0
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        if f.severity in ("Critical", "High") and f.confidence == "likely":
            critical_high_likely += 1
    return severity_counts, critical_high_likely


def _findings_from_recon_secrets(recon_report) -> list[Finding]:
    """Recon (`stof/recon/secrets_scanner.py`) already scans every
    inline/external script and HTML comment for secret-shaped strings
    (API keys, JWTs, private-key blocks, generic token/secret
    assignments) -- confirmed live against a real target where this
    caught a hardcoded third-party API token in a shipped JS bundle.
    That detection used to dead-end as a console log line ("N
    secret(s)") and a raw JSON dump: never a `Finding`, so it never
    reached severity, OWASP/CWE classification, the HTML/Excel reports,
    or the dashboard's finding counts -- a confirmed real detection
    silently invisible everywhere a tester actually looks. One `Finding`
    per `SecretFinding`, `technique_id` deliberately left unset (this
    didn't come from a `TestCaseResult`/technique catalog entry) with
    `cwe`/`owasp_category` stamped directly rather than through
    `classify_finding_taxonomy()`, since "hardcoded credential exposed
    client-side" is unambiguous regardless of which page it came from."""
    if recon_report is None or not recon_report.secrets:
        return []
    findings = []
    for secret in recon_report.secrets:
        # `ReconReport.secrets` stores plain dicts (see
        # `recon_engine.run_recon`'s own `secret_findings.extend({...})`
        # call), not `secrets_scanner.SecretFinding` objects -- it's
        # already been through a dict round-trip once by the time it
        # gets here (also true after a JSON reload via
        # `write_recon_report`/`load_recon_report`).
        source_url = secret["source_url"]
        label = secret["label"]
        match_preview = secret["match_preview"]
        endpoint = Endpoint(url=source_url, method="GET", endpoint_type="api" if source_url.endswith(".js") else "page")
        findings.append(Finding(
            module_id="disclosure_tests",
            vuln_type=f"Hardcoded Secret Exposed Client-Side ({label})",
            severity="High",
            cvss_score=8.6,
            endpoint=endpoint,
            user_role="",
            request_raw=f"GET {source_url}",
            response_raw=f"matched pattern '{label}': {match_preview}",
            description=(
                f"A {label}-shaped secret was found in a client-accessible resource at "
                f"'{source_url}' ({match_preview}). Client-side JS/HTML is visible to "
                f"any visitor, so any real credential embedded there must be treated as public."
            ),
            recommendation=(
                "Revoke this credential if it is real and confirm whether it is still active. "
                "Never ship API keys/tokens/secrets in client-side JS, HTML, or source maps -- "
                "route the calls that need it through a server-side component and use a secrets-"
                "management solution to store it."
            ),
            cwe="CWE-798 - Use of Hard-coded Credentials",
            owasp_category="A02:2025 - Security Misconfiguration",
        ))
    return findings


def _coverage_funnel(endpoint_list, vuln_results, all_findings) -> dict[str, int]:
    """Discovered -> tested -> verified-exploitable, for the
    dashboard's coverage view. "Tested" comes from `vuln_results`
    (every `TestCaseResult` from every module, not just the FAILs
    `extract_findings()` keeps) -- it used to be discarded right after
    computing PASS/FAIL/SKIP counts (the `_vuln_results` underscore-
    prefix said as much), even though it's the only place that
    actually knows which endpoints a technique probed. Scoped to this
    project's own modules; Burp Active Scan's own endpoint coverage
    isn't tracked here, so it's never counted in."""
    tested_endpoint_urls = {r.endpoint.url for r in vuln_results if r.endpoint is not None}
    verified_exploitable_urls = {f.endpoint.url for f in all_findings if f.endpoint is not None}
    return {
        "endpoints_discovered": len(endpoint_list),
        "endpoints_tested": len(tested_endpoint_urls),
        "endpoints_verified_exploitable": len(verified_exploitable_urls),
    }


def _module_note(module_name: str, all_findings, jwt_roles: list[str] | None = None) -> dict:
    count = sum(1 for f in all_findings if f.module_id == module_name)
    note = None
    if count == 0 and module_name == "jwt_tests":
        note = _jwt_tests_note(jwt_roles or [])
    return {"module": module_name, "finding_count": count, "note": note}


async def _authenticated_session(session_manager, session_pool, role: str, target_url: str):
    """Same authentication as `_authenticated_context()` below, but
    returns the `Session` object itself rather than applying it to a
    context -- `WorkflowRunner.run_workflow()` needs the `Session`
    directly (it resolves `{{user.username}}`/`{{user.password}}`
    tokens from `session.user_id`, and applies it to a context itself
    via `PlaywrightEngine.replay()`), not a context already synced to
    one role's cookies."""
    context = await session_pool.get_context(role)
    page = await context.new_page()
    try:
        return await session_manager.get_session(role, page)
    finally:
        await page.close()


async def _authenticated_context(session_manager, session_pool, role: str, target_url: str):
    context = await session_pool.get_context(role)
    page = await context.new_page()
    try:
        session = await session_manager.get_session(role, page)
    finally:
        await page.close()
    return await session_pool.apply_session(session, target_url)


async def _replay_workflows(workflow_ids: list[str], users_by_role: dict, users_config, session_manager, session_pool, console: ScanConsole) -> None:
    """A "REPLAYING RECORDED WORKFLOWS" phase, run once, early -- before
    vulnerability testing starts -- for every workflow id passed via
    `--workflow`. Real, working use of `WorkflowRunner` (Layer 6),
    which previously existed fully built (recording, storage,
    token-resolved replay via `PlaywrightEngine`) but was never called
    from anywhere in the scan pipeline: a recorded checkout flow, signup
    wizard, or any other multi-step journey the crawler's own link-
    following can't reach on its own is exercised here, extending what
    the rest of the scan can discover and test past whatever the
    crawler found by itself.

    Deliberately scoped to "replay it, log what happened" for this
    first wiring -- not yet: merging newly-reached pages back into the
    crawler's endpoint list, or feeding workflow state into any
    vulnerability module's own detection logic (e.g. business-logic
    abuse testing mid-flow). Both are real, valuable follow-ups; this
    phase's own log output already reports exactly what it did and
    didn't do, so that boundary is visible, not silently assumed.

    Which role a workflow replays as isn't yet configurable per
    workflow from the UI/CLI -- same "admin if present, else whichever
    role is first" heuristic `recon_role` already uses elsewhere in
    this function, logged explicitly so it's never a silent guess."""
    console.phase("REPLAYING RECORDED WORKFLOWS")
    replay_role = "admin" if "admin" in users_by_role else next(iter(users_by_role), None)
    if replay_role is None:
        console.info("Skipped -- no configured user to authenticate the replay with")
        return

    repository = WorkflowRepository()
    engine = PlaywrightEngine(session_pool)
    runner = WorkflowRunner(repository, engine, users_config)

    for workflow_id in workflow_ids:
        try:
            session = await _authenticated_session(session_manager, session_pool, replay_role, "")
            result = await runner.run_workflow(workflow_id, session)
        except Exception as exc:
            console.info(f"'{workflow_id}' (as role '{replay_role}'): could not replay -- {exc}")
            continue
        console.workflow_replayed(
            workflow_id, replay_role, result.success,
            result.completed_actions, result.total_actions, result.final_url, error=result.error,
        )


def _resolve_crawl_roles(role_override: str | None, users_by_role: dict, users_path: str) -> list[str]:
    """Which role(s) `_run_crawl()` should authenticate and crawl as.

    An explicit `--role` always crawls as exactly that one role --
    unchanged from before. With no override, crawl as *every*
    configured role and merge the results (see `_run_crawl`'s loop): a
    low-priv role's crawl can otherwise never surface an admin-only
    endpoint (or vice versa) since each crawl used to simply overwrite
    `endpoints.json`. A target with only one configured role naturally
    keeps today's single-crawl behavior either way -- there's nothing
    to merge. Pure and side-effect-free (raises `click.ClickException`
    on bad input, same as the rest of this file's validation) so it's
    unit-testable without a browser."""
    if role_override is not None:
        if role_override not in users_by_role:
            raise click.ClickException(f"role '{role_override}' is not configured in '{users_path}'")
        return [role_override]

    crawl_roles = list(users_by_role.keys())
    if not crawl_roles:
        raise click.ClickException("no configured user to authenticate the crawl with")
    return crawl_roles


async def _crawl_all_roles(
    session_manager, session_pool, crawl_roles: list[str], crawler_config: CrawlerConfig,
    target_url: str, echo,
) -> list:
    """Crawls as each role in `crawl_roles` in turn and merges the
    results (see `endpoint_store.merge()`), logging a per-role progress
    line only when there's more than one role -- a single-role crawl's
    output stays identical to before Wave 1b. Split out of `_run_crawl`
    so the role-fan-out loop itself (the actual Wave 1b behavior change)
    is isolated from that function's already-substantial setup code."""
    endpoints: list = []
    for crawl_role in crawl_roles:
        context = await _authenticated_context(session_manager, session_pool, crawl_role, target_url)
        role_endpoints = await _with_retry(
            lambda context=context: run_crawler(target_url, context, crawler_config)
        )
        endpoints = merge_endpoints(endpoints, role_endpoints)
        if len(crawl_roles) > 1:
            echo(
                f"[CRAWL] role '{crawl_role}': {len(role_endpoints)} endpoint(s) found, "
                f"{len(endpoints)} total after merge"
            )
    return endpoints


async def _run_crawl(
    config_path: str,
    users_path: str,
    role_override: str | None,
    output_path: str,
    max_depth: int,
    max_pages: int,
    headless_override: bool | None,
    console: ScanConsole | None = None,
) -> int:
    echo = console.echo if console is not None else click.echo
    load_dotenv()
    config = load_config(config_path)
    rate_limiter.configure_from_intensity(config.testing.scan_intensity)
    users = load_users(users_path)
    users_by_role = {u.role: u for u in users.users}

    crawl_roles = _resolve_crawl_roles(role_override, users_by_role, users_path)

    login_provider = _build_login_provider(config)
    jwt_provider = JWTAuthProvider(token_url=config.target.jwt_token_url)
    session_store = SessionStore(db_path=Path("data") / "stof.db")
    session_manager = SessionManager(
        users=users_by_role,
        providers={"form_login": login_provider, "jwt": jwt_provider},
        store=session_store,
    )

    headless = config.browser.headless if headless_override is None else headless_override

    echo(f"[CRAWL] Crawling {config.target.base_url} as role(s) {', '.join(crawl_roles)}...")
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless, slow_mo=config.browser.slowmo_ms or None)
        session_pool = SessionPool(browser, ignore_https_errors=True)
        await _attach_assisted_login_contexts(pw, config, session_pool, session_manager, login_provider, users_by_role, echo)
        try:
            # One shared PassiveEngine across every role's crawl in this
            # run -- it only accumulates observations from traffic the
            # crawl(s) already made, so feeding it multiple roles' traffic
            # is exactly "more observations", not a correctness concern.
            passive_engine = PassiveEngine()
            crawler_config = CrawlerConfig(
                max_depth=max_depth, max_pages=max_pages,
                exclude_path_patterns=tuple(config.target.crawler_exclude_patterns or ()),
                passive_engine=passive_engine,
            )
            endpoints = await _crawl_all_roles(
                session_manager, session_pool, crawl_roles, crawler_config, config.target.base_url, echo
            )
            anon_context = await session_pool.new_anonymous_context()
            try:
                await verify_auth_required(endpoints, anon_context)
            finally:
                await anon_context.close()
        finally:
            await session_pool.shutdown()

    write_endpoints(endpoints, path=output_path)
    forms = sum(1 for e in endpoints if e.endpoint_type == "form")
    apis = sum(1 for e in endpoints if e.endpoint_type == "api")
    pages = sum(1 for e in endpoints if e.endpoint_type == "page")
    echo(
        f"[CRAWL] Discovered {len(endpoints)} endpoint(s) ({forms} forms, {apis} API, {pages} pages) -> {output_path}"
    )
    if console is not None:
        console.crawl_summary(len(endpoints), forms, apis, pages)

    # Passive observations: derived entirely from traffic the crawl
    # above already made -- no additional request. A separate file, not
    # merged into endpoints.json, since an Observation is a candidate
    # for an existing testcase family (TC-017/053/054/056/057/027), not
    # an Endpoint or a Finding -- existing consumers of endpoints.json
    # are unaffected either way.
    passive_path = str(Path(output_path).parent / "passive_observations.json")
    Path(passive_path).write_text(
        json.dumps([o.to_dict() for o in passive_engine.observations], indent=2), encoding="utf-8"
    )
    if passive_engine.observations:
        summary = ", ".join(f"{count} {kind}" for kind, count in sorted(passive_engine.summary().items()))
        echo(f"[PASSIVE] {len(passive_engine.observations)} observation(s) ({summary}) -> {passive_path}")
    return 0


async def _run_scan(
    config_path: str,
    users_path: str,
    role: str | None,
    endpoints_path: str,
    max_depth: int,
    max_pages: int,
    module_names: list[str] | None,
    output: str | None,
    headless: bool | None,
    recrawl: bool,
    log_dir: str | Path = DEFAULT_LOG_DIR,
    scan_id: str | None = None,
    workflow_ids: list[str] | None = None,
) -> int:
    """`_run_crawl()` then `_run_test()`, back to back -- two separate
    browser launches (crawl's, then test's own), not one shared
    session. Simpler and lower-risk than merging their lifecycles, and
    matches how a human would run the two existing commands by hand.

    Owns one `ScanConsole` (one scan id, one log file) spanning both
    phases -- `_run_test()` is told to borrow it rather than create
    its own, so the crawl phase's output and the test phase's output
    land in the same `<log_dir>/scan_<id>.log`, not two.

    `module_names` is `None` when `--module` wasn't passed -- resolved
    here (not left for `_run_test()` to resolve again) since the
    resolved list is needed for the banner before `_run_test()` runs.

    `scan_id` is normally auto-generated (a caller can't know it ahead
    of time); an external caller that needs to correlate this process
    with its own tracking record before the log/report files exist
    (stof/ui's backend) can pass one in instead."""
    scan_id = scan_id or uuid.uuid4().hex[:8]
    load_dotenv()
    config = load_config(config_path)
    rate_limiter.configure_from_intensity(config.testing.scan_intensity)
    module_names = _resolve_module_names(module_names, config)
    console = ScanConsole(scan_id, log_dir=log_dir)
    file_handler = attach_file_logging(console.log_path)
    try:
        console.banner(scan_id, config.target.base_url, module_names)

        if recrawl or not Path(endpoints_path).is_file():
            console.phase("CRAWL & ENDPOINT DISCOVERY")
            crawl_exit = await _run_crawl(config_path, users_path, role, endpoints_path, max_depth, max_pages, headless, console=console)
            if crawl_exit != 0:
                return crawl_exit
        else:
            console.phase("CRAWL & ENDPOINT DISCOVERY")
            console.info(f"Skipped -- reusing existing '{endpoints_path}' (pass --recrawl to force a fresh crawl)")

        return await _run_test(module_names, endpoints_path, config_path, users_path, output, headless, scan_id=scan_id, console=console, workflow_ids=workflow_ids)
    finally:
        detach_file_logging(file_handler)
        console.close()


async def _run_test(
    module_names: list[str] | None,
    endpoints_path: str,
    config_path: str,
    users_path: str,
    output_override: str | None,
    headless_override: bool | None,
    scan_id: str | None = None,
    console: ScanConsole | None = None,
    log_dir: str | Path = DEFAULT_LOG_DIR,
    workflow_ids: list[str] | None = None,
) -> int:
    """Owns its `ScanConsole` (creates the scan id, prints the banner,
    attaches file logging, closes everything at the end) when called
    standalone as `stof test`. When called from `_run_scan()`, both
    `scan_id` and `console` are already provided -- borrowed, not
    owned, so this function must not print a second banner or detach
    the file handler out from under the crawl phase that logged to it
    first. `log_dir` is only consulted when this function creates its
    own console (tests redirect it away from the real `data/logs/`).

    `module_names` may already be resolved (passed in by `_run_scan()`)
    or `None`/raw (standalone `stof test`) -- `_resolve_module_names()`
    is a no-op on an already-resolved list, so calling it
    unconditionally here is safe either way."""
    owns_console = console is None
    if scan_id is None:
        scan_id = uuid.uuid4().hex[:8]
    started_at = time.monotonic()

    load_dotenv()
    config = load_config(config_path)
    module_names = _resolve_module_names(module_names, config)
    # As early as possible -- before the crawler or any module makes its
    # first real request -- so `config.testing.scan_intensity` governs
    # this ENTIRE run. See `stof.core.rate_limiter`'s own docstring for
    # why this exists.
    rate_limiter.configure_from_intensity(config.testing.scan_intensity)

    if owns_console:
        console = ScanConsole(scan_id, log_dir=log_dir)
    file_handler = attach_file_logging(console.log_path) if owns_console else None
    try:
        if owns_console:
            console.banner(scan_id, config.target.base_url, module_names)
        users = load_users(users_path)
        users_by_role = {u.role: u for u in users.users}

        endpoint_list = load_endpoints(endpoints_path)
        if not endpoint_list:
            raise click.ClickException(
                f"No endpoints found at '{endpoints_path}' -- run the crawler first (`stof crawl`)."
            )

        jwt_roles = _jwt_roles(users_by_role)

        login_provider = _build_login_provider(config)
        jwt_provider = JWTAuthProvider(token_url=config.target.jwt_token_url)
        session_store = SessionStore(db_path=Path("data") / "stof.db")
        session_manager = SessionManager(
            users=users_by_role,
            providers={"form_login": login_provider, "jwt": jwt_provider},
            store=session_store,
        )
        # As early as possible, same rationale as the rate limiter's own
        # `configure()` call above -- every state-changing technique
        # calls `self._register_cleanup(...)` (see `stof/cleanup/
        # registry.py`) the moment it performs a real write, so the
        # registry must be configured before any module runs.
        cleanup_registry.configure(scan_id=scan_id, db_path=Path("data") / "stof.db")

        headless = config.browser.headless if headless_override is None else headless_override

        all_findings = []
        recon_report = None
        walkthroughs: list = []
        module_rows: list[tuple[str, dict[str, int]]] = []
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=headless, slow_mo=config.browser.slowmo_ms or None)
            session_pool = SessionPool(browser, ignore_https_errors=True)
            await _attach_assisted_login_contexts(pw, config, session_pool, session_manager, login_provider, users_by_role, console.echo)
            evidence = EvidenceCollector(scan_id=scan_id, base_dir=Path(config.output.evidence_dir))

            try:
                console.phase("RECONNAISSANCE & ENDPOINT CONTEXT")
                recon_role = "admin" if "admin" in users_by_role else next(iter(users_by_role), None)
                if recon_role is None:
                    console.info("Recon skipped -- no configured user to authenticate recon with")
                else:
                    console.info("Running reconnaissance (tech stack, headers, exposed paths, secrets, parameters)...")
                    try:
                        recon_context = await _authenticated_context(session_manager, session_pool, recon_role, config.target.base_url)
                        recon_report = await _with_retry(
                            lambda: run_recon(endpoint_list, recon_context, config.target.base_url)
                        )
                        # Scan-id-stamped copy is the durable record (never
                        # overwritten by a later scan, matching how reports/
                        # logs are already namespaced); the flat path is kept
                        # too as a "most recent scan" convenience pointer.
                        write_recon_report(recon_report, path=Path("data") / "recon" / f"scan_{scan_id}.json")
                        write_recon_report(recon_report, path=Path("data") / "recon_results.json")
                        console.info(
                            f"{recon_report.pages_analyzed} page(s) analyzed, "
                            f"{len(recon_report.missing_security_headers)} with missing security headers, "
                            f"{len(recon_report.exposed_paths)} exposed path(s), {len(recon_report.secrets)} secret(s)"
                        )
                        new_route_endpoints = _endpoints_from_discovered_routes(recon_report, config.target.base_url)
                        if new_route_endpoints:
                            before_count = len(endpoint_list)
                            endpoint_list = merge_endpoints(endpoint_list, new_route_endpoints)
                            write_endpoints(endpoint_list, path=endpoints_path)
                            console.info(
                                f"{len(endpoint_list) - before_count} new endpoint(s) queued from route "
                                f"strings mined out of JS bundles -- testing this scan, same as any other "
                                f"discovered endpoint"
                            )
                    except KeyError as exc:
                        console.info(f"Recon skipped: {exc}")

                # Context-aware testing, Phase 1 (see stof/recon/target_profile.py's
                # own docstring for the full reasoning): classify the target's
                # stack family from whatever recon just found, THEN build the
                # module instances -- module_builders has to come after recon
                # completes so configuration_tests.py's candidate-path narrowing
                # sees the real profile, not the "unknown" default. Nothing
                # between the old build-then-recon ordering and this one
                # actually depended on module_builders existing earlier.
                target_profile = build_target_profile(recon_report)
                if target_profile.stack_family != "unknown":
                    console.info(f"Target stack profile: '{target_profile.stack_family}' (confidence: {target_profile.confidence})")
                # Grown in place as each module's own findings surface new
                # id-shaped values -- see `_run_all_vuln_modules()`'s own
                # comment right before its `module_findings.extend(...)` line.
                shared_candidate_ids = list(config.target.idor_candidate_ids or _GENERIC_IDOR_CANDIDATE_IDS)
                module_builders = _build_module_builders(config, jwt_roles, users_by_role, target_profile, shared_candidate_ids)

                if workflow_ids:
                    await _replay_workflows(workflow_ids, users_by_role, users, session_manager, session_pool, console)

                module_names, profile_skips = _apply_application_profile(module_names, endpoint_list, jwt_roles)
                role_auth = {role: user.auth_type for role, user in users_by_role.items()}
                has_graphql = any("graphql" in e.url.lower() for e in endpoint_list)
                console.application_profile(role_auth, has_graphql, profile_skips)

                console.phase("VULNERABILITY TESTING")

                async def _run_all_vuln_modules() -> tuple[list, list]:
                    nonlocal browser, session_pool
                    module_findings: list = []
                    all_results: list = []
                    total_modules = len(module_names)
                    for i, name in enumerate(module_names):
                        console.progress_bar(i, total_modules, f"running {name}...")
                        vuln_module = module_builders[name]()
                        if hasattr(vuln_module, "target_url"):
                            vuln_module.target_url = config.target.base_url
                        try:
                            # A real, reproducible bug found live (confirmed
                            # via /proc CPU-tick sampling across the whole
                            # Python/Node-driver/Chrome process tree showing
                            # near-zero activity for 13+ minutes straight,
                            # not just "slow"): one module hanging used to
                            # take the entire scan down with it, forcing a
                            # manual kill every time. `base.py`'s per-
                            # TECHNIQUE isolation (`_safe_result`) already
                            # existed for exactly this failure class one
                            # level down -- this closes the same gap one
                            # level up, per module. 8 minutes is generous
                            # even for the slowest known legitimate case
                            # (ssrf_tests' TC-137.2 connect-timeout oracle,
                            # which deliberately waits out real TCP
                            # timeouts twice per candidate parameter).
                            results = await asyncio.wait_for(
                                _with_retry(
                                    # Deliberately reads session_pool live, not
                                    # a value frozen at lambda-definition time --
                                    # value frozen at lambda-definition time --
                                    # a prior iteration may have just replaced
                                    # it (browser restart after a dead-driver
                                    # detection, below), and this module's own
                                    # call needs the live one, not the dead one.
                                    lambda vm=vuln_module: vm.run_techniques(endpoint_list, session_manager, session_pool, evidence=evidence)  # noqa: B023
                                ),
                                timeout=480,
                            )
                        except TimeoutError:
                            click.echo(f"[STOF]  ⚠ {name} did not finish within 8 minutes -- skipping it and moving on, rest of the scan is unaffected")
                            results = [TestCaseResult(
                                test_id=name, technique_id=f"{name}.timeout", technique="module timed out",
                                vuln_type="N/A", module_id=name, severity="Info", status=ERROR,
                                detail="This module did not complete within the 8-minute per-module ceiling and was skipped so the rest of the scan could continue. Investigate separately (re-run with just --module " + name + ").",
                            )]
                        if _module_hit_dead_driver(results):
                            # The browser process/CDP connection itself died --
                            # every technique in this module (and, left alone,
                            # every module after it) would keep failing the
                            # same way against the same dead browser. Restart
                            # it once here so the REMAINING modules in this
                            # scan get a real, working browser instead of a
                            # wall of identical "connection closed" ERROR
                            # results -- this module's own results are kept
                            # as-is (an honest ERROR, not silently retried and
                            # hidden), only the browser is recovered for what
                            # comes next.
                            click.echo(f"[STOF]  ⚠ browser driver appears to have died during {name} -- restarting the browser for the remaining modules")
                            try:
                                await browser.close()
                            except Exception as exc:
                                click.echo(f"[STOF]  (old browser was already unusable: {exc})")
                            try:
                                browser = await pw.chromium.launch(headless=headless, slow_mo=config.browser.slowmo_ms or None)
                                session_pool = SessionPool(browser, ignore_https_errors=True)
                                click.echo("[STOF]  ✓ browser restarted, continuing scan")
                            except Exception as exc:
                                click.echo(f"[STOF]  ✗ could not restart the browser ({exc}) -- remaining modules will likely fail the same way")
                        console.progress_bar(i + 1, total_modules, f"{name} complete")
                        console.module_header(name, len(results))
                        for result in results:
                            console.test_result(result)
                        console.not_automated_note(results)
                        counts = summarize(results)
                        console.module_summary(name, counts)
                        module_rows.append((name, counts))
                        all_results.extend(results)
                        new_findings = extract_findings(results)
                        module_findings.extend(new_findings)
                        # See `_grow_shared_candidate_ids`'s own docstring --
                        # this module's OWN findings may have just leaked an
                        # id-shaped value a LATER module in `module_names`
                        # can now try, without waiting for a future re-scan.
                        _grow_shared_candidate_ids(shared_candidate_ids, new_findings, name, console)
                    return module_findings, all_results

                # Burp's Active Scan is independent of stof's own modules and
                # can run for a long time -- run both concurrently (CLAUDE.md
                # rule 5: "Use asyncio.gather() for parallelism in the
                # orchestrator") rather than blocking the fast IDOR/JWT tests
                # behind it. Gated on run_active_scan specifically, NOT just
                # `enabled` -- see BurpConfig's docstring for the real bug
                # this split fixes: a single shared flag used to silently
                # turn every scan (even a one-module sanity check) into a
                # wait on Burp's own 30-minute crawl+audit, which was never
                # what "capture evidence via Burp" was supposed to mean.
                if config.burp.enabled and config.burp.run_active_scan:
                    (vuln_findings, vuln_results), burp_findings = await asyncio.gather(
                        _run_all_vuln_modules(), _run_burp_scan(pw, config, endpoint_list, evidence)
                    )
                else:
                    vuln_findings, vuln_results = await _run_all_vuln_modules()
                    burp_findings = []

                all_findings.extend(vuln_findings)
                all_findings.extend(burp_findings)
                all_findings.extend(_findings_from_recon_secrets(recon_report))

                # Distinct from the Active Scan above (gated on
                # run_active_scan): this only sends each already-confirmed
                # finding's representative request through Burp's PROXY to
                # capture a real request/response into the finding itself --
                # exactly what was actually asked for, independent of
                # whether Burp's own scanner runs at all. Never raises out
                # of this block if Burp isn't reachable.
                if config.burp.enabled and all_findings:
                    console.phase("CAPTURING EVIDENCE VIA BURP")
                    console.info(f"Sending {len(all_findings)} confirmed finding(s) through Burp's proxy at {config.burp.proxy_url}...")
                    enriched = await capture_findings_via_burp(pw, config.burp.proxy_url, all_findings, session_manager=session_manager, click_echo=click.echo)
                    console.info(f"Burp capture enriched {enriched}/{len(all_findings)} finding(s) with real request/response evidence")

                if config.output.generate_walkthrough and all_findings:
                    console.phase("BUILDING WALKTHROUGH REPORT")
                    console.info(f"Replaying {len(all_findings)} confirmed finding(s) with a real browser to capture step-by-step evidence...")

                    def _walkthrough_progress(done: int, total: int, label: str) -> None:
                        console.progress_bar(done, total, label)

                    walkthroughs = await build_walkthroughs(
                        all_findings, session_manager, session_pool, scan_id,
                        screenshot_base_dir=config.output.evidence_dir,
                        progress=_walkthrough_progress,
                        login_url=config.target.login_url,
                        username_selector=config.target.username_selector,
                        password_selector=config.target.password_selector,
                        submit_selector=config.target.submit_selector,
                        users_by_role=users_by_role,
                    )
                    error_count = sum(1 for w in walkthroughs if w.build_error)
                    console.info(f"Walkthrough report built for {len(walkthroughs)} finding(s) ({error_count} with a build error)")
            finally:
                await session_pool.shutdown()

        duration = round(time.monotonic() - started_at, 1)
        # Same "scan-id-stamped is durable, flat path is a convenience
        # pointer" pattern as the recon report above -- this file used to
        # be the ONLY copy, so every new scan silently erased the
        # previous scan's raw findings even though its HTML/JSON/Excel
        # reports (already scan-id-namespaced) survived untouched.
        write_findings(all_findings, path=Path("data") / "findings" / f"scan_{scan_id}.json")
        write_findings(all_findings, path=Path("data") / "findings.json")
        # SQLite mirror, same `data/stof.db` every other store already
        # uses -- this is the cross-scan lookup baseline/diff mode reads
        # from below (`FindingDB.load_scan()`); it previously had no
        # writer wired in anywhere (see its own docstring).
        finding_db = FindingDB(db_path=Path("data") / "stof.db")
        finding_db.save(scan_id, all_findings)

        if module_rows:
            console.summary_table(module_rows)

        module_notes = [_module_note(name, all_findings, jwt_roles=jwt_roles) for name in module_names]
        modules_run = list(module_names)
        if config.burp.enabled and config.burp.run_active_scan:
            modules_run.append("burp_active_scan")
            module_notes.append(_module_note("burp_active_scan", all_findings))

        coverage = _coverage_funnel(endpoint_list, vuln_results, all_findings)

        reports_dir = output_override or config.output.reports_dir
        # Looked up BEFORE this scan's own report is written below --
        # `find_baseline_scan_id` reads existing `scan_*.json` report
        # files under `reports_dir`, so this scan's own (not yet
        # written) report can never accidentally match itself.
        baseline_scan_id = find_baseline_scan_id(config.target.base_url, scan_id, reports_dir=reports_dir)
        baseline_findings = finding_db.load_scan(baseline_scan_id) if baseline_scan_id else []
        baseline_diff = compute_diff(baseline_findings, all_findings, baseline_scan_id)

        scan_metadata = {
            "scan_id": scan_id,
            "target": config.target.base_url,
            "modules_run": modules_run,
            "module_notes": module_notes,
            "duration_seconds": duration,
            "coverage": coverage,
            "skipped_techniques": skipped_techniques(vuln_results),
            "cleanup": cleanup_registry.summary_for_current_scan(),
            "baseline_diff": baseline_diff.to_dict(),
        }
        report_paths = generate_reports(
            all_findings, scan_metadata, output_dir=reports_dir,
            recon_report=recon_report.to_dict() if recon_report is not None else None,
            walkthroughs=walkthroughs,
        )

        severity_counts, critical_high_likely = _severity_summary(all_findings)
        console.findings_by_severity(severity_counts, critical_high_likely=critical_high_likely)
        console.reports(
            str(report_paths.html), str(report_paths.json), str(report_paths.excel),
            walkthrough=str(report_paths.walkthrough) if report_paths.walkthrough else None,
        )
        console.footer(duration)

        return 0
    finally:
        _revert_state_changing_probes_flag(config_path)
        if owns_console:
            detach_file_logging(file_handler)
            console.close()


if __name__ == "__main__":
    cli()
