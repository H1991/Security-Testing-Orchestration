"""Unit tests for stof/main.py's `stof test` command.

Only the pure/validation parts are exercised here (unknown module
rejection, missing-endpoints error) -- the full authenticated-scan path
needs a real browser and a real target, covered instead by
`tests/integration/test_idor_tests_demo.py`.
"""
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import click
import pytest
from click.testing import CliRunner

from stof.config.schema import Config, TargetConfig
from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding
from stof.main import (
    _KNOWN_MODULES,
    _apply_application_profile,
    _attach_assisted_login_contexts,
    _build_form_login_provider,
    _build_login_provider,
    _build_module_builders,
    _burp_scope_prefix,
    _burp_seed_urls,
    _coverage_funnel,
    _endpoints_from_discovered_routes,
    _findings_from_recon_secrets,
    _grow_shared_candidate_ids,
    _looks_like_driver_dead,
    _module_hit_dead_driver,
    _module_note,
    _replay_workflows,
    _resolve_crawl_roles,
    _resolve_module_names,
    _revert_state_changing_probes_flag,
    _run_scan,
    cli,
)


def _write_config(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "target": {"base_url": "https://x", "login_url": "https://x/login"},
        "browser": {"headless": True, "slowmo_ms": 0, "proxy": None},
        "modules": {"crawler": True, "jwt_tests": False, "auth_tests": False, "idor_tests": True, "oauth_tests": False, "csrf_tests": False},
        "output": {"reports_dir": str(tmp_path / "reports"), "evidence_dir": str(tmp_path / "evidence")},
    }))
    users_path = tmp_path / "users.json"
    users_path.write_text(json.dumps({"users": [
        {"id": "admin-01", "role": "admin", "username": "admin", "password": "pw", "auth_type": "form_login"},
    ]}))
    return config_path, users_path


def test_test_command_rejects_unknown_module(tmp_path):
    config_path, users_path = _write_config(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, [
        "test", "--module", "not_a_real_module",
        "--config", str(config_path), "--users", str(users_path),
        "--endpoints", str(tmp_path / "endpoints.json"),
    ])

    assert result.exit_code != 0
    assert "Unknown module" in result.output


def test_test_command_errors_when_no_endpoints_found(tmp_path):
    config_path, users_path = _write_config(tmp_path)
    (tmp_path / "endpoints.json").write_text("[]")
    runner = CliRunner()

    result = runner.invoke(cli, [
        "test", "--module", "idor_tests",
        "--config", str(config_path), "--users", str(users_path),
        "--endpoints", str(tmp_path / "endpoints.json"),
    ])

    assert result.exit_code != 0
    assert "No endpoints found" in result.output


def test_cli_group_has_test_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "test" in result.output


# ---------------------------------------------------------------------------
# scan — the one-command crawl + every-implemented-module pipeline
# ---------------------------------------------------------------------------


def test_scan_command_rejects_unknown_module(tmp_path):
    config_path, users_path = _write_config(tmp_path)
    runner = CliRunner()

    with patch("stof.main._ensure_dependencies_installed"):
        result = runner.invoke(cli, [
            "scan", "--module", "not_a_real_module",
            "--config", str(config_path), "--users", str(users_path),
        ])

    assert result.exit_code != 0
    assert "Unknown module" in result.output


def test_cli_group_has_scan_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output


def test_scan_help_lists_every_implemented_module_as_the_default():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    for module_name in ("idor_tests", "jwt_tests", "auth_tests", "disclosure_tests", "graphql_tests", "deserialization_tests"):
        assert module_name in result.output


# ---------------------------------------------------------------------------
# _resolve_module_names -- config.json's "modules" block is the real
# default when --module isn't passed, not a second hardcoded list that
# ignored it (the bug where toggling "idor_tests": false in config.json
# used to silently do nothing).
# ---------------------------------------------------------------------------


def _config_with_modules(modules_kwargs: dict) -> Config:
    from stof.config.schema import ModulesConfig

    return Config(
        target=TargetConfig(base_url="https://x", login_url="https://x/login"),
        modules=ModulesConfig(**modules_kwargs),
        output={"reports_dir": "reports", "evidence_dir": "evidence"},
    )


def test_resolve_module_names_explicit_wins_over_config():
    config = _config_with_modules({"idor_tests": True})

    resolved = _resolve_module_names(["jwt_tests"], config)

    assert resolved == ["jwt_tests"]


def test_resolve_module_names_explicit_rejects_unknown_module():
    config = _config_with_modules({"idor_tests": True})

    with pytest.raises(Exception, match="Unknown module"):
        _resolve_module_names(["not_a_real_module"], config)


def test_resolve_module_names_defaults_to_configs_enabled_modules_in_execution_order():
    config = _config_with_modules({"idor_tests": True, "configuration_tests": True, "jwt_tests": True})

    resolved = _resolve_module_names(None, config)

    assert resolved == ["jwt_tests", "idor_tests", "configuration_tests"]


def test_resolve_module_names_errors_clearly_when_nothing_is_enabled():
    config = _config_with_modules({})

    with pytest.raises(Exception, match="No vulnerability modules are enabled"):
        _resolve_module_names(None, config)


# ---------------------------------------------------------------------------
# _apply_application_profile -- post-crawl "does this module's required
# surface actually exist" filter, on top of whatever was already selected.
# ---------------------------------------------------------------------------


def test_apply_application_profile_drops_jwt_tests_when_no_jwt_role_configured():
    filtered, skips = _apply_application_profile(["idor_tests", "jwt_tests"], [], jwt_roles=[])

    assert filtered == ["idor_tests"]
    assert len(skips) == 1
    assert "jwt_tests" in skips[0]


def test_apply_application_profile_keeps_jwt_tests_when_a_jwt_role_is_configured():
    filtered, skips = _apply_application_profile(["jwt_tests"], [], jwt_roles=["normal"])

    assert filtered == ["jwt_tests"]
    assert skips == []


def test_apply_application_profile_drops_graphql_tests_when_no_graphql_endpoint_found():
    endpoints = [Endpoint(url="https://x/rest/users", method="GET", endpoint_type="api")]

    filtered, skips = _apply_application_profile(["idor_tests", "graphql_tests"], endpoints, jwt_roles=[])

    assert filtered == ["idor_tests"]
    assert len(skips) == 1
    assert "graphql_tests" in skips[0]


def test_apply_application_profile_keeps_graphql_tests_when_a_graphql_endpoint_exists():
    endpoints = [Endpoint(url="https://x/graphql", method="POST", endpoint_type="api")]

    filtered, skips = _apply_application_profile(["graphql_tests"], endpoints, jwt_roles=[])

    assert filtered == ["graphql_tests"]
    assert skips == []


def test_apply_application_profile_never_touches_other_modules():
    filtered, skips = _apply_application_profile(
        ["idor_tests", "auth_tests", "configuration_tests", "disclosure_tests", "deserialization_tests"],
        [], jwt_roles=[],
    )

    assert filtered == ["idor_tests", "auth_tests", "configuration_tests", "disclosure_tests", "deserialization_tests"]
    assert skips == []


@pytest.mark.asyncio
async def test_run_scan_crawls_then_tests_when_no_endpoints_file_exists(tmp_path):
    config_path, users_path = _write_config(tmp_path)
    endpoints_path = tmp_path / "endpoints.json"  # doesn't exist
    with patch("stof.main._run_crawl", new=AsyncMock(return_value=0)) as mock_crawl, \
         patch("stof.main._run_test", new=AsyncMock(return_value=0)) as mock_test:
        exit_code = await _run_scan(str(config_path), str(users_path), None, str(endpoints_path), 3, 100, ["idor_tests"], None, None, recrawl=False, log_dir=str(tmp_path / "logs"))

    assert exit_code == 0
    mock_crawl.assert_awaited_once()  # ran despite recrawl=False, because the file simply doesn't exist yet
    mock_test.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_scan_skips_crawl_when_endpoints_exist_and_recrawl_false(tmp_path):
    config_path, users_path = _write_config(tmp_path)
    endpoints_path = tmp_path / "endpoints.json"
    endpoints_path.write_text("[]")
    with patch("stof.main._run_crawl", new=AsyncMock(return_value=0)) as mock_crawl, \
         patch("stof.main._run_test", new=AsyncMock(return_value=0)) as mock_test:
        exit_code = await _run_scan(str(config_path), str(users_path), None, str(endpoints_path), 3, 100, ["idor_tests"], None, None, recrawl=False, log_dir=str(tmp_path / "logs"))

    assert exit_code == 0
    mock_crawl.assert_not_awaited()
    mock_test.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_scan_recrawls_even_if_endpoints_file_already_exists(tmp_path):
    config_path, users_path = _write_config(tmp_path)
    endpoints_path = tmp_path / "endpoints.json"
    endpoints_path.write_text("[]")
    with patch("stof.main._run_crawl", new=AsyncMock(return_value=0)) as mock_crawl, \
         patch("stof.main._run_test", new=AsyncMock(return_value=0)) as mock_test:
        await _run_scan(str(config_path), str(users_path), None, str(endpoints_path), 3, 100, ["idor_tests"], None, None, recrawl=True, log_dir=str(tmp_path / "logs"))

    mock_crawl.assert_awaited_once()
    mock_test.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_scan_stops_and_does_not_test_when_crawl_fails(tmp_path):
    config_path, users_path = _write_config(tmp_path)
    endpoints_path = tmp_path / "endpoints.json"
    with patch("stof.main._run_crawl", new=AsyncMock(return_value=1)), \
         patch("stof.main._run_test", new=AsyncMock(return_value=0)) as mock_test:
        exit_code = await _run_scan(str(config_path), str(users_path), None, str(endpoints_path), 3, 100, ["idor_tests"], None, None, recrawl=True, log_dir=str(tmp_path / "logs"))

    assert exit_code == 1
    mock_test.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_scan_writes_a_log_file(tmp_path):
    config_path, users_path = _write_config(tmp_path)
    endpoints_path = tmp_path / "endpoints.json"
    log_dir = tmp_path / "logs"
    with patch("stof.main._run_crawl", new=AsyncMock(return_value=0)), \
         patch("stof.main._run_test", new=AsyncMock(return_value=0)):
        await _run_scan(str(config_path), str(users_path), None, str(endpoints_path), 3, 100, ["idor_tests"], None, None, recrawl=False, log_dir=str(log_dir))

    log_files = list(log_dir.glob("scan_*.log"))
    assert len(log_files) == 1
    content = log_files[0].read_text(encoding="utf-8")
    assert "STOF" in content
    assert "CRAWL & ENDPOINT DISCOVERY" in content


# ---------------------------------------------------------------------------
# _module_note
# ---------------------------------------------------------------------------


def _finding(module_id: str) -> Finding:
    endpoint = Endpoint(url="https://x/a", method="GET", endpoint_type="page", parameters=[])
    return Finding(
        module_id=module_id, vuln_type="X", severity="High", cvss_score=8.1, endpoint=endpoint,
        user_role="admin", request_raw="GET x", response_raw="HTTP 200", description="d", recommendation="r",
        discovered_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def test_module_note_counts_findings_for_that_module_only():
    findings = [_finding("idor_tests"), _finding("idor_tests"), _finding("jwt_tests")]

    note = _module_note("idor_tests", findings)

    assert note == {"module": "idor_tests", "finding_count": 2, "note": None}


# ---------------------------------------------------------------------------
# _grow_shared_candidate_ids -- cross-module identifier sharing
# ---------------------------------------------------------------------------


def _finding_with_leaked_id(leaked_id: str) -> Finding:
    endpoint = Endpoint(url="https://x/a", method="GET", endpoint_type="page", parameters=[])
    return Finding(
        module_id="disclosure_tests", vuln_type="PII Exposure via API Response", severity="Medium", cvss_score=6.5,
        endpoint=endpoint, user_role="admin", request_raw="GET x",
        response_raw=f'{{"accountId": "{leaked_id}", "email": "a@x.com"}}',
        description="d", recommendation="r", discovered_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def test_grow_shared_candidate_ids_adds_a_newly_leaked_id():
    shared = ["1", "2"]
    console = _FakeConsole()

    _grow_shared_candidate_ids(shared, [_finding_with_leaked_id("800047")], "disclosure_tests", console)

    assert "800047" in shared
    assert any("1 new object id candidate" in msg for msg in console.infos)


def test_grow_shared_candidate_ids_skips_an_already_known_id():
    shared = ["800047"]
    console = _FakeConsole()

    _grow_shared_candidate_ids(shared, [_finding_with_leaked_id("800047")], "disclosure_tests", console)

    assert shared == ["800047"]  # not duplicated
    assert console.infos == []  # nothing NEW to announce


def test_grow_shared_candidate_ids_respects_the_cap():
    shared = [str(i) for i in range(60)]  # already at the default cap
    console = _FakeConsole()

    _grow_shared_candidate_ids(shared, [_finding_with_leaked_id("800047")], "disclosure_tests", console)

    assert len(shared) == 60
    assert "800047" not in shared


def test_grow_shared_candidate_ids_no_op_on_empty_findings():
    shared = ["1", "2"]
    console = _FakeConsole()

    _grow_shared_candidate_ids(shared, [], "disclosure_tests", console)

    assert shared == ["1", "2"]
    assert console.infos == []


def test_module_note_explains_zero_jwt_findings_when_no_jwt_role_configured():
    note = _module_note("jwt_tests", [], jwt_roles=[])

    assert note["finding_count"] == 0
    assert "Not applicable" in note["note"]
    assert "auth_type" in note["note"]


def test_module_note_does_not_claim_no_jwt_role_when_one_actually_ran():
    """Regression: a real JWT-authenticated role can run the probe and
    still legitimately find nothing (e.g. the module's own safety check
    skipped an endpoint that doesn't enforce auth) -- the note must not
    then falsely claim no jwt role was configured at all."""
    note = _module_note("jwt_tests", [], jwt_roles=["jwt_user"])

    assert note["finding_count"] == 0
    assert "no configured user" not in note["note"]
    assert "jwt_user" in note["note"]


def test_module_note_no_explanation_for_zero_idor_findings():
    """Only jwt_tests has a documented "this is expected, not a gap"
    explanation -- a real module finding nothing shouldn't get an
    unwarranted excuse attached."""
    note = _module_note("idor_tests", [])

    assert note["finding_count"] == 0
    assert note["note"] is None


# ---------------------------------------------------------------------------
# _findings_from_recon_secrets
# ---------------------------------------------------------------------------


class _FakeReconReport:
    def __init__(self, secrets, discovered_routes=None):
        self.secrets = secrets
        self.discovered_routes = discovered_routes or []


def test_findings_from_recon_secrets_returns_empty_for_no_recon():
    assert _findings_from_recon_secrets(None) == []


def test_findings_from_recon_secrets_returns_empty_when_none_found():
    assert _findings_from_recon_secrets(_FakeReconReport([])) == []


def test_findings_from_recon_secrets_converts_a_detected_secret_into_a_real_finding():
    """Regression: recon's own secrets scanner already detects
    hardcoded credentials in client-side JS (confirmed live -- a real
    third-party API token in a shipped bundle), but that used to only
    ever become a console log line and a raw JSON dump, never a
    `Finding` -- invisible in every report, the dashboard, and
    severity counts despite being a genuine, confirmed detection."""
    secret = {"source_url": "https://x/assets/app-abc123.js", "label": "Generic API Key Assignment", "match_preview": "apikey...6789"}

    findings = _findings_from_recon_secrets(_FakeReconReport([secret]))

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "High"
    assert f.module_id == "disclosure_tests"
    assert "Generic API Key Assignment" in f.vuln_type
    assert f.endpoint.url == "https://x/assets/app-abc123.js"
    assert f.endpoint.endpoint_type == "api"
    assert f.cwe == "CWE-798 - Use of Hard-coded Credentials"
    assert f.owasp_category == "A02:2025 - Security Misconfiguration"


def test_findings_from_recon_secrets_handles_multiple_secrets_independently():
    secrets = [
        {"source_url": "https://x/a.js", "label": "AWS Access Key", "match_preview": "AKIA1...abcd"},
        {"source_url": "https://x/page", "label": "Private Key Block", "match_preview": "-----B...KEY--"},
    ]

    findings = _findings_from_recon_secrets(_FakeReconReport(secrets))

    assert len(findings) == 2
    assert findings[1].endpoint.endpoint_type == "page"  # non-.js source stays a "page" endpoint


# ---------------------------------------------------------------------------
# _endpoints_from_discovered_routes
# ---------------------------------------------------------------------------


def test_endpoints_from_discovered_routes_returns_empty_for_no_recon():
    assert _endpoints_from_discovered_routes(None, "https://x/") == []


def test_endpoints_from_discovered_routes_returns_empty_when_none_found():
    assert _endpoints_from_discovered_routes(_FakeReconReport([], []), "https://x/") == []


def test_endpoints_from_discovered_routes_resolves_a_route_string_into_a_real_endpoint():
    """Regression: `secrets_scanner.find_routes()` mines route strings
    (a Vue/React router config's own `path:"/..."` entries) out of JS
    bundles, but a route string found this run used to sit in a recon
    report file only, never actually queued for THIS scan's vuln
    modules to test -- exactly the sidebar-driven admin screens the
    crawler's own click-exploration still can't fully reach on a
    single pass."""
    route = {"path": "/kauthor/categories", "source_url": "https://x/assets/router.js"}

    endpoints = _endpoints_from_discovered_routes(_FakeReconReport([], [route]), "https://x/")

    assert len(endpoints) == 1
    assert endpoints[0].url == "https://x/kauthor/categories"
    assert endpoints[0].method == "GET"
    assert endpoints[0].endpoint_type == "page"


def test_endpoints_from_discovered_routes_resolves_against_base_url_origin():
    route = {"path": "/admin/users"}

    endpoints = _endpoints_from_discovered_routes(_FakeReconReport([], [route]), "https://test.example.com/app/login")

    assert endpoints[0].url == "https://test.example.com/admin/users"


# ---------------------------------------------------------------------------
# _coverage_funnel
# ---------------------------------------------------------------------------


def _tc_result(status: str, endpoint: Endpoint | None = None):
    from stof.modules.results import PASS, TestCaseResult

    kwargs = {}
    if status == "FAIL":
        kwargs["finding"] = _finding("idor_tests")
    return TestCaseResult(
        test_id="TC-X", technique_id="TC-X.1", technique="t", vuln_type="v",
        module_id="idor_tests", severity="Info", status=status or PASS, detail="",
        endpoint=endpoint, **kwargs,
    )


def test_coverage_funnel_counts_discovered_tested_and_verified_exploitable():
    from stof.modules.results import FAIL, PASS, SKIPPED

    endpoints = [_endpoint("https://x/a"), _endpoint("https://x/b"), _endpoint("https://x/c")]
    finding = _finding("idor_tests")
    finding.endpoint = _endpoint("https://x/a")
    vuln_results = [
        _tc_result(PASS, endpoint=_endpoint("https://x/a")),
        _tc_result(SKIPPED, endpoint=_endpoint("https://x/b")),
        _tc_result(FAIL, endpoint=_endpoint("https://x/a")),
    ]

    coverage = _coverage_funnel(endpoints, vuln_results, [finding])

    assert coverage == {"endpoints_discovered": 3, "endpoints_tested": 2, "endpoints_verified_exploitable": 1}


def test_coverage_funnel_ignores_results_with_no_endpoint():
    from stof.modules.results import PASS

    vuln_results = [_tc_result(PASS, endpoint=None)]

    coverage = _coverage_funnel([], vuln_results, [])

    assert coverage["endpoints_tested"] == 0


def test_coverage_funnel_zero_across_the_board_with_no_data():
    assert _coverage_funnel([], [], []) == {
        "endpoints_discovered": 0, "endpoints_tested": 0, "endpoints_verified_exploitable": 0,
    }


# ---------------------------------------------------------------------------
# _burp_seed_urls
# ---------------------------------------------------------------------------


def _endpoint(url: str) -> Endpoint:
    return Endpoint(url=url, method="GET", endpoint_type="page", parameters=[])


def test_burp_seed_urls_filters_out_non_http_hrefs():
    """A real endpoint list from demo.testfire.net includes a
    `javascript:` pseudo-URL picked up from a link's href -- Burp's
    REST API rejects its *entire* urls array (400 ClientError) if even
    one entry isn't an absolute http(s) URL, so this must never reach
    Burp."""
    endpoints = [
        _endpoint("https://demo.testfire.net/bank/main.jsp"),
        _endpoint("javascript:checkSiteStatus('AltoroMutual')"),
        _endpoint("https://demo.testfire.net/admin/admin.jsp"),
    ]

    seed_urls = _burp_seed_urls(endpoints, "https://demo.testfire.net")

    assert seed_urls == ["https://demo.testfire.net/admin/admin.jsp", "https://demo.testfire.net/bank/main.jsp"]


def test_burp_seed_urls_deduplicates():
    endpoints = [_endpoint("https://x/a"), _endpoint("https://x/a"), _endpoint("https://x/b")]

    assert _burp_seed_urls(endpoints, "https://x") == ["https://x/a", "https://x/b"]


def test_burp_seed_urls_falls_back_to_base_url_when_nothing_valid():
    endpoints = [_endpoint("javascript:void(0)"), _endpoint("mailto:test@x.com")]

    assert _burp_seed_urls(endpoints, "https://x") == ["https://x"]


def test_burp_seed_urls_falls_back_to_base_url_when_no_endpoints():
    assert _burp_seed_urls([], "https://x") == ["https://x"]


# ---------------------------------------------------------------------------
# _burp_scope_prefix
# ---------------------------------------------------------------------------


def test_burp_scope_prefix_strips_spa_hash_fragment():
    """A hash-routed SPA's real backend traffic (e.g. /rest/..., /api/...)
    never carries the `#/...` route fragment -- using it verbatim as
    Burp's scope prefix would silently exclude everything real."""
    assert _burp_scope_prefix("https://preview.owasp-juice.shop/#/") == "https://preview.owasp-juice.shop"


def test_burp_scope_prefix_strips_path_for_plain_targets_too():
    assert _burp_scope_prefix("https://demo.testfire.net/index.jsp") == "https://demo.testfire.net"


# ---------------------------------------------------------------------------
# _build_module_builders / _build_form_login_provider -- config-driven,
# no target hardcoded into main.py
# ---------------------------------------------------------------------------


def _config(**target_overrides) -> Config:
    return Config(
        target=TargetConfig(base_url="https://x", login_url="https://x/login", **target_overrides),
        output={"reports_dir": "reports", "evidence_dir": "evidence"},
    )


def _user_config(role: str, auth_type: str):
    from stof.config.schema import UserConfig

    return UserConfig(id=f"{role}-01", role=role, username="u", password="p", auth_type=auth_type)


def test_build_module_builders_uses_generic_idor_ids_when_unconfigured():
    config = _config()

    builders = _build_module_builders(config, [], {})
    module = builders["idor_tests"]()

    assert module.config.candidate_ids == [str(i) for i in range(1, 21)]


def test_build_module_builders_uses_configured_idor_ids():
    config = _config(idor_candidate_ids=["800000", "800001"])

    builders = _build_module_builders(config, [], {})
    module = builders["idor_tests"]()

    assert module.config.candidate_ids == ["800000", "800001"]


def test_build_module_builders_uses_the_shared_candidate_ids_list_by_reference():
    """When given, `shared_candidate_ids` is used AS-IS (not copied) --
    growing it in place after this call must be visible to a module
    built from the SAME `_build_module_builders()` call, since Python
    closures are late-binding. See `_grow_shared_candidate_ids`'s own
    docstring for why this matters."""
    config = _config()
    shared = ["1", "2"]

    builders = _build_module_builders(config, [], {}, shared_candidate_ids=shared)
    shared.append("800001")  # simulates a later module's own discovery
    module = builders["idor_tests"]()

    assert module.config.candidate_ids is shared
    assert "800001" in module.config.candidate_ids


def test_build_module_builders_passes_through_jwt_roles():
    config = _config()

    builders = _build_module_builders(config, ["normal"], {})
    module = builders["jwt_tests"]()

    assert module.roles == ["normal"]


def test_jwt_roles_comes_from_users_auth_type():
    from stof.main import _jwt_roles

    users_by_role = {
        "admin": _user_config("admin", "form_login"),
        "normal": _user_config("normal", "jwt"),
    }

    assert _jwt_roles(users_by_role) == ["normal"]


def test_build_module_builders_wires_auth_test_config_from_users_and_target():
    config = _config(
        jwt_token_url="https://x/rest/user/login",
        change_password_url="https://x/rest/user/change-password",
        reset_password_request_url="https://x/rest/user/reset-password",
    )
    users_by_role = {
        "admin": _user_config("admin", "form_login"),
        "normal": _user_config("normal", "form_login"),
    }

    builders = _build_module_builders(config, [], users_by_role)
    module = builders["auth_tests"]()

    assert module.config.login_json_endpoint == "https://x/rest/user/login"
    assert module.config.change_password_url == "https://x/rest/user/change-password"
    assert module.config.reset_password_request_url == "https://x/rest/user/reset-password"
    assert module.config.test_role == "normal"
    assert module.config.test_username == "u"  # from _user_config's fixed username
    assert module.config.test_current_password == "p"
    assert module.config.victim_email == "u"  # admin's username, same fixture


def test_build_module_builders_auth_test_config_none_when_no_users_configured():
    config = _config()

    builders = _build_module_builders(config, [], {})
    module = builders["auth_tests"]()

    assert module.config.test_role is None
    assert module.config.test_username is None
    assert module.config.victim_email is None


def test_build_module_builders_wires_disclosure_graphql_deserialization_high_priv_role():
    config = _config()
    users_by_role = {"admin": _user_config("admin", "form_login"), "normal": _user_config("normal", "form_login")}

    builders = _build_module_builders(config, [], users_by_role)

    assert builders["disclosure_tests"]().config.high_priv_role == "admin"
    assert builders["graphql_tests"]().config.high_priv_role == "admin"
    assert builders["graphql_tests"]().config.low_priv_role == "normal"
    assert builders["deserialization_tests"]().config.high_priv_role == "admin"


def test_build_module_builders_passes_configured_jwt_role_claim():
    config = _config(jwt_role_claim="data.role")

    builders = _build_module_builders(config, ["normal"], {})
    module = builders["jwt_tests"]()

    assert module.config.role_claim == "data.role"


def test_build_form_login_provider_falls_back_to_generic_selectors_when_unset():
    from stof.auth.form_login import GENERIC_PASSWORD_SELECTORS, GENERIC_USERNAME_SELECTORS

    provider = _build_form_login_provider(_config())

    assert provider._username_selector == GENERIC_USERNAME_SELECTORS
    assert provider._password_selector == GENERIC_PASSWORD_SELECTORS


def test_build_form_login_provider_uses_configured_selectors_when_set():
    config = _config(username_selector="#email", password_selector="#password", submit_selector="#loginButton")

    provider = _build_form_login_provider(config)

    assert provider._username_selector == "#email"
    assert provider._password_selector == "#password"
    assert provider._submit_selector == "#loginButton"


def test_build_login_provider_returns_form_login_by_default():
    """requires_assisted_login defaults to False -- every normal target
    is completely unaffected by the assisted-login feature."""
    from stof.auth.form_login import FormLoginProvider

    provider = _build_login_provider(_config())

    assert isinstance(provider, FormLoginProvider)


def test_build_login_provider_returns_assisted_login_when_flagged():
    from stof.auth.assisted_login import AssistedLoginProvider

    config = _config(requires_assisted_login=True)

    provider = _build_login_provider(config)

    assert isinstance(provider, AssistedLoginProvider)
    assert provider._login_url == "https://x/login"


def test_build_login_provider_forwards_success_selector_when_assisted():
    from stof.auth.assisted_login import AssistedLoginProvider

    config = _config(requires_assisted_login=True, success_selector="text=Dashboard")

    provider = _build_login_provider(config)

    assert isinstance(provider, AssistedLoginProvider)
    assert provider._success_selector == "text=Dashboard"


# ---------------------------------------------------------------------------
# _attach_assisted_login_contexts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_attach_assisted_login_contexts_noop_when_flag_unset():
    """Zero behavior change for a normal target: never even tries to
    connect over CDP."""
    config = _config()  # requires_assisted_login defaults False
    pw = AsyncMock()

    await _attach_assisted_login_contexts(pw, config, AsyncMock(), AsyncMock(), AsyncMock(), {}, lambda *a: None)

    pw.chromium.connect_over_cdp.assert_not_awaited()


@pytest.mark.asyncio
async def test_attach_assisted_login_contexts_noop_when_no_form_login_roles():
    config = _config(requires_assisted_login=True)
    pw = AsyncMock()
    users_by_role = {"api-user": _user_config("api-user", "jwt")}

    await _attach_assisted_login_contexts(pw, config, AsyncMock(), AsyncMock(), AsyncMock(), users_by_role, lambda *a: None)

    pw.chromium.connect_over_cdp.assert_not_awaited()


@pytest.mark.asyncio
async def test_attach_assisted_login_contexts_raises_clear_error_when_cdp_connect_fails():
    config = _config(requires_assisted_login=True)
    pw = AsyncMock()
    pw.chromium.connect_over_cdp = AsyncMock(side_effect=Exception("connection refused"))
    users_by_role = {"admin": _user_config("admin", "form_login")}

    with pytest.raises(click.ClickException, match="no assisted-login browser session was found"):
        await _attach_assisted_login_contexts(pw, config, AsyncMock(), AsyncMock(), AsyncMock(), users_by_role, lambda *a: None)


@pytest.mark.asyncio
async def test_attach_assisted_login_contexts_raises_when_not_enough_contexts_open():
    config = _config(requires_assisted_login=True)
    pw = AsyncMock()
    external_browser = AsyncMock()
    external_browser.contexts = []  # operator hasn't logged in / opened a window yet
    pw.chromium.connect_over_cdp = AsyncMock(return_value=external_browser)
    users_by_role = {"admin": _user_config("admin", "form_login")}

    with pytest.raises(click.ClickException, match="needs one confirmed browser context"):
        await _attach_assisted_login_contexts(pw, config, AsyncMock(), AsyncMock(), AsyncMock(), users_by_role, lambda *a: None)


@pytest.mark.asyncio
async def test_attach_assisted_login_contexts_happy_path_seeds_session_and_attaches_context():
    config = _config(requires_assisted_login=True)
    pw = AsyncMock()
    external_browser = AsyncMock()
    fake_context = AsyncMock()
    fake_page = AsyncMock()
    fake_context.pages = [fake_page]
    external_browser.contexts = [fake_context]
    pw.chromium.connect_over_cdp = AsyncMock(return_value=external_browser)

    session_pool = AsyncMock()
    session_manager = AsyncMock()
    login_provider = AsyncMock()
    fake_session = object()
    login_provider.authenticate = AsyncMock(return_value=fake_session)
    users_by_role = {"admin": _user_config("admin", "form_login")}
    messages = []

    await _attach_assisted_login_contexts(pw, config, session_pool, session_manager, login_provider, users_by_role, messages.append)

    login_provider.authenticate.assert_awaited_once_with(users_by_role["admin"], fake_page)
    session_manager.seed_session.assert_called_once_with(fake_session)
    session_pool.attach_external_context.assert_awaited_once_with("admin", fake_context)
    assert any("Assisted login confirmed" in m for m in messages)


# ---------------------------------------------------------------------------
# crawl command -- validation only (the real crawl needs a browser + target)
# ---------------------------------------------------------------------------


def test_crawl_command_rejects_unconfigured_role(tmp_path):
    config_path, users_path = _write_config(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, [
        "crawl", "--role", "not_a_real_role",
        "--config", str(config_path), "--users", str(users_path),
        "--output", str(tmp_path / "endpoints.json"),
    ])

    assert result.exit_code != 0
    assert "not configured" in result.output


def test_cli_group_has_crawl_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "crawl" in result.output


# ---------------------------------------------------------------------------
# _resolve_crawl_roles() -- multi-role crawl-merge role selection (Wave 1b)
# ---------------------------------------------------------------------------


def test_resolve_crawl_roles_explicit_override_crawls_only_that_role():
    users_by_role = {"admin": _user_config("admin", "form_login"), "normal": _user_config("normal", "form_login")}

    roles = _resolve_crawl_roles("normal", users_by_role, "users.json")

    assert roles == ["normal"]


def test_resolve_crawl_roles_rejects_unconfigured_override():
    users_by_role = {"admin": _user_config("admin", "form_login")}

    with pytest.raises(click.ClickException, match="not configured"):
        _resolve_crawl_roles("not_a_real_role", users_by_role, "users.json")


def test_resolve_crawl_roles_no_override_crawls_every_configured_role():
    users_by_role = {"admin": _user_config("admin", "form_login"), "normal": _user_config("normal", "jwt")}

    roles = _resolve_crawl_roles(None, users_by_role, "users.json")

    assert roles == ["admin", "normal"]


def test_resolve_crawl_roles_no_override_single_role_unchanged():
    """A target with only one configured role crawls once, same as
    before Wave 1b -- nothing to merge."""
    users_by_role = {"admin": _user_config("admin", "form_login")}

    roles = _resolve_crawl_roles(None, users_by_role, "users.json")

    assert roles == ["admin"]


def test_resolve_crawl_roles_no_users_configured_raises():
    with pytest.raises(click.ClickException, match="no configured user"):
        _resolve_crawl_roles(None, {}, "users.json")


# ---------------------------------------------------------------------------
# configure -- interactive setup wizard for the target URL + credentials
# ---------------------------------------------------------------------------


def _configure_input(base_url="https://example.com", login_url="https://example.com/login", wants_jwt="n") -> str:
    lines = [base_url, login_url, wants_jwt, "admin@example.com", "AdminPass123", "user@example.com", "UserPass123"]
    lines += ["y"] * len(_KNOWN_MODULES)  # one confirm per _KNOWN_MODULES entry
    return "\n".join(lines) + "\n"


def test_configure_writes_a_valid_config_users_and_env_from_scratch(tmp_path):
    config_path = tmp_path / "config.json"
    users_path = tmp_path / "users.json"
    env_path = tmp_path / ".env"
    runner = CliRunner()

    result = runner.invoke(cli, [
        "configure", "--config", str(config_path), "--users", str(users_path), "--env-file", str(env_path),
    ], input=_configure_input())

    assert result.exit_code == 0, result.output
    assert "configuration is valid" in result.output

    config_doc = json.loads(config_path.read_text())
    assert config_doc["target"]["base_url"] == "https://example.com"
    assert config_doc["target"]["login_url"] == "https://example.com/login"
    assert config_doc["modules"]["idor_tests"] is True

    users_doc = json.loads(users_path.read_text())
    usernames = {u["role"]: u["username"] for u in users_doc["users"]}
    assert usernames == {"admin": "admin@example.com", "normal": "user@example.com"}

    env_text = env_path.read_text()
    assert "ADMIN_PASSWORD=AdminPass123" in env_text
    assert "USER_PASSWORD=UserPass123" in env_text


def test_configure_never_writes_a_plaintext_password_into_json_files(tmp_path):
    config_path = tmp_path / "config.json"
    users_path = tmp_path / "users.json"
    env_path = tmp_path / ".env"
    runner = CliRunner()

    runner.invoke(cli, [
        "configure", "--config", str(config_path), "--users", str(users_path), "--env-file", str(env_path),
    ], input=_configure_input())

    config_text = config_path.read_text()
    users_text = users_path.read_text()
    assert "AdminPass123" not in config_text
    assert "AdminPass123" not in users_text
    assert "UserPass123" not in config_text
    assert "UserPass123" not in users_text
    assert "{{env:ADMIN_PASSWORD}}" in users_text
    assert "{{env:USER_PASSWORD}}" in users_text


def test_configure_rejects_an_invalid_base_url(tmp_path):
    config_path = tmp_path / "config.json"
    users_path = tmp_path / "users.json"
    env_path = tmp_path / ".env"
    runner = CliRunner()

    result = runner.invoke(cli, [
        "configure", "--config", str(config_path), "--users", str(users_path), "--env-file", str(env_path),
    ], input="not-a-url\n")

    assert result.exit_code != 0
    assert "doesn't look like a valid" in result.output
    assert not config_path.exists()


def test_configure_preserves_existing_browser_output_and_burp_settings(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "target": {"base_url": "https://old.example.com", "login_url": "https://old.example.com/login"},
        "browser": {"headless": False, "slowmo_ms": 250, "proxy": "http://proxy:8080"},
        "modules": {"crawler": True},
        "output": {"reports_dir": "custom/reports", "evidence_dir": "custom/evidence"},
        "burp": {"enabled": True, "api_url": "http://127.0.0.1:9999", "api_key": "{{env:BURP_API_KEY}}", "scan_timeout_s": 600, "poll_interval_s": 5},
    }))
    users_path = tmp_path / "users.json"
    env_path = tmp_path / ".env"
    runner = CliRunner()

    result = runner.invoke(cli, [
        "configure", "--config", str(config_path), "--users", str(users_path), "--env-file", str(env_path),
    ], input=_configure_input(base_url="https://new.example.com", login_url="https://new.example.com/login"))

    assert result.exit_code == 0, result.output
    config_doc = json.loads(config_path.read_text())
    assert config_doc["target"]["base_url"] == "https://new.example.com"
    assert config_doc["browser"] == {"headless": False, "slowmo_ms": 250, "proxy": "http://proxy:8080"}
    assert config_doc["output"] == {"reports_dir": "custom/reports", "evidence_dir": "custom/evidence"}
    assert config_doc["burp"]["api_url"] == "http://127.0.0.1:9999"


def test_configure_upserts_env_values_without_touching_unrelated_lines(tmp_path):
    config_path = tmp_path / "config.json"
    users_path = tmp_path / "users.json"
    env_path = tmp_path / ".env"
    env_path.write_text("ADMIN_PASSWORD=old-value\nSOME_OTHER_VAR=keep-me\n")
    runner = CliRunner()

    result = runner.invoke(cli, [
        "configure", "--config", str(config_path), "--users", str(users_path), "--env-file", str(env_path),
    ], input=_configure_input())

    assert result.exit_code == 0, result.output
    env_text = env_path.read_text()
    assert "ADMIN_PASSWORD=AdminPass123" in env_text
    assert "old-value" not in env_text
    assert "SOME_OTHER_VAR=keep-me" in env_text


def test_cli_group_has_configure_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "configure" in result.output


# ---------------------------------------------------------------------------
# _revert_state_changing_probes_flag -- auto-disarms the manually-armed
# allow_state_changing_probes safety gate after every scan/test run, so it
# can't be left `true` on disk by accident (it repeatedly was, by hand).
# ---------------------------------------------------------------------------


def test_revert_state_changing_probes_flag_flips_true_to_false(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"target": {}, "testing": {"allow_state_changing_probes": True}}))

    _revert_state_changing_probes_flag(str(config_path))

    assert json.loads(config_path.read_text())["testing"]["allow_state_changing_probes"] is False


def test_revert_state_changing_probes_flag_leaves_false_untouched(tmp_path):
    config_path = tmp_path / "config.json"
    original = json.dumps({"target": {}, "testing": {"allow_state_changing_probes": False}})
    config_path.write_text(original)

    _revert_state_changing_probes_flag(str(config_path))

    assert json.loads(config_path.read_text())["testing"]["allow_state_changing_probes"] is False


def test_revert_state_changing_probes_flag_tolerates_missing_testing_block(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"target": {}}))

    _revert_state_changing_probes_flag(str(config_path))  # must not raise

    assert "testing" not in json.loads(config_path.read_text())


def test_revert_state_changing_probes_flag_tolerates_missing_file(tmp_path):
    _revert_state_changing_probes_flag(str(tmp_path / "does_not_exist.json"))  # must not raise


# ---------------------------------------------------------------------------
# _replay_workflows() -- "REPLAYING RECORDED WORKFLOWS" phase (--workflow)
# ---------------------------------------------------------------------------


class _FakeConsole:
    """Mirrors the two real `ScanConsole` methods `_replay_workflows()`
    calls -- `workflow_replayed()`'s own real implementation both
    prints via `info()` AND emits a structured event (see
    console.py's own docstring for why: a workflow's replay outcome
    used to be invisible to the web UI, only ever landing in the raw
    log file), so this fake reproduces that same "info() call plus a
    structured record" shape rather than just stubbing one or the
    other."""
    def __init__(self):
        self.phases: list[str] = []
        self.infos: list[str] = []
        self.workflow_events: list[dict] = []

    def phase(self, title):
        self.phases.append(title)

    def info(self, message):
        self.infos.append(message)

    def workflow_replayed(self, workflow_id, role, success, completed_actions, total_actions, final_url, error=None):
        if success:
            self.info(f"'{workflow_id}' (as role '{role}'): replayed {completed_actions}/{total_actions} action(s) successfully, landed on {final_url}")
        else:
            self.info(f"'{workflow_id}' (as role '{role}'): stopped after {completed_actions}/{total_actions} action(s) -- {error}")
        self.workflow_events.append({
            "workflow_id": workflow_id, "role": role, "success": success,
            "completed_actions": completed_actions, "total_actions": total_actions,
            "final_url": final_url, "error": error,
        })


@pytest.mark.asyncio
async def test_replay_workflows_logs_success_with_role_and_final_url():
    from stof.engine.playwright_engine import ReplayResult

    console = _FakeConsole()
    fake_session = object()
    fake_runner = AsyncMock()
    fake_runner.run_workflow.return_value = ReplayResult(
        workflow_id="wf-1", success=True, completed_actions=4, total_actions=4, final_url="https://x/dashboard",
    )

    with patch("stof.main.WorkflowRepository"), \
         patch("stof.main.WorkflowRunner", return_value=fake_runner), \
         patch("stof.main._authenticated_session", new=AsyncMock(return_value=fake_session)):
        await _replay_workflows(["wf-1"], {"admin": object()}, object(), object(), object(), console)

    assert console.phases == ["REPLAYING RECORDED WORKFLOWS"]
    assert len(console.infos) == 1
    assert "wf-1" in console.infos[0]
    assert "role 'admin'" in console.infos[0]
    assert "4/4" in console.infos[0]
    assert "https://x/dashboard" in console.infos[0]
    fake_runner.run_workflow.assert_awaited_once_with("wf-1", fake_session)

    # The structured event, not just the terminal-style info() line --
    # this is what the web console's Live Activity feed actually reads
    # (info() alone never reached it, only the raw log file).
    assert len(console.workflow_events) == 1
    assert console.workflow_events[0] == {
        "workflow_id": "wf-1", "role": "admin", "success": True,
        "completed_actions": 4, "total_actions": 4, "final_url": "https://x/dashboard", "error": None,
    }


@pytest.mark.asyncio
async def test_replay_workflows_logs_partial_failure_with_error():
    from stof.engine.playwright_engine import ReplayResult

    console = _FakeConsole()
    fake_runner = AsyncMock()
    fake_runner.run_workflow.return_value = ReplayResult(
        workflow_id="wf-2", success=False, completed_actions=2, total_actions=5,
        final_url="https://x/login", error="TimeoutError: waiting for selector '#submit'",
    )

    with patch("stof.main.WorkflowRepository"), \
         patch("stof.main.WorkflowRunner", return_value=fake_runner), \
         patch("stof.main._authenticated_session", new=AsyncMock(return_value=object())):
        await _replay_workflows(["wf-2"], {"normal": object()}, object(), object(), object(), console)

    assert len(console.infos) == 1
    assert "2/5" in console.infos[0]
    assert "TimeoutError" in console.infos[0]
    assert console.workflow_events[0]["success"] is False
    assert console.workflow_events[0]["error"] == "TimeoutError: waiting for selector '#submit'"


@pytest.mark.asyncio
async def test_replay_workflows_one_bad_id_does_not_stop_the_others():
    from stof.engine.playwright_engine import ReplayResult

    console = _FakeConsole()
    fake_runner = AsyncMock()
    fake_runner.run_workflow.side_effect = [
        KeyError("no workflow 'missing'"),
        ReplayResult(workflow_id="wf-ok", success=True, completed_actions=1, total_actions=1, final_url="https://x/"),
    ]

    with patch("stof.main.WorkflowRepository"), \
         patch("stof.main.WorkflowRunner", return_value=fake_runner), \
         patch("stof.main._authenticated_session", new=AsyncMock(return_value=object())):
        await _replay_workflows(["missing", "wf-ok"], {"admin": object()}, object(), object(), object(), console)

    assert len(console.infos) == 2
    assert "could not replay" in console.infos[0]
    assert "wf-ok" in console.infos[1]


@pytest.mark.asyncio
async def test_replay_workflows_skips_when_no_role_configured():
    console = _FakeConsole()

    await _replay_workflows(["wf-1"], {}, object(), object(), object(), console)

    assert console.phases == ["REPLAYING RECORDED WORKFLOWS"]
    assert "Skipped" in console.infos[0]


@pytest.mark.asyncio
async def test_replay_workflows_prefers_admin_role_when_multiple_configured():
    from stof.engine.playwright_engine import ReplayResult

    console = _FakeConsole()
    fake_runner = AsyncMock()
    fake_runner.run_workflow.return_value = ReplayResult(
        workflow_id="wf-1", success=True, completed_actions=1, total_actions=1, final_url="https://x/",
    )

    with patch("stof.main.WorkflowRepository"), \
         patch("stof.main.WorkflowRunner", return_value=fake_runner), \
         patch("stof.main._authenticated_session", new=AsyncMock(return_value=object())):
        await _replay_workflows(["wf-1"], {"normal": object(), "admin": object()}, object(), object(), object(), console)

    assert "role 'admin'" in console.infos[0]


# ---------------------------------------------------------------------------
# Driver-death detection (resilience) -- confirmed live: a dead Playwright
# driver connection never raises up through vm.run_techniques() (per-
# technique isolation already turns it into an ERROR result), so recovery
# has to inspect the RESULTS a module returned, not catch an exception.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "detail,expected",
    [
        ("Browser.new_context: Connection closed while reading from the driver", True),
        ("APIRequestContext.get: Connection closed while reading from the driver", True),
        ("Target page, context or browser has been closed", True),
        ("Target closed", True),
        ("some ordinary probe failure: timeout", False),
        ("", False),
        (None, False),
    ],
)
def test_looks_like_driver_dead(detail, expected):
    assert _looks_like_driver_dead(detail) is expected


def _result(status: str, detail: str = ""):
    from stof.modules.results import TestCaseResult

    return TestCaseResult(
        test_id="TC-X", technique_id="TC-X.1", technique="t", vuln_type="v",
        module_id="x", severity="Info", status=status, detail=detail,
    )


def test_module_hit_dead_driver_true_when_an_error_result_has_the_signature():
    from stof.modules.results import ERROR, PASS

    results = [_result(PASS), _result(ERROR, "Connection closed while reading from the driver")]
    assert _module_hit_dead_driver(results) is True


def test_module_hit_dead_driver_false_for_an_ordinary_error():
    from stof.modules.results import ERROR, PASS

    results = [_result(PASS), _result(ERROR, "unexpected: division by zero")]
    assert _module_hit_dead_driver(results) is False


def test_module_hit_dead_driver_false_when_no_results():
    assert _module_hit_dead_driver([]) is False


def test_module_hit_dead_driver_ignores_non_error_status_with_matching_text():
    # A PASS/SKIPPED result whose detail happens to mention the phrase
    # (e.g. quoting it back in a description) must not trigger a browser
    # restart -- only a real ERROR status counts.
    from stof.modules.results import SKIPPED

    results = [_result(SKIPPED, "unrelated to Connection closed while reading from the driver")]
    assert _module_hit_dead_driver(results) is False
