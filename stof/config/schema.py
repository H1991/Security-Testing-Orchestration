"""Pydantic models for STOF configuration contracts (Layer 1).

These models are the data contract every other layer receives via
dependency injection. No other module should read config JSON directly —
they receive `Config`, `UsersConfig`, or `AuthTestsConfig` instances.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

AuthType = Literal["form_login", "jwt"]
Severity = Literal["Critical", "High", "Medium", "Low", "Info"]


class TargetConfig(BaseModel):
    """`*_selector` fields describe this target's own login form and are
    optional: leave them unset and `FormLoginProvider` falls back to a
    generic, app-agnostic set of candidate selectors (see
    `stof.auth.form_login`) instead of any one target's specific DOM.
    Set them explicitly here when the generic auto-detect doesn't match
    a particular target's form, or to skip probing and go straight to
    the known-correct selector.

    `idor_candidate_ids` is similarly optional -- unset falls back to a
    generic small sequential-ID range rather than any one target's own
    ID scheme."""

    model_config = ConfigDict(extra="forbid")

    base_url: str
    login_url: str
    username_selector: str | list[str] | None = None
    password_selector: str | list[str] | None = None
    submit_selector: str | list[str] | None = None
    success_selector: str | list[str] | None = None
    idor_candidate_ids: list[str] | None = None
    # JWT auth (Layer 4's JWTAuthProvider / Layer 9's jwt_tests): both
    # optional and target-specific, same philosophy as the selectors
    # above. `jwt_token_url` is where a real login call gets a token
    # from; `jwt_role_claim` supports a dotted path (e.g. "data.role")
    # for targets that nest claims under a wrapper key instead of a
    # flat top-level one.
    jwt_token_url: str | None = None
    jwt_role_claim: str | None = None
    # `auth_tests` (Layer 9's `modules/auth_tests.py`): same
    # optional/target-agnostic philosophy -- unset means that specific
    # technique reports SKIPPED (not an error) rather than guessing at
    # a URL shape this target might not even have.
    change_password_url: str | None = None
    reset_password_request_url: str | None = None
    reset_password_complete_url: str | None = None
    # TC-129.2 (session_weakness_tests.py, mixed into auth_tests): same
    # optional/target-agnostic philosophy -- unset means that technique
    # falls back to a generic logout-link/button click instead of a
    # known URL.
    logout_url: str | None = None
    # Layer 7's crawler (`crawler.CrawlerConfig.exclude_path_patterns`):
    # substrings of hrefs the crawler should never visit -- for a page
    # on this specific target that's not security-relevant and causes
    # crawl instability (e.g. background navigations that wedge the
    # browser's CDP connection). Empty/unset means no exclusions -- no
    # target's URL scheme is hardcoded into the crawler itself.
    crawler_exclude_patterns: list[str] | None = None


class BrowserConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    headless: bool = True
    slowmo_ms: int = 0
    proxy: Optional[str] = None


class ModulesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    crawler: bool = True
    jwt_tests: bool = False
    auth_tests: bool = False
    idor_tests: bool = False
    business_logic_tests: bool = False
    cache_tests: bool = False
    configuration_tests: bool = False
    disclosure_tests: bool = False
    graphql_tests: bool = False
    deserialization_tests: bool = False
    sqli_tests: bool = False
    ssrf_tests: bool = False
    xss_tests: bool = False
    injection_variants_tests: bool = False
    oauth_tests: bool = False
    csrf_tests: bool = False


class OutputConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reports_dir: str
    evidence_dir: str
    # Opt-out, not opt-in: the plain-English, screenshot-backed
    # Walkthrough Report (Layer 13) is a standard, permanent report
    # type generated alongside HTML/JSON/Excel for every FAIL finding,
    # not a rare toggle -- default true.
    generate_walkthrough: bool = True


class BurpConfig(BaseModel):
    """Layer 3C — Burp Suite Professional REST API connection.

    `api_key` should be `{{env:BURP_API_KEY}}` in config.json, resolved
    the same way `users.json` resolves passwords -- never a literal key
    committed to the repo. `enabled` defaults to false: per CLAUDE.md's
    own documented rule for this exact flag ("The orchestrator skips it
    when burp.enabled is false in config") -- Burp's Active Scan sends
    real attack payloads at the live target, not read-only probing.
    Contrast `crawler.CrawlerConfig.submit_forms_with_test_data`, a
    lighter-weight active-testing deviation that IS on by default (see
    that module's own docstring for why); Burp's Active Scan is a much
    bigger blast radius and stays opt-in here.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    api_url: str = "http://127.0.0.1:1337"
    api_key: str = ""
    scan_timeout_s: int = 600
    poll_interval_s: int = 5
    # Burp Collaborator server for out-of-band (blind SSRF/XXE/blind
    # injection) confirmation. Empty by default -- OOB wiring reads this
    # but is not itself built yet (Phase 2 roadmap item); an empty value
    # means "no Collaborator configured", not an error. `{{env:VAR}}`
    # resolves the same way `api_key` does if the user prefers not to
    # commit the pool address to the repo.
    collaborator_url: str = ""


class TestingConfig(BaseModel):
    """Cross-module safety gate for state-changing probes.

    Every write-verb technique across the vuln modules (IDOR/BOLA writes,
    CSRF, mass assignment, tenant-scope POST substitution, password-change
    probing, ...) reads its own module config's `allow_state_changing_
    probes` field, which defaults to `False` in Python. This block is the
    single place a caller flips that on for every module at once via
    config.json, instead of editing each module's dataclass default in
    code -- explicit, auditable, and off by default, matching this
    project's own resilience-first convention for anything that writes to
    a live target.
    """

    model_config = ConfigDict(extra="forbid")

    allow_state_changing_probes: bool = False


class Config(BaseModel):
    """Top-level contract loaded from `config/config.json`."""

    model_config = ConfigDict(extra="forbid")

    target: TargetConfig
    browser: BrowserConfig = Field(default_factory=BrowserConfig)
    modules: ModulesConfig = Field(default_factory=ModulesConfig)
    output: OutputConfig
    burp: BurpConfig = Field(default_factory=BurpConfig)
    testing: TestingConfig = Field(default_factory=TestingConfig)


class UserConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    role: str
    username: str
    password: str
    auth_type: AuthType


class UsersConfig(BaseModel):
    """Top-level contract loaded from `config/users.json`."""

    model_config = ConfigDict(extra="forbid")

    users: list[UserConfig]


class AuthTestCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    module: str
    enabled: bool = True
    payloads: list[str] = Field(default_factory=list)
    severity: Severity


class AuthTestsConfig(BaseModel):
    """Top-level contract loaded from `config/auth_tests.json`."""

    model_config = ConfigDict(extra="forbid")

    tests: list[AuthTestCase]
