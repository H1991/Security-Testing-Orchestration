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
    # Opt-in only: for a target sitting behind a bot-challenge (e.g.
    # Cloudflare's "Performing security verification" interstitial) that
    # STOF's own automated browser can never pass on its own. When True,
    # `main.py` skips the normal FormLoginProvider flow for the test
    # role entirely and instead connects over CDP to a real, human-
    # operated browser (see `stof/auth/assisted_login.py` and
    # `stof/recorder/cdp.py`) that has already cleared the challenge --
    # the human's real browser keeps handling that role's traffic for
    # the whole scan, since a captured cookie alone does not survive a
    # handoff to a different browser/IP (Cloudflare's clearance is
    # bound to the fingerprint that earned it, confirmed via research
    # this session). Every target defaults to False -- a normal target
    # with no bot-challenge is completely unaffected by this feature.
    requires_assisted_login: bool = False


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
    file_upload_tests: bool = False
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
    committed to the repo.

    `enabled` and `run_active_scan` are deliberately SEPARATE flags, not
    one -- a real bug found live: `enabled` used to gate both "capture
    evidence for STOF's own findings via Burp's proxy" (explicitly
    requested, read-only from Burp's own scanning perspective, fast)
    AND "let Burp additionally run its own Active Scan" (a much bigger,
    slower, real-attack-payload operation the user explicitly did NOT
    ask for) as one switch. The result: every scan silently also
    triggered a full Burp Active Scan and then blocked on it via
    `asyncio.gather()`, turning even a single-module sanity scan into a
    30-minute wait for Burp's own crawl+audit to finish or time out --
    confirmed live by querying Burp's own REST API mid-scan and finding
    it genuinely still crawling, not hung. `enabled` now means only
    "Burp integration is on" (config UI, evidence capture); the much
    bigger blast-radius Active Scan needs `run_active_scan` explicitly
    true as well.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    # Burp's own Active Scan sends real attack payloads at the live
    # target and can run for a long time -- opt-in separately from
    # `enabled` (see class docstring). False by default even when Burp
    # integration itself is on.
    run_active_scan: bool = False
    api_url: str = "http://127.0.0.1:1337"
    # Burp's intercepting PROXY listener -- distinct from api_url (the
    # REST API, scan control only). Traffic sent through this is what
    # actually lands in Burp's own Proxy history; used by
    # `engine/burp_capture.py` to get a real request/response captured
    # for a confirmed finding, since the REST API itself has no general
    # proxy-history query endpoint to pull one back after the fact.
    proxy_url: str = "http://127.0.0.1:8080"
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
