# STOF — Security Testing Orchestration Framework
## CLAUDE.md — Project Architecture & Development Guide

> **AI Instruction**: This file is the single source of truth for STOF.
> Read it fully before writing any code, suggesting any change, or answering
> any architecture question. Do not deviate from the module boundaries,
> file layout, or naming conventions defined here without explicit instruction.

---

# Code Quality Standards

When writing or modifying code, optimize for:
Same functionality + same tests + same security + lower complexity + less duplication + fewest unnecessary dependencies.

Do NOT optimize for minimum lines of code alone. Do NOT invent unnecessary
abstractions, wrapper classes, or config layers "for extensibility" unless asked.

Before considering a task done:
1. Run the test suite — it must pass.
2. Run the linter/static analysis tool for this language.
3. Check for duplicated logic (DRY violations) — extract shared code instead of copy-pasting.
4. Report LOC, cyclomatic complexity, and duplication delta vs. the previous version.


---
name: dry-code-review
description: Use after writing or refactoring code to check for unnecessary bulk, duplication, or over-engineering. Trigger whenever the user asks to "clean up", "simplify", "make DRY", or after any multi-file code generation task.
---

# DRY Code Review Loop

1. Run the existing test suite. Record pass/fail.
2. Run static analysis for the language in use (see tools below). Record:
   - LOC
   - Cyclomatic complexity per function
   - Duplicate code blocks
   - Function/class count
   - New dependency count
3. If duplication or complexity is high relative to functionality, propose a
   refactor that removes it WITHOUT changing behavior.
4. Apply the refactor.
5. Re-run tests. They must still pass.
6. Re-run static analysis. Report the before/after diff in a short table.

Tools by language:
- Python: ruff, pylint, radon (complexity), flake8-duplicate-code
- JS/TS: eslint, jscpd (duplication)
- Java/general: PMD, Sonar
- Multi-language security+quality: semgrep

## Project Summary

STOF is a **CLI-first**, **Python + Playwright** automated security testing
framework focused on authentication and session vulnerabilities. It is
designed to be **loosely coupled** — every layer is an independent Python
module with a clean interface. Modules communicate through shared data
contracts (dataclasses / TypedDicts), never through direct imports of
each other's internals.

**Phase 1 scope** (current):
- Layers 1–7, 12 (evidence), 13 (reporting)
- Auth: Form Login + JWT/API Token only
- No Burp Suite integration (Layer 3C deferred to Phase 2)
- No AI analysis (Layer 14 deferred to Phase 2)
- Interface: **CLI only** (no Web UI in Phase 1)

**Stack**: Python 3.11 · Playwright (async) · SQLite · Click (CLI) · Jinja2
(HTML reports) · pytest (unit tests)

---

## Repository Layout

```
stof/
│
├── CLAUDE.md                   ← this file (always read first)
├── README.md
├── pyproject.toml              ← single place for deps and tool config
├── .env.example                ← env var template (never commit .env)
│
├── config/
│   ├── config.json             ← main config (targets, browser, modules)
│   ├── users.json              ← roles and credentials
│   └── auth_tests.json         ← test cases and payloads
│
├── stof/                       ← main package
│   │
│   ├── __init__.py
│   ├── main.py                 ← CLI entry point (Click)
│   │
│   ├── core/                   ← Layer 2 — Orchestrator
│   │   ├── __init__.py
│   │   ├── orchestrator.py     ← job scheduling, lifecycle, fan-out
│   │   ├── job.py              ← Job dataclass and status enum
│   │   └── logger.py           ← structured logging (all layers use this)
│   │
│   ├── config/                 ← Layer 1 — Configuration
│   │   ├── __init__.py
│   │   ├── loader.py           ← loads + validates all config files
│   │   ├── schema.py           ← Pydantic models for config contracts
│   │   └── validator.py        ← config validation rules
│   │
│   ├── recorder/               ← Layer 3A — Browser Recorder
│   │   ├── __init__.py
│   │   ├── recorder.py         ← CDP attach, event capture
│   │   ├── event_handler.py    ← click / input / XHR / navigation capture
│   │   └── exporter.py         ← emits neutral JSON actions
│   │
│   ├── engine/                 ← Layer 3B — Playwright Engine
│   │   ├── __init__.py
│   │   ├── playwright_engine.py ← async workflow replay
│   │   ├── interceptor.py      ← request/response interception + injection
│   │   ├── multi_session.py    ← concurrent multi-user session management
│   │   └── screenshot.py       ← screenshot on assertion / finding
│   │
│   ├── auth/                   ← Layer 4 — Authentication Manager
│   │   ├── __init__.py
│   │   ├── base.py             ← AuthProvider abstract base class
│   │   ├── form_login.py       ← form-based login (Phase 1)
│   │   ├── jwt_auth.py         ← JWT / API token injection (Phase 1)
│   │   ├── oauth.py            ← OAuth 2.0 / OIDC (Phase 2 stub)
│   │   ├── saml.py             ← SAML (Phase 2 stub)
│   │   └── mfa.py              ← MFA / TOTP (Phase 2 stub)
│   │
│   ├── session/                ← Layer 5 — Session Manager
│   │   ├── __init__.py
│   │   ├── session_manager.py  ← persistence, re-auth, role switching
│   │   ├── token_refresh.py    ← JWT refresh logic
│   │   └── session_store.py    ← in-memory + SQLite session store
│   │
│   ├── workflows/              ← Layer 6 — Workflow Repository
│   │   ├── __init__.py
│   │   ├── repository.py       ← load / store / list workflows
│   │   ├── models.py           ← NeutralAction, Workflow dataclasses
│   │   └── runner.py           ← executes a workflow via Playwright engine
│   │
│   ├── crawler/                ← Layer 7 — Crawler & Endpoint Discovery
│   │   ├── __init__.py
│   │   ├── crawler.py          ← BFS crawl via Playwright (authenticated)
│   │   ├── form_detector.py    ← discover all input forms
│   │   ├── api_sniffer.py      ← capture XHR/fetch API calls
│   │   └── endpoint_store.py   ← normalise + write endpoints.json
│   │
│   ├── modules/                ← Layer 9 — Vulnerability Modules (plugins)
│   │   ├── __init__.py
│   │   ├── base.py             ← VulnModule abstract base class
│   │   ├── registry.py         ← module loader (reads config flags)
│   │   ├── jwt_tests.py        ← JWT replay, expiry, alg:none (Phase 1)
│   │   ├── auth_tests.py       ← session fixation, brute, lockout (Phase 1)
│   │   ├── idor_tests.py       ← horizontal + vertical priv-esc (Phase 1)
│   │   ├── oauth_tests.py      ← Phase 2 stub
│   │   ├── csrf_tests.py       ← Phase 2 stub
│   │   └── race_tests.py       ← Phase 2 stub
│   │
│   ├── findings/               ← Layer 10 — Unified Findings Store
│   │   ├── __init__.py
│   │   ├── models.py           ← Finding dataclass (normalised schema)
│   │   └── store.py            ← in-memory + SQLite findings persistence
│   │
│   ├── evidence/               ← Layer 12 — Evidence Collection
│   │   ├── __init__.py
│   │   └── collector.py        ← screenshots, req/resp, session state
│   │
│   └── reporting/              ← Layer 13 — Reporting Engine
│       ├── __init__.py
│       ├── reporter.py         ← orchestrates all report formats
│       ├── html_report.py      ← Jinja2 HTML report
│       ├── json_report.py      ← machine-readable JSON
│       ├── excel_report.py     ← openpyxl Excel (VAPT format)
│       └── templates/
│           └── report.html.j2  ← Jinja2 template
│
├── data/                       ← runtime output (git-ignored)
│   ├── sessions/               ← session files
│   ├── evidence/               ← screenshots and logs
│   ├── workflows/              ← recorded workflow JSON files
│   ├── reports/                ← generated HTML/JSON/Excel
│   └── stof.db                 ← SQLite database
│
└── tests/
    ├── unit/                   ← pytest unit tests per module
    └── integration/            ← end-to-end tests against DVWA / JuiceShop
```

---

## Layer 1 — Configuration Layer

**Package**: `stof/config/`
**Responsibility**: Load, validate, and expose all configuration. No other
module reads config files directly — they always call the config loader.

### Config files

**`config/config.json`** — main runtime config:
```json
{
  "target": {
    "base_url": "http://localhost:3000",
    "login_url": "http://localhost:3000/login"
  },
  "browser": {
    "headless": true,
    "slowmo_ms": 0,
    "proxy": null
  },
  "modules": {
    "crawler": true,
    "jwt_tests": true,
    "auth_tests": true,
    "idor_tests": false,
    "oauth_tests": false,
    "csrf_tests": false
  },
  "output": {
    "reports_dir": "data/reports",
    "evidence_dir": "data/evidence"
  }
}
```

**`config/users.json`** — role-to-credential map:
```json
{
  "users": [
    {
      "id": "admin-01",
      "role": "admin",
      "username": "admin@target.com",
      "password": "{{env:ADMIN_PASSWORD}}",
      "auth_type": "form_login"
    },
    {
      "id": "user-01",
      "role": "normal",
      "username": "user@target.com",
      "password": "{{env:USER_PASSWORD}}",
      "auth_type": "jwt"
    }
  ]
}
```

> `{{env:VAR}}` tokens are resolved at load time from environment variables.
> Passwords are NEVER stored in plain text in config files.

**`config/auth_tests.json`** — test case and payload library:
```json
{
  "tests": [
    {
      "id": "AUTH-001",
      "name": "Session Fixation",
      "module": "auth_tests",
      "enabled": true,
      "payloads": ["JSESSIONID=FIXED123"],
      "severity": "High"
    }
  ]
}
```

### Key rules
- `loader.py` is the only file that reads from disk. All other modules
  receive a `Config` Pydantic model object.
- `{{env:VAR}}` substitution happens in `loader.py` before validation.
- `validator.py` raises `ConfigError` (never a raw exception) if any
  required field is missing or malformed.
- Config is loaded once at startup and passed down via dependency injection.

---

## Layer 2 — Orchestrator / Scan Engine

**Package**: `stof/core/`
**Responsibility**: Fan out work to Layer 3A/3B/7, manage job lifecycle,
checkpoint state, handle retries, trigger reporting.

### Job lifecycle
```
QUEUED → RUNNING → [PAUSED] → COMPLETED
                 ↘ FAILED → RETRY → RUNNING
```

### Key rules
- `orchestrator.py` imports from `config`, `engine`, `recorder`,
  `crawler`, `auth`, `session`, `workflows`, `modules`, `findings`,
  `evidence`, `reporting`. It is the **only** module that ties layers
  together. No other module imports from orchestrator.
- Each scan run gets a `Job` with a UUID, start time, target URL,
  enabled modules list, and status.
- State is checkpointed to SQLite after each layer completes, so a
  crash at Layer 7 can resume from Layer 7, not Layer 1.

---

## Layer 3A — Browser Recorder

**Package**: `stof/recorder/`
**Responsibility**: Attach to a running Chrome/Edge instance via CDP,
capture all user interactions, and export them as neutral JSON actions.

### How it works
1. Start Chrome with `--remote-debugging-port=9222`
2. `recorder.py` connects via Playwright's CDP attach (not a new browser —
   it attaches to the *existing* browser the tester is using)
3. `event_handler.py` listens for: `Page.navigate`, `Input.dispatchKeyEvent`,
   mouse clicks, XHR/fetch via `Network.*` events
4. `exporter.py` serialises captured events to a `Workflow` JSON file
   in `data/workflows/`

### Neutral JSON action format
```json
{
  "workflow_id": "wf-20260720-001",
  "target_url": "http://localhost:3000",
  "recorded_at": "2026-07-20T10:00:00Z",
  "actions": [
    {"type": "navigate", "url": "http://localhost:3000/login"},
    {"type": "fill",     "selector": "#username", "value": "{{user.username}}"},
    {"type": "fill",     "selector": "#password", "value": "{{user.password}}"},
    {"type": "click",    "selector": "button[type=submit]"},
    {"type": "wait_for", "selector": ".dashboard", "timeout_ms": 5000}
  ]
}
```

> `{{user.username}}` and `{{user.password}}` are template tokens resolved
> at replay time from `users.json`. Never hardcode credentials in workflows.

### Key rules
- Recorder is an **optional, separate CLI command**: `stof record`
- It does NOT run during a scan. Scan uses pre-recorded workflows from
  `data/workflows/`.
- Recorder output is always written to `data/workflows/` and committed
  to the repo (credentials are tokenised, not literal values).

---

## Layer 3B — Playwright Engine

**Package**: `stof/engine/`
**Responsibility**: Replay neutral JSON workflows, support concurrent
multi-user sessions, intercept and inject into requests, capture
screenshots on finding.

### Key rules
- All Playwright code is **async** (`asyncio` + `async_playwright`).
- `playwright_engine.py` exposes a single async interface:
  `async def replay(workflow: Workflow, session: Session) -> ReplayResult`
- `interceptor.py` registers `page.on("request")` and
  `page.on("response")` handlers. Vulnerability modules call
  `interceptor.inject_payload(pattern, payload)` — they do NOT
  manipulate pages directly.
- `multi_session.py` manages a pool of browser contexts (one per user
  role). Contexts are reused across test runs within a scan.
- `screenshot.py` is called by vulnerability modules when a finding
  is confirmed — never called speculatively.
- **Layer 3C (Burp Controller) is a stub in Phase 1.** The file
  `engine/burp_controller.py` exists but raises `NotImplementedError`.
  The orchestrator skips it when `burp.enabled` is false in config.

---

## Layer 4 — Authentication Manager

**Package**: `stof/auth/`
**Phase 1 scope**: Form Login + JWT/API Token only.

### Abstract base class

Every auth provider implements this interface:

```python
# stof/auth/base.py
from abc import ABC, abstractmethod
from stof.session.models import Session

class AuthProvider(ABC):
    @abstractmethod
    async def authenticate(self, user: UserConfig, page) -> Session:
        """Perform login and return a populated Session."""
        ...

    @abstractmethod
    async def refresh(self, session: Session, page) -> Session:
        """Refresh the session. Raise AuthExpiredError if impossible."""
        ...

    @abstractmethod
    async def is_authenticated(self, session: Session, page) -> bool:
        """Check if the current session is still valid."""
        ...
```

### Form Login (`stof/auth/form_login.py`)
- Navigates to `config.target.login_url`
- Fills username + password selectors from `users.json`
- Submits the form
- Waits for a success selector or URL change
- Captures resulting cookies into a `Session` object
- Detects login failure and raises `AuthFailedError`

### JWT / API Token (`stof/auth/jwt_auth.py`)
- Reads the token from `users.json` (via `{{env:VAR}}`) or performs
  a token endpoint call if `token_url` is set
- Injects the token as an `Authorization: Bearer <token>` header via
  the Playwright request interceptor (not via form)
- Tracks token expiry from the JWT `exp` claim
- On expiry, calls the `refresh_url` if configured, else raises
  `AuthExpiredError` for the session manager to handle

### Phase 2 stubs
`oauth.py`, `saml.py`, `mfa.py` exist as stub files with:
```python
raise NotImplementedError("Phase 2 — not yet implemented")
```
This ensures Phase 2 work has a clear home without polluting Phase 1.

### Auth provider registry
```python
# stof/auth/__init__.py
AUTH_PROVIDERS = {
    "form_login": FormLoginProvider,
    "jwt":        JWTAuthProvider,
    # Phase 2:
    # "oauth":   OAuthProvider,
    # "saml":    SAMLProvider,
}

def get_provider(auth_type: str) -> AuthProvider:
    if auth_type not in AUTH_PROVIDERS:
        raise ConfigError(f"Unknown auth_type: {auth_type}")
    return AUTH_PROVIDERS[auth_type]()
```

---

## Layer 5 — Session Manager

**Package**: `stof/session/`
**Responsibility**: Maintain live sessions for all user roles across the
duration of a scan. Handle expiry, re-authentication, and role switching.

### Session model
```python
@dataclass
class Session:
    session_id: str           # UUID
    user_id:    str           # from users.json
    role:       str           # "admin" | "normal" | ...
    auth_type:  str           # "form_login" | "jwt"
    cookies:    dict          # name → value
    headers:    dict          # e.g. {"Authorization": "Bearer ..."}
    created_at: datetime
    expires_at: datetime | None
    is_valid:   bool = True
```

### Key rules
- `session_manager.py` holds a dict of `role → Session`.
- Before each vulnerability test, the module calls
  `session_manager.get_session(role)` — it never manages its own auth.
- If `session.is_valid` is False or session is expired,
  `session_manager` calls the auth provider's `refresh()` silently.
- If refresh fails, it calls `authenticate()` from scratch.
- Sessions are persisted to SQLite (`session_store.py`) so a resume
  after crash can reuse valid sessions.

---

## Layer 6 — Workflow Repository

**Package**: `stof/workflows/`
**Responsibility**: Load, store, and version neutral JSON workflow files.
Provide a `runner.py` that executes a workflow via the Playwright engine.

### Key rules
- `repository.py` scans `data/workflows/` and indexes all `.json` files.
- Workflows are identified by `workflow_id` (from the JSON) and a
  human-readable `name`.
- `runner.py` is the only file that calls `engine.playwright_engine.replay()`.
  Vulnerability modules call `runner.run_workflow(workflow_id, session)`,
  never the engine directly.
- Credential tokens (`{{user.username}}`) are resolved by `runner.py`
  at execution time from the active `Session`.

---

## Layer 7 — Crawler & Endpoint Discovery

**Package**: `stof/crawler/`
**Technology**: Playwright (async) — fully browser-based, authenticated crawl.
**This is a Phase 1 module.**

### What it does
After authentication, the crawler maps the full attack surface of the
target application. It runs as a separate phase before any vulnerability
modules execute, so all modules benefit from a complete endpoint map.

### `crawler.py` — BFS crawl
```python
async def crawl(start_url: str, session: Session, config: CrawlerConfig) -> list[Endpoint]:
    """
    BFS crawl from start_url using an authenticated Playwright browser context.
    Returns a deduplicated list of Endpoint objects.
    """
```
- Uses the authenticated browser context from the session manager
  (so it crawls as a logged-in user — no re-authentication needed)
- BFS queue of URLs, visited set to prevent loops
- Respects `max_depth` and `max_pages` from config to prevent runaway
- Stays within the same origin as `target.base_url`

### `form_detector.py` — form surface discovery
- On each crawled page, scans DOM for `<form>` elements
- Extracts: action URL, method, all input names and types
- Records as `FormEndpoint` — these are priority targets for auth tests

### `api_sniffer.py` — XHR/fetch endpoint capture
- Registers `page.on("request")` during crawl
- Captures all `XHR` and `fetch` requests made by the page
- Extracts: URL, method, request headers, content-type
- Deduplicates by `(method, path)` pattern

### `endpoint_store.py` — normalise and persist
```python
@dataclass
class Endpoint:
    url:         str
    method:      str         # GET | POST | PUT | DELETE | PATCH
    endpoint_type: str       # "page" | "form" | "api" | "websocket"
    parameters:  list[str]   # query params or body field names
    auth_required: bool
    discovered_at: datetime
```
- Writes `data/endpoints.json` — consumed by all vulnerability modules
- Also persists to SQLite for cross-scan comparison

### Key rules
- Crawler runs as its own async task, started by the orchestrator
  after authentication is confirmed.
- Crawler does **not** send attack payloads — it is passive discovery only.
- All vulnerability modules read from `endpoints.json` via
  `endpoint_store.load()` — they never call the crawler directly.
- Crawler is enabled/disabled via `modules.crawler: true/false` in config.

---

## Layers 9–13 (Abbreviated for Phase 1)

### Layer 9 — Vulnerability Modules

**Package**: `stof/modules/`

Every module implements:
```python
class VulnModule(ABC):
    module_id:   str     # e.g. "jwt_tests"
    name:        str
    phase:       int     # 1 or 2

    @abstractmethod
    async def run(
        self,
        endpoints: list[Endpoint],
        session_manager: SessionManager,
        runner: WorkflowRunner,
        evidence: EvidenceCollector,
    ) -> list[Finding]:
        ...
```

**Phase 1 active modules**: `jwt_tests`, `auth_tests`, `idor_tests`
**Phase 2 stubs**: `oauth_tests`, `csrf_tests`, `race_tests`

`registry.py` reads `config.modules` and only instantiates modules where
the flag is `true`. Adding a new module = create a new file + register
it in `registry.py`. No changes to orchestrator or any other module.

### Layer 10 — Unified Findings Store

**Package**: `stof/findings/`

```python
@dataclass
class Finding:
    finding_id:    str
    module_id:     str
    vuln_type:     str      # e.g. "Session Fixation"
    severity:      str      # Critical | High | Medium | Low | Info
    cvss_score:    float
    endpoint:      Endpoint
    user_role:     str
    request_raw:   str
    response_raw:  str
    evidence_refs: list[str]   # paths to screenshots / logs
    description:   str
    recommendation: str
    discovered_at: datetime
    scanner_source: str     # "stof" | "burp" (Phase 2)
```

### Layer 12 — Evidence Collection

**Package**: `stof/evidence/`
- `collector.py` is called by vulnerability modules via:
  `await evidence.capture(page, session, label="finding-AUTH-001")`
- Captures: screenshot (PNG), request/response (text), session cookies
- Stores to `data/evidence/<scan_id>/<label>/`
- Returns a list of file paths stored in `Finding.evidence_refs`

### Layer 13 — Reporting Engine

**Package**: `stof/reporting/`
- `reporter.py` is called by the orchestrator at the end of a scan
- Input: `list[Finding]`, scan metadata (target, duration, user roles)
- Output: HTML report, JSON report, Excel report in `data/reports/`
- HTML uses Jinja2 template with embedded screenshots (base64)
- Excel format follows standard VAPT report structure

---

## CLI Interface

**Entry point**: `stof/main.py` using Click.

```bash
# Record a workflow (manual browser session)
stof record --output data/workflows/login_flow.json

# Run a full scan
stof scan \
  --config config/config.json \
  --users config/users.json \
  --tests config/auth_tests.json \
  --modules crawler,jwt_tests,auth_tests \
  --output data/reports/

# Run crawler only (endpoint discovery without vuln tests)
stof crawl \
  --config config/config.json \
  --output data/endpoints.json

# Run a specific module against a known endpoint list
stof test \
  --module jwt_tests \
  --endpoints data/endpoints.json \
  --output data/reports/

# List available modules
stof modules list

# Show last scan summary
stof report --last
```

### Output during a scan (stdout)
```
[STOF] Scan started: target=http://localhost:3000 scan_id=abc123
[AUTH]  ✓ Authenticated as admin (form_login)
[AUTH]  ✓ Authenticated as user  (jwt)
[CRAWL] Discovered 47 endpoints (12 forms, 23 API, 12 pages)
[MOD]   Running jwt_tests on 23 API endpoints...
[FIND]  ⚠ HIGH   JWT alg:none accepted — /api/v1/users (AUTH-003)
[MOD]   Running auth_tests on 12 form endpoints...
[FIND]  ⚠ HIGH   Session not invalidated after logout — /logout (AUTH-007)
[REPORT] HTML  → data/reports/scan_abc123.html
[REPORT] JSON  → data/reports/scan_abc123.json
[REPORT] Excel → data/reports/scan_abc123.xlsx
[STOF]  Scan complete. 2 findings (2 High, 0 Medium, 0 Low)
```

---

## Data Contracts — Module Communication Rules

Modules communicate **only** through these shared types.
Direct imports between sibling modules are forbidden.

```
config  → Config (Pydantic model)
crawler → list[Endpoint]
auth    → Session
modules → list[Finding]
evidence → list[str] (file paths)
```

Allowed import directions:
```
main.py
  → core/orchestrator.py
      → config/loader.py
      → recorder/recorder.py
      → engine/playwright_engine.py
      → crawler/crawler.py
      → auth/*
      → session/session_manager.py
      → workflows/runner.py
      → modules/registry.py  → modules/*.py
      → findings/store.py
      → evidence/collector.py
      → reporting/reporter.py
```

**Forbidden**: `crawler` importing from `modules`, `modules` importing
from `auth`, `reporting` importing from `engine`, etc. If you need data
from another layer, receive it as a parameter — never import it directly.

---

## Phase 2 Additions (Do Not Implement Yet)

These are listed here so stubs are created with correct names:

| Layer | Addition |
|---|---|
| 3C | `engine/burp_controller.py` — Burp REST API integration |
| 4 | `auth/oauth.py`, `auth/saml.py`, `auth/mfa.py` |
| 8 | `core/test_orchestrator.py` — config-driven plugin loader |
| 9 | `modules/oauth_tests.py`, `modules/csrf_tests.py`, `modules/race_tests.py` |
| 11 | `findings/burp_normalizer.py` — normalize Burp findings into Finding schema |
| 14 | `analysis/ai_engine.py` — risk prioritization, deduplication |
| 15 | `ui/` — FastAPI + React Web UI |

---

## Development Rules for Claude

1. **Read this file first.** Never suggest changes that violate the module
   boundaries or import rules defined above.

2. **One module per task.** When asked to implement a layer, implement only
   that layer's package. Do not modify other packages unless explicitly asked.

3. **No cross-module imports between siblings.** If a module needs data from
   another, it receives it as a function parameter. Orchestrator is the only
   file that knows about multiple layers.

4. **Stubs over gaps.** Phase 2 components must exist as stub files with
   `raise NotImplementedError(...)`. Never leave a blank file or a TODO comment
   as a placeholder — it must be a real Python file with a real exception.

5. **Async throughout.** All Playwright interaction is `async`. Use `asyncio.gather()`
   for parallelism in the orchestrator. Never use `time.sleep()`.

6. **Credentials never in code.** All credentials come from environment
   variables via `{{env:VAR}}` resolution in `config/loader.py`.

7. **Tests alongside code.** Every new module gets a `tests/unit/test_<module>.py`
   with at minimum: a happy-path test, a failure test, and an input validation test.

8. **CLI is the interface.** Do not add Flask/FastAPI routes, HTML templates
   for a web server, or any HTTP server code in Phase 1.

9. **Phase 1 auth scope is fixed.** Do not implement OAuth, SAML, or MFA in
   Phase 1 even if asked. Create the stub and note it is Phase 2.

10. **Crawler is Playwright-only.** Do not use `requests`, `httpx`, `scrapy`,
    or any non-browser HTTP library in `stof/crawler/`. The crawler must use
    the authenticated browser context from the session manager.
