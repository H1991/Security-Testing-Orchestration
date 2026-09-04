# STOF — Security Testing Orchestration Framework
## Technical overview for external review

*Written for sharing with another AI model / external reviewer to get a second opinion on architecture, coverage, and open risks. Everything below reflects the actual, current state of the codebase — not aspirational scope.*

---

## 1. What it is

STOF is a CLI-first, Python + Playwright automated security testing (DAST) tool focused on authentication, session, and application-layer vulnerabilities. It drives a real headless browser through a target application, discovers its attack surface via an authenticated crawl, then runs a library of vulnerability-detection techniques against the discovered endpoints — producing HTML/JSON/Excel reports plus per-finding evidence (screenshots, raw request/response).

A FastAPI + vanilla JS web console sits on top of the CLI (`stof scan` etc. run as real OS subprocesses of the console, not in-process), giving a non-CLI operator a UI to configure targets/credentials, launch scans, and browse findings.

**Stack**: Python 3.11, Playwright (async), SQLite, Click (CLI), FastAPI + uvicorn (console), Jinja2 (HTML reports), openpyxl (Excel reports), pytest.

---

## 2. Architecture (layered, loosely coupled)

Each layer is an independent package communicating only through shared dataclasses/Pydantic models — no layer imports another layer's internals directly; the orchestrator (`stof/main.py`) is the one place that ties layers together.

```
Layer 1  config/          Pydantic config schema, {{env:VAR}} secret resolution
Layer 2  core/             Job orchestration, CLI entry point (main.py)
Layer 3A recorder/         CDP-attach workflow recording (operator's own browser)
Layer 3B engine/           Playwright replay, multi-session pool, request interception
Layer 4  auth/             AuthProvider implementations (see §4)
Layer 5  session/          Session cache, refresh/re-auth, SQLite-backed crash resume
Layer 6  workflows/        Recorded-workflow repository + replay runner
Layer 7  crawler/          Authenticated BFS crawl, form + API endpoint discovery
Layer 9  modules/          Vulnerability detection modules (the actual test techniques)
Layer 10 findings/         Normalized Finding schema, SQLite persistence
Layer 12 evidence/         Screenshot/request-response capture per finding
Layer 13 reporting/        HTML/JSON/Excel report generation
Layer 3C engine/burp_*     Optional Burp Suite Pro integration (see §6)
```

---

## 3. Vulnerability coverage — what's actually implemented

**143 individual techniques across 14 active modules**, all with real detection logic (not stubs), each mapped to a real CWE/OWASP WSTG reference:

| Module | Techniques | Notable coverage |
|---|---:|---|
| Authentication (`auth_tests` + `session_weakness_tests`) | 31 | Lockout bypass via spoofed XFF, session fixation, logout invalidation, concurrent-session handling, password policy |
| IDOR (`idor_tests`) | 46 (19 in default profile) | Horizontal/vertical object access, HTTP-method-override bypass, tenant-scope escape |
| Configuration (`configuration_tests`) | 15 | Admin panel exposure, CORS, CSP, security headers, mixed content, **TLS certificate expiry/chain validation**, path-relative stylesheet import (PRSSI) |
| Information Disclosure (`disclosure_tests`) | 10 | PII in API responses/URLs, source map/VCS exposure, secrets in HTML comments, path traversal |
| SQL Injection (`sqli_tests`) | 8 | Error-based, boolean-blind, time-blind, login-bypass |
| Cross-Site Scripting (`xss_tests`) | 8 | Reflected (3 context variants), stored (plant/verify), **DOM-based XSS (real in-browser execution confirmation)**, **DOM-based open redirect**, **DOM data manipulation (storage/attribute sink instrumentation)**, CSS injection |
| JWT / API Token (`jwt_tests`) | 8 | Signature mismatch, `alg:none`, weak HMAC brute-force, RS256→HS256 confusion, claim tampering, replay-after-logout, exposure scanning, `kid` header injection |
| SSRF (`ssrf_tests`) | 7 | Including OOB callback support via operator-supplied collaborator |
| CSRF (`csrf_tests`) | 6 | Missing token, stripped-token acceptance, Origin/Referer spoofing |
| Deserialization (`deserialization_tests`) | 6 | Fingerprinting + format discovery (RCE gadget-chain sending deliberately NOT automated — see §7) |
| Business Logic / Identity (`business_logic_tests`) | 5 | Reserved-username registration, self-assigned privilege, workflow-step skipping, race condition, sequential usage-limit bypass |
| GraphQL (`graphql_tests`) | 5 | Introspection, field/object-level authorization |
| File Upload (`file_upload_tests`) | 2 | Dangerous-extension acceptance, double-extension bypass (disabled by default — real write action) |
| Injection Variants (`injection_variants_tests`) | 2 | HTTP parameter pollution, CSV/formula injection |
| Web Cache Poisoning/Deception (`cache_tests`) | 2 | |

**Checklist coverage against the project's own tracked 80-item OWASP WSTG/API checklist: 45/80 enabled.** The remaining 35 are *explicitly* documented as gaps, not silently missing — categorized as:
- **Phase-2-deferred by design**: OAuth, SAML, MFA (explicit project rule — not started even if asked)
- **Declined on safety grounds**: DoS-shaped techniques (XML bomb, resource-exhaustion probes) — refused as real denial-of-service against a live target, not a "safe" version built instead
- **Needs app-specific knowledge a generic scanner can't safely infer**: negative-amount/payment tampering, RBAC permission matrices, black-box timing oracles — documented rationale in code, not rushed into false-positive-prone heuristics
- **Structurally invisible to black-box testing**: server-log-dependent checks (e.g. "are failed logins logged server-side")

---

## 4. Authentication support

Four real mechanisms, auto-detected/operator-selected per target role (admin/normal, extensible beyond two):

1. **Form login** (`form_login`) — generic candidate-selector auto-detection (no CSS selectors required for most targets), with manual override support. As of this session, also auto-detects and captures **localStorage/sessionStorage-based bearer tokens** for modern SPAs that don't use cookies at all.
2. **JWT / API token** (`jwt`) — pre-issued token injected as `Authorization: Bearer`, with optional token-endpoint exchange and expiry tracking via the JWT's own `exp` claim.
3. **Manual session cookies** — operator captures a session in their own real browser, pastes the cookie header into the console; STOF seeds it directly and skips login entirely for that role. Documented limitation: doesn't help against cookies bound to the originating IP/TLS fingerprint (e.g. Cloudflare's `cf_clearance`).
4. **Assisted login (CDP-driven, human-in-the-loop)** — built, then *intentionally paused*: a server-side headless browser with live screencast + input relay let an operator manually clear a bot challenge once, with the session then reused for the whole scan. Root cause for pausing: Cloudflare Turnstile (and similar) detect the CDP/automation fingerprint itself (`navigator.webdriver`, headless rendering signature), independent of who's actually clicking — so this doesn't reliably work against Cloudflare-protected targets without a further headed-in-Xvfb rework (not yet done). Backend fully intact, UI trigger hidden pending that rework.

---

## 5. Session-aware scanning

- One `Session` per role, cached and reused across the whole scan (`SessionManager`), automatically refreshed/re-authenticated only when actually needed (`needs_refresh()`), persisted to SQLite for crash-resume.
- `SessionPool` maintains one browser context per role, reused across modules within a scan.
- Modules never manage their own auth — they call `session_manager.get_session(role, page)` and get back a ready session regardless of which of the 4 mechanisms above produced it.

---

## 6. Optional Burp Suite Pro integration

Two independent toggles (deliberately split — confirmed a real prior bug where one flag silently enabled both):
- **Evidence capture** (`burp.enabled`): after a scan, every confirmed finding gets one representative request re-sent through Burp's own proxy listener, landing in Burp's Proxy history *and* appended (never overwriting) onto the Finding's own evidence. Confirmed working end-to-end in a real scan this session (24/28 findings enriched).
- **Active Scan** (`burp.run_active_scan`): drives Burp's REST API to additionally run Burp's own scanner and merge its issues in. Requires Burp's REST API service enabled separately in Burp's own settings.

---

## 7. Explicit safety boundaries (by design, not oversight)

- Every write-verb/state-changing technique (account creation, cache-poisoning confirmation, file upload, workflow-step probes) is gated behind a manually-armed `allow_state_changing_probes` flag, off by default.
- RCE gadget-chain sending, real DoS payloads, and TLS/bot-detection evasion are explicitly **not automated** — detection/fingerprinting only, with the actual exploit step left to a human reviewer.
- XSS/SQLi techniques use unique per-run random markers and response-inspection (not real page rendering) wherever possible; the one exception (DOM-based XSS) navigates a real browser but only ever fires a harmless `confirm()` dialog, auto-dismissed immediately.

---

## 8. Test coverage / quality gates

- **1356 passing unit tests**, 1 pre-existing unrelated failure tracked and left untouched.
- ruff + radon (cyclomatic complexity) enforced on every edit via a blocking pre-commit-style hook.
- Every new technique this session was verified two ways: unit tests with mocked HTTP, *and* a live scan against a real target (`demo.testfire.net`, a public OWASP-adjacent demo banking app) with log inspection.

---

## 9. Known issues / open questions worth a second opinion

1. **Assisted login vs. modern bot detection** — is there a better architectural answer than "headed Chromium in a virtual display" for defeating fingerprint-based bot detection while a human is genuinely driving the browser? Is this even the right problem to keep solving, vs. steering users toward IP-allowlisting/staging environments?
2. **No authentication on the web console itself** — confirmed gap, not yet fixed. Currently mitigated only by "don't expose it publicly." What's the minimum viable auth layer for a tool like this (basic auth behind a reverse proxy vs. building real auth in)?
3. **Scan reliability under resource pressure** — observed one real browser-driver crash mid-scan on a resource-constrained shared machine (`Connection closed while reading from the driver`); no retry/backoff logic exists for a Playwright driver disconnect mid-scan. Worth a resilience pass?
4. **Containerization** — no Dockerfile yet. Playwright + Chromium's OS-level dependencies, SQLite state persistence, and the optional same-host Burp Suite Pro dependency all need to be reflected in a real deployment story for shipping to a client.
5. **`MODULE_EXECUTION_ORDER` class of bug** — found and fixed one real instance this session (a hardcoded module list that silently drifted out of sync with the actual registered module set, dropping 5 modules from every default scan run with no warning). Worth asking: is there a structural way to make "the enabled-module list" have a single source of truth instead of three separate registries (`ModulesConfig` fields, `MODULE_EXECUTION_ORDER`, `MODULE_FACTORIES`) that can independently drift?
