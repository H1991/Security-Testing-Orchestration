# STOF — Security Testing Orchestration Framework
## Technical overview for external review

*Written for sharing with another reviewer (human or AI) to get a second opinion on architecture, coverage, and open risks. Everything below reflects the actual, current state of the codebase — verified against real numbers from the running tool and the test suite, not aspirational scope. Last verified: 2026-09-10.*

---

## 1. What it is

STOF is a CLI-first, Python + Playwright automated security testing (DAST) tool focused on authentication, session, and application-layer vulnerabilities. It drives a real headless browser through a target application, discovers its attack surface via an authenticated crawl, then runs a library of vulnerability-detection techniques against the discovered endpoints — producing HTML/JSON/Excel reports plus per-finding evidence (screenshots, raw request/response).

A FastAPI + vanilla JS web console sits on top of the CLI (`stof scan` etc. run as real OS subprocesses of the console, not in-process), giving a non-CLI operator a UI to configure targets/credentials, launch and queue scans, and browse findings/trends across a whole application portfolio.

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
Layer 11 findings/burp_*   Normalizes Burp Suite Active Scan issues into STOF's Finding schema
Layer 12 evidence/         Screenshot/request-response capture per finding
Layer 13 reporting/        HTML/JSON/Excel report generation
Layer 15 ui/               FastAPI console + vanilla-JS single-page frontend (see §6)
Layer 3C engine/burp_*     Optional Burp Suite Pro integration (see §8)
recon/                     Passive tech-stack fingerprinting, misconfig/secrets/parameter discovery — runs automatically every scan, feeds the console's "Detected technologies" panel
```

---

## 3. Vulnerability coverage — what's actually implemented

**154 individual techniques across 27 test cases, in 15 active modules**, all with real detection logic (not stubs), each mapped to a real CWE/OWASP WSTG reference. Counted live from the running tool's own test catalog, not hand-maintained:

| Module | Techniques | Notable coverage |
|---|---:|---|
| Authentication (`auth_tests`) | 32 | Default credentials, weak password policy, password reset/change flows, session/rate-limit weaknesses (13 techniques alone), weak security questions, auth-schema bypass |
| IDOR / Access Control (`idor_tests` + mixins) | 29 | Broken access control, privilege escalation, IDOR, BOLA, BFLA, role manipulation, tenant-isolation BOLA — split across `bfla_tests.py`/`role_tests.py`/`mass_assignment_tests.py`/`tenant_tests.py` mixins composed into one module (see §2 note) |
| Configuration (`configuration_tests`) | 15 | Admin panel exposure, CORS, CSP, security headers, mixed content, TLS certificate expiry/chain validation, path-relative stylesheet import (PRSSI), cloud storage bucket exposure |
| Information Disclosure (`disclosure_tests`) | 12 | PII in API responses/URLs, source map/VCS exposure, secrets in HTML comments, path traversal |
| Cross-Site Scripting (`xss_tests`) | 9 | Reflected (3 context variants), **stored (plant/verify)**, **DOM-based XSS (real in-browser execution confirmation via `confirm()` dialog)**, DOM-based open redirect, DOM data manipulation, CSS injection, HTML injection |
| JWT / API Token (`jwt_tests`) | 8 | Signature mismatch, `alg:none`, weak HMAC brute-force, RS256→HS256 confusion, claim tampering, replay-after-logout, exposure scanning, `kid` header injection |
| SQL Injection (`sqli_tests`) | 8 | Error-based, boolean-blind, time-blind, login-bypass, header-based, second-order, JSON-body, cookie-based |
| Business Logic / Identity (`business_logic_tests`) | 7 | Reserved-username registration, self-assigned privilege, workflow-step skipping, **workflow state-machine modeling (every intermediate step probed, not just the last)**, race condition, sequential usage-limit bypass |
| SSRF (`ssrf_tests`) | 7 | Including OOB callback support via operator-supplied collaborator, server-side open redirect |
| CSRF (`csrf_tests`) | 6 | Missing token, stripped-token acceptance, Origin/Referer spoofing |
| Deserialization (`deserialization_tests`) | 6 | Fingerprinting + format discovery (RCE gadget-chain sending deliberately NOT automated — see §9) |
| Injection Variants (`injection_variants_tests`) | 6 | HTTP parameter pollution, CSV/formula injection, **OS command injection (time-based blind)**, **XXE**, **SSTI**, **NoSQL injection (MongoDB operator auth bypass)** |
| GraphQL (`graphql_tests`) | 5 | Introspection, field/object-level authorization |
| Web Cache Poisoning/Deception (`cache_tests`) | 2 | |
| File Upload (`file_upload_tests`) | 2 | Dangerous-extension acceptance, double-extension bypass (disabled by default — real write action) |

**Checklist coverage against the project's own tracked OWASP WSTG/API checklist has grown steadily; the remaining gaps are *explicitly* documented, not silently missing** — categorized as:
- **Phase-2-deferred by design**: OAuth, SAML, MFA (explicit project rule — not started even if asked)
- **Declined on safety grounds**: DoS-shaped techniques (XML bomb, resource-exhaustion probes) — refused as real denial-of-service against a live target, not a "safe" version built instead
- **Needs app-specific knowledge a generic scanner can't safely infer**: negative-amount/payment tampering, RBAC permission matrices, black-box timing oracles — documented rationale in code, not rushed into false-positive-prone heuristics
- **Structurally invisible to black-box testing**: server-log-dependent checks (e.g. "are failed logins logged server-side")
- **Real, currently-open gaps** (see §9): LDAP injection, blind XSS with a real out-of-band callback confirmation (distinct from the plant/verify Stored XSS above, which only checks a *specific* already-discovered endpoint), and a known-vulnerable-component/CVE-matching check against the fingerprinted tech stack

---

## 3.5 How vulnerability detection actually works — the detection-oracle taxonomy

This is the part most worth an external reviewer's scrutiny: STOF is not a payload-and-hope scanner. Every technique across all 154 reduces to one of a small number of **oracles** — a specific, falsifiable signal that separates "vulnerable" from "not," always compared against a baseline, never a bare status-code check. The same handful of oracle shapes get reused deliberately across modules (shared helper files like `_injection_shared.py`, `_idor_shared.py`) rather than reinvented per technique:

1. **Differential response comparison** — take a baseline (unmodified or benign-value request), then a payload request, and compare. A raw hash-equality check is deliberately avoided (`response_similarity()` uses `difflib.SequenceMatcher`, a graded closeness ratio) because a real dynamic page's timestamp/nonce/per-request id would make an exact-hash comparison over-flag on noise that has nothing to do with the injected value. Used by: boolean-blind SQLi, HTTP Parameter Pollution, XXE's file-read check.

2. **Fingerprint matching** — a curated list of real, specific signatures (database error strings, XML parser exceptions), checked as substrings, deliberately excluding generic words like "error" alone that would false-positive on any app error page. Used by: SQLi error-based, XXE's parser-error fallback.

3. **Timing-based blind detection** — inject a bounded sleep payload, measure the response-latency delta against a baseline, and — critically — **require the delay to repeat once before ever reporting it**, since a single slow response is exactly as likely to be network jitter as a real injected delay. Capped at one short delay (2–6s), never an open-ended or repeated-beyond-confirmation sleep, since this runs against real, often shared/third-party demo targets STOF doesn't own. Used by: SQLi time-based blind, the new OS Command Injection technique (4 shell-separator styles tried in sequence, stopping at first repeatable hit).

4. **Marker-based evaluation proof** — plant a unique, per-run-random string (`stofxss<8 hex chars>`, or two random integers for an arithmetic check) and require the *effect* of evaluation to appear (the computed product, the substituted file content) while the **raw, un-evaluated payload text is absent** from the response. This is what distinguishes "the app executed my input" from "the app just echoed it back" — the single most common false-positive shape in naive scanners. Used by: XSS reflected/stored, the new SSTI technique (polyglot `{{a*b}}`/`${a*b}`/`<%= a*b %>` across Jinja2/Twig/Freemarker/ERB syntax, checking the literal product appears while the raw expression text doesn't).

5. **Real in-browser execution confirmation** — for the one class where response-inspection is structurally insufficient (DOM-based XSS, whose sink may never touch the network — `location.hash` is never sent in an HTTP request at all), STOF navigates an actual Playwright `Page` with a `page.on('dialog')` listener registered *before* navigation, and only reports a FAIL when a dialog genuinely fires and its message contains this run's own marker. Genuine proof of execution, not a signal merely consistent with one.

6. **Plant-then-verify across role/time/endpoint** — a two-act technique: a low-privilege authenticated context plants a marker into a free-text field, then a *separate*, higher-privileged context later checks a *different* endpoint for that marker reflecting back unencoded. This is the real shape stored-XSS, second-order SQLi, and CSV/formula injection all disclosed reports (see knowledge bases) actually take — the injection point and the execution point are different requests, sometimes different users entirely.

7. **Authenticated-success differential, never a bare non-error status** — for auth-bypass-shaped techniques (SQLi login bypass, the new NoSQL operator injection), success requires either a redirect away from the login page or a JSON response carrying a plausible auth-token-shaped field that a definitely-wrong-credentials baseline lacks — never "the response wasn't a 4xx," since a rejected login routinely re-renders the same page with HTTP 200.

8. **Cross-identity confirmation for authorization bugs** — IDOR/BOLA findings require a *second, genuinely different* authenticated session independently reaching the same object, never single-session enumeration alone; a soft-403-aware classifier (`classify_response()`) treats a 200 whose body says "access denied" as DENIED rather than a false ALLOWED.

Every technique that plants real data or sends a real write is gated behind an explicit, per-target `allow_state_changing_probes` flag, off by default (§9). Every technique's evidence is a truncated, honestly-worded signal (`"a timing signal consistent with..."`, `"a candidate signal only: no data was extracted"`) — the codebase enforces a hard boundary between "STOF found a strong signal this technique class is present" and "STOF confirmed a working exploit," and never lets a Finding's own wording claim more than the oracle actually proved. A `Finding`'s declared `severity` and `cvss_score` are checked for consistency at construction time (`severity_for_score()`) and the object **raises** if they disagree — this caught a real bug during this session's development (a new XXE technique labeled `Critical` with a score that actually maps to `High`).

**Research grounding**: every technique traces to a real, cited source — a disclosed HackerOne/bug-bounty report, an OWASP WSTG methodology page, or PortSwigger's Web Security Academy — recorded in a per-module knowledge-base JSON under `stof/payloads/` (e.g. `sqli_knowledge_base.json` cites 4 specific disclosed HackerOne reports and what each contributed to the detection design; the newest, `injection_variants_knowledge_base.json`, cites the Rocket.Chat NoSQL-injection disclosures, the Glovo SSTI report, and four separate disclosed XXE reports against DoD/Starbucks/Semrush/X). This is a deliberate project convention, not incidental documentation — the goal is that every technique's *shape* (not just its payload) reflects how the vulnerability class is actually exploited in the wild, not a generic textbook payload list.

---

## 4. Authentication support

Four real mechanisms, auto-detected/operator-selected per target role (admin/normal, extensible beyond two):

1. **Form login** (`form_login`) — generic candidate-selector auto-detection (no CSS selectors required for most targets), with manual override support. Also auto-detects and captures **localStorage/sessionStorage-based bearer tokens** for modern SPAs that don't use cookies at all.
2. **JWT / API token** (`jwt`) — pre-issued token injected as `Authorization: Bearer`, with optional token-endpoint exchange and expiry tracking via the JWT's own `exp` claim.
3. **Manual session cookies** — operator captures a session in their own real browser, pastes the cookie header into the console; STOF seeds it directly and skips login entirely for that role. Documented limitation: doesn't help against cookies bound to the originating IP/TLS fingerprint (e.g. Cloudflare's `cf_clearance`).
4. **Assisted login (CDP-driven, human-in-the-loop)** — built, then *intentionally paused*: a server-side headless browser with live screencast + input relay let an operator manually clear a bot challenge once, with the session then reused for the whole scan. Root cause for pausing: Cloudflare Turnstile (and similar) detect the CDP/automation fingerprint itself (`navigator.webdriver`, headless rendering signature), independent of who's actually clicking — so this doesn't reliably work against Cloudflare-protected targets without a further headed-in-Xvfb rework (not yet done). Backend fully intact, UI trigger hidden pending that rework.

---

## 5. Session-aware scanning

- One `Session` per role, cached and reused across the whole scan (`SessionManager`), automatically refreshed/re-authenticated only when actually needed (`needs_refresh()`), persisted to SQLite for crash-resume.
- `SessionPool` maintains one browser context per role, reused across modules within a scan.
- Modules never manage their own auth — they call `session_manager.get_session(role, page)` and get back a ready session regardless of which of the 4 mechanisms above produced it.

---

## 6. The web console — architecture and recent additions

FastAPI backend (`stof/ui/server.py`) + a single-file vanilla JS/HTML/CSS frontend (`stof/ui/static/index.html`, ~6000+ lines, no build step, no framework). A scan is a genuine OS subprocess (`python -m stof.main scan ...`) the server launches and tails structured progress from (`data/logs/scan_<id>.events.jsonl`), not an in-process task — meaning a scan survives a server restart, though the server's in-memory tracking of it does not (see the failure-visibility fix below for how that gap was closed).

**Concurrent scan queue**: previously, the server hard-rejected a second scan outright (409) regardless of target. Now up to `MAX_CONCURRENT_SCANS` (configurable, default 2) run genuinely concurrently — confirmed live via `ps` showing two real, independent `stof.main` subprocesses — with a FIFO queue for anything beyond that. Two scans against the *same* target still collide (409, by design — duplicate attack traffic against one target is never desirable); different targets don't. Deliberately built as an in-process semaphore + queue, not a Redis/Celery-style distributed task queue — every scan subprocess is already safely isolated per-scan-id (its own evidence directory, its own Burp task_id, config read once at launch), so the only thing actually limiting concurrency was one hardcoded check; a distributed queue only earns its complexity the day scans need to run across multiple *machines*, not just multiple slots on one.

**Failure visibility**: a scan that failed used to show nothing more than a red "FAILED" badge — the real reason (an exception, a crash, the last 15 lines of process output) was captured server-side but never surfaced in the UI, and was lost entirely once the server restarted (only a *successful* scan writes a durable report; a failure previously wrote nothing to disk at all). Now every failure persists a `data/logs/scan_<id>.failure.json` record, survives a restart, and the Scan Summary modal shows a dedicated "Why this scan failed" panel with the real error and the captured process output.

**Dashboard / Applications / Findings pages**: OWASP Top 10 findings and test-coverage shown as donut/ring charts (CSS `conic-gradient`, no charting library) scoped to OWASP Web Top 10 only (not mixed with API Top 10 categories, which use a different `API1:2023`-shaped taxonomy tier); a per-application findings-trend line chart (Catmull-Rom-smoothed SVG path) instead of one confusing mixed-scan-sequence line, since STOF is a portfolio tool testing multiple unrelated applications, not a single-app tool; a "Detected technologies" panel on the Attack Surface card, surfacing the recon layer's tech-stack fingerprint (already computed on every scan, previously written to disk and never read by the console at all).

**Test Modules page**: redesigned from a table into a card grid (one card per module, grouped by technique family), each showing real technique counts, a coverage bar, and the same enable/disable toggle that already wrote to `config.json` — expand-in-place to see each real test case's severity/CWE/standard.

**Performance**: a dashboard reload used to fire ~22 parallel `/findings` requests (one per completed scan, unconditionally, on every 30-second poll, regardless of which page was even visible) — root-caused via a live `performance.getEntriesByType('resource')` capture, fixed by gating the per-row fetch behind the Scans panel actually being on-screen.

---

## 7. Passive reconnaissance (recon/)

Runs automatically as part of every `stof scan`'s "RECONNAISSANCE & ENDPOINT CONTEXT" phase, consuming Layer 7's already-discovered endpoints rather than re-crawling: tech-stack fingerprinting (headers/cookies/body-signature matching via a native Playwright `APIRequestContext` equivalent of `httpx`), missing-security-header checks, exposed-path/secrets scanning, and parameter discovery. Writes `data/recon_results.json`, now surfaced in the console (see §6) after previously being computed and silently discarded.

---

## 8. Optional Burp Suite Pro integration

Two independent toggles (deliberately split — confirmed a real prior bug where one flag silently enabled both):
- **Evidence capture** (`burp.enabled`): after a scan, every confirmed finding gets one representative request re-sent through Burp's own proxy listener, landing in Burp's Proxy history *and* appended (never overwriting) onto the Finding's own evidence.
- **Active Scan** (`burp.run_active_scan`): drives Burp's REST API to additionally run Burp's own scanner and merge its issues in (Layer 11, `findings/burp_normalizer.py`, normalizes Burp's issue format into STOF's own `Finding` schema). Requires Burp's REST API service enabled separately in Burp's own settings, and the Burp instance must be network-reachable from wherever the scan subprocess runs (confirmed live: pointing a target at `127.0.0.1` when Burp runs on a *different* machine than the scan silently fails Active Scan with no useful error — an operator-facing gotcha worth documenting prominently, not a code bug).

---

## 9. Explicit safety boundaries (by design, not oversight)

- Every write-verb/state-changing technique (account creation, cache-poisoning confirmation, file upload, workflow-step probes, the stored-XSS/second-order-SQLi/CSV-injection plant phase) is gated behind a manually-armed, per-target `allow_state_changing_probes` flag, off by default.
- RCE gadget-chain sending, real DoS payloads, and TLS/bot-detection evasion are explicitly **not automated** — detection/fingerprinting only, with the actual exploit step left to a human reviewer.
- The new OS Command Injection technique never reads command output (timing-only oracle); the new XXE technique only ever targets one low-sensitivity file (`/etc/hostname`, never anything credential-shaped); the new SSTI technique proves template evaluation occurred without attempting real code execution; the new NoSQL technique confirms an auth bypass without extracting any real stored data.
- XSS/SQLi/the new injection techniques use unique per-run random markers and response-inspection wherever possible; the one exception (DOM-based XSS) navigates a real browser but only ever fires a harmless `confirm()` dialog, auto-dismissed immediately.

---

## 10. Test coverage / quality gates

- **1753 passing unit tests** (1 pre-existing, unrelated, intentionally-untouched failure tracked separately).
- ruff + radon (cyclomatic complexity) enforced on every edit via a blocking pre-commit-style hook; MI (maintainability index) checked per touched file.
- Every new technique is verified two ways, never just one: unit tests with mocked HTTP/timing, **and** a live scan against a real target with log inspection — and where a technique's core logic is hard to trust from mocks alone (the new command-injection/XXE/SSTI work), a standalone synthetic HTTP server was built and driven with STOF's *real* Playwright-backed session machinery to prove the oracle fires correctly against genuine network traffic, not just simulated responses.

---

## 11. Known issues / open questions worth a second opinion

1. **No authentication on the web console itself** — confirmed gap, not yet fixed. Currently mitigated only by "don't expose it publicly." What's the minimum viable auth layer for a tool like this (basic auth behind a reverse proxy vs. building real auth in)?
2. **Containerization** — no Dockerfile yet, despite being discussed. Playwright + Chromium's OS-level dependencies, SQLite state persistence, and the optional same-host-or-reachable Burp Suite Pro dependency all need to be reflected in a real deployment story.
3. **A specific, reproducible crawler stability issue against `demo.testfire.net`** — the crawler's click-probe exploration phase has stalled indefinitely (no error, no timeout firing) at least 3 times against this one target, always shortly after the login-form submission step. Two *different* underlying causes were found and fixed this session (an external-redirect "disclaimer" page the crawler kept retrying clicks against; a slow feedback-form page) via per-target `crawler_exclude_patterns`, but a third occurrence had no diagnosable error signature at all — consistent with the crawler's own documented risk that a sufficiently wedged CDP transport can survive past its 30-second watchdog. Worth a focused reliability pass specifically on the click-probe phase's own timeout handling.
4. **Assisted login vs. modern bot detection** — is there a better architectural answer than "headed Chromium in a virtual display" for defeating fingerprint-based bot detection while a human is genuinely driving the browser? Is this even the right problem to keep solving, vs. steering users toward IP-allowlisting/staging environments?
5. **Real, still-open detection gaps** (see §3): LDAP injection; blind XSS with genuine out-of-band callback confirmation (today's Stored XSS only checks a specific, already-discovered endpoint — it can't catch execution happening somewhere STOF never crawled, e.g. an admin panel); a known-vulnerable-component/CVE-matching check against the recon layer's own fingerprinted tech stack (needs an actual vulnerability database, a materially bigger, separately-scoped effort).
6. **Task-queue concurrency is single-box** (see §6) — the right call at current scale (confirmed: nothing else in the codebase needed changing to make this safe), but worth revisiting if STOF ever needs to scan across multiple machines rather than multiple slots on one.
