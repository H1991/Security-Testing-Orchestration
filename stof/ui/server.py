"""FastAPI application for the STOF web console (see package docstring
in `stof/ui/__init__.py` for the "thin supervisor over the CLI"
design). Run with:

    uvicorn stof.ui.server:app --reload --port 8787

or `python -m stof.ui.server`.
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from stof.core.logger import get_logger
from stof.recorder import cdp

_log = get_logger("ui.server")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = REPO_ROOT / "config" / "config.json"
USERS_PATH = REPO_ROOT / "config" / "users.json"
SESSIONS_DB_PATH = REPO_ROOT / "data" / "stof.db"  # same path stof/main.py's SessionStore uses
ENV_PATH = REPO_ROOT / ".env"
TESTCASES_PATH = REPO_ROOT / "config" / "testcases.json"
LOGS_DIR = REPO_ROOT / "data" / "logs"
REPORTS_DIR = REPO_ROOT / "data" / "reports"
FINDINGS_DIR = REPO_ROOT / "data" / "findings"
WORKFLOWS_DIR = REPO_ROOT / "data" / "workflows"
EVIDENCE_DIR = REPO_ROOT / "data" / "evidence"
RECON_DIR = REPO_ROOT / "data" / "recon"
# {scan_id: name} -- deliberately NOT part of the report JSON that
# stof/reporting/reporter.py (Layer 13) generates: a display label is a
# UI-only concept, and every scan (including ones the CLI ran directly,
# with no server process involved at all) already gets a full report on
# disk before this console ever sees it. A tiny sidecar file the console
# owns end-to-end avoids teaching the reporting module about a field it
# has no other use for.
SCAN_NAMES_PATH = REPO_ROOT / "data" / "scan_names.json"
STATIC_DIR = Path(__file__).resolve().parent / "static"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Same module identifiers `stof/main.py::_KNOWN_MODULES` declares --
# duplicated here (not imported) so the UI package stays import-light
# and never pulls in Playwright/pydantic-config machinery just to know
# module *names*; `_technique_counts()` below is the only place actual
# counts come from, and it reads the same source of truth (testcases.json)
# the CLI's own `--module` help text is generated from.
_KNOWN_MODULES = (
    "crawler", "jwt_tests", "auth_tests", "idor_tests", "configuration_tests",
    "disclosure_tests", "graphql_tests", "deserialization_tests", "sqli_tests",
    "ssrf_tests", "xss_tests", "csrf_tests", "injection_variants_tests", "cache_tests",
    "business_logic_tests", "file_upload_tests",
)

_MODULE_LABELS: dict[str, str] = {
    "crawler": "Crawler & Endpoint Discovery",
    "jwt_tests": "JWT / API Token",
    "auth_tests": "Authentication",
    "idor_tests": "IDOR",
    "configuration_tests": "Configuration",
    "disclosure_tests": "Information Disclosure",
    "graphql_tests": "GraphQL",
    "deserialization_tests": "Deserialization",
    "sqli_tests": "SQL Injection",
    "ssrf_tests": "Server-Side Request Forgery",
    "xss_tests": "Cross-Site Scripting",
    "csrf_tests": "CSRF",
    "injection_variants_tests": "Injection Variants",
    "cache_tests": "Web Cache Poisoning / Deception",
    "business_logic_tests": "Business Logic / Identity",
    "file_upload_tests": "File Upload",
}


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _read_json(path: Path) -> Any:
    if not path.is_file():
        return None
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _load_scan_names() -> dict[str, str]:
    return _read_json(SCAN_NAMES_PATH) or {}


def _save_scan_name(scan_id: str, name: str) -> None:
    names = _load_scan_names()
    name = name.strip()
    if name:
        names[scan_id] = name
    else:
        names.pop(scan_id, None)  # empty string clears a name, same as never setting one
    SCAN_NAMES_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCAN_NAMES_PATH.write_text(json.dumps(names, indent=2) + "\n", encoding="utf-8")


_TC_ID_RE = re.compile(r'"(TC-\d+(?:\.\d+)?)"')
_MIXIN_IMPORT_RE = re.compile(r"^from \.(\w+) import \w*Mixin", re.MULTILINE)
MODULES_DIR = REPO_ROOT / "stof" / "modules"


def _module_source_files(mod_id: str) -> list[Path]:
    """A module's own file, plus every same-package file it pulls a
    `*Mixin` class from (`auth_tests.py` <- `session_weakness_tests.py`,
    `idor_tests.py` <- `bfla_tests.py`/`mass_assignment_tests.py`/
    `role_tests.py`/`tenant_tests.py`, ...). Those mixin files hold
    real, live techniques that run as part of the parent module but
    aren't string-literal-present in the parent's own source -- without
    this, technique counts and the showcase list below silently
    under-report exactly those modules (confirmed live: auth_tests.py
    alone found 5 TC-ids; the module actually runs 26 techniques once
    session_weakness_tests.py's own TC-129.x entries are counted too)."""
    path = MODULES_DIR / f"{mod_id}.py"
    if not path.is_file():
        return []
    files = [path]
    text = path.read_text(encoding="utf-8", errors="ignore")
    for mixin_module in _MIXIN_IMPORT_RE.findall(text):
        mixin_path = MODULES_DIR / f"{mixin_module}.py"
        if mixin_path.is_file():
            files.append(mixin_path)
    return files


def _technique_counts() -> dict[str, int]:
    """`testcases.json`'s own "module" field predates several of these
    module ids (earlier waves used loose category labels like "auth"/
    "injection" instead of the Python module id) and can't be trusted
    to group cleanly by `_KNOWN_MODULES` -- grouping by it under-counts
    or zeroes out modules whose techniques were registered before the
    field's naming settled. Counting distinct `"TC-<n>.<m>"` sub-
    technique-id string literals directly in each module's own source
    file is slower to compute but ground-truth accurate, and doesn't
    silently misreport a module as having 0 techniques."""
    counts: dict[str, int] = {}
    for mod_id in _KNOWN_MODULES:
        ids: set[str] = set()
        for path in _module_source_files(mod_id):
            ids |= set(_TC_ID_RE.findall(path.read_text(encoding="utf-8", errors="ignore")))
        sub_ids = {i for i in ids if "." in i}
        counts[mod_id] = len(sub_ids) if sub_ids else len(ids)
    return counts


def _module_testcases(mod_id: str) -> list[dict]:
    """The showcase list for one module: every top-level TC-id its own
    source file references, resolved against `testcases.json`'s rich
    per-test record (name/severity/description/compliance/CWE) --
    same ground-truth-from-source approach as `_technique_counts()`,
    since `testcases.json`'s own "module" field can't be trusted to
    group entries correctly (see that function's docstring). A TC-id
    present in source but genuinely unregistered in testcases.json is
    skipped rather than fabricated -- this only ever shows real,
    documented test cases."""
    ids: set[str] = set()
    for path in _module_source_files(mod_id):
        ids |= set(_TC_ID_RE.findall(path.read_text(encoding="utf-8", errors="ignore")))
    top_ids = {i.split(".")[0] for i in ids}
    doc = _read_json(TESTCASES_PATH) or {}
    by_id = {t["id"]: t for t in doc.get("tests", [])}
    out = []
    for tid in top_ids:
        entry = by_id.get(tid)
        if entry is None:
            continue
        out.append({
            "id": entry["id"],
            "name": entry.get("name"),
            "severity": entry.get("severity"),
            "description": entry.get("description"),
            "compliance": entry.get("compliance"),
            "cwe_id": entry.get("cwe_id"),
        })
    out.sort(key=lambda t: int(t["id"].split("-")[1]))
    return out


# ---------------------------------------------------------------------------
# In-memory scan registry -- one process's worth of state, matching the
# "running locally" scope of this build. A restart loses live-scan
# tracking (not the underlying data -- logs/reports/findings on disk
# survive); reattaching after a restart is a real Phase-2-of-Phase-2
# gap, not pretended away here.
# ---------------------------------------------------------------------------


class ScanRecord:
    def __init__(self, scan_id: str, target: str, modules: list[str], workflow_ids: list[str] | None = None) -> None:
        self.scan_id = scan_id
        self.target = target
        self.modules = modules
        self.workflow_ids = workflow_ids or []
        self.status = "running"  # running | complete | failed
        self.exit_code: int | None = None
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.finished_at: str | None = None
        # Structured events (see `stof/core/console.py`'s `_emit_event`)
        # -- what the UI actually renders. `raw_lines` (the subprocess's
        # literal terminal output: ANSI-stripped but still box-drawn,
        # progress-bar-redrawn CLI text) is kept server-side ONLY, never
        # broadcast -- the whole point of the structured event stream is
        # that the web console never has to show, or fragile-parse,
        # pretty-printed terminal output.
        self.raw_lines: list[str] = []
        self.events: list[dict] = []
        self.current_phase: str | None = None
        self.modules_state: dict[str, dict] = {}
        self.live_findings: list[dict] = []
        self.crawl: dict | None = None
        self.process: asyncio.subprocess.Process | None = None
        # Set by POST /api/scans/{id}/stop, read back in
        # _run_scan_process once the subprocess actually exits -- lets
        # that same exit-handling code tell "operator stopped this on
        # purpose" apart from "the process crashed," which otherwise
        # look identical (both a nonzero/negative exit code).
        self.stop_requested = False


class ScanRegistry:
    def __init__(self) -> None:
        self._scans: dict[str, ScanRecord] = {}

    def create(self, target: str, modules: list[str], workflow_ids: list[str] | None = None) -> ScanRecord:
        scan_id = uuid.uuid4().hex[:8]
        record = ScanRecord(scan_id, target, modules, workflow_ids=workflow_ids)
        self._scans[scan_id] = record
        return record

    def get(self, scan_id: str) -> ScanRecord | None:
        return self._scans.get(scan_id)

    def all(self) -> list[ScanRecord]:
        return sorted(self._scans.values(), key=lambda r: r.started_at, reverse=True)

    def remove(self, scan_id: str) -> None:
        self._scans.pop(scan_id, None)


REGISTRY = ScanRegistry()
_BACKGROUND_TASKS: set[asyncio.Task] = set()

# ---------------------------------------------------------------------------
# Global live channel -- ONE persistent WebSocket per connected browser
# tab (not one per scan being watched). Real enterprise consoles (the
# ones this UI is modeled on) keep the WHOLE app reactive from a single
# connection -- nav badges, KPI cards, every tab, not just whichever
# resource happens to be open -- rather than forcing a manual refresh
# or polling per-view. Every cross-cutting change (a scan's progress, a
# module toggle, a new report, a saved workflow) broadcasts here;
# `GET /api/scans/{id}` remains the source of truth for a scan's full
# event history, replayed once on attach, with this channel carrying
# everything from that point on.
# ---------------------------------------------------------------------------

GLOBAL_SUBSCRIBERS: set[WebSocket] = set()


async def _broadcast_global(event: dict) -> None:
    payload = json.dumps(event)
    dead: list[WebSocket] = []
    for ws in GLOBAL_SUBSCRIBERS:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        GLOBAL_SUBSCRIBERS.discard(ws)


def _apply_event_to_state(record: ScanRecord, event: dict) -> None:
    """Folds one structured event into `record`'s live snapshot state,
    so `GET /api/scans/{id}` can answer "what's the current state"
    without a client having to replay the whole event list itself."""
    kind = event.get("event")
    if kind == "crawl_completed":
        record.crawl = {
            "endpoint_count": event.get("endpoint_count"), "forms": event.get("forms"),
            "apis": event.get("apis"), "pages": event.get("pages"),
        }
    elif kind == "phase":
        record.current_phase = event.get("title")
    elif kind == "module_started":
        record.modules_state[event["module"]] = {
            "status": "running", "technique_count": event.get("technique_count"),
            "counts": {}, "total": None,
        }
    elif kind == "module_completed":
        state = record.modules_state.setdefault(event["module"], {"status": "running", "technique_count": None})
        state["status"] = "complete"
        state["counts"] = event.get("counts", {})
        state["total"] = event.get("total")
    elif kind == "finding":
        record.live_findings.append(event)


async def _broadcast_event(record: ScanRecord, event: dict) -> None:
    """Records the event on `record` (so a client attaching later still
    gets full history via `GET /api/scans/{id}`) and fans it out on the
    ONE global channel, tagged with `scan_id` -- every connected tab
    gets it, not just a tab that happens to have this specific scan
    open, so nav badges/KPIs/the scans list all stay live regardless
    of which panel is on screen."""
    record.events.append(event)
    _apply_event_to_state(record, event)
    await _broadcast_global({"event": "scan_event", "scan_id": record.scan_id, "data": event})


async def _tail_events_file(record: ScanRecord, events_path: Path, stop_event: asyncio.Event) -> None:
    """Polls `events_path` (the JSON-lines file `ScanConsole._emit_event`
    writes to, see `stof/core/console.py`) for new lines and broadcasts
    each as a structured event. Polling, not a filesystem-watch API, on
    purpose -- this file is written by a SEPARATE process (the scan
    subprocess), gets at most a few dozen lines over a multi-minute
    scan, and a 400ms poll is imperceptible at that rate without an
    extra dependency. Runs until `stop_event` fires (the subprocess
    exited), then does one final read to catch any events written in
    the gap between the last poll and process exit."""
    position = 0

    async def _drain_once() -> None:
        nonlocal position
        if not events_path.is_file():
            return
        with events_path.open("r", encoding="utf-8") as f:
            f.seek(position)
            for raw_line in f:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    event = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                await _broadcast_event(record, event)
            position = f.tell()

    while not stop_event.is_set():
        await _drain_once()
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=0.4)
        except asyncio.TimeoutError:
            continue
    await _drain_once()


async def _run_scan_process(record: ScanRecord, module_names: list[str] | None, workflow_ids: list[str] | None = None) -> None:
    """Launches `stof scan` as a real subprocess of the same interpreter
    this server runs under -- the CLI's own dependency-check, browser
    launch, module orchestration and report generation are the ONE
    place that logic lives (see package docstring). Structured progress
    is broadcast from the scan's `.events.jsonl` file (see
    `_tail_events_file`), not scraped from the subprocess's own
    terminal-formatted stdout -- that raw text is still captured (into
    `record.raw_lines`) purely so a crash that happens before
    `ScanConsole` even starts (an import error, a traceback) is still
    visible in `record.status == "failed"`'s error reporting, never
    broadcast to the UI as literal CLI output."""
    args = [
        sys.executable, "-m", "stof.main", "scan",
        "--config", str(CONFIG_PATH),
        "--users", str(REPO_ROOT / "config" / "users.json"),
        "--scan-id", record.scan_id,
    ]
    if module_names:
        args += ["--module", ",".join(module_names)]
    if workflow_ids:
        args += ["--workflow", ",".join(workflow_ids)]

    try:
        process = await asyncio.create_subprocess_exec(
            *args, cwd=REPO_ROOT,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except Exception as exc:
        record.status = "failed"
        record.finished_at = datetime.now(timezone.utc).isoformat()
        await _broadcast_event(record, {"event": "error", "message": f"failed to launch scan process: {exc}"})
        return

    record.process = process
    events_path = LOGS_DIR / f"scan_{record.scan_id}.events.jsonl"
    stop_event = asyncio.Event()
    tail_task = asyncio.create_task(_tail_events_file(record, events_path, stop_event))

    if process.stdout is None:
        record.status = "failed"
        record.finished_at = datetime.now(timezone.utc).isoformat()
        await _broadcast_event(record, {"event": "error", "message": "scan process started with no stdout pipe"})
        stop_event.set()
        await tail_task
        return

    while True:
        raw = await process.stdout.readline()
        if not raw:
            break
        line = _strip_ansi(raw.decode("utf-8", errors="replace").rstrip("\n"))
        if line:
            record.raw_lines.append(line)

    exit_code = await process.wait()
    stop_event.set()
    await tail_task

    record.exit_code = exit_code
    if record.stop_requested:
        record.status = "stopped"
    else:
        record.status = "complete" if exit_code == 0 else "failed"
    record.finished_at = datetime.now(timezone.utc).isoformat()
    error_tail = None
    if record.status == "failed":
        error_tail = "\n".join(record.raw_lines[-15:])
    await _broadcast_event(record, {"event": "process_exited", "exit_code": exit_code, "status": record.status, "error_tail": error_tail})


# ---------------------------------------------------------------------------
# Recording registry -- one workflow-recording session at a time.
#
# v1 of this launched its OWN headed Chromium (`pw.chromium.launch
# (headless=False, ...)`) for one-click convenience -- confirmed live
# (twice, against a real deployment) that this breaks the instant the
# server process itself doesn't have a display attached (started from a
# terminal/IDE/service with no $DISPLAY, or the operator's browser tab
# is on a different machine than the server): Chromium has nowhere to
# open a window and the launch fails outright, with no way to recover
# short of fixing the server process's own environment.
#
# Reworked to CDP-ATTACH instead, matching what `stof/recorder/
# recorder.py` (the CLI's own recorder) already does and documents as
# the intended design: the operator starts their OWN browser, on their
# OWN machine, with remote debugging enabled -- a completely normal
# desktop launch that always has a display, because the OS itself
# opened it, not this server process. STOF then just connects over the
# network (CDP, not a GUI operation) to that already-open, already-
# visible window. This is why it also doesn't matter whether the
# console is reached from the same machine as the server or a browser
# on the LAN: the browser being recorded is always wherever the
# operator started it, never wherever the server happens to be running.
# ---------------------------------------------------------------------------

# Moved to stof/recorder/cdp.py so stof/main.py's assisted-login path
# (see AssistedLoginProvider) can share the exact same CDP-attach
# conventions instead of forking a second implementation -- one debug
# port, one set of operator instructions, two features. These names are
# kept as thin aliases so every existing call site below is unaffected.
RECORDING_CDP_PORT = cdp.CDP_PORT
_recording_cdp_host = cdp.cdp_host
_recording_cdp_endpoint = cdp.cdp_endpoint
_recording_launch_command = cdp.launch_command


class RecordingSession:
    def __init__(self, recording_id: str, target_url: str, name: str) -> None:
        self.recording_id = recording_id
        self.target_url = target_url
        self.name = name
        self.status = "starting"  # starting | recording | complete | failed
        self.error: str | None = None
        self.workflow_id: str | None = None
        self.workflow_path: str | None = None
        self.action_count: int | None = None
        self.stop_event = asyncio.Event()
        self.done_event = asyncio.Event()


class RecordingRegistry:
    def __init__(self) -> None:
        self.current: RecordingSession | None = None


RECORDINGS = RecordingRegistry()


async def _run_recording(session: RecordingSession) -> None:
    from playwright.async_api import async_playwright

    from stof.recorder import build_workflow, tokenize_credentials, write_workflow
    from stof.recorder.event_handler import EventHandler

    users = None
    if USERS_PATH.is_file():
        try:
            from stof.config import load_dotenv, load_users
            load_dotenv()
            # Tokenisation matches against the RESOLVED password (what the
            # operator actually typed into the browser), not the literal
            # "{{env:VAR}}" string in users.json -- load_users() is what
            # resolves that substitution from .env, same as every CLI path.
            users = load_users(USERS_PATH)
        except Exception as exc:
            _log.warning(f"could not load users.json for credential tokenisation: {exc}")

    try:
        async with async_playwright() as pw:
            try:
                cdp_endpoint = _recording_cdp_endpoint()
                browser = await pw.chromium.connect_over_cdp(cdp_endpoint)
            except Exception as exc:
                raise RuntimeError(
                    f"could not connect to a browser at {cdp_endpoint} -- start one first with remote "
                    "debugging enabled (see the Workflows tab for the exact command), then click Record again. "
                    f"Original error: {exc}"
                ) from exc
            # Reuse the operator's own already-open context/tab if one
            # exists, matching recorder.py's own attach logic exactly --
            # a fresh context here would lose whatever session/cookies
            # they already have, and a second Chromium *window* (not
            # just a tab) can't be created inside an existing browser
            # process the way a fresh `new_context()` can silently end
            # up doing.
            context = browser.contexts[0] if browser.contexts else await browser.new_context()
            page = context.pages[0] if context.pages else await context.new_page()
            await page.goto(session.target_url)

            handler = EventHandler()
            await handler.attach(page)
            session.status = "recording"

            await session.stop_event.wait()

            await handler.detach()
            final_url = page.url
            # Deliberately no browser.close() -- this is the operator's
            # own real browser, CDP-attached, not one this server
            # launched. Closing it here would end their whole browsing
            # session, not just disconnect Playwright's client (see
            # recorder.py's own docstring for the same warning).

        tokenized = tokenize_credentials(handler.actions, users)
        workflow = build_workflow(target_url=final_url, actions=tokenized, workflow_id=session.recording_id)
        filename = f"{_slugify(session.name)}.json" if session.name else None
        path = write_workflow(workflow, WORKFLOWS_DIR / (filename or f"{workflow['workflow_id']}.json"))

        session.workflow_id = workflow["workflow_id"]
        session.workflow_path = str(path)
        session.action_count = len(tokenized)
        session.status = "complete"
    except Exception as exc:
        _log.warning(f"recording session '{session.recording_id}' failed: {exc}")
        session.status = "failed"
        session.error = str(exc)
    finally:
        session.done_event.set()


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "workflow"


def _write_dotenv_value(path: Path, key: str, value: str) -> None:
    """Upserts `KEY=value` in a dotenv file -- same convention
    `stof configure`'s CLI wizard already uses (see `stof/main.py`),
    duplicated narrowly here rather than imported since importing
    `stof.main` would pull in Click and the whole CLI module just for
    one helper."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    prefix = f"{key}="
    replaced = False
    for i, line in enumerate(lines):
        if line.startswith(prefix):
            lines[i] = f"{key}={value}"
            replaced = True
            break
    if not replaced:
        lines.append(f"{key}={value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# API models
# ---------------------------------------------------------------------------


class StartScanRequest(BaseModel):
    modules: list[str] | None = None
    name: str | None = None
    workflow_ids: list[str] | None = None
    confirm_authorized: bool = Field(
        ..., description="Must be true. The operator is confirming they hold explicit authorization to test the currently-configured target."
    )


class ScanNameRequest(BaseModel):
    name: str


class ModuleToggleRequest(BaseModel):
    enabled: bool


class TargetUpdateRequest(BaseModel):
    base_url: str
    login_url: str
    username_selector: str | None = None
    password_selector: str | None = None
    submit_selector: str | None = None
    # Opt-in per target (stof.config.schema.TargetConfig.requires_assisted_login,
    # stof.auth.assisted_login.AssistedLoginProvider) -- for a target behind
    # a bot-challenge STOF's own automated browser can never pass alone.
    # `None` (omitted) leaves whatever's already configured untouched, same
    # partial-update convention as the selector fields above.
    requires_assisted_login: bool | None = None


class BrowserUpdateRequest(BaseModel):
    headless: bool = True


class OobUpdateRequest(BaseModel):
    collaborator_url: str = ""


class BurpUpdateRequest(BaseModel):
    enabled: bool = False
    # Separate from `enabled` on purpose -- see stof/config/schema.py's
    # BurpConfig docstring for the real bug this split fixes (a single
    # flag used to silently turn on Burp's own much slower Active Scan
    # alongside evidence capture, with no way to have one without the
    # other).
    run_active_scan: bool = False
    api_url: str = "http://127.0.0.1:1337"
    api_key: str | None = None  # None = leave the stored key unchanged; "" clears it
    scan_timeout_s: int = 1800
    poll_interval_s: int = 5
    # Burp's intercepting PROXY listener -- a different port than the
    # REST API (api_url), which only controls/queries scans. Traffic
    # sent here is what actually shows up in Burp's own Proxy history;
    # Burp's own default listener is 127.0.0.1:8080.
    proxy_url: str = "http://127.0.0.1:8080"


class BurpTestRequest(BaseModel):
    # Both optional so "Test connection" can verify the already-saved
    # config (api_key included, even though it's write-only and never
    # sent back to the browser) without the operator re-typing it --
    # only used when the form field was left blank.
    api_url: str | None = None
    api_key: str | None = None


class CredentialsUpdateRequest(BaseModel):
    admin_username: str | None = None
    admin_password: str | None = None
    normal_username: str | None = None
    normal_password: str | None = None
    # "form_login" (default, browser login form, auto-detected) or "jwt"
    # (no login step -- `admin_password`/`normal_password` is read as a
    # pre-issued bearer token instead, see stof/auth/jwt_auth.py's own
    # docstring on why `password` doubles as the token field). `None`
    # leaves whatever's already configured untouched, same partial-update
    # convention the rest of this endpoint already uses.
    admin_auth_type: Literal["form_login", "jwt"] | None = None
    normal_auth_type: Literal["form_login", "jwt"] | None = None


class StartRecordingRequest(BaseModel):
    name: str
    target_url: str | None = None


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="STOF Console API")


@app.get("/api/health")
def health() -> dict:
    return {"ok": True}


@app.get("/api/config")
def get_config() -> dict:
    doc = _read_json(CONFIG_PATH)
    if doc is None:
        raise HTTPException(404, f"{CONFIG_PATH} not found -- run `stof configure` first")
    # Never echo raw {{env:VAR}} tokens' resolved values back -- config.json
    # itself never holds a literal secret (see CLAUDE.md rule 6), so
    # returning it verbatim is safe; nothing here touches users.json.
    return doc


@app.get("/api/modules")
def get_modules() -> list[dict]:
    doc = _read_json(CONFIG_PATH) or {}
    enabled = doc.get("modules", {})
    counts = _technique_counts()
    return [
        {
            "id": mod_id,
            "name": _MODULE_LABELS.get(mod_id, mod_id),
            "enabled": bool(enabled.get(mod_id, mod_id == "crawler")),
            "locked": mod_id == "crawler",
            "technique_count": counts.get(mod_id, 0),
        }
        for mod_id in _KNOWN_MODULES
    ]


@app.get("/api/modules/{module_id}/testcases")
def get_module_testcases(module_id: str) -> list[dict]:
    if module_id not in _KNOWN_MODULES:
        raise HTTPException(404, f"unknown module '{module_id}'")
    return _module_testcases(module_id)


@app.put("/api/modules/{module_id}")
async def set_module(module_id: str, body: ModuleToggleRequest) -> dict:
    if module_id not in _KNOWN_MODULES:
        raise HTTPException(404, f"unknown module '{module_id}'")
    if module_id == "crawler":
        raise HTTPException(400, "crawler cannot be disabled -- every other module depends on its endpoint map")
    doc = _read_json(CONFIG_PATH)
    if doc is None:
        raise HTTPException(404, f"{CONFIG_PATH} not found")
    doc.setdefault("modules", {})[module_id] = body.enabled
    CONFIG_PATH.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    await _broadcast_global({"event": "module_toggled", "id": module_id, "enabled": body.enabled})
    return {"id": module_id, "enabled": body.enabled}


@app.get("/api/testing")
def get_testing_flag() -> dict:
    doc = _read_json(CONFIG_PATH) or {}
    return {"allow_state_changing_probes": bool(doc.get("testing", {}).get("allow_state_changing_probes", False))}


@app.put("/api/testing")
async def set_testing_flag(body: dict) -> dict:
    doc = _read_json(CONFIG_PATH)
    if doc is None:
        raise HTTPException(404, f"{CONFIG_PATH} not found")
    doc.setdefault("testing", {})["allow_state_changing_probes"] = bool(body.get("allow_state_changing_probes", False))
    CONFIG_PATH.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    await _broadcast_global({"event": "testing_changed", "allow_state_changing_probes": doc["testing"]["allow_state_changing_probes"]})
    return doc["testing"]


@app.put("/api/config/target")
def set_target(body: TargetUpdateRequest) -> dict:
    doc = _read_json(CONFIG_PATH)
    if doc is None:
        raise HTTPException(404, f"{CONFIG_PATH} not found -- run `stof configure` first")
    target = doc.setdefault("target", {})
    target["base_url"] = body.base_url
    target["login_url"] = body.login_url
    # `None` means "field omitted from this PUT" -- leave whatever is
    # already there untouched (a partial update, not a full replace).
    # Only an explicit empty string clears a previously-set selector
    # back to auto-detect. Getting this backwards once already wiped a
    # real target's working selectors during testing -- see git history
    # if this file ever gets one.
    for field_name in ("username_selector", "password_selector", "submit_selector"):
        value = getattr(body, field_name)
        if value is None:
            continue
        if value == "":
            target.pop(field_name, None)
        else:
            target[field_name] = value
    if body.requires_assisted_login is not None:
        target["requires_assisted_login"] = body.requires_assisted_login
    CONFIG_PATH.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return target


@app.put("/api/config/browser")
def set_browser(body: BrowserUpdateRequest) -> dict:
    doc = _read_json(CONFIG_PATH)
    if doc is None:
        raise HTTPException(404, f"{CONFIG_PATH} not found")
    browser = doc.setdefault("browser", {})
    browser["headless"] = body.headless
    CONFIG_PATH.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return browser


@app.put("/api/config/oob")
async def set_oob(body: OobUpdateRequest) -> dict:
    """Updates ONLY `burp.collaborator_url` -- deliberately does not
    touch `burp.enabled`/`api_url`/`api_key`, which gate the much
    heavier, separate Burp Active Scan integration (Layer 3C). An
    operator supplying an OOB collaborator host (their own Burp
    Collaborator client, interactsh, or any equivalent) for
    `ssrf_tests.py`'s TC-137.6 shouldn't also silently enable Burp's
    full active scanning as a side effect of that."""
    doc = _read_json(CONFIG_PATH)
    if doc is None:
        raise HTTPException(404, f"{CONFIG_PATH} not found")
    burp = doc.setdefault("burp", {"enabled": False, "run_active_scan": False, "api_url": "http://127.0.0.1:1337", "api_key": "", "scan_timeout_s": 1800, "poll_interval_s": 5})
    burp["collaborator_url"] = body.collaborator_url.strip()
    CONFIG_PATH.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    await _broadcast_global({"event": "oob_changed", "collaborator_url": burp["collaborator_url"]})
    return {"collaborator_url": burp["collaborator_url"]}


@app.get("/api/config/burp")
def get_burp_config() -> dict:
    """Never echoes `api_key` back (write-only, same convention as
    `/api/credentials` for account passwords) -- only whether one is
    currently set, so the Settings form can show "configured" without
    ever displaying or re-transmitting the key itself."""
    doc = _read_json(CONFIG_PATH) or {}
    burp = doc.get("burp", {})
    return {
        "enabled": bool(burp.get("enabled", False)),
        "run_active_scan": bool(burp.get("run_active_scan", False)),
        "api_url": burp.get("api_url", "http://127.0.0.1:1337"),
        "proxy_url": burp.get("proxy_url", "http://127.0.0.1:8080"),
        "api_key_set": bool(burp.get("api_key")),
        "scan_timeout_s": burp.get("scan_timeout_s", 1800),
        "poll_interval_s": burp.get("poll_interval_s", 5),
    }


@app.put("/api/config/burp")
async def set_burp_config(body: BurpUpdateRequest) -> dict:
    doc = _read_json(CONFIG_PATH)
    if doc is None:
        raise HTTPException(404, f"{CONFIG_PATH} not found")
    burp = doc.setdefault("burp", {"enabled": False, "run_active_scan": False, "api_url": "http://127.0.0.1:1337", "api_key": "", "scan_timeout_s": 1800, "poll_interval_s": 5, "proxy_url": "http://127.0.0.1:8080"})
    burp["enabled"] = body.enabled
    burp["run_active_scan"] = body.run_active_scan
    burp["api_url"] = body.api_url.strip().rstrip("/")
    burp["proxy_url"] = body.proxy_url.strip().rstrip("/")
    burp["scan_timeout_s"] = body.scan_timeout_s
    burp["poll_interval_s"] = body.poll_interval_s
    if body.api_key is not None:
        burp["api_key"] = body.api_key.strip()
    CONFIG_PATH.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    await _broadcast_global({"event": "burp_config_changed", "enabled": burp["enabled"]})
    return get_burp_config()


@app.post("/api/burp/test-connection")
async def test_burp_connection(body: BurpTestRequest) -> dict:
    """Lightweight reachability/auth check -- does NOT start a scan.
    Probes `GET {base}/{key}/v0.1/scan/<a task id that can't exist>`:
    Burp answers this itself (400/404-shaped -- exact code not
    live-verified for a *wrong* key, see burp_controller.py's own
    "not live-verified" precedent) if the API key is accepted, refuses
    the connection outright if nothing is listening on that URL, and a
    key Burp doesn't recognize should surface as a distinct error
    rather than "task not found" -- reported here as a best-effort
    `authorized` guess, not a guarantee, exactly like every other
    "not live-verified against every Burp version" caveat already
    documented in this codebase's Burp integration."""
    doc = _read_json(CONFIG_PATH) or {}
    stored = doc.get("burp", {})
    api_url = (body.api_url or stored.get("api_url") or "http://127.0.0.1:1337").strip().rstrip("/")
    api_key = body.api_key if body.api_key is not None else stored.get("api_key", "")
    if not api_key:
        return {"reachable": False, "authorized": False, "error": "no API key configured"}

    if not api_url.startswith(("http://", "https://")):
        return {"reachable": False, "authorized": False, "error": "api_url must be http:// or https://"}

    def _check() -> dict:
        import urllib.error
        import urllib.request
        url = f"{api_url}/{api_key}/v0.1/scan/999999999999"
        try:
            request = urllib.request.Request(url, method="GET")  # noqa: S310 -- scheme validated above
            with urllib.request.urlopen(request, timeout=5) as resp:  # noqa: S310
                return {"reachable": True, "authorized": True, "status": resp.status}
        except urllib.error.HTTPError as exc:
            # Burp responded at all -> reachable. 401/403 = key rejected;
            # anything else (400/404 for the bogus task id) means the
            # key was accepted and Burp just doesn't have that task.
            return {"reachable": True, "authorized": exc.code not in (401, 403), "status": exc.code}
        except Exception as exc:
            return {"reachable": False, "authorized": False, "error": str(exc)}

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check)


def _apply_credentials_update(
    by_role: dict, role: str, default_id: str, username: str | None, env_var: str, auth_type: str | None
) -> None:
    """One role's slice of `set_credentials()`'s partial update -- pulled
    out so the endpoint itself reads as one straight-line sequence
    instead of a repeated if/if/if block per role, and stays under this
    project's complexity gate (CLAUDE.md's own quality standard)."""
    if username is not None:
        entry = by_role.setdefault(role, {"id": default_id, "role": role, "auth_type": "form_login"})
        entry["username"] = username
        entry["password"] = f"{{{{env:{env_var}}}}}"
    if auth_type is not None and role in by_role:
        by_role[role]["auth_type"] = auth_type


@app.put("/api/credentials")
def set_credentials(body: CredentialsUpdateRequest) -> dict:
    """Mirrors `stof configure`'s own credential-handling rule (CLAUDE.md
    rule 6): a password is written ONLY to `.env`, never to users.json,
    which only ever gets a `{{env:VAR}}` token. Usernames are plain
    identifiers (not secrets) and go straight into users.json."""
    users_doc = _read_json(USERS_PATH) or {"users": []}
    by_role = {u.get("role"): u for u in users_doc.get("users", [])}

    _apply_credentials_update(by_role, "admin", "admin-01", body.admin_username, "ADMIN_PASSWORD", body.admin_auth_type)
    _apply_credentials_update(by_role, "normal", "user-01", body.normal_username, "USER_PASSWORD", body.normal_auth_type)

    if body.admin_password:
        _write_dotenv_value(ENV_PATH, "ADMIN_PASSWORD", body.admin_password)
    if body.normal_password:
        _write_dotenv_value(ENV_PATH, "USER_PASSWORD", body.normal_password)

    users_doc["users"] = list(by_role.values())
    USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    USERS_PATH.write_text(json.dumps(users_doc, indent=2) + "\n", encoding="utf-8")
    # Never echo a password back, even the token form -- the response
    # confirms which usernames are now configured, nothing else.
    return {"admin_username": by_role.get("admin", {}).get("username"), "normal_username": by_role.get("normal", {}).get("username")}


@app.delete("/api/credentials/{role}")
def delete_credentials(role: str) -> dict:
    """Drops one role from `users.json` entirely -- the other half of
    single-account support: a target that only issues one account has
    no admin (or no normal-user) entry to begin with, and an operator
    who was handed just one needs a way to remove whichever placeholder
    role was there before, not just leave it stale. `stof/main.py`'s own
    role resolution already collapses `high_priv_role`/`low_priv_role`
    to whatever's left when one role is gone (see EXPLOIT_COVERAGE.md's
    TC-055.5 note for how cross-identity techniques degrade honestly
    once that happens) -- this just lets that state be reached from the
    UI instead of hand-editing the file."""
    users_doc = _read_json(USERS_PATH) or {"users": []}
    remaining = [u for u in users_doc.get("users", []) if u.get("role") != role]
    if len(remaining) == len(users_doc.get("users", [])):
        raise HTTPException(404, f"no '{role}' account configured in users.json")
    users_doc["users"] = remaining
    USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    USERS_PATH.write_text(json.dumps(users_doc, indent=2) + "\n", encoding="utf-8")
    return {"removed": role, "remaining_roles": [u.get("role") for u in remaining]}


@app.get("/api/recordings/launch-command")
def get_recording_launch_command() -> dict:
    return {**_recording_launch_command(), "cdp_endpoint": _recording_cdp_endpoint()}


@app.post("/api/recordings")
async def start_recording(body: StartRecordingRequest) -> dict:
    if RECORDINGS.current is not None and RECORDINGS.current.status in ("starting", "recording"):
        raise HTTPException(409, f"a recording ('{RECORDINGS.current.recording_id}') is already in progress -- stop it first")

    target_url = body.target_url
    if not target_url:
        doc = _read_json(CONFIG_PATH) or {}
        target_url = doc.get("target", {}).get("base_url")
    if not target_url:
        raise HTTPException(400, "no target_url given and no target.base_url configured")

    recording_id = f"wf-{uuid.uuid4().hex[:8]}"
    session = RecordingSession(recording_id, target_url, body.name)
    RECORDINGS.current = session
    task = asyncio.create_task(_run_recording(session))
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)
    return {"recording_id": recording_id, "status": session.status, "target_url": target_url}


@app.get("/api/recordings/current")
def get_current_recording() -> dict:
    session = RECORDINGS.current
    if session is None:
        return {"status": "idle"}
    return {
        "recording_id": session.recording_id, "status": session.status, "target_url": session.target_url,
        "name": session.name, "error": session.error, "workflow_id": session.workflow_id,
        "action_count": session.action_count,
    }


@app.post("/api/recordings/current/stop")
async def stop_recording() -> dict:
    session = RECORDINGS.current
    if session is None or session.status not in ("starting", "recording"):
        raise HTTPException(404, "no recording currently in progress")
    session.stop_event.set()
    try:
        await asyncio.wait_for(session.done_event.wait(), timeout=30)
    except asyncio.TimeoutError:
        raise HTTPException(504, "recording did not stop within 30s -- the browser window may need to be closed manually") from None
    if session.status == "failed":
        raise HTTPException(500, f"recording failed: {session.error}")
    await _broadcast_global({
        "event": "workflow_saved", "workflow_id": session.workflow_id,
        "name": session.name, "action_count": session.action_count,
    })
    return {
        "recording_id": session.recording_id, "workflow_id": session.workflow_id,
        "workflow_path": session.workflow_path, "action_count": session.action_count,
    }


# ---------------------------------------------------------------------------
# Verify Login -- "does the configured account actually log in?" is a
# question an operator wants answered by *seeing it happen*, not by
# reading a JSON blob.
#
# v1 of this launched a real headed (non-headless) Chromium window on
# the machine running this server process, on the theory that the
# operator and the server are the same desktop. Confirmed live (twice,
# against a real deployment) that this assumption is wrong for how
# STOF Console actually gets used: the server runs on one machine and
# is reached over the LAN from another, so a headed window has nowhere
# to appear -- and even where a display technically exists, whatever
# process supervises uvicorn (systemd, a plain background nohup, this
# exact restart-from-a-tool scenario) frequently has no $DISPLAY in its
# environment at all, which is a completely different failure from "no
# X server exists" but produces the identical Playwright error.
#
# Headless + a screenshot handed back to the browser the operator is
# ALREADY looking at sidesteps both problems entirely: no X server is
# ever required, and it works identically whether the operator is on
# the server box or three rooms away on the LAN.
# ---------------------------------------------------------------------------


class VerifyLoginSession:
    def __init__(self, verify_id: str, role: str) -> None:
        self.verify_id = verify_id
        self.role = role
        self.status = "starting"  # starting | success | failed
        self.error: str | None = None
        self.matched_via: str | None = None
        self.target_url: str | None = None
        self.screenshot_data_url: str | None = None
        self.done_event = asyncio.Event()


class VerifyLoginRegistry:
    def __init__(self) -> None:
        self.current: VerifyLoginSession | None = None


VERIFY_LOGIN = VerifyLoginRegistry()


def _short_error(exc: Exception) -> str:
    """Playwright exceptions carry a multi-line message -- a one-line
    summary ("BrowserType.launch: Target page, context or browser has
    been closed") followed by the full browser call log (launch args,
    PIDs, stderr) where the actually-useful diagnostic line lives.
    Confirmed live: showing only the first line just repeats that same
    generic wrapper for every launch failure regardless of cause, which
    is worse than useless for anyone trying to fix it. This scans the
    full message for a handful of known, actionable Playwright/Chromium
    failure signatures and surfaces THAT line instead; falls back to
    the first line only when nothing recognizable is found. The full
    text always still goes to the server log via `_log.warning(...)`
    in the caller."""
    text = str(exc).strip()
    if not text:
        return exc.__class__.__name__
    lines = text.splitlines()
    diagnostic_markers = (
        "Missing X server",
        "Executable doesn't exist",
        "Please run the following command",
        "cannot run as root",
        "Host system is missing dependencies",
    )
    for line in lines:
        stripped = line.strip().lstrip("|").strip()
        if any(marker in stripped for marker in diagnostic_markers):
            return stripped[:220]
    return lines[0][:200]


async def _run_verify_login(session: VerifyLoginSession) -> None:
    from playwright.async_api import async_playwright

    from stof.auth.base import AuthFailedError
    from stof.config import load_config, load_dotenv, load_users
    from stof.main import _build_form_login_provider

    load_dotenv()
    try:
        config = load_config(CONFIG_PATH)
        users = load_users(USERS_PATH)
        user = next((u for u in users.users if u.role == session.role), None)
        if user is None:
            raise ValueError(f"no user with role '{session.role}' in users.json")
        if user.auth_type != "form_login":
            raise ValueError(
                f"role '{session.role}' uses auth_type '{user.auth_type}' -- Verify Login only "
                "drives a real browser through a form login, since that's the flow an end user "
                "actually experiences (a JWT/API-token role never sees a login page at all)"
            )
        provider = _build_form_login_provider(config)
    except Exception as exc:
        session.status = "failed"
        session.error = _short_error(exc)
        session.done_event.set()
        return

    session.target_url = config.target.login_url
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            # ignore_https_errors matches the real scan path (stof/main.py) --
            # security-testing targets (this one included: demo.testfire.net)
            # routinely run expired/self-signed certs that have nothing to do
            # with whether the login flow itself works.
            context = await browser.new_context(viewport={"width": 1280, "height": 800}, ignore_https_errors=True)
            page = await context.new_page()
            try:
                await provider.authenticate(user, page)
                session.status = "success"
                session.matched_via = page.url
            except AuthFailedError as exc:
                session.status = "failed"
                session.error = _short_error(exc)
            except Exception as exc:
                session.status = "failed"
                session.error = _short_error(exc)
            # Screenshot either way -- on failure it's the single most
            # useful piece of evidence there is (a visible "invalid
            # credentials" banner, a WAF block page, a blank timeout),
            # not just a consolation prize for the success case.
            try:
                png_bytes = await page.screenshot(type="png")
                session.screenshot_data_url = "data:image/png;base64," + base64.b64encode(png_bytes).decode("ascii")
            except Exception as exc:
                _log.warning(f"verify-login session '{session.verify_id}' screenshot failed: {exc}")
            await browser.close()
    except Exception as exc:
        # Browser-launch failure before a screenshot was even possible
        # (or before, if launch() itself failed) -- either way, surface
        # it rather than leaving the operator staring at "starting" forever.
        if session.status == "starting":
            session.status = "failed"
            session.error = _short_error(exc)
        _log.warning(f"verify-login session '{session.verify_id}' browser error: {exc}")
    finally:
        # Deliberately does NOT clear VERIFY_LOGIN.current -- same
        # precedent as RECORDINGS above: a finished (success/failed)
        # session stays visible to GET /current until a new one starts
        # and overwrites it. Clearing it here raced the frontend's own
        # poll: the task could reach this line and wipe the "failed"
        # status before the next 1.2s poll ever saw it (confirmed live).
        session.done_event.set()


# Shared by the context launch and the screencast size (see the comment
# at the Page.startScreencast call below) so the two can never drift
# apart and silently break click coordinates again.
ASSISTED_LOGIN_VIEWPORT = {"width": 1280, "height": 800}


class AssistedLoginRoleSession:
    """One role's live browser context within the shared assisted-login
    browser -- the state a WebSocket connection and the confirm/status
    endpoints all need to reach the same running page. `context`/`page`
    deliberately stay open across requests (never closed by this
    session's own code) -- `stof/main.py`'s scan subprocess later
    reconnects over CDP and reuses this exact context for the whole
    scan, per `AssistedLoginProvider`'s own module docstring."""

    def __init__(self, role: str, login_url: str) -> None:
        self.role = role
        self.login_url = login_url
        self.status = "starting"  # starting | ready | confirmed | failed
        self.error: str | None = None
        self.context = None
        self.page = None
        self.cdp_session = None
        self.frame_session_id: str | None = None


class AssistedLoginBrowserRegistry:
    """Owns the ONE shared Playwright driver + Browser process behind
    every assisted-login role -- launched lazily on first use and kept
    alive across requests (deliberately NOT `async with async_playwright()`,
    which would tear the browser down at the end of a single request;
    this browser needs to survive from "operator clicks Start" through
    the end of a real scan run, potentially many minutes later)."""

    def __init__(self) -> None:
        self.playwright = None
        self.browser = None
        self.sessions: dict[str, AssistedLoginRoleSession] = {}
        self.lock = asyncio.Lock()


ASSISTED_LOGIN = AssistedLoginBrowserRegistry()


async def _ensure_assisted_login_browser():
    """Starts the shared Playwright driver + Chromium browser (headless,
    with its CDP debug port bound to 127.0.0.1 only -- see
    `stof/recorder/cdp.py`'s `ASSISTED_LOGIN_CDP_PORT`) on first call;
    every later call reuses the same running browser. Headless is fine
    here even though a human "views" this browser -- the screencast
    (`Page.startScreencast`) captures rendered frames regardless of
    whether there's a real display, the same way Playwright's own
    screenshot API already works headless."""
    from playwright.async_api import async_playwright

    async with ASSISTED_LOGIN.lock:
        if ASSISTED_LOGIN.browser is not None:
            return ASSISTED_LOGIN.browser
        ASSISTED_LOGIN.playwright = await async_playwright().start()
        ASSISTED_LOGIN.browser = await ASSISTED_LOGIN.playwright.chromium.launch(
            headless=True,
            args=[f"--remote-debugging-port={cdp.ASSISTED_LOGIN_CDP_PORT}", "--remote-debugging-address=127.0.0.1"],
        )
        _log.info(f"assisted-login browser started, CDP debug port {cdp.ASSISTED_LOGIN_CDP_PORT} (127.0.0.1 only)")
        return ASSISTED_LOGIN.browser


async def _start_assisted_login_session(role: str, login_url: str) -> AssistedLoginRoleSession:
    session = AssistedLoginRoleSession(role, login_url)
    ASSISTED_LOGIN.sessions[role] = session
    try:
        browser = await _ensure_assisted_login_browser()
        # A fresh, isolated context per role -- never shared -- so each
        # role's cookies/login state stay genuinely separate within the
        # one shared browser process, the same isolation a separate
        # Chrome profile would give, without the overhead of launching
        # a whole extra browser process per role.
        session.context = await browser.new_context(ignore_https_errors=True, viewport=ASSISTED_LOGIN_VIEWPORT)
        session.page = await session.context.new_page()
        await session.page.goto(login_url)
        session.cdp_session = await session.context.new_cdp_session(session.page)

        def _on_frame(event: dict) -> None:
            session.frame_session_id = event.get("sessionId")

        session.cdp_session.on("Page.screencastFrame", _on_frame)
        # maxWidth/maxHeight deliberately match ASSISTED_LOGIN_VIEWPORT
        # exactly (not some smaller preview size) -- Chrome downscales
        # frames to fit within these bounds, and a mismatch here silently
        # breaks click coordinates: the frontend maps a click's on-screen
        # position to page coordinates using the *frame's own pixel size*
        # (img.naturalWidth/Height), so a scaled-down frame makes every
        # click land in the wrong place on the real page -- exactly the
        # "can't click the CAPTCHA checkbox" bug this fixed.
        await session.cdp_session.send(
            "Page.startScreencast",
            {
                "format": "jpeg",
                "quality": 70,
                "maxWidth": ASSISTED_LOGIN_VIEWPORT["width"],
                "maxHeight": ASSISTED_LOGIN_VIEWPORT["height"],
                "everyNthFrame": 1,
            },
        )
        session.status = "ready"
    except Exception as exc:
        session.status = "failed"
        session.error = _short_error(exc)
        _log.warning(f"assisted-login session for role '{role}' failed to start: {exc}")
    return session


@app.get("/api/auth/roles")
def get_auth_roles() -> list[dict]:
    """Whatever roles are actually configured in `users.json` -- could
    be one account, could be five. Verify Login's role picker reads
    this instead of assuming a fixed admin+normal pair, since a target
    handed to STOF for testing frequently only comes with a single
    account (see the account-provisioning reality check baked into
    `EXPLOIT_COVERAGE.md`'s own cross-identity-technique notes)."""
    try:
        from stof.config import load_dotenv, load_users
        load_dotenv()
        users = load_users(USERS_PATH)
    except Exception as exc:
        _log.warning(f"could not load users.json for the Verify Login role picker: {exc}")
        return []
    return [
        {"role": u.role, "username": u.username, "auth_type": u.auth_type, "verifiable": u.auth_type == "form_login"}
        for u in users.users
    ]


class VerifyLoginRequest(BaseModel):
    role: str = "normal"


@app.post("/api/auth/verify-login")
async def start_verify_login(body: VerifyLoginRequest) -> dict:
    if VERIFY_LOGIN.current is not None and VERIFY_LOGIN.current.status == "starting":
        raise HTTPException(409, "a Verify Login check is already running -- wait for it to finish")
    verify_id = f"vl-{uuid.uuid4().hex[:8]}"
    session = VerifyLoginSession(verify_id, body.role)
    VERIFY_LOGIN.current = session
    task = asyncio.create_task(_run_verify_login(session))
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)
    return {"verify_id": verify_id, "status": session.status, "role": session.role}


class ManualSessionRequest(BaseModel):
    role: str
    cookies: str  # raw "name=value; name2=value2" -- what a browser's devtools/Network tab shows
    expires_hours: int = 6


def _parse_cookie_header(raw: str) -> dict[str, str]:
    """Parses a `name=value; name2=value2` cookie header string, the
    exact format an operator copies straight out of their own real
    browser's devtools (Application tab, or a request's `Cookie`
    header) -- no reformatting asked of them. Malformed/empty segments
    are skipped rather than raising, since a trailing `;` or stray
    whitespace in a pasted value is common and shouldn't block the
    whole paste over one bad segment."""
    cookies: dict[str, str] = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, value = part.partition("=")
        name = name.strip()
        if name:
            cookies[name] = value.strip()
    return cookies


@app.post("/api/auth/manual-session")
def set_manual_session(body: ManualSessionRequest) -> dict:
    """Seeds a role's session directly from cookies the operator captured
    in their own, real, non-automated browser -- for targets where
    STOF's automated login (form-based or assisted) can't be used at
    all. A scan then skips login entirely for this role: `SessionManager`
    already treats any unexpired seeded session as ready-to-use without
    calling a provider (see `stof/session/session_manager.py`'s
    `seed_session`/`needs_refresh`), the exact mechanism Assisted Login
    also relies on -- this just seeds the store a different way.

    Honest limitation, not hidden: a cookie captured on a DIFFERENT
    machine/network than wherever the scan actually runs can still be
    rejected by targets that bind the cookie to the originating
    IP/TLS fingerprint (e.g. Cloudflare's cf_clearance) -- this only
    reliably works for ordinary session-cookie auth, not bot-challenge
    cookies from a different egress point."""
    cookies = _parse_cookie_header(body.cookies)
    if not cookies:
        raise HTTPException(400, "no cookies could be parsed -- expected 'name=value; name2=value2'")
    from datetime import datetime, timedelta, timezone

    from stof.session.models import Session
    from stof.session.session_store import SessionStore

    session = Session(
        user_id=f"{body.role}-manual",
        role=body.role,
        auth_type="manual_cookie",
        cookies=cookies,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=body.expires_hours),
    )
    SessionStore(db_path=SESSIONS_DB_PATH).save(session)
    return {"role": body.role, "cookie_count": len(cookies), "expires_at": session.expires_at.isoformat()}


@app.delete("/api/auth/manual-session/{role}")
def clear_manual_session(role: str) -> dict:
    from stof.session.session_store import SessionStore

    SessionStore(db_path=SESSIONS_DB_PATH).delete(role)
    return {"role": role, "cleared": True}


class AssistedLoginStartRequest(BaseModel):
    role: str


@app.post("/api/auth/assisted-login/start")
async def start_assisted_login(body: AssistedLoginStartRequest) -> dict:
    """Launches (or reuses) the shared assisted-login browser and opens
    a fresh context/page for `role`, navigated to the configured login
    URL and screencasting. The frontend then opens the WebSocket
    (`/ws/assisted-login/{role}`) to actually see and drive it."""
    from stof.config import load_config, load_dotenv, load_users
    load_dotenv()
    config = load_config(CONFIG_PATH)
    users = load_users(USERS_PATH)
    user = next((u for u in users.users if u.role == body.role), None)
    if user is None:
        raise HTTPException(404, f"no user with role '{body.role}' in users.json")
    if user.auth_type != "form_login":
        raise HTTPException(400, f"role '{body.role}' uses auth_type '{user.auth_type}' -- assisted login only applies to a real login form")

    session = await _start_assisted_login_session(body.role, config.target.login_url)
    return {"role": session.role, "status": session.status, "error": session.error}


@app.get("/api/auth/assisted-login/status")
def get_assisted_login_status(role: str) -> dict:
    session = ASSISTED_LOGIN.sessions.get(role)
    if session is None:
        return {"role": role, "status": "idle"}
    return {"role": session.role, "status": session.status, "error": session.error}


@app.post("/api/auth/assisted-login/confirm")
async def confirm_assisted_login(body: AssistedLoginStartRequest) -> dict:
    """Checked once the operator says they've completed login (cleared
    the bot-challenge, submitted credentials) in the live view -- reuses
    the exact same success-selector/URL-change detection `FormLoginProvider`
    itself relies on, so this is never just "the operator said so"."""
    from stof.auth.base import AuthFailedError
    from stof.auth.form_login import wait_for_login_success
    from stof.config import load_config, load_dotenv
    load_dotenv()
    config = load_config(CONFIG_PATH)

    session = ASSISTED_LOGIN.sessions.get(body.role)
    if session is None or session.page is None:
        raise HTTPException(404, f"no assisted-login session in progress for role '{body.role}' -- start one first")
    try:
        await wait_for_login_success(
            session.page, session.login_url, config.target.success_selector, timeout_ms=3000, context_label=f"assisted login (role={body.role})"
        )
    except AuthFailedError as exc:
        session.status = "ready"  # still usable -- the operator can keep trying in the live view
        return {"role": body.role, "confirmed": False, "detail": str(exc)}
    session.status = "confirmed"
    return {"role": body.role, "confirmed": True}


@app.websocket("/ws/assisted-login/{role}")
async def assisted_login_stream(websocket: WebSocket, role: str) -> None:
    """Bidirectional: relays `Page.screencastFrame` events out to the
    browser tab as `{"type":"frame","data": <base64 jpeg>}`, and relays
    mouse/keyboard events the operator performs on the live-view canvas
    back in as real CDP `Input.dispatch*` calls against the actual
    server-side page -- the operator is genuinely typing into and
    clicking the real browser that will go on to run the scan, not a
    simulation of it."""
    await websocket.accept()
    session = ASSISTED_LOGIN.sessions.get(role)
    if session is None or session.cdp_session is None:
        await websocket.close(code=4004, reason=f"no assisted-login session for role '{role}'")
        return

    def _forward_frame(event: dict) -> None:
        data = event.get("data")
        if data is None:
            return
        task = asyncio.ensure_future(websocket.send_json({"type": "frame", "data": data}))
        _BACKGROUND_TASKS.add(task)
        task.add_done_callback(_BACKGROUND_TASKS.discard)
        ack_task = asyncio.ensure_future(session.cdp_session.send("Page.screencastFrameAck", {"sessionId": event.get("sessionId")}))
        _BACKGROUND_TASKS.add(ack_task)
        ack_task.add_done_callback(_BACKGROUND_TASKS.discard)

    session.cdp_session.on("Page.screencastFrame", _forward_frame)
    try:
        while True:
            message = await websocket.receive_json()
            await _dispatch_assisted_login_input(session, message)
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        _log.warning(f"assisted-login stream for role '{role}' ended unexpectedly: {exc}")
    finally:
        session.cdp_session.remove_listener("Page.screencastFrame", _forward_frame)
        # Deliberately does NOT close session.page/context/the browser --
        # the operator may reconnect, and the login session (once
        # confirmed) needs to survive until the scan subprocess has
        # reconnected over CDP and finished using it.


async def _dispatch_assisted_login_input(session: "AssistedLoginRoleSession", message: dict) -> None:
    """Translates one input message from the live-view client into the
    matching CDP `Input.dispatch*` call. Unknown/malformed messages are
    ignored (never crash the socket over one bad client-side event)."""
    kind = message.get("type")
    try:
        if kind == "mouse":
            await session.cdp_session.send("Input.dispatchMouseEvent", {
                "type": message["event"],  # "mousePressed" | "mouseReleased" | "mouseMoved"
                "x": message["x"],
                "y": message["y"],
                "button": message.get("button", "left"),
                "clickCount": message.get("clickCount", 1),
            })
        elif kind == "wheel":
            await session.cdp_session.send("Input.dispatchMouseEvent", {
                "type": "mouseWheel",
                "x": message["x"],
                "y": message["y"],
                "deltaX": message.get("deltaX", 0),
                "deltaY": message.get("deltaY", 0),
            })
        elif kind == "key":
            await session.cdp_session.send("Input.dispatchKeyEvent", {
                "type": message["event"],  # "keyDown" | "keyUp" | "char"
                "text": message.get("text", ""),
                "key": message.get("key", ""),
                "code": message.get("code", ""),
            })
    except Exception as exc:
        _log.debug(f"assisted-login input dispatch failed (role={session.role}): {exc}")


@app.get("/api/auth/verify-login/current")
def get_current_verify_login() -> dict:
    session = VERIFY_LOGIN.current
    if session is None:
        return {"status": "idle"}
    return {
        "verify_id": session.verify_id, "status": session.status, "role": session.role,
        "error": session.error, "matched_via": session.matched_via, "target_url": session.target_url,
        "screenshot_data_url": session.screenshot_data_url,
    }


# ---------------------------------------------------------------------------
# Tool health check -- "is STOF itself working correctly" is a real
# question to answer BEFORE trusting it to test a real target, not
# after. `stof/`'s core package has a large unit test suite
# (tests/unit); this runs it as a real subprocess (same pattern as a
# scan) and surfaces pass/fail right in the console instead of that
# suite only ever being visible to whoever happens to run pytest by
# hand. This does NOT add test coverage for stof/ui/server.py itself
# (a real, separate gap) -- it makes the coverage that already exists
# actually visible where an operator will see it: right before they
# click "Start scan."
# ---------------------------------------------------------------------------

_PYTEST_SUMMARY_RE = re.compile(
    r"(?:(?P<failed>\d+) failed, )?(?P<passed>\d+) passed(?:, (?P<skipped>\d+) skipped)?.* in (?P<duration>[\d.]+)s"
)
_PYTEST_FAILURE_RE = re.compile(r"^FAILED (\S+)")


class HealthCheckSession:
    def __init__(self, check_id: str) -> None:
        self.check_id = check_id
        self.status = "running"  # running | passed | failed | error
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.finished_at: str | None = None
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.duration_s: float | None = None
        self.failing_tests: list[str] = []
        self.error: str | None = None


class HealthCheckRegistry:
    def __init__(self) -> None:
        self.current: HealthCheckSession | None = None


HEALTH_CHECK = HealthCheckRegistry()


async def _run_health_check(session: HealthCheckSession) -> None:
    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "pytest", "tests/unit", "-q", "--tb=line",
            cwd=REPO_ROOT, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
    except Exception as exc:
        session.status = "error"
        session.error = _short_error(exc)
        session.finished_at = datetime.now(timezone.utc).isoformat()
        return

    lines: list[str] = []
    if process.stdout is not None:
        while True:
            raw = await process.stdout.readline()
            if not raw:
                break
            lines.append(_strip_ansi(raw.decode("utf-8", errors="replace").rstrip("\n")))
    await process.wait()

    session.failing_tests = [m.group(1) for line in lines if (m := _PYTEST_FAILURE_RE.match(line))][:20]
    summary_line = next((line for line in reversed(lines) if " in " in line and ("passed" in line or "failed" in line)), "")
    m = _PYTEST_SUMMARY_RE.search(summary_line)
    if m:
        session.passed = int(m.group("passed") or 0)
        session.failed = int(m.group("failed") or 0)
        session.skipped = int(m.group("skipped") or 0)
        session.duration_s = float(m.group("duration"))
        session.status = "failed" if session.failed else "passed"
    else:
        session.status = "error"
        session.error = "could not parse pytest output" + (f" -- tail: {lines[-1]}" if lines else " (no output)")
    session.finished_at = datetime.now(timezone.utc).isoformat()


@app.post("/api/health/run-tests")
async def start_health_check() -> dict:
    if HEALTH_CHECK.current is not None and HEALTH_CHECK.current.status == "running":
        raise HTTPException(409, "a test run is already in progress")
    check_id = f"hc-{uuid.uuid4().hex[:8]}"
    session = HealthCheckSession(check_id)
    HEALTH_CHECK.current = session
    task = asyncio.create_task(_run_health_check(session))
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)
    return {"check_id": check_id, "status": session.status}


@app.get("/api/health/run-tests/current")
def get_current_health_check() -> dict:
    session = HEALTH_CHECK.current
    if session is None:
        return {"status": "idle"}
    return {
        "check_id": session.check_id, "status": session.status,
        "passed": session.passed, "failed": session.failed, "skipped": session.skipped,
        "duration_s": session.duration_s, "failing_tests": session.failing_tests, "error": session.error,
        "started_at": session.started_at, "finished_at": session.finished_at,
    }


@app.get("/api/workflows")
def list_workflows() -> list[dict]:
    if not WORKFLOWS_DIR.is_dir():
        return []
    out = []
    for path in sorted(WORKFLOWS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        doc = _read_json(path)
        if doc is None or "workflow_id" not in doc:
            continue
        out.append({
            "workflow_id": doc["workflow_id"], "name": path.stem, "target_url": doc.get("target_url"),
            "recorded_at": doc.get("recorded_at"), "action_count": len(doc.get("actions", [])),
        })
    return out


@app.get("/api/workflows/{workflow_id}")
def get_workflow(workflow_id: str) -> dict:
    if not WORKFLOWS_DIR.is_dir():
        raise HTTPException(404, "no workflows recorded yet")
    for path in WORKFLOWS_DIR.glob("*.json"):
        doc = _read_json(path)
        if doc is not None and doc.get("workflow_id") == workflow_id:
            doc["name"] = path.stem
            return doc
    raise HTTPException(404, f"no workflow '{workflow_id}'")


@app.get("/api/recordings/standalone-script")
def download_standalone_recorder() -> FileResponse:
    """Serves `tools/record_workflow.py` -- the offline, zero-STOF-install
    counterpart to the CDP-attach recording above, for a tester whose
    only path to the target is their own laptop, not this server."""
    path = REPO_ROOT / "tools" / "record_workflow.py"
    if not path.is_file():
        raise HTTPException(404, "record_workflow.py not found on this server")
    return FileResponse(path, media_type="text/x-python", filename="record_workflow.py")


@app.post("/api/workflows/upload")
async def upload_workflow(file: UploadFile) -> dict:
    """Import a workflow JSON recorded offline (see `tools/record_workflow.py`)
    -- the standalone-script counterpart to the CDP-attach recording flow
    above, for testers whose environment can't reach a client-network
    debug port at all: they record locally on their own machine, then
    hand the resulting file to this endpoint."""
    raw = await file.read()
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"not valid JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise HTTPException(400, "workflow file must be a JSON object")
    missing = [key for key in ("workflow_id", "target_url", "actions") if key not in doc]
    if missing:
        raise HTTPException(400, f"missing required field(s): {', '.join(missing)}")
    if not isinstance(doc["actions"], list):
        raise HTTPException(400, "'actions' must be a list")
    for i, action in enumerate(doc["actions"]):
        if not isinstance(action, dict) or "type" not in action:
            raise HTTPException(400, f"action {i} is missing a 'type' field")

    WORKFLOWS_DIR.mkdir(parents=True, exist_ok=True)
    stem = Path(file.filename).stem if file.filename else doc["workflow_id"]
    filename = f"{_slugify(stem)}.json"
    path = WORKFLOWS_DIR / filename
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    await _broadcast_global({"event": "workflow_saved", "workflow_id": doc["workflow_id"]})
    return {
        "workflow_id": doc["workflow_id"], "name": path.stem,
        "target_url": doc["target_url"], "action_count": len(doc["actions"]),
    }


@app.delete("/api/workflows/{workflow_id}")
async def delete_workflow(workflow_id: str) -> dict:
    if not WORKFLOWS_DIR.is_dir():
        raise HTTPException(404, "no workflows recorded yet")
    for path in WORKFLOWS_DIR.glob("*.json"):
        doc = _read_json(path)
        if doc is not None and doc.get("workflow_id") == workflow_id:
            path.unlink()
            await _broadcast_global({"event": "workflow_deleted", "workflow_id": workflow_id})
            return {"deleted": workflow_id}
    raise HTTPException(404, f"no workflow '{workflow_id}'")


@app.post("/api/scans")
async def start_scan(body: StartScanRequest) -> dict:
    if not body.confirm_authorized:
        raise HTTPException(
            400,
            "confirm_authorized must be true -- the operator must explicitly confirm authorization "
            "to test the configured target before a scan (which sends real attack payloads) can start.",
        )
    # A scan is a real subprocess driving a real Playwright browser that
    # sends real attack payloads -- nothing previously stopped a second
    # (third, tenth...) POST here from launching another one on top of
    # an already-running scan, whether from a double-click, a second
    # browser tab, or a script hitting this endpoint directly. That's
    # not just wasted resources: it's unbounded, unintended attack
    # traffic multiplying against the same target. One scan at a time,
    # same 409 pattern already used for Verify Login and Recording.
    already_running = next((r for r in REGISTRY.all() if r.status == "running"), None)
    if already_running is not None:
        raise HTTPException(
            409,
            f"scan '{already_running.scan_id}' is already running against "
            f"'{already_running.target}' -- stop it first (POST /api/scans/{already_running.scan_id}/stop) "
            "or wait for it to finish before starting another.",
        )
    doc = _read_json(CONFIG_PATH)
    if doc is None:
        raise HTTPException(404, f"{CONFIG_PATH} not found -- run `stof configure` first")
    target = doc.get("target", {}).get("base_url", "unknown")

    record = REGISTRY.create(target, body.modules or [], workflow_ids=body.workflow_ids)
    if body.name:
        _save_scan_name(record.scan_id, body.name)
    task = asyncio.create_task(_run_scan_process(record, body.modules, workflow_ids=body.workflow_ids))
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)
    await _broadcast_global({
        "event": "scan_created", "scan_id": record.scan_id, "target": target,
        "modules": record.modules, "started_at": record.started_at,
    })
    return {"scan_id": record.scan_id, "target": target, "status": record.status}


@app.patch("/api/scans/{scan_id}/name")
def rename_scan(scan_id: str, body: ScanNameRequest) -> dict:
    """Works for ANY scan_id, not just ones this server process
    launched -- a tester often only knows what to call a scan after
    looking at its results, sometimes long after the fact, and a scan
    started from the CLI directly is just as nameable as one started
    from this console."""
    _save_scan_name(scan_id, body.name)
    return {"scan_id": scan_id, "name": body.name.strip() or None}


@app.get("/api/scans")
def list_scans() -> list[dict]:
    names = _load_scan_names()
    live = {r.scan_id: r for r in REGISTRY.all()}
    out = []
    for r in live.values():
        out.append({
            "scan_id": r.scan_id, "name": names.get(r.scan_id), "target": r.target, "modules": r.modules,
            "status": r.status, "exit_code": r.exit_code,
            "started_at": r.started_at, "finished_at": r.finished_at,
        })
    # Also surface past scans this process never launched (e.g. run from
    # the CLI directly, or from a previous server process) by reading
    # whatever report JSON files already exist on disk.
    if REPORTS_DIR.is_dir():
        for path in sorted(REPORTS_DIR.glob("scan_*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            m = re.match(r"scan_([0-9a-f]+)\.json$", path.name)
            if not m or m.group(1) in live:
                continue
            report = _read_json(path) or {}
            out.append({
                "scan_id": m.group(1), "name": names.get(m.group(1)), "target": report.get("target", "unknown"),
                "modules": report.get("modules_run", []), "status": "complete", "exit_code": 0,
                "started_at": report.get("generated_at"), "finished_at": report.get("generated_at"),
            })
    # One consistent "most recent first" ordering regardless of source
    # (in-memory vs. disk-recovered) -- the Dashboard's default scan
    # picker depends on out[0] actually being the newest.
    out.sort(key=lambda s: s.get("started_at") or "", reverse=True)
    return out


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    record = REGISTRY.get(scan_id)
    if record is not None:
        return {
            "scan_id": record.scan_id, "name": _load_scan_names().get(record.scan_id),
            "target": record.target, "modules": record.modules, "workflow_ids": record.workflow_ids,
            "status": record.status, "exit_code": record.exit_code,
            "started_at": record.started_at, "finished_at": record.finished_at,
            "current_phase": record.current_phase, "modules_state": record.modules_state,
            "live_findings": record.live_findings, "events": record.events, "crawl": record.crawl,
        }
    report_path = REPORTS_DIR / f"scan_{scan_id}.json"
    report = _read_json(report_path)
    if report is None:
        raise HTTPException(404, f"no scan '{scan_id}' known to this server and no report on disk")

    # This server process never launched this scan (it finished before
    # this process started, or a restart dropped the in-memory record)
    # -- reconstruct the same snapshot a live scan would have by
    # replaying its `.events.jsonl` file through the identical folding
    # logic, instead of returning empty stubs. This is what used to
    # leave the Dashboard's KPIs permanently blank for anything but the
    # scan that happened to be actively running when the page loaded.
    replay = ScanRecord(scan_id, report.get("target", "unknown"), report.get("modules_run", []))
    events_path = LOGS_DIR / f"scan_{scan_id}.events.jsonl"
    if events_path.is_file():
        for raw_line in events_path.read_text(encoding="utf-8").splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                event = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            replay.events.append(event)
            _apply_event_to_state(replay, event)
    return {
        "scan_id": scan_id, "name": _load_scan_names().get(scan_id), "target": report.get("target", "unknown"),
        "modules": report.get("modules_run", []), "status": "complete", "exit_code": 0,
        "started_at": report.get("generated_at"), "finished_at": report.get("generated_at"),
        "current_phase": replay.current_phase, "modules_state": replay.modules_state,
        "live_findings": replay.live_findings, "events": replay.events, "crawl": replay.crawl,
    }


@app.post("/api/scans/{scan_id}/stop")
async def stop_scan(scan_id: str) -> dict:
    """SIGTERM's the scan's real subprocess, escalating to SIGKILL if it
    hasn't exited within 10s. `_run_scan_process`'s own exit-handling
    code (unchanged otherwise) notices `record.stop_requested` and
    reports `status: "stopped"` rather than `"failed"` once the process
    actually dies -- terminating it here doesn't itself flip the
    status; that still happens exactly once, in the one place that
    already reads the real exit code."""
    record = REGISTRY.get(scan_id)
    if record is None:
        raise HTTPException(404, f"no running scan '{scan_id}' known to this server")
    if record.status != "running":
        raise HTTPException(409, f"scan '{scan_id}' is not running (status: {record.status})")
    if record.process is None or record.process.returncode is not None:
        raise HTTPException(409, f"scan '{scan_id}' has no live process to stop")

    record.stop_requested = True
    record.process.terminate()
    try:
        await asyncio.wait_for(record.process.wait(), timeout=10)
    except asyncio.TimeoutError:
        record.process.kill()
        await record.process.wait()
    return {"scan_id": scan_id, "status": "stopping"}


@app.get("/api/evidence/{evidence_path:path}")
def get_evidence_file(evidence_path: str) -> FileResponse:
    """Serves one file under `data/evidence/` (a finding's screenshot,
    request/response capture) for the Findings-tab detail modal.
    `Finding.evidence_refs` stores paths like `data/evidence/<scan_id>/
    <label>/<file>` (see `evidence/collector.py`) -- this strips a
    leading `data/evidence/` if present so it accepts either that full
    stored form or just the part after it, then resolves strictly
    inside EVIDENCE_DIR to block path traversal (`../../etc/passwd`)."""
    relative = evidence_path.removeprefix("data/evidence/").removeprefix("data\\evidence\\")
    path = (EVIDENCE_DIR / relative).resolve()
    if EVIDENCE_DIR.resolve() not in path.parents or not path.is_file():
        raise HTTPException(404, "evidence file not found")
    return FileResponse(path)


@app.get("/api/scans/{scan_id}/findings")
def get_findings(scan_id: str) -> dict:
    report = _read_json(REPORTS_DIR / f"scan_{scan_id}.json")
    if report is not None:
        return report
    findings = _read_json(FINDINGS_DIR / f"scan_{scan_id}.json")
    if findings is None:
        raise HTTPException(404, f"no findings for scan '{scan_id}' yet")
    return {"scan_id": scan_id, "findings": findings, "summary": None}


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str) -> dict:
    """Removes every trace of one scan: its report (HTML/JSON/XLSX/
    walkthrough), log + events files, raw findings, evidence
    screenshots, recon snapshot, and the in-memory `ScanRegistry`
    record if this server process happens to still hold one (deleting
    the report files alone, by hand outside the API, leaves a stale
    in-memory record that `GET /api/scans` keeps serving until the
    server restarts -- confirmed live, this is the bug that motivated
    building a real delete endpoint instead of a shell `rm`)."""
    record = REGISTRY.get(scan_id)
    if record is not None and record.status == "running":
        raise HTTPException(409, "cannot delete a scan that's still running -- wait for it to finish or fail first")
    if record is None and not any(REPORTS_DIR.glob(f"scan_{scan_id}.*")):
        raise HTTPException(404, f"no scan '{scan_id}' known to this server")

    REGISTRY.remove(scan_id)
    removed = []
    for path in REPORTS_DIR.glob(f"scan_{scan_id}.*"):
        path.unlink(missing_ok=True)
        removed.append(path.name)
    for path in REPORTS_DIR.glob(f"scan_{scan_id}_*"):  # e.g. the walkthrough report
        path.unlink(missing_ok=True)
        removed.append(path.name)
    for path in (LOGS_DIR / f"scan_{scan_id}.log", LOGS_DIR / f"scan_{scan_id}.events.jsonl",
                 FINDINGS_DIR / f"scan_{scan_id}.json", RECON_DIR / f"scan_{scan_id}.json"):
        if path.is_file():
            path.unlink(missing_ok=True)
            removed.append(path.name)
    evidence_dir = EVIDENCE_DIR / scan_id
    if evidence_dir.is_dir():
        shutil.rmtree(evidence_dir, ignore_errors=True)
        removed.append(f"evidence/{scan_id}/")

    await _broadcast_global({"event": "scan_deleted", "scan_id": scan_id})
    return {"deleted": scan_id, "removed": removed}


@app.websocket("/api/stream")
async def global_stream(websocket: WebSocket) -> None:
    """The one persistent connection a browser tab holds for its whole
    session. Carries every cross-cutting change: `scan_event` (wraps a
    per-scan structured event, tagged with `scan_id` -- see
    `_broadcast_event`), `scan_created`, `module_toggled`,
    `testing_changed`, `workflow_saved`, `workflow_deleted`,
    `report_generated`. A client that needs one scan's full event
    history (e.g. attaching mid-scan, or after its own reconnect) gets
    it from `GET /api/scans/{id}`'s own `events` field -- this socket
    only ever carries what happens FROM the moment it connects."""
    await websocket.accept()
    GLOBAL_SUBSCRIBERS.add(websocket)
    try:
        while True:
            # Client sends nothing meaningful; this just detects disconnect.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        GLOBAL_SUBSCRIBERS.discard(websocket)


@app.get("/api/dashboard/summary")
def get_dashboard_summary() -> dict:
    """Aggregates across every completed scan's report JSON on disk --
    the executive/leadership view: risk posture over time, not one
    scan's detail. Deliberately reads `data/reports/scan_*.json`
    directly (the same durable, scan-id-namespaced files the CLI has
    always written) rather than the in-memory ScanRegistry, so this
    reflects every scan ever run against this target, including ones
    from before this server process started or from the CLI directly."""
    reports: list[dict] = []
    if REPORTS_DIR.is_dir():
        for path in sorted(REPORTS_DIR.glob("scan_*.json")):
            report = _read_json(path)
            if report is not None and "summary" in report:
                reports.append(report)
    reports.sort(key=lambda r: r.get("generated_at") or "")

    if not reports:
        return {
            "total_scans": 0, "latest": None, "trend": [], "top_modules": [],
            "coverage": {"modules_with_findings": 0, "modules_total": len(_KNOWN_MODULES) - 1},
        }

    trend = [
        {
            "scan_id": r.get("scan_id"), "target": r.get("target"), "generated_at": r.get("generated_at"),
            "by_severity": r.get("summary", {}).get("by_severity", {}),
            "total": r.get("summary", {}).get("total_findings", 0),
        }
        for r in reports[-12:]  # last 12 scans -- enough for a trend read, not a wall of bars
    ]

    module_counts: dict[str, dict[str, int]] = {}
    for r in reports:
        for finding in r.get("findings", []):
            mod_id = finding.get("module_id", "unknown")
            entry = module_counts.setdefault(mod_id, {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0, "total": 0})
            sev = finding.get("severity", "Info")
            if sev in entry:
                entry[sev] += 1
            entry["total"] += 1
    top_modules = sorted(
        [{"module": mod_id, **counts} for mod_id, counts in module_counts.items()],
        key=lambda m: (m["Critical"], m["High"], m["total"]), reverse=True,
    )[:8]

    latest = reports[-1]
    return {
        "total_scans": len(reports),
        "latest": {
            "scan_id": latest.get("scan_id"), "target": latest.get("target"),
            "generated_at": latest.get("generated_at"),
            "by_severity": latest.get("summary", {}).get("by_severity", {}),
            "total": latest.get("summary", {}).get("total_findings", 0),
        },
        "trend": trend,
        "top_modules": top_modules,
        "coverage": {
            "modules_with_findings": len(module_counts),
            "modules_total": len(_KNOWN_MODULES) - 1,  # exclude crawler (not a technique module)
        },
    }


@app.get("/api/reports")
def list_reports() -> list[dict]:
    if not REPORTS_DIR.is_dir():
        return []
    names = _load_scan_names()
    # scan_id -> target, from whichever report JSON exists for it -- the
    # cheapest source of truth already on disk, read once per request
    # rather than once per file (an HTML/XLSX/JSON triple all share one).
    target_by_scan: dict[str, str] = {}
    out = []
    for path in sorted(REPORTS_DIR.glob("scan_*.*"), key=lambda p: p.stat().st_mtime, reverse=True):
        if path.suffix not in (".html", ".json", ".xlsx"):
            continue
        m = re.match(r"scan_([0-9a-f]+)", path.stem)
        scan_id = m.group(1) if m else None
        target = None
        if scan_id:
            if scan_id not in target_by_scan:
                report = _read_json(REPORTS_DIR / f"scan_{scan_id}.json")
                target_by_scan[scan_id] = (report or {}).get("target", "unknown")
            target = target_by_scan[scan_id]
        stat = path.stat()
        out.append({
            "filename": path.name,
            "scan_id": scan_id,
            "scan_name": names.get(scan_id) if scan_id else None,
            "target": target,
            "type": path.suffix.lstrip(".").upper(),
            "size_bytes": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        })
    return out


@app.get("/api/reports/{filename}")
def get_report_file(filename: str):
    # `filename` must resolve to a direct child of REPORTS_DIR with no
    # path-traversal component -- the only file-serving endpoint this
    # API exposes, so this check is load-bearing.
    if "/" in filename or "\\" in filename or filename.startswith("."):
        raise HTTPException(400, "invalid filename")
    path = REPORTS_DIR / filename
    if not path.is_file() or path.resolve().parent != REPORTS_DIR.resolve():
        raise HTTPException(404, "report not found")
    if path.suffix == ".html":
        return HTMLResponse(path.read_text(encoding="utf-8"))
    if path.suffix == ".json":
        return JSONResponse(_read_json(path))
    return FileResponse(path)


# ---------------------------------------------------------------------------
# Static UI
# ---------------------------------------------------------------------------

if STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("stof.ui.server:app", host="127.0.0.1", port=8787, reload=True)
