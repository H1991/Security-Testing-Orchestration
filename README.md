# STOF — Security Testing Orchestration Framework

CLI-first, Python + Playwright automated security testing framework
focused on authentication and session vulnerabilities. See
[CLAUDE.md](CLAUDE.md) for the full architecture (single source of truth).

Phase 1 build status: **Layer 1 — Configuration**, **Layer 2 —
Orchestrator**, **Layer 3A — Browser Recorder**, **Layer 3B —
Playwright Engine**, **Layer 4 — Authentication Manager**,
**Layer 5 — Session Manager**, **Layer 6 — Workflow Repository**, and
**Layer 7 — Crawler & Endpoint Discovery** complete.

**Layer 8 — Configuration-driven Test Orchestrator** is also built,
ahead of its documented Phase 2 slot, at explicit request.

## Setup (Linux / macOS / Windows)

Requires Python 3.11+. Commands are cross-platform except where noted.

```bash
# 1. Create and activate a virtual environment
python -m venv .venv

#    Linux / macOS:
source .venv/bin/activate
#    Windows (cmd.exe):
.venv\Scripts\activate.bat
#    Windows (PowerShell):
.venv\Scripts\Activate.ps1

# 2. Install the project in editable mode with dev dependencies
pip install -e ".[dev]"
```

## Testing

```bash
pytest tests/unit/ -v
```

All I/O in `stof/config/` goes through `pathlib.Path` with explicit
UTF-8 encoding, and `stof/core/` uses only `sqlite3`/`asyncio` from the
standard library — no OS-specific paths or calls — so both behave
identically on Linux and Windows.

## Manually testing Layer 3A (Browser Recorder) against real Chrome

The recorder attaches to a Chrome instance you already have open — it
does not launch one. `pip install -e ".[dev]"` installs the `playwright`
Python package, which is enough for this (no `playwright install`
browser download needed, since we're attaching over CDP to your own
Chrome, not a Playwright-managed one).

```bash
# 1. Launch Chrome with a remote debugging port, using a scratch profile
#    (a fresh profile avoids conflicts with your normal Chrome session).
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/stof-chrome-profile &

# 2. In the Chrome window that opens, navigate to the target
#    (e.g. https://demo.testfire.net) yourself.

# 3. In another terminal, with the venv active, start recording:
python -m stof.recorder \
  --output data/workflows/test_login.json \
  --users config/users.json

# 4. Back in Chrome: click around, fill in the login form, submit.

# 5. Return to the terminal running the recorder and press Enter to stop.
#    Inspect the result:
cat data/workflows/test_login.json
```

Things worth checking in the output: `navigate` actions appear for each
page you visited, `click`/`fill` actions appear for your interactions,
and — importantly — any value you typed that matches a password/username
in `config/users.json` should show up as `{{user.password}}` /
`{{user.username}}`, never as the literal value.

## Secrets

Copy `.env.example` to `.env` and fill in real values, then export them
into your shell (or use your OS's env var manager) before running a
scan — `config/users.json` resolves `{{env:VAR}}` tokens from the
process environment. Never commit `.env`.
