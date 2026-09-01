"""Layer 15 — `stof/ui/`: FastAPI backend for the STOF web console.

Phase 2 addition (CLAUDE.md's own Phase 2 table lists `ui/` as
"FastAPI + React Web UI"). Deliberately does NOT reimplement any of
Layers 1-13 -- it shells out to the existing `stof scan` CLI command
(same one a terminal user runs) as a subprocess and streams its stdout
to the browser over a WebSocket, then reads the same JSON/HTML/Excel
report files `stof scan` already writes to `data/reports/`. The
orchestration logic itself has exactly one owner (`stof/main.py`'s
`_run_scan`); this package is a thin process-supervisor and file-reader
in front of it, not a second implementation.
"""
