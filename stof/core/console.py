"""Layer 2 — enterprise-style scan console + per-scan log file.

Every `stof scan`/`stof test` run gets its own persistent transcript at
`data/logs/scan_<scan_id>.log` -- CLAUDE.md's own structured-logging
rule ("all layers use this") extended to the CLI's progress output
too, not just internal `_log.*` calls, so a completed scan's full
record survives after the terminal closes and can be attached to a
report or reviewed after the fact.

`ScanConsole` owns exactly one scan's output. Terminal and log file are
DELIBERATELY not identical: the terminal is a compact, scannable,
box-drawn display (PASS/SKIP techniques print one line, no detail --
only FAIL/ERROR earns a second line, so a long scan's live output
isn't drowned in text for results nobody needs to act on); the log
file is the complete plain-text record -- every technique, full detail,
ANSI-stripped, UTC-timestamped -- so nothing is lost, it's just not
all shoved at the terminal while a scan is running.

`attach_file_logging()` additionally routes every layer's own
`_log.info/warning/error` calls (crawler, auth, session, modules, ...)
into the same file, so the log is the one place that has everything --
not just this file's own banner/phase/summary lines.

A THIRD, sibling output exists alongside the two above: `data/logs/
scan_<id>.events.jsonl`, one JSON object per structured milestone
(phase change, module started/completed, a FAIL/ERROR finding, scan
complete). This is deliberately NOT derived by re-parsing the terminal
or log text -- `stof/ui/server.py`'s web console needs a live, correct
"module X is now running / done, N pass / M fail" view, and re-parsing
box-drawn, `\r`-redrawn, colorized human output for that is fragile by
construction (confirmed: it silently broke once already, since
`progress_bar()`'s raw carriage-return redraws never even reach the
plain-text log). Real automation-facing tools (scanner status APIs,
CI webhooks) emit a structured event stream for exactly this reason --
this is that stream, kept intentionally small (only the milestones a
consumer actually needs), with the human-formatted output remaining
the terminal/log file's job unchanged.
"""
from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import click

from .logger import LayerTagFormatter

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

DEFAULT_LOG_DIR = Path("data/logs")

# Box-drawing glyphs -- kept as named constants (not inlined) so the one
# "what does this terminal render as" concern lives in one place.
_TL, _TR, _BL, _BR = "╭", "╮", "╰", "╯"
_H, _V = "─", "│"
_ML, _MR, _MT, _MB, _MX = "├", "┤", "┬", "┴", "┼"

_STATUS_ICON = {"PASS": "✔", "FAIL": "✖", "SKIPPED": "○", "NOT_IMPLEMENTED": "⊘", "ERROR": "⚠"}
_STATUS_LABEL = {"PASS": "PASS", "FAIL": "FAIL", "SKIPPED": "SKIP", "NOT_IMPLEMENTED": "N/A ", "ERROR": "ERR "}
_STATUS_COLOR = {"PASS": "green", "FAIL": "red", "SKIPPED": "yellow", "NOT_IMPLEMENTED": "white", "ERROR": "red"}
_SEVERITY_COLOR = {"Critical": "red", "High": "red", "Medium": "yellow", "Low": "blue", "Info": "cyan"}
_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def attach_file_logging(log_path: str | Path) -> logging.Handler:
    """Adds a `FileHandler` to the shared `stof` logger namespace (see
    `core/logger.py`) so every layer's `_log.*` call lands in the same
    per-scan log file `ScanConsole` writes its own lines to. Returns
    the handler so the caller can remove it when the scan ends --
    `configure_logging()`'s console handler is process-lifetime, but a
    scan's file handler must not leak into the next scan's log.

    Also raises the `stof` logger's own level to INFO if it's currently
    less permissive: `stof/main.py` never calls `configure_logging()`
    (only `recorder/__main__.py` does), so every `_log.info(...)` call
    across every layer -- crawler, auth, session, modules, evidence,
    reporting -- was being silently dropped at the logger level before
    it ever reached a handler; only WARNING+ leaked out via Python's
    own last-resort handler. A per-scan log file that's supposed to be
    the complete record of a scan needs those INFO lines too."""
    logger = logging.getLogger("stof")
    if logger.level == logging.NOTSET or logger.level > logging.INFO:
        logger.setLevel(logging.INFO)

    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(path, encoding="utf-8")
    formatter = LayerTagFormatter("%(asctime)s.%(msecs)03dZ [%(tag)s] %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
    # `logging.Formatter.formatTime()` uses local time by default --
    # without this, these lines would carry a "Z" (UTC) suffix while
    # actually being local-time, silently disagreeing with
    # `ScanConsole`'s own `datetime.now(timezone.utc)` timestamps in
    # the very same log file (live-verified: a 5.5-hour IST/UTC gap
    # between adjacent lines before this fix).
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)
    return handler


def detach_file_logging(handler: logging.Handler) -> None:
    logging.getLogger("stof").removeHandler(handler)
    handler.close()


class ScanConsole:
    """Enterprise-formatted terminal output for one scan, tee'd to a
    persistent per-scan log file at `data/logs/scan_<scan_id>.log`."""

    WIDTH = 88

    def __init__(self, scan_id: str, log_dir: str | Path = DEFAULT_LOG_DIR) -> None:
        self.scan_id = scan_id
        self.log_path = Path(log_dir) / f"scan_{scan_id}.log"
        self.events_path = Path(log_dir) / f"scan_{scan_id}.events.jsonl"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log_file = self.log_path.open("a", encoding="utf-8")
        self._events_file = self.events_path.open("a", encoding="utf-8")
        self._started_at = time.monotonic()

    def _write_log_line(self, line: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        self._log_file.write(f"{ts} {_strip_ansi(line)}\n")
        self._log_file.flush()

    def _emit_event(self, event_type: str, **fields) -> None:
        record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event_type, **fields}
        self._events_file.write(json.dumps(record) + "\n")
        self._events_file.flush()

    def echo(self, line: str = "") -> None:
        """Terminal + log, identical content -- used for every line
        where the two shouldn't diverge (banners, headers, summaries).
        `test_result()` is the one deliberate exception (see class
        docstring) and writes to each destination itself instead."""
        click.echo(line)
        self._write_log_line(line)

    def rule(self, heavy: bool = False) -> None:
        self.echo(click.style((_H if heavy else "·") * self.WIDTH, dim=not heavy, bold=heavy))

    def _panel(self, lines: list[str]) -> None:
        """Draws a rounded box around `lines` (already `click.style`d --
        width math uses the ANSI-stripped length)."""
        inner = self.WIDTH - 2
        self.echo(click.style(_TL + _H * inner + _TR, dim=True))
        for line in lines:
            pad = inner - 2 - len(_strip_ansi(line))
            self.echo(click.style(_V, dim=True) + f" {line}" + " " * max(pad, 0) + " " + click.style(_V, dim=True))
        self.echo(click.style(_BL + _H * inner + _BR, dim=True))

    def banner(self, scan_id: str, target: str, modules: list[str]) -> None:
        self.echo("")
        self._panel([
            click.style("STOF", bold=True, fg="cyan") + click.style("  ·  Security Testing Orchestration Framework", dim=True),
            "",
            click.style(f"{'Scan ID':<19}", dim=True) + scan_id,
            click.style(f"{'Target':<19}", dim=True) + target,
            click.style(f"{'Started':<19}", dim=True) + f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
            click.style(f"{'Modules':<19}", dim=True) + ", ".join(modules),
            click.style(f"{'Log':<19}", dim=True) + str(self.log_path),
        ])
        self.echo("")
        self._emit_event("scan_started", scan_id=scan_id, target=target, modules=modules)

    def phase(self, title: str) -> None:
        """No hardcoded N-of-M count -- `stof test` and `stof scan`
        both call this (the latter also for its own crawl phase before
        `_run_test`'s own phases), and the two entry points don't
        share a single global phase counter to stay in sync with."""
        self.echo("")
        self.echo(click.style("▶ ", fg="cyan", bold=True) + click.style(title, bold=True))
        self.rule()
        self._emit_event("phase", title=title)

    def info(self, message: str) -> None:
        self.echo(f"  {click.style('·', dim=True)} {message}")

    def workflow_replayed(
        self, workflow_id: str, role: str, success: bool,
        completed_actions: int, total_actions: int, final_url: str, error: str | None = None,
    ) -> None:
        """Structured counterpart to the terminal line `_replay_workflows()`
        (stof/main.py) already prints via `info()` -- that alone left the
        web console with no way to show a replayed workflow's outcome
        anywhere but the raw log file (confirmed live: the phase title
        showed up in Live Activity, the actual replay result never did).
        Kept as its own event type (not folded into a generic "info"
        event) so the UI can render it distinctly, the same way
        `crawl_completed`/`module_completed` already get their own
        dedicated rendering instead of being parsed out of prose."""
        if success:
            self.info(f"'{workflow_id}' (as role '{role}'): replayed {completed_actions}/{total_actions} action(s) successfully, landed on {final_url}")
        else:
            self.info(f"'{workflow_id}' (as role '{role}'): stopped after {completed_actions}/{total_actions} action(s) -- {error}")
        self._emit_event(
            "workflow_replayed", workflow_id=workflow_id, role=role, success=success,
            completed_actions=completed_actions, total_actions=total_actions, final_url=final_url, error=error,
        )

    def crawl_summary(self, endpoint_count: int, forms: int, apis: int, pages: int) -> None:
        """Called once, right after the crawl phase writes `endpoints.json`
        -- the "Endpoints mapped" figure the web console's Dashboard KPI
        needs has nowhere else to come from (it's never in the final
        report JSON, only ever printed to the terminal), so this emits
        a structured event alongside the existing terminal line rather
        than making the UI reconstruct it from prose."""
        self._emit_event("crawl_completed", endpoint_count=endpoint_count, forms=forms, apis=apis, pages=pages)

    def application_profile(self, role_auth: dict[str, str], has_graphql: bool, module_skips: list[str]) -> None:
        """Printed once per scan, right after crawl+recon and before
        vulnerability testing starts -- what STOF actually detected
        about this application (not a guess dressed up as one: every
        line here is a directly observed fact -- a role's configured
        `auth_type`, or a URL literally containing "graphql" somewhere
        in the crawl), and which modules that ruled out before they
        ever ran a single technique."""
        self.echo("")
        self.echo(click.style("▶ ", fg="cyan", bold=True) + click.style("APPLICATION PROFILE", bold=True))
        self.rule()
        for role, auth_type in role_auth.items():
            self.echo(f"  {click.style(f'{role:<10}', dim=True)}auth: {auth_type}")
        graphql_label = click.style(f"{'GraphQL':<10}", dim=True)
        self.echo(f"  {graphql_label}{'detected' if has_graphql else 'not detected'}")
        if module_skips:
            self.echo("")
            self.echo(f"  {click.style('Not applicable to this target:', dim=True)}")
            for skip in module_skips:
                self.echo(f"    {click.style('⊘', dim=True)} {skip}")

    def progress_bar(self, current: int, total: int, label: str) -> None:
        """Terminal-only, single overwriting line (`\\r`, no newline
        until the final call) -- deliberately NOT routed through
        `echo()`/the log file, since a live-updating bar rendered as
        dozens of intermediate lines in a plain-text log would just be
        noise; the log's `module_header`/`module_summary` lines already
        record the same progression permanently. Call with
        `current == total` last to finalize the line with a newline."""
        if total <= 0:
            return
        width = 30
        filled = int(width * min(current, total) / total)
        bar = "█" * filled + "░" * (width - filled)
        pct = int(min(current, total) / total * 100)
        line = f"  [{click.style(bar, fg='cyan')}] {pct:>3}%  ({current}/{total})  {label}"
        click.echo(f"\r\033[K{line}", nl=False)
        if current >= total:
            click.echo()

    def module_header(self, module_name: str, technique_count: int) -> None:
        self.echo("")
        label = click.style(f"  {module_name}", bold=True, fg="cyan")
        count = click.style(f"{technique_count} technique(s)", dim=True)
        pad = self.WIDTH - len(_strip_ansi(label)) - len(_strip_ansi(count))
        self.echo(label + " " * max(pad, 1) + count)
        self.echo(click.style("  " + _H * (self.WIDTH - 2), dim=True))
        self._emit_event("module_started", module=module_name, technique_count=technique_count)

    def test_result(self, result) -> None:
        """Terminal: one compact line per technique -- icon, id, name,
        role. Detail is only printed there for FAIL/ERROR, so a scan's
        live output stays scannable instead of repeating a PASS/SKIP
        sentence 60 times. Log file: every technique, full detail,
        every time -- it's the complete record, the terminal is not.

        NOT_IMPLEMENTED is the one status that never prints to the
        terminal here at all -- interleaving "this target didn't
        trigger it" (SKIPPED) with "this tool doesn't have code for it
        yet" (NOT_IMPLEMENTED) in the same scrolling wall of results
        makes a scan look like it's padding its technique count with
        things it can't actually do. `not_automated_note()` reports
        those once, clearly labeled, after a module's real results --
        never inline with them. The log file still gets every status,
        every time, since it's the complete record regardless of how
        the terminal chooses to present it."""
        label = _STATUS_LABEL.get(result.status, result.status[:4])
        color = _STATUS_COLOR.get(result.status, "white")
        if result.status != "NOT_IMPLEMENTED":
            icon = _STATUS_ICON.get(result.status, "?")
            badge = click.style(f"{icon} {label}", fg=color, bold=(result.status in ("FAIL", "ERROR")))
            role_part = click.style(f"  {result.user_role}", dim=True) if result.user_role else ""
            term_line = f"  {badge}  {result.technique_id:<10} {result.technique}{role_part}"
            click.echo(term_line)
            if result.status in ("FAIL", "ERROR"):
                detail = result.detail
                if len(detail) > 200:
                    detail = detail[:199] + "…"
                click.echo(click.style(f"       └─ {detail}", dim=True))
        else:
            role_part = click.style(f"  {result.user_role}", dim=True) if result.user_role else ""

        log_status = click.style(f"[{label}]", fg=color)
        self._write_log_line(f"   {log_status} {result.technique_id:<9} {result.technique}{role_part}")
        self._write_log_line(f"          {result.detail}")
        if result.status in ("FAIL", "ERROR"):
            self._emit_event(
                "finding", module=result.module_id, technique_id=result.technique_id,
                technique=result.technique, severity=result.severity, status=result.status,
                detail=result.detail, role=result.user_role,
            )

    def not_automated_note(self, results: list) -> None:
        """One consolidated, clearly-labeled line for a module's
        NOT_IMPLEMENTED techniques -- shown once, after its real
        results, never mixed into the per-technique wall (see
        `test_result()`'s own docstring for why)."""
        not_implemented = [r for r in results if r.status == "NOT_IMPLEMENTED"]
        if not not_implemented:
            return
        ids = ", ".join(r.technique_id for r in not_implemented)
        self.echo(f"  {click.style('⊘ Not automated by this tool:', dim=True)} {ids} {click.style('(see EXPLOIT_COVERAGE.md for why)', dim=True)}")

    def module_summary(self, module_name: str, counts: dict[str, int]) -> None:
        order = (("PASS", "green"), ("FAIL", "red"), ("SKIPPED", "yellow"), ("NOT_IMPLEMENTED", "white"), ("ERROR", "red"))
        parts = [click.style(f"{counts[s]} {_STATUS_LABEL[s].strip()}", fg=color) for s, color in order if counts.get(s)]
        total = sum(counts.values())
        self.echo(f"  {click.style('Summary', dim=True)}  " + (", ".join(parts) if parts else "no techniques run") + click.style(f"  ({total} total)", dim=True))
        self._emit_event("module_completed", module=module_name, counts=counts, total=total)

    def summary_table(self, rows: list[tuple[str, dict[str, int]]]) -> None:
        """`rows`: [(module_name, status_counts), ...]. Box-drawn table
        -- column widths are fixed (module names/counts here are all
        short, known-shape strings) rather than computed, to keep the
        border math simple and exact."""
        self.echo("")
        self.echo(click.style("▶ ", fg="cyan", bold=True) + click.style("SCAN SUMMARY", bold=True))

        name_w = max([len(name) for name, _ in rows] + [len("TOTAL")]) + 2
        col_w = 6
        cols = ("PASS", "FAIL", "SKIP", "N/A", "ERR", "TOTAL")

        def border(left, mid, right):
            return left + mid.join([_H * name_w] + [_H * col_w] * len(cols)) + right

        def row(label, values, *, bold=False, colors=None):
            cells = []
            for i, val in enumerate(values):
                text = f"{val:>{col_w}}"
                if colors and colors[i]:
                    text = click.style(text, fg=colors[i], bold=bold)
                elif bold:
                    text = click.style(text, bold=True)
                cells.append(text)
            label_text = click.style(f"{label:<{name_w}}", bold=bold)
            return click.style(_V, dim=True) + label_text + click.style(_V, dim=True) + click.style(_V, dim=True).join(cells) + click.style(_V, dim=True)

        header_colors = (None, None, None, None, None, None)
        self.echo(click.style(border(_TL, _MT, _TR), dim=True))
        self.echo(row("MODULE", cols, bold=True, colors=header_colors))
        self.echo(click.style(border(_ML, _MX, _MR), dim=True))

        totals = {"PASS": 0, "FAIL": 0, "SKIPPED": 0, "NOT_IMPLEMENTED": 0, "ERROR": 0}
        value_colors = ("green", "red", "yellow", "white", "red", None)
        for name, counts in rows:
            for k in totals:
                totals[k] += counts.get(k, 0)
            values = (counts.get("PASS", 0), counts.get("FAIL", 0), counts.get("SKIPPED", 0),
                      counts.get("NOT_IMPLEMENTED", 0), counts.get("ERROR", 0), sum(counts.values()))
            self.echo(row(name, values, colors=value_colors))

        self.echo(click.style(border(_ML, _MX, _MR), dim=True))
        grand_total = sum(totals.values())
        totals_values = (totals["PASS"], totals["FAIL"], totals["SKIPPED"], totals["NOT_IMPLEMENTED"], totals["ERROR"], grand_total)
        self.echo(row("TOTAL", totals_values, bold=True, colors=value_colors))
        self.echo(click.style(border(_BL, _MB, _BR), dim=True))

    def findings_by_severity(self, counts: dict[str, int], critical_high_likely: int = 0) -> None:
        self.echo("")
        parts = [
            click.style("●", fg=_SEVERITY_COLOR.get(sev, "white")) + f" {sev} {counts[sev]}"
            for sev in _SEVERITY_ORDER if counts.get(sev)
        ]
        label = click.style("Findings", dim=True)
        self.echo(f"  {label}  " + ("   ".join(parts) if parts else click.style("none", fg="green")))
        # Surfaced separately from the severity line itself, not folded
        # into it -- this is the one number that answers "how many of
        # my Critical/High findings can I trust without opening the
        # report," which severity counts alone can't say (a Finding
        # STOF is honest it couldn't fully confirm -- a timing signal, an
        # accepted-but-unverifiable change -- is still Critical/High
        # severity, just not yet PROVEN). See `Finding.confidence`.
        if critical_high_likely:
            self.echo(f"  {click.style(f'{critical_high_likely} Critical/High finding(s) need manual confirmation', fg='yellow')} {click.style('(see report for which)', dim=True)}")

    def _labeled_path(self, label: str, path: str) -> str:
        return f"    {click.style(f'{label:<12}', dim=True)}{path}"

    def reports(self, html: str, json_: str, excel: str, walkthrough: str | None = None) -> None:
        self.echo("")
        self.echo(f"  {click.style('Reports', dim=True)}")
        self.echo(self._labeled_path("HTML", html))
        self.echo(self._labeled_path("JSON", json_))
        self.echo(self._labeled_path("Excel", excel))
        if walkthrough:
            self.echo(self._labeled_path("Walkthrough", walkthrough))
        self.echo(self._labeled_path("Log", str(self.log_path)))
        self._emit_event("reports_generated", html=html, json=json_, excel=excel, walkthrough=walkthrough)

    def footer(self, duration_s: float) -> None:
        self.echo("")
        self._panel([click.style("✔", fg="green", bold=True) + click.style(f"  Scan complete in {duration_s}s", bold=True)])
        self._emit_event("scan_completed", duration_seconds=duration_s)

    def close(self) -> None:
        self._log_file.close()
        self._events_file.close()
