"""Recon Engine — orchestrates tech detection, misconfig scanning,
secrets scanning, and parameter discovery into one consolidated report.

Native equivalents of httpx + nuclei + SecretFinder + Arjun (see each
submodule's docstring for what it maps to and why it isn't a wrapper
around the actual tool). Consumes Layer 7's already-discovered
endpoints rather than re-crawling -- this sits *after* the crawler in
the pipeline, enriching what it found, not replacing it.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from stof.core.logger import get_logger

from . import misconfig_scanner, secrets_scanner, tech_detector
from .parameter_discovery import discover_parameters
from .port_scanner import scan_ports

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext

    from stof.crawler.endpoint_store import Endpoint

_log = get_logger("recon.recon_engine")

DEFAULT_RECON_PATH = Path("data/recon_results.json")


@dataclass
class ReconReport:
    target: str
    scanned_at: str
    pages_analyzed: int
    open_ports: list[dict] = field(default_factory=list)
    tech_stack: list[dict] = field(default_factory=list)
    missing_security_headers: dict[str, list[str]] = field(default_factory=dict)
    exposed_paths: list[dict] = field(default_factory=list)
    error_disclosures: list[dict] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    parameters: dict[str, list[dict]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


async def run_recon(
    endpoints: list["Endpoint"],
    context: "BrowserContext",
    target_url: str,
    max_tech_pages: int = 30,
    max_secret_scan_pages: int = 10,
    page_watchdog_s: float = 30.0,
) -> ReconReport:
    page_urls = list(dict.fromkeys(e.url for e in endpoints if e.endpoint_type == "page"))

    # -- port_scanner (nmap-lite) -- runs first, matching a real pentest's
    # own recon ordering (network scan before web-app-level enumeration).
    try:
        open_ports = await scan_ports(target_url)
    except Exception as exc:
        _log.warning(f"port scan failed for '{target_url}': {exc}")
        open_ports = []
    open_ports_out = [{"port": p.port, "service_guess": p.service_guess, "banner": p.banner} for p in open_ports]

    # -- tech_detector (httpx-equivalent) ---------------------------------
    tech_stack: list[dict] = []
    missing_headers: dict[str, list[str]] = {}
    all_tech: set[str] = set()
    for url in page_urls[:max_tech_pages]:
        profile = await tech_detector.analyze_url(context, url)
        tech_stack.append(
            {
                "url": profile.url,
                "status_code": profile.status_code,
                "title": profile.title,
                "content_type": profile.content_type,
                "tech": profile.tech,
            }
        )
        all_tech.update(profile.tech)
        # status_code is None only when the request itself failed (see
        # tech_detector.analyze_url's except branch) -- an empty headers
        # dict on an actual 200 response legitimately means "every
        # security header is missing," which must still be reported.
        if profile.status_code is not None:
            missing = misconfig_scanner.check_missing_security_headers(profile.headers)
            if missing:
                missing_headers[profile.url] = missing

    # -- misconfig_scanner (nuclei-equivalent) ----------------------------
    exposed = await misconfig_scanner.scan_exposed_paths(context, target_url)
    exposed_paths = [{"url": e.url, "status_code": e.status_code} for e in exposed]

    error_disclosures: list[dict] = []
    probe_targets = [urljoin_safe(target_url, "definitely-not-a-real-page-xyz123")]
    param_endpoints = [e for e in endpoints if e.method == "GET" and e.parameters and e.endpoint_type != "page"]
    if param_endpoints:
        sample = param_endpoints[0]
        probe_targets.append(f"{sample.url}?{sample.parameters[0]}=invalid-9999999")
    for probe_url in probe_targets:
        disclosure = await misconfig_scanner.probe_error_disclosure(context, probe_url)
        if disclosure is not None:
            error_disclosures.append(
                {"url": disclosure.url, "status_code": disclosure.status_code, "leaked": disclosure.leaked}
            )

    # -- secrets_scanner (SecretFinder-equivalent) ------------------------
    secret_findings: list[dict] = []
    sample_pages = page_urls[:max_secret_scan_pages]
    probe_page = await context.new_page()
    try:
        for url in sample_pages:

            async def _scan_one(url: str = url) -> None:
                await probe_page.goto(url, timeout=10000)
                findings = await secrets_scanner.scan_page_for_secrets(probe_page)
                secret_findings.extend(
                    {"source_url": f.source_url, "label": f.label, "match_preview": f.match_preview}
                    for f in findings
                )

            try:
                # `timeout=10000` above is `page.goto()`'s own timeout,
                # which can fail to fire at all if the underlying CDP
                # connection is wedged (live-verified: a burst of
                # `net::ERR_NETWORK_CHANGED`/interrupted-navigation
                # failures across consecutive pages left this loop
                # hung indefinitely with no further progress -- the
                # exact same failure class `crawler.py`'s own
                # `page_watchdog_s` exists to catch). `asyncio.wait_for`
                # is the hard backstop independent of that.
                await asyncio.wait_for(_scan_one(), timeout=page_watchdog_s)
            except Exception as exc:
                _log.warning(f"secrets scan failed for '{url}': {exc}")
    finally:
        await probe_page.close()

    # -- parameter_discovery (Arjun-equivalent, passive) -------------------
    params = discover_parameters(endpoints)
    parameters_out = {key: [{"name": p.name, "guessed_type": p.guessed_type} for p in plist] for key, plist in params.items()}

    report = ReconReport(
        target=target_url,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        pages_analyzed=len(tech_stack),
        open_ports=open_ports_out,
        tech_stack=tech_stack,
        missing_security_headers=missing_headers,
        exposed_paths=exposed_paths,
        error_disclosures=error_disclosures,
        secrets=secret_findings,
        parameters=parameters_out,
    )
    _log.info(
        f"recon of '{target_url}' complete: {len(open_ports_out)} open port(s), "
        f"{len(tech_stack)} page(s) analyzed, "
        f"{len(all_tech)} distinct tech signature(s), {len(exposed_paths)} exposed path(s), "
        f"{len(error_disclosures)} error disclosure(s), {len(secret_findings)} secret(s), "
        f"{len(parameters_out)} endpoint(s) with parameters"
    )
    return report


def urljoin_safe(base: str, path: str) -> str:
    base = base.rstrip("/")
    return f"{base}/{path.lstrip('/')}"


def write_recon_report(report: ReconReport, path: str | Path = DEFAULT_RECON_PATH) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    _log.info(f"wrote recon report -> {output_path}")
    return output_path
