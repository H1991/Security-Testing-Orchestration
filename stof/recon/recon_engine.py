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
    from playwright.async_api import BrowserContext, Page

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
    # Route strings mined from shipped JS bundles (a Vue/React/Angular
    # router config's own `path:"/..."` entries) that the crawler's DOM/
    # click-driven discovery never reached -- see `secrets_scanner.
    # find_routes()`'s own comment for why this exists. Each entry is
    # `{"path": ..., "source_url": <bundle it came from>}`; a route
    # string alone isn't proof the endpoint is reachable or that
    # anything sits behind it, so this is a hint for the crawler/
    # tester to follow up on, not a confirmed `Endpoint`.
    discovered_routes: list[dict] = field(default_factory=list)
    parameters: dict[str, list[dict]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


async def _scan_known_js_assets(
    probe_page: "Page", js_asset_urls: list[str], page_watchdog_s: float,
    secret_findings: list[dict], route_findings: dict[str, dict],
) -> None:
    """Directly fetches and scans every already-discovered `.js` asset
    URL for secrets and route strings -- these never get scanned by the
    page-navigation loop above them: navigating a browser straight to a
    raw `.js` URL renders it as plain text with no `<script>` tag
    wrapping it, so `scan_page_for_secrets_and_routes()`'s DOM-based
    script extraction finds nothing there. Confirmed live against a
    real target: a route-mining pass had already discovered exactly
    this shape of URL (a lazy-loaded, feature-specific JS chunk, only
    ever linked from a screen this scan's sampled pages never happened
    to visit) sitting unscanned in the endpoint list the whole time.
    Mutates `secret_findings`/`route_findings` in place, same
    accumulator shape `run_recon()`'s own page loop already uses."""
    for js_url in js_asset_urls:

        async def _scan_one(js_url: str = js_url) -> None:
            response = await probe_page.context.request.get(js_url, timeout=20000)
            body = await response.text()
            secret_findings.extend(
                {"source_url": js_url, "label": f.label, "match_preview": f.match_preview}
                for f in secrets_scanner.find_secrets(body, js_url)
            )
            for path in secrets_scanner.find_routes(body):
                route_findings.setdefault(path, {"path": path, "source_url": js_url})

        try:
            await asyncio.wait_for(_scan_one(), timeout=page_watchdog_s)
        except Exception as exc:
            _log.warning(f"secrets scan of JS asset '{js_url}' failed: {exc}")


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

    # -- secrets_scanner (SecretFinder-equivalent) + route mining ---------
    secret_findings: list[dict] = []
    route_findings: dict[str, dict] = {}  # path -> {"path", "source_url"}, dedup across pages
    # Endpoints that are themselves a `.js` asset URL -- e.g. one route-
    # mined out of ANOTHER bundle's own router config -- never get their
    # OWN content scanned by the page loop below: navigating a browser
    # straight to a raw `.js` URL renders it as plain text with no
    # `<script>` tag wrapping it, so `scan_page_for_secrets_and_routes()`'s
    # DOM-based script extraction finds nothing there. Confirmed live
    # against a real target: a route-mining pass had already discovered
    # exactly this shape of URL (a lazy-loaded, feature-specific JS
    # chunk, only ever linked from a screen this scan's sampled pages
    # never happened to visit) sitting unscanned in the endpoint list
    # the whole time. Fetched directly instead, same as any other
    # external script this module already fetches -- capped
    # independently of `max_secret_scan_pages` since these are cheap,
    # single-file fetches, not full page navigations.
    js_asset_urls = [
        e.url for e in endpoints if e.url.split("?", 1)[0].split("#", 1)[0].lower().endswith(".js")
    ][:max_secret_scan_pages]
    sample_pages = page_urls[:max_secret_scan_pages]
    probe_page = await context.new_page()
    try:
        for url in sample_pages:

            async def _scan_one(url: str = url) -> None:
                await probe_page.goto(url, timeout=10000)
                findings, routes = await secrets_scanner.scan_page_for_secrets_and_routes(probe_page)
                secret_findings.extend(
                    {"source_url": f.source_url, "label": f.label, "match_preview": f.match_preview}
                    for f in findings
                )
                for path in routes:
                    route_findings.setdefault(path, {"path": path, "source_url": probe_page.url})

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

        await _scan_known_js_assets(probe_page, js_asset_urls, page_watchdog_s, secret_findings, route_findings)
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
        discovered_routes=list(route_findings.values()),
        parameters=parameters_out,
    )
    _log.info(
        f"recon of '{target_url}' complete: {len(open_ports_out)} open port(s), "
        f"{len(tech_stack)} page(s) analyzed, "
        f"{len(all_tech)} distinct tech signature(s), {len(exposed_paths)} exposed path(s), "
        f"{len(error_disclosures)} error disclosure(s), {len(secret_findings)} secret(s), "
        f"{len(route_findings)} route(s) mined from JS bundles, "
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
