"""Recon — Nmap-lite: native TCP connect port scan + banner grab.

Playwright/browser-based recon (tech_detector, misconfig_scanner, ...)
can only ever see what a browser sees: HTTP(S) on whatever port the
target URL names. It has no way to know whether SSH, a database, or an
internal admin service is *also* listening on the same host -- exactly
the "open ports and running services" question a pentest's own first
recon phase (Nmap) always asks. Native equivalent, not a subprocess
wrapper around the real `nmap` binary (see `stof/tools/` for that
wrapper pattern) -- nmap isn't required to be installed for this to
run, matching `stof/recon/`'s existing dependency-free-by-default
philosophy (tech_detector/misconfig_scanner are native equivalents of
httpx/nuclei for the same reason).

Deliberately a small, curated port list -- not a full 1-65535 sweep,
which is slow and noisy for a read-only recon pass. Covers the common
web/db/admin/remote-access ports a real target is actually likely to
expose, the same "curated known-set, not exhaustive" approach this
project's other recon submodules already use (e.g.
`configuration_tests.py`'s admin-panel/sample-file wordlists).

Read-only by construction: a completed TCP handshake, plus (at most)
reading whatever a service announces unsolicited on connect -- never a
payload sent past that. No different in kind from the browser itself
completing a TCP handshake to load a page.
"""
from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from urllib.parse import urlsplit

from stof.core.logger import get_logger

_log = get_logger("recon.port_scanner")

COMMON_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 3000, 3128, 3306, 3389, 5000,
    5432, 5900, 5984, 6379, 7001, 8000, 8008, 8080, 8081, 8443, 8888,
    9000, 9090, 9200, 9300, 11211, 27017,
)

# Human-readable label for a handful of common ports, used only when no
# banner is returned -- not a substitute for the banner itself, which
# is the real signal when a service actually provides one.
_WELL_KNOWN_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}


@dataclass
class OpenPort:
    port: int
    service_guess: str | None
    banner: str | None = None


async def _probe_port(host: str, port: int, timeout_s: float) -> OpenPort | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_s)
    except Exception:
        return None
    banner = None
    # A handful of services announce themselves immediately on connect
    # (SSH, FTP, SMTP, many DB wire protocols); HTTP(S) ports don't, so
    # a blank/failed read here is expected, not a failure -- the port
    # is still open regardless of whether it said anything.
    with contextlib.suppress(Exception):
        data = await asyncio.wait_for(reader.read(256), timeout=min(timeout_s, 2.0))
        if data:
            banner = data.decode(errors="replace").strip().splitlines()[0][:200]
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
    return OpenPort(port=port, service_guess=_WELL_KNOWN_SERVICES.get(port), banner=banner)


async def scan_ports(
    target_url: str, ports: tuple[int, ...] = COMMON_PORTS, timeout_s: float = 3.0, concurrency: int = 20,
) -> list[OpenPort]:
    """TCP connect scan of `target_url`'s host across `ports`, with a
    best-effort banner grab on whatever answers."""
    host = urlsplit(target_url).hostname
    if not host:
        _log.warning(f"could not extract a host from '{target_url}' -- skipping port scan")
        return []

    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(port: int) -> OpenPort | None:
        async with semaphore:
            return await _probe_port(host, port, timeout_s)

    results = await asyncio.gather(*(_bounded(p) for p in ports))
    open_ports = sorted((r for r in results if r is not None), key=lambda r: r.port)
    _log.info(f"port scan of '{host}': {len(open_ports)}/{len(ports)} common port(s) open")
    return open_ports
