"""Unit tests for Recon — stof.recon.port_scanner (Nmap-lite)."""
import asyncio

import pytest

from stof.recon.port_scanner import OpenPort, scan_ports


@pytest.mark.asyncio
async def test_scan_ports_finds_a_real_listening_port():
    """Live, real-socket test against localhost -- opens a genuine TCP
    listener on an ephemeral port and confirms the scanner finds it,
    without mocking asyncio's own connection machinery (which would
    just test the mock, not the actual TCP-scan logic)."""
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        async with server:
            results = await scan_ports("http://127.0.0.1", ports=(port,), timeout_s=2.0)
    finally:
        server.close()

    assert len(results) == 1
    assert results[0].port == port


@pytest.mark.asyncio
async def test_scan_ports_skips_a_closed_port():
    # Bind and immediately close, so nothing is listening on this port,
    # but it's unlikely to collide with anything else on the machine.
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()

    results = await scan_ports("http://127.0.0.1", ports=(port,), timeout_s=1.0)

    assert results == []


@pytest.mark.asyncio
async def test_scan_ports_grabs_a_banner_when_the_service_sends_one():
    async def _greet(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
        await writer.drain()

    server = await asyncio.start_server(_greet, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        async with server:
            results = await scan_ports("http://127.0.0.1", ports=(port,), timeout_s=2.0)
    finally:
        server.close()

    assert len(results) == 1
    assert results[0].banner == "SSH-2.0-OpenSSH_9.6"


@pytest.mark.asyncio
async def test_scan_ports_handles_an_invalid_port_number_gracefully():
    results = await scan_ports("http://127.0.0.1", ports=(9999999,), timeout_s=0.1)

    assert results == []


@pytest.mark.asyncio
async def test_scan_ports_returns_empty_for_an_unresolvable_target():
    results = await scan_ports("not-a-url-at-all", ports=(80,))

    assert results == []


def test_open_port_service_guess_for_common_ports():
    from stof.recon.port_scanner import _WELL_KNOWN_SERVICES

    assert _WELL_KNOWN_SERVICES[22] == "ssh"
    assert _WELL_KNOWN_SERVICES[443] == "https"
    assert _WELL_KNOWN_SERVICES[3306] == "mysql"


def test_open_port_is_a_plain_dataclass():
    port = OpenPort(port=80, service_guess="http", banner=None)
    assert port.port == 80
    assert port.banner is None
