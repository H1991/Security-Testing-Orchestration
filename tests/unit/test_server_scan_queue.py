"""Unit tests for the in-process concurrent-scan queue in
stof/ui/server.py -- `MAX_CONCURRENT_SCANS`, `_running_scan_count()`,
and `_drain_scan_queue()`.

Regression context: STOF used to hard-block a second scan outright
(409) regardless of target -- a scan against Juice Shop couldn't run
while one against demo.testfire.net was in progress, even though
they're fully independent (own evidence dir, own Burp task_id,
config.json read once at launch). This queue lifts that to N
concurrent slots (configurable via STOF_MAX_CONCURRENT_SCANS) while
still blocking two scans against the SAME target at once -- see
`start_scan()`'s own `same_target` check, not covered here since it's
exercised through the HTTP layer.

`_launch_scan_task` is monkeypatched in every test that would
otherwise trigger it, so no real subprocess/Chromium ever launches --
these tests are pure and fast.
"""
from stof.ui import server


def _reset_registry(monkeypatch):
    """Fresh ScanRegistry + empty queue per test -- the module-level
    REGISTRY/_SCAN_QUEUE singletons must not leak state between tests."""
    fresh_registry = server.ScanRegistry()
    monkeypatch.setattr(server, "REGISTRY", fresh_registry)
    monkeypatch.setattr(server, "_SCAN_QUEUE", [])
    return fresh_registry


def test_running_scan_count_counts_only_running(monkeypatch):
    registry = _reset_registry(monkeypatch)
    registry.create("http://a.test", [], status="running")
    registry.create("http://b.test", [], status="queued")
    registry.create("http://c.test", [], status="complete")

    assert server._running_scan_count() == 1


async def test_drain_scan_queue_launches_next_queued_scan_when_slot_frees(monkeypatch):
    registry = _reset_registry(monkeypatch)
    monkeypatch.setattr(server, "MAX_CONCURRENT_SCANS", 1)
    launched: list[str] = []
    monkeypatch.setattr(server, "_launch_scan_task", lambda record, modules, workflow_ids: launched.append(record.scan_id))

    queued = registry.create("http://b.test", ["auth_tests"], status="queued")
    server._SCAN_QUEUE.append(queued.scan_id)

    await server._drain_scan_queue()

    assert launched == [queued.scan_id]
    assert queued.status == "running"
    assert queued.scan_id not in server._SCAN_QUEUE


async def test_drain_scan_queue_respects_max_concurrent_scans(monkeypatch):
    registry = _reset_registry(monkeypatch)
    monkeypatch.setattr(server, "MAX_CONCURRENT_SCANS", 1)
    launched: list[str] = []
    monkeypatch.setattr(server, "_launch_scan_task", lambda record, modules, workflow_ids: launched.append(record.scan_id))

    registry.create("http://a.test", [], status="running")  # slot already taken
    queued = registry.create("http://b.test", [], status="queued")
    server._SCAN_QUEUE.append(queued.scan_id)

    await server._drain_scan_queue()

    assert launched == []
    assert queued.status == "queued"
    assert [queued.scan_id] == server._SCAN_QUEUE


async def test_drain_scan_queue_launches_multiple_when_multiple_slots_free(monkeypatch):
    registry = _reset_registry(monkeypatch)
    monkeypatch.setattr(server, "MAX_CONCURRENT_SCANS", 2)
    launched: list[str] = []
    monkeypatch.setattr(server, "_launch_scan_task", lambda record, modules, workflow_ids: launched.append(record.scan_id))

    q1 = registry.create("http://a.test", [], status="queued")
    q2 = registry.create("http://b.test", [], status="queued")
    server._SCAN_QUEUE.extend([q1.scan_id, q2.scan_id])

    await server._drain_scan_queue()

    assert set(launched) == {q1.scan_id, q2.scan_id}
    assert server._SCAN_QUEUE == []


async def test_drain_scan_queue_skips_a_scan_cancelled_while_waiting(monkeypatch):
    """A queued scan stopped via POST /api/scans/{id}/stop flips its
    status to "stopped" but (by design) is NOT removed from
    _SCAN_QUEUE synchronously in every caller -- _drain_scan_queue must
    still skip it safely rather than launching a stopped scan."""
    registry = _reset_registry(monkeypatch)
    monkeypatch.setattr(server, "MAX_CONCURRENT_SCANS", 5)
    launched: list[str] = []
    monkeypatch.setattr(server, "_launch_scan_task", lambda record, modules, workflow_ids: launched.append(record.scan_id))

    cancelled = registry.create("http://a.test", [], status="queued")
    cancelled.status = "stopped"  # cancelled out-of-band
    still_queued = registry.create("http://b.test", [], status="queued")
    server._SCAN_QUEUE.extend([cancelled.scan_id, still_queued.scan_id])

    await server._drain_scan_queue()

    assert launched == [still_queued.scan_id]


def test_max_concurrent_scans_defaults_to_two(monkeypatch):
    monkeypatch.delenv("STOF_MAX_CONCURRENT_SCANS", raising=False)
    import importlib

    reloaded = importlib.reload(server)
    try:
        assert reloaded.MAX_CONCURRENT_SCANS == 2
    finally:
        importlib.reload(server)  # restore for any test running after this one


def test_max_concurrent_scans_reads_env_override(monkeypatch):
    monkeypatch.setenv("STOF_MAX_CONCURRENT_SCANS", "4")
    import importlib

    reloaded = importlib.reload(server)
    try:
        assert reloaded.MAX_CONCURRENT_SCANS == 4
    finally:
        monkeypatch.delenv("STOF_MAX_CONCURRENT_SCANS", raising=False)
        importlib.reload(server)
