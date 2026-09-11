"""Unit tests for Layer 3B -- stof.engine.guarded_context.

Fakes stand in for Playwright's `APIRequestContext`/`BrowserContext` --
same "mock the I/O boundary, not the library" convention this project's
other engine/crawler tests already use. Real scope/rate-limit/audit
behavior is exercised end to end; no real network call."""
import pytest

from stof.core.traffic_guard import OutOfScopeError, TrafficGuard
from stof.engine.guarded_context import GuardedBrowserContext, GuardedRequestContext


class _FakeResponse:
    def __init__(self, status: int, headers: dict[str, str] | None = None, body: bytes = b""):
        self.status = status
        self.headers = headers or {}
        self._body = body

    async def body(self) -> bytes:
        return self._body


class _FakeRequestContext:
    def __init__(self):
        self.calls: list[tuple[str, str, dict]] = []
        self._response = _FakeResponse(200, {"content-type": "text/plain"}, b"ok")

    async def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self._response

    async def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self._response

    async def head(self, url, **kwargs):
        self.calls.append(("HEAD", url, kwargs))
        return self._response

    async def storage_state(self):
        return {"cookies": []}


class _FakeBrowserContext:
    def __init__(self, request):
        self.request = request
        self.closed = False

    async def close(self):
        self.closed = True


# ---------------------------------------------------------------------------
# GuardedRequestContext
# ---------------------------------------------------------------------------


async def test_get_issues_the_real_call_and_returns_its_response():
    real = _FakeRequestContext()
    guard = TrafficGuard(allowed_origins={"https://x.example:443"})
    guarded = GuardedRequestContext(real, guard, role="admin")

    response = await guarded.get("https://x.example/page")

    assert response.status == 200
    assert real.calls == [("GET", "https://x.example/page", {})]


async def test_get_raises_out_of_scope_and_never_calls_the_real_method():
    real = _FakeRequestContext()
    guard = TrafficGuard(allowed_origins={"https://x.example:443"})
    guarded = GuardedRequestContext(real, guard, role=None)

    with pytest.raises(OutOfScopeError):
        await guarded.get("https://evil.example/steal")

    assert real.calls == []


async def test_post_forwards_kwargs_to_the_real_call():
    real = _FakeRequestContext()
    guard = TrafficGuard(allowed_origins={"https://x.example:443"})
    guarded = GuardedRequestContext(real, guard, role=None)

    await guarded.post("https://x.example/api", data="body", headers={"X-Test": "1"})

    assert real.calls == [("POST", "https://x.example/api", {"data": "body", "headers": {"X-Test": "1"}})]


async def test_every_request_is_recorded_in_the_audit_log(tmp_path):
    real = _FakeRequestContext()
    audit_path = tmp_path / "audit_log.jsonl"
    guard = TrafficGuard(allowed_origins={"https://x.example:443"}, audit_path=audit_path)
    guarded = GuardedRequestContext(real, guard, role="admin")

    await guarded.get("https://x.example/a")
    await guarded.post("https://x.example/b", data="x")

    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert guard.total_requests == 2


async def test_an_out_of_scope_attempt_is_never_recorded_as_a_sent_request():
    real = _FakeRequestContext()
    guard = TrafficGuard(allowed_origins={"https://x.example:443"})
    guarded = GuardedRequestContext(real, guard, role=None)

    with pytest.raises(OutOfScopeError):
        await guarded.get("https://evil.example/steal")

    assert guard.total_requests == 0  # scope is checked before any audit entry is built


async def test_getattr_delegates_unwrapped_methods_to_the_real_request_context():
    real = _FakeRequestContext()
    guard = TrafficGuard(allowed_origins={"https://x.example:443"})
    guarded = GuardedRequestContext(real, guard, role=None)

    state = await guarded.storage_state()

    assert state == {"cookies": []}


async def test_a_failed_request_is_still_audited_with_the_error_and_then_reraised():
    class _FailingRequestContext(_FakeRequestContext):
        async def get(self, url, **kwargs):
            raise RuntimeError("connection reset")

    real = _FailingRequestContext()
    audit_path = None  # exercise the no-file-write path too, just verify re-raise + counting
    guard = TrafficGuard(allowed_origins={"https://x.example:443"}, audit_path=audit_path)
    guarded = GuardedRequestContext(real, guard, role=None)

    with pytest.raises(RuntimeError, match="connection reset"):
        await guarded.get("https://x.example/broken")

    assert guard.total_requests == 1  # the attempt was still recorded, even though it failed


# ---------------------------------------------------------------------------
# GuardedBrowserContext
# ---------------------------------------------------------------------------


async def test_guarded_browser_context_wraps_request_and_delegates_everything_else():
    real_request = _FakeRequestContext()
    real_context = _FakeBrowserContext(real_request)
    guard = TrafficGuard(allowed_origins={"https://x.example:443"})

    guarded_context = GuardedBrowserContext(real_context, guard, role="admin")
    await guarded_context.request.get("https://x.example/x")
    await guarded_context.close()

    assert real_request.calls == [("GET", "https://x.example/x", {})]
    assert real_context.closed is True
