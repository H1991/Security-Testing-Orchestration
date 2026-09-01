"""Unit tests for Layer 2 — stof.core.orchestrator.

Layer 4/7/9/etc. don't exist yet in this incremental build, so phases are
represented by injected fake async callables — exactly the seam
`Orchestrator.run()` is designed around (see orchestrator.py docstring).
"""
import pytest

from stof.config.schema import Config, OutputConfig, TargetConfig
from stof.core.job import Job, JobStatus
from stof.core.orchestrator import Orchestrator, ScanPhase


def _config() -> Config:
    return Config(
        target=TargetConfig(
            base_url="https://demo.testfire.net",
            login_url="https://demo.testfire.net/bank/login.aspx",
        ),
        output=OutputConfig(reports_dir="data/reports", evidence_dir="data/evidence"),
    )


def _orchestrator(tmp_path, **kwargs) -> Orchestrator:
    return Orchestrator(_config(), db_path=tmp_path / "stof.db", **kwargs)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_executes_phases_in_order_and_completes(tmp_path):
    orchestrator = _orchestrator(tmp_path)
    job = orchestrator.create_job("https://demo.testfire.net", ["crawler", "jwt_tests"])

    calls: list[str] = []

    async def make_phase(name: str):
        async def run(job: Job) -> None:
            calls.append(name)

        return ScanPhase(name=name, run=run)

    phases = [await make_phase("auth"), await make_phase("crawler"), await make_phase("modules")]

    result = await orchestrator.run(job, phases)

    assert calls == ["auth", "crawler", "modules"]
    assert result.status == JobStatus.COMPLETED
    assert result.current_layer is None

    reloaded = orchestrator.load_job(job.job_id)
    assert reloaded is not None
    assert reloaded.status == JobStatus.COMPLETED


# ---------------------------------------------------------------------------
# Failure cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_fails_job_after_exhausting_retries(tmp_path):
    orchestrator = _orchestrator(tmp_path, max_retries=2)
    job = orchestrator.create_job("https://demo.testfire.net", [])

    async def always_fails(job: Job) -> None:
        raise RuntimeError("target unreachable")

    phases = [ScanPhase(name="crawler", run=always_fails)]

    result = await orchestrator.run(job, phases)

    assert result.status == JobStatus.FAILED
    assert result.retry_count == 2
    assert "target unreachable" in result.error


@pytest.mark.asyncio
async def test_run_recovers_after_transient_failure(tmp_path):
    orchestrator = _orchestrator(tmp_path, max_retries=3)
    job = orchestrator.create_job("https://demo.testfire.net", [])

    attempts = {"n": 0}

    async def fails_twice_then_succeeds(job: Job) -> None:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise RuntimeError("flaky")

    phases = [ScanPhase(name="crawler", run=fails_twice_then_succeeds)]

    result = await orchestrator.run(job, phases)

    assert result.status == JobStatus.COMPLETED
    assert result.retry_count == 2


# ---------------------------------------------------------------------------
# Crash-resume behaviour (checkpointing)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_resumes_from_checkpointed_layer_not_from_the_start(tmp_path):
    orchestrator = _orchestrator(tmp_path)
    job = orchestrator.create_job("https://demo.testfire.net", [])

    # Simulate a crash that happened while the job was mid-way through
    # the "crawler" phase: persist that state directly, bypassing run().
    job.transition(JobStatus.RUNNING)
    job.current_layer = "crawler"
    orchestrator._save(job)

    called: list[str] = []

    async def should_not_run_again(job: Job) -> None:
        called.append("auth")
        raise AssertionError("auth phase must not re-run after resume")

    async def crawler_phase(job: Job) -> None:
        called.append("crawler")

    phases = [
        ScanPhase(name="auth", run=should_not_run_again),
        ScanPhase(name="crawler", run=crawler_phase),
    ]

    result = await orchestrator.run(job, phases)

    assert called == ["crawler"]
    assert result.status == JobStatus.COMPLETED
