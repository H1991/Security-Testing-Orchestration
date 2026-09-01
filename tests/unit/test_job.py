"""Unit tests for Layer 2 — stof.core.job."""
import pytest

from stof.core.job import InvalidJobTransition, Job, JobStatus


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_job_full_lifecycle_happy_path():
    job = Job(target_url="https://demo.testfire.net", enabled_modules=["jwt_tests"])
    assert job.status == JobStatus.QUEUED

    job.transition(JobStatus.RUNNING)
    job.transition(JobStatus.PAUSED)
    job.transition(JobStatus.RUNNING)
    job.transition(JobStatus.COMPLETED)

    assert job.status == JobStatus.COMPLETED


def test_job_round_trips_through_row_serialisation():
    job = Job(target_url="https://demo.testfire.net", enabled_modules=["jwt_tests", "auth_tests"])
    job.transition(JobStatus.RUNNING)
    job.current_layer = "crawler"

    restored = Job.from_row(job.to_row())

    assert restored.job_id == job.job_id
    assert restored.target_url == job.target_url
    assert restored.enabled_modules == job.enabled_modules
    assert restored.status == job.status
    assert restored.current_layer == job.current_layer


# ---------------------------------------------------------------------------
# Failure cases
# ---------------------------------------------------------------------------


def test_job_rejects_skipping_running_state():
    job = Job(target_url="https://demo.testfire.net", enabled_modules=[])

    with pytest.raises(InvalidJobTransition):
        job.transition(JobStatus.COMPLETED)


def test_job_rejects_transition_out_of_completed():
    job = Job(target_url="https://demo.testfire.net", enabled_modules=[])
    job.transition(JobStatus.RUNNING)
    job.transition(JobStatus.COMPLETED)

    with pytest.raises(InvalidJobTransition):
        job.transition(JobStatus.RUNNING)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_job_retry_path_requires_failed_first():
    job = Job(target_url="https://demo.testfire.net", enabled_modules=[])
    job.transition(JobStatus.RUNNING)

    with pytest.raises(InvalidJobTransition):
        job.transition(JobStatus.RETRY)

    job.transition(JobStatus.FAILED)
    job.transition(JobStatus.RETRY)
    job.transition(JobStatus.RUNNING)
    assert job.status == JobStatus.RUNNING
