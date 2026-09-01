"""Unit tests for Layer 3A — stof.recorder.exporter."""
import json

from stof.config.schema import UserConfig, UsersConfig
from stof.recorder import exporter
from stof.recorder.exporter import (
    REDACTED_PLACEHOLDER,
    build_workflow,
    tokenize_credentials,
    write_workflow,
)

_USERS = UsersConfig(
    users=[
        UserConfig(
            id="admin-01",
            role="admin",
            username="admin@target.com",
            password="s3cr3t-admin",
            auth_type="form_login",
        )
    ]
)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_tokenize_credentials_replaces_matching_username_and_password():
    actions = [
        {"type": "navigate", "url": "https://demo.testfire.net/login"},
        {"type": "fill", "selector": "#user", "value": "admin@target.com", "field_type": "text"},
        {"type": "fill", "selector": "#pass", "value": "s3cr3t-admin", "field_type": "password"},
        {"type": "click", "selector": "button[type=submit]"},
    ]

    tokenized = tokenize_credentials(actions, _USERS)

    assert tokenized[1]["value"] == "{{user.username}}"
    assert tokenized[2]["value"] == "{{user.password}}"
    # field_type is internal bookkeeping, must not leak into the exported schema
    assert "field_type" not in tokenized[1]
    assert "field_type" not in tokenized[2]


def test_build_and_write_workflow_round_trips(tmp_path):
    actions = [{"type": "navigate", "url": "https://demo.testfire.net"}]
    workflow = build_workflow("https://demo.testfire.net", actions, workflow_id="wf-test-001")

    path = write_workflow(workflow, tmp_path / "workflows" / "wf-test-001.json")

    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["workflow_id"] == "wf-test-001"
    assert on_disk["target_url"] == "https://demo.testfire.net"
    assert on_disk["actions"] == actions
    assert "recorded_at" in on_disk


# ---------------------------------------------------------------------------
# Failure / defensive redaction
# ---------------------------------------------------------------------------


def test_unmatched_password_field_is_redacted_not_stored(monkeypatch):
    actions = [
        {"type": "fill", "selector": "#pass", "value": "typo-password", "field_type": "password"}
    ]

    # Patch the module's logger directly rather than using caplog: other
    # test modules configure the shared "stof" logger's handlers/propagate,
    # and ordering-dependent global logging state shouldn't be what this
    # test is asserting on.
    warnings: list[str] = []
    monkeypatch.setattr(exporter._log, "warning", lambda msg, *a, **k: warnings.append(msg))

    tokenized = tokenize_credentials(actions, _USERS)

    assert tokenized[0]["value"] == REDACTED_PLACEHOLDER
    assert "typo-password" not in json.dumps(tokenized)
    assert any("redacting" in message for message in warnings)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_non_credential_text_field_is_left_untouched():
    actions = [{"type": "fill", "selector": "#search", "value": "hello world", "field_type": "text"}]

    tokenized = tokenize_credentials(actions, _USERS)

    assert tokenized[0]["value"] == "hello world"


def test_tokenize_credentials_without_users_only_redacts_password_fields():
    actions = [
        {"type": "fill", "selector": "#search", "value": "hello", "field_type": "text"},
        {"type": "fill", "selector": "#pass", "value": "hunter2", "field_type": "password"},
    ]

    tokenized = tokenize_credentials(actions, users=None)

    assert tokenized[0]["value"] == "hello"
    assert tokenized[1]["value"] == REDACTED_PLACEHOLDER
