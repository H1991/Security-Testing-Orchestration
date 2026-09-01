"""Unit tests for Layer 1 — stof.config.loader.load_dotenv.

`ADMIN_PASSWORD` in this project's real `.env.example` is a literal SQLi
test payload (`'or''='`) for the intentionally-vulnerable demo target.
`bash source` would mangle that value via shell quote parsing, so
`load_dotenv` must never apply shell-style quote handling — these tests
pin that behaviour down.
"""
from stof.config.loader import load_dotenv


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_load_dotenv_sets_unset_variables(tmp_path, monkeypatch):
    monkeypatch.delenv("SOME_TEST_VAR", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("SOME_TEST_VAR=hello\n", encoding="utf-8")

    load_dotenv(env_file)

    assert monkeypatch is not None  # keep monkeypatch fixture alive for cleanup
    import os

    assert os.environ["SOME_TEST_VAR"] == "hello"
    del os.environ["SOME_TEST_VAR"]


def test_load_dotenv_preserves_literal_quote_characters(tmp_path, monkeypatch):
    monkeypatch.delenv("SQLI_PAYLOAD_VAR", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("SQLI_PAYLOAD_VAR='or''='\n", encoding="utf-8")

    load_dotenv(env_file)

    import os

    assert os.environ["SQLI_PAYLOAD_VAR"] == "'or''='"
    del os.environ["SQLI_PAYLOAD_VAR"]


def test_load_dotenv_falls_back_to_env_example(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FALLBACK_VAR", raising=False)
    (tmp_path / ".env.example").write_text("FALLBACK_VAR=from-example\n", encoding="utf-8")

    load_dotenv()

    import os

    assert os.environ["FALLBACK_VAR"] == "from-example"
    del os.environ["FALLBACK_VAR"]


# ---------------------------------------------------------------------------
# Failure / no-op cases
# ---------------------------------------------------------------------------


def test_load_dotenv_missing_file_is_a_no_op(tmp_path):
    load_dotenv(tmp_path / "does_not_exist.env")  # must not raise


def test_load_dotenv_skips_blank_lines_and_comments(tmp_path, monkeypatch):
    monkeypatch.delenv("COMMENTED_VAR", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("\n# a comment\nCOMMENTED_VAR=value\n", encoding="utf-8")

    load_dotenv(env_file)

    import os

    assert os.environ["COMMENTED_VAR"] == "value"
    del os.environ["COMMENTED_VAR"]


# ---------------------------------------------------------------------------
# Input validation — shell values already set take precedence
# ---------------------------------------------------------------------------


def test_load_dotenv_never_overrides_an_already_set_variable(tmp_path, monkeypatch):
    monkeypatch.setenv("ALREADY_SET_VAR", "from-shell")
    env_file = tmp_path / ".env"
    env_file.write_text("ALREADY_SET_VAR=from-file\n", encoding="utf-8")

    load_dotenv(env_file)

    import os

    assert os.environ["ALREADY_SET_VAR"] == "from-shell"
