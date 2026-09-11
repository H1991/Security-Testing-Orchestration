"""Unit tests for stof.ui.targets -- the pure Target Profile transforms
behind the console's multi-application support (see the module's own
docstring for why disk I/O is deliberately kept out of this module and
tested at the server.py call sites instead, matching test_server_
dashboard_summary.py's precedent)."""
import json

from stof.ui import targets

# ---------------------------------------------------------------------------
# slugify / new_target_id
# ---------------------------------------------------------------------------


def test_slugify_lowercases_and_hyphenates():
    assert targets.slugify("Kapture KM Staging") == "kapture-km-staging"


def test_slugify_empty_falls_back_to_target():
    assert targets.slugify("   ") == "target"


def test_new_target_id_is_unique_against_existing_ids():
    assert targets.new_target_id("Acme", {"acme"}) == "acme-2"
    assert targets.new_target_id("Acme", {"acme", "acme-2"}) == "acme-3"


def test_new_target_id_no_collision_returns_base_slug():
    assert targets.new_target_id("Fresh App", set()) == "fresh-app"


# ---------------------------------------------------------------------------
# env_key
# ---------------------------------------------------------------------------


def test_env_key_admin_vs_normal_prefix():
    assert targets.env_key("admin", "acme") == "ADMIN_PASSWORD__ACME"
    assert targets.env_key("normal", "acme") == "USER_PASSWORD__ACME"


def test_env_key_sanitizes_non_alnum_target_id():
    assert targets.env_key("admin", "kapture-km-staging") == "ADMIN_PASSWORD__KAPTURE_KM_STAGING"


# ---------------------------------------------------------------------------
# load / save
# ---------------------------------------------------------------------------


def test_load_missing_file_returns_default_store(tmp_path):
    doc = targets.load(tmp_path / "targets.json")
    assert doc == {"targets": [], "active_target_id": None}


def test_load_malformed_json_falls_back_to_default(tmp_path):
    path = tmp_path / "targets.json"
    path.write_text("{not json", encoding="utf-8")
    assert targets.load(path) == {"targets": [], "active_target_id": None}


def test_save_then_load_roundtrips(tmp_path):
    path = tmp_path / "targets.json"
    doc = {"targets": [targets.new_profile("acme", "Acme")], "active_target_id": "acme"}
    targets.save(path, doc)
    loaded = targets.load(path)
    assert loaded["active_target_id"] == "acme"
    assert loaded["targets"][0]["id"] == "acme"
    assert json.loads(path.read_text(encoding="utf-8"))["active_target_id"] == "acme"


# ---------------------------------------------------------------------------
# find / new_profile
# ---------------------------------------------------------------------------


def test_find_returns_none_when_absent():
    doc = {"targets": [targets.new_profile("acme", "Acme")]}
    assert targets.find(doc, "nope") is None


def test_find_returns_matching_profile():
    doc = {"targets": [targets.new_profile("acme", "Acme")]}
    assert targets.find(doc, "acme")["name"] == "Acme"


def test_new_profile_defaults():
    profile = targets.new_profile("acme", "Acme")
    assert profile["app_type"] == "web"
    assert profile["environment"] == "production"
    assert profile["scan_intensity"] == "standard"
    assert profile["allow_state_changing_probes"] is False
    assert profile["roles"] == []  # zero accounts is a valid, fully-supported starting state
    assert profile["created_at"] == profile["updated_at"]


def test_load_backfills_environment_for_a_profile_saved_before_the_field_existed(tmp_path):
    path = tmp_path / "targets.json"
    profile = targets.new_profile("acme", "Acme")
    del profile["environment"]  # simulates targets.json written before this field existed
    path.write_text(json.dumps({"targets": [profile], "active_target_id": "acme"}), encoding="utf-8")
    loaded = targets.load(path)
    assert loaded["targets"][0]["environment"] == "production"


# ---------------------------------------------------------------------------
# apply_fields
# ---------------------------------------------------------------------------


def test_apply_fields_sets_direct_fields():
    profile = targets.new_profile("acme", "Acme")
    targets.apply_fields(profile, {"base_url": "https://a.example", "login_url": "https://a.example/login", "app_type": "api"})
    assert profile["base_url"] == "https://a.example"
    assert profile["login_url"] == "https://a.example/login"
    assert profile["app_type"] == "api"


def test_apply_fields_leaves_omitted_fields_untouched():
    profile = targets.new_profile("acme", "Acme")
    profile["base_url"] = "https://existing.example"
    targets.apply_fields(profile, {"app_type": "api"})
    assert profile["base_url"] == "https://existing.example"


def test_apply_fields_sets_environment():
    profile = targets.new_profile("acme", "Acme")
    targets.apply_fields(profile, {"environment": "staging"})
    assert profile["environment"] == "staging"


def test_apply_fields_none_never_overwrites():
    profile = targets.new_profile("acme", "Acme")
    profile["base_url"] = "https://existing.example"
    targets.apply_fields(profile, {"base_url": None})
    assert profile["base_url"] == "https://existing.example"


def test_apply_fields_empty_string_clears_selector():
    profile = targets.new_profile("acme", "Acme")
    profile["username_selector"] = "#user"
    targets.apply_fields(profile, {"username_selector": ""})
    assert profile["username_selector"] is None


def test_apply_fields_bool_flags_accept_explicit_false():
    profile = targets.new_profile("acme", "Acme")
    profile["allow_state_changing_probes"] = True
    targets.apply_fields(profile, {"allow_state_changing_probes": False})
    assert profile["allow_state_changing_probes"] is False


def test_apply_fields_updates_timestamp():
    profile = targets.new_profile("acme", "Acme")
    before = profile["updated_at"]
    targets.apply_fields(profile, {"app_type": "api"})
    assert profile["updated_at"] >= before


# ---------------------------------------------------------------------------
# set_role_credentials / mark_password_set / remove_role -- N free-text
# roles, not a fixed admin/normal pair. `profile["roles"]` is now a
# list; `_role()` below fetches one entry by its display label, mirroring
# how a caller (server.py) actually looks a role up.
# ---------------------------------------------------------------------------


def _role(profile: dict, role: str) -> dict | None:
    return next((r for r in profile["roles"] if r["role"] == role), None)


def test_set_role_credentials_sets_username_and_auth_type():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "jwt")
    entry = _role(profile, "admin")
    assert entry["username"] == "admin@acme.com"
    assert entry["auth_type"] == "jwt"
    assert entry["id"] == "admin-01"  # historical id, back-compat with existing .env files


def test_set_role_credentials_creates_an_arbitrary_free_text_role():
    """A tester with a role that isn't "admin" or "normal" -- e.g. a
    third support account -- works identically, not just the two
    historical role names."""
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "Support Agent", "support@acme.com", "form_login")
    entry = _role(profile, "Support Agent")
    assert entry["username"] == "support@acme.com"
    assert entry["id"] == "support-agent"  # derived from the role's own slug, unique by construction


def test_set_role_credentials_supports_more_than_two_roles_at_once():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "form_login")
    targets.set_role_credentials(profile, "normal", "user@acme.com", "form_login")
    targets.set_role_credentials(profile, "Read-only", "viewer@acme.com", "form_login")
    assert [r["role"] for r in profile["roles"]] == ["admin", "normal", "Read-only"]


def test_set_role_credentials_empty_string_clears_role_in_place():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "jwt")
    targets.mark_password_set(profile, "admin")
    targets.set_role_credentials(profile, "admin", "", None)
    entry = _role(profile, "admin")
    assert entry["username"] is None
    assert entry["auth_type"] == "form_login"
    assert entry["password_set"] is False


def test_set_role_credentials_both_none_is_a_noop():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "existing", "form_login")
    targets.set_role_credentials(profile, "admin", None, None)
    assert _role(profile, "admin")["username"] == "existing"


def test_set_role_credentials_username_only_never_creates_a_role_for_auth_type_alone():
    """auth_type with no username, for a role that doesn't exist yet --
    nothing to attach it to, so this must not silently create a
    credential-less role entry."""
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", None, "jwt")
    assert profile["roles"] == []


def test_mark_password_set():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "normal", "user@acme.com", "form_login")
    targets.mark_password_set(profile, "normal")
    assert _role(profile, "normal")["password_set"] is True


def test_mark_password_set_is_a_noop_for_a_role_that_does_not_exist():
    profile = targets.new_profile("acme", "Acme")
    targets.mark_password_set(profile, "admin")
    assert profile["roles"] == []


def test_set_role_credentials_empty_string_clears_totp_flag_too():
    """Removing an account removes whatever MFA was configured for it
    -- a stale totp_secret_set flag with no username behind it would
    silently keep referencing a .env key for an account that no longer
    exists in this profile."""
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "form_login")
    targets.set_role_totp_secret(profile, "admin", "JBSWY3DPEHPK3PXP")
    targets.set_role_credentials(profile, "admin", "", None)
    assert _role(profile, "admin")["totp_secret_set"] is False


def test_remove_role_drops_the_entry_and_returns_it():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "form_login")
    targets.set_role_credentials(profile, "normal", "user@acme.com", "form_login")
    removed = targets.remove_role(profile, "admin")
    assert removed["id"] == "admin-01"
    assert [r["role"] for r in profile["roles"]] == ["normal"]


def test_remove_role_returns_none_when_no_such_role():
    profile = targets.new_profile("acme", "Acme")
    assert targets.remove_role(profile, "admin") is None


# ---------------------------------------------------------------------------
# set_role_totp_secret
# ---------------------------------------------------------------------------


def test_set_role_totp_secret_marks_set_for_a_real_value():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "form_login")
    targets.set_role_totp_secret(profile, "admin", "JBSWY3DPEHPK3PXP")
    assert _role(profile, "admin")["totp_secret_set"] is True


def test_set_role_totp_secret_empty_string_clears_the_flag():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "form_login")
    targets.set_role_totp_secret(profile, "admin", "JBSWY3DPEHPK3PXP")
    targets.set_role_totp_secret(profile, "admin", "")
    assert _role(profile, "admin")["totp_secret_set"] is False


def test_set_role_totp_secret_none_is_a_noop():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "form_login")
    targets.set_role_totp_secret(profile, "admin", "JBSWY3DPEHPK3PXP")
    targets.set_role_totp_secret(profile, "admin", None)
    assert _role(profile, "admin")["totp_secret_set"] is True  # untouched, not reset


def test_set_role_totp_secret_is_a_noop_for_a_role_that_does_not_exist():
    """TOTP with no username to attach it to is meaningless -- same
    principle as mark_password_set's own no-op-when-absent case."""
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_totp_secret(profile, "admin", "JBSWY3DPEHPK3PXP")
    assert profile["roles"] == []


# ---------------------------------------------------------------------------
# set_role_login_workflow -- "recorded_workflow" auth_type's own setting
# ---------------------------------------------------------------------------


def test_set_role_login_workflow_sets_the_id():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "recorded_workflow")
    targets.set_role_login_workflow(profile, "admin", "spa-login")
    assert _role(profile, "admin")["login_workflow_id"] == "spa-login"


def test_set_role_login_workflow_empty_string_clears_it():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "recorded_workflow")
    targets.set_role_login_workflow(profile, "admin", "spa-login")
    targets.set_role_login_workflow(profile, "admin", "")
    assert _role(profile, "admin")["login_workflow_id"] is None


def test_set_role_login_workflow_none_is_a_noop():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "recorded_workflow")
    targets.set_role_login_workflow(profile, "admin", "spa-login")
    targets.set_role_login_workflow(profile, "admin", None)
    assert _role(profile, "admin")["login_workflow_id"] == "spa-login"  # untouched, not reset


def test_set_role_login_workflow_is_a_noop_for_a_role_that_does_not_exist():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_login_workflow(profile, "admin", "spa-login")
    assert profile["roles"] == []


def test_removing_a_role_via_empty_username_also_clears_its_login_workflow():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "recorded_workflow")
    targets.set_role_login_workflow(profile, "admin", "spa-login")
    targets.set_role_credentials(profile, "admin", "", None)
    assert _role(profile, "admin")["login_workflow_id"] is None


def test_totp_env_key_shape():
    assert targets.totp_env_key("admin", "kapture-km-staging") == "ADMIN_TOTP_SECRET__KAPTURE_KM_STAGING"
    assert targets.totp_env_key("normal", "kapture-km-staging") == "USER_TOTP_SECRET__KAPTURE_KM_STAGING"


def test_env_key_custom_role_derives_prefix_from_its_own_label():
    assert targets.env_key("Support Agent", "acme") == "SUPPORT_AGENT_PASSWORD__ACME"
    assert targets.totp_env_key("Support Agent", "acme") == "SUPPORT_AGENT_TOTP_SECRET__ACME"


# ---------------------------------------------------------------------------
# roles migration -- a targets.json written before roles became a list
# ---------------------------------------------------------------------------


def test_load_migrates_a_legacy_flat_role_profile_into_a_roles_list(tmp_path):
    path = tmp_path / "targets.json"
    profile = targets.new_profile("acme", "Acme")
    del profile["roles"]
    profile.update({
        "admin_username": "admin@acme.com", "admin_auth_type": "form_login",
        "admin_password_set": True, "admin_totp_secret_set": False,
        "normal_username": "user@acme.com", "normal_auth_type": "jwt",
        "normal_password_set": False, "normal_totp_secret_set": True,
    })
    path.write_text(json.dumps({"targets": [profile], "active_target_id": "acme"}), encoding="utf-8")
    loaded = targets.load(path)
    migrated = loaded["targets"][0]
    assert "admin_username" not in migrated  # old flat keys are gone, not left as dead weight
    assert _role(migrated, "admin") == {
        "id": "admin-01", "role": "admin", "username": "admin@acme.com",
        "auth_type": "form_login", "password_set": True, "totp_secret_set": False,
    }
    assert _role(migrated, "normal")["auth_type"] == "jwt"
    assert _role(migrated, "normal")["totp_secret_set"] is True


def test_load_migration_skips_a_role_with_no_username(tmp_path):
    path = tmp_path / "targets.json"
    profile = targets.new_profile("acme", "Acme")
    del profile["roles"]
    profile.update({
        "admin_username": "admin@acme.com", "admin_auth_type": "form_login",
        "admin_password_set": True, "admin_totp_secret_set": False,
        "normal_username": None, "normal_auth_type": "form_login",
        "normal_password_set": False, "normal_totp_secret_set": False,
    })
    path.write_text(json.dumps({"targets": [profile], "active_target_id": "acme"}), encoding="utf-8")
    migrated = targets.load(path)["targets"][0]
    assert [r["role"] for r in migrated["roles"]] == ["admin"]


def test_load_does_not_reprocess_a_profile_that_already_has_a_roles_list(tmp_path):
    path = tmp_path / "targets.json"
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "Support Agent", "support@acme.com", "form_login")
    path.write_text(json.dumps({"targets": [profile], "active_target_id": "acme"}), encoding="utf-8")
    loaded = targets.load(path)["targets"][0]
    assert [r["role"] for r in loaded["roles"]] == ["Support Agent"]


# ---------------------------------------------------------------------------
# target_block / testing_block / user_entries
# ---------------------------------------------------------------------------


def test_target_block_includes_only_set_selectors():
    profile = targets.new_profile("acme", "Acme")
    profile["base_url"] = "https://a.example"
    profile["login_url"] = "https://a.example/login"
    profile["username_selector"] = "#user"
    block = targets.target_block(profile)
    assert block == {
        "base_url": "https://a.example",
        "login_url": "https://a.example/login",
        "requires_assisted_login": False,
        "username_selector": "#user",
    }


def test_target_block_includes_crawler_exclusions_and_idor_candidate_ids_when_set():
    """Regression test for a real bug caught via live testing: these two
    TargetConfig fields (stof/config/schema.py) were dropped entirely by
    an earlier version of target_block(), which silently wiped a real
    target's tuned crawler_exclude_patterns/idor_candidate_ids on the
    very next activation."""
    profile = targets.new_profile("acme", "Acme")
    profile["base_url"] = "https://a.example"
    profile["login_url"] = "https://a.example/login"
    profile["crawler_exclude_patterns"] = ["survey_questions", "privacypolicy"]
    profile["idor_candidate_ids"] = ["800000", "800001"]
    block = targets.target_block(profile)
    assert block["crawler_exclude_patterns"] == ["survey_questions", "privacypolicy"]
    assert block["idor_candidate_ids"] == ["800000", "800001"]


def test_apply_fields_sets_list_fields():
    profile = targets.new_profile("acme", "Acme")
    targets.apply_fields(profile, {"crawler_exclude_patterns": ["a", "b"], "idor_candidate_ids": ["1", "2"]})
    assert profile["crawler_exclude_patterns"] == ["a", "b"]
    assert profile["idor_candidate_ids"] == ["1", "2"]


def test_apply_fields_empty_list_clears_list_field():
    profile = targets.new_profile("acme", "Acme")
    profile["crawler_exclude_patterns"] = ["a", "b"]
    targets.apply_fields(profile, {"crawler_exclude_patterns": []})
    assert profile["crawler_exclude_patterns"] is None


def test_apply_fields_none_list_field_leaves_untouched():
    profile = targets.new_profile("acme", "Acme")
    profile["crawler_exclude_patterns"] = ["a", "b"]
    targets.apply_fields(profile, {"crawler_exclude_patterns": None})
    assert profile["crawler_exclude_patterns"] == ["a", "b"]


def test_testing_block_reflects_profile_safety_settings():
    profile = targets.new_profile("acme", "Acme")
    profile["scan_intensity"] = "cautious"
    profile["allow_state_changing_probes"] = True
    assert targets.testing_block(profile) == {"allow_state_changing_probes": True, "scan_intensity": "cautious"}


def test_user_entries_includes_only_roles_with_a_username_and_a_password():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "form_login")
    targets.mark_password_set(profile, "admin")
    entries = targets.user_entries(profile)
    assert len(entries) == 1
    assert entries[0] == {
        "id": "admin-01",
        "role": "admin",
        "username": "admin@acme.com",
        "password": "{{env:ADMIN_PASSWORD}}",
        "auth_type": "form_login",
    }


def test_user_entries_excludes_a_role_with_a_username_but_no_password_yet():
    """Regression test for a real bug caught via live testing: a role
    saved with only a username (a tester fills in what they know and
    saves, meaning to add the password moments later) used to still get
    a {{env:...}} password token pointing at an unset env var --
    stof.config.loader.load_users() raises on that, which broke
    GET /api/auth/roles (and a real scan) for EVERY role in the file,
    not just the incomplete one."""
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "form_login")
    targets.mark_password_set(profile, "admin")
    targets.set_role_credentials(profile, "Support Agent", "support@acme.com", "form_login")
    entries = targets.user_entries(profile)
    assert [e["role"] for e in entries] == ["admin"]


def test_user_entries_empty_when_no_roles_configured():
    profile = targets.new_profile("acme", "Acme")
    assert targets.user_entries(profile) == []


def test_user_entries_normal_role_uses_user_password_token():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "normal", "user@acme.com", "jwt")
    targets.mark_password_set(profile, "normal")
    entries = targets.user_entries(profile)
    assert entries[0]["password"] == "{{env:USER_PASSWORD}}"
    assert entries[0]["auth_type"] == "jwt"


def test_user_entries_includes_totp_secret_token_when_configured():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "form_login")
    targets.mark_password_set(profile, "admin")
    targets.set_role_totp_secret(profile, "admin", "JBSWY3DPEHPK3PXP")
    entries = targets.user_entries(profile)
    assert entries[0]["totp_secret"] == "{{env:ADMIN_TOTP_SECRET}}"


def test_user_entries_omits_totp_secret_key_entirely_when_not_configured():
    """Matches UserConfig.totp_secret's own None default -- most users
    have no MFA at all, so the key shouldn't even be present (not a
    null value) in the generated users.json entry."""
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "form_login")
    targets.mark_password_set(profile, "admin")
    entries = targets.user_entries(profile)
    assert "totp_secret" not in entries[0]


def test_user_entries_normal_role_totp_uses_user_totp_secret_token():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "normal", "user@acme.com", "form_login")
    targets.mark_password_set(profile, "normal")
    targets.set_role_totp_secret(profile, "normal", "JBSWY3DPEHPK3PXP")
    entries = targets.user_entries(profile)
    assert entries[0]["totp_secret"] == "{{env:USER_TOTP_SECRET}}"


def test_user_entries_supports_an_arbitrary_third_role():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "form_login")
    targets.mark_password_set(profile, "admin")
    targets.set_role_credentials(profile, "normal", "user@acme.com", "form_login")
    targets.mark_password_set(profile, "normal")
    targets.set_role_credentials(profile, "Support Agent", "support@acme.com", "form_login")
    targets.mark_password_set(profile, "Support Agent")
    entries = targets.user_entries(profile)
    assert len(entries) == 3
    assert entries[2]["role"] == "Support Agent"
    assert entries[2]["password"] == "{{env:SUPPORT_AGENT_PASSWORD}}"


def test_user_entries_includes_login_workflow_id_for_recorded_workflow_roles():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "recorded_workflow")
    targets.mark_password_set(profile, "admin")
    targets.set_role_login_workflow(profile, "admin", "spa-login")
    entries = targets.user_entries(profile)
    assert entries[0]["login_workflow_id"] == "spa-login"


def test_user_entries_omits_login_workflow_id_when_not_set():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "form_login")
    targets.mark_password_set(profile, "admin")
    entries = targets.user_entries(profile)
    assert "login_workflow_id" not in entries[0]
