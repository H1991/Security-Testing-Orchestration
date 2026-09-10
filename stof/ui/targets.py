"""Target Profile store -- the STOF Console's multi-application layer.

STOF's actual scan engine (`stof.config.schema.Config`, `stof/main.py`,
every vulnerability module) stays genuinely single-target per run, by
design: one `Config` object, dependency-injected, read from
`config/config.json`, exactly as CLAUDE.md's Layer 1 has always
specified -- the CLI (`stof scan --config ... --users ...`) is completely
unaffected by anything in this module.

This module adds a layer ABOVE that, owned entirely by the console: a
named, reusable "Target Profile" (one saved application -- base URL,
login, credentials, application type, per-target scan safety) an
operator can create, edit, and switch between from New Scan.
"Activating" a profile writes its fields into `config.json`'s
`target`/`testing` blocks and `users.json` -- the exact files
`stof/main.py` has always read -- so the scan engine never learns a
multi-target concept exists; it only ever sees "the" target for
whatever run is about to happen, same as before this module existed.
This mirrors how Acunetix/AppScan/Veracode DAST separate a reusable
Target/Application profile from the engine's own per-scan config.

Passwords are never written to `targets.json` -- same `{{env:VAR}}`-token
philosophy `users.json` already uses (CLAUDE.md rule 6), just with a
per-profile env var name (`ADMIN_PASSWORD__<TARGET_ID>`) so two
profiles' credentials for the same role never collide in `.env`. Only a
`<role>_password_set` boolean is persisted for the UI to show
"configured" without ever reading a secret back -- same convention
`burp.api_key_set` already uses in `stof/ui/server.py`.

Disk I/O (reading/writing `targets.json`, `.env`, `config.json`,
`users.json`) deliberately stays OUT of this module -- it only builds
and transforms plain dicts. `stof/ui/server.py` owns every file path and
every write, matching this project's own `tests/unit/test_server_
dashboard_summary.py` precedent of testing pure aggregation helpers
without spinning up the FastAPI app or touching disk.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APP_TYPES = ("web", "api", "mobile_api", "other")
AUTH_TYPES = ("form_login", "jwt")
SCAN_INTENSITIES = ("cautious", "standard", "aggressive")

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_ENV_KEY_RE = re.compile(r"[^A-Z0-9]+")

_DEFAULT_IDS = {"admin": "admin-01", "normal": "user-01"}


def slugify(name: str) -> str:
    slug = _SLUG_RE.sub("-", name.strip().lower()).strip("-")
    return slug or "target"


def new_target_id(name: str, existing_ids: Any) -> str:
    """A short, readable, unique id derived from the profile's name
    (e.g. "Kapture KM Staging" -> "kapture-km-staging"), not a raw
    UUID -- this id shows up in `.env` key names, so a slug is worth
    the tiny extra work over `uuid4().hex`."""
    existing = set(existing_ids)
    base = slugify(name)
    candidate = base
    n = 2
    while candidate in existing:
        candidate = f"{base}-{n}"
        n += 1
    return candidate


def env_key(role: str, target_id: str) -> str:
    """`ADMIN_PASSWORD__KAPTURE_KM_STAGING` / `USER_PASSWORD__...` -- the
    per-profile `.env` key a target's stored password/token lives
    under. `role` is "admin" or "normal", matching `users.json`'s own
    role names; "normal" maps to the pre-existing `USER_PASSWORD`
    prefix for continuity with the single-target convention this
    replaces."""
    prefix = "ADMIN_PASSWORD" if role == "admin" else "USER_PASSWORD"
    suffix = _ENV_KEY_RE.sub("_", target_id.upper()).strip("_")
    return f"{prefix}__{suffix}"


def totp_env_key(role: str, target_id: str) -> str:
    """`ADMIN_TOTP_SECRET__KAPTURE_KM_STAGING` / `USER_TOTP_SECRET__...`
    -- same per-profile `.env` scoping shape as `env_key()`, for the
    optional TOTP/MFA secret (`stof.config.schema.UserConfig.
    totp_secret`) instead of the password."""
    prefix = "ADMIN_TOTP_SECRET" if role == "admin" else "USER_TOTP_SECRET"
    suffix = _ENV_KEY_RE.sub("_", target_id.upper()).strip("_")
    return f"{prefix}__{suffix}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_store() -> dict:
    return {"targets": [], "active_target_id": None}


def load(path: Path) -> dict:
    if not path.is_file():
        return default_store()
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default_store()
    if not isinstance(doc, dict):
        return default_store()
    doc.setdefault("targets", [])
    doc.setdefault("active_target_id", None)
    # Additive migration for a targets.json written before "environment"
    # existed -- same convention findings/store.py's own schema
    # migration uses for an on-disk file predating a newer field.
    for profile in doc["targets"]:
        profile.setdefault("environment", "production")
    return doc


def save(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def find(doc: dict, target_id: str) -> dict | None:
    return next((t for t in doc["targets"] if t["id"] == target_id), None)


def new_profile(target_id: str, name: str) -> dict:
    """A fresh profile with every field defaulted -- callers layer
    `apply_fields`/`set_role_credentials` on top for whatever the
    create request actually supplied, so this is the one place
    new-profile defaults live."""
    now = _now()
    return {
        "id": target_id,
        "name": name,
        "app_type": "web",
        # Pure metadata, same as app_type -- never read by the scan
        # engine or by any technique's own logic. Exists so an operator
        # running STOF against several real deployments of the same
        # application (staging vs. production) can tell them apart on
        # the Applications/Scans pages, the same environment tagging
        # every enterprise DAST console (Acunetix, AppScan, Invicti)
        # already shows next to a target's name.
        "environment": "production",
        "base_url": "",
        "login_url": "",
        "username_selector": None,
        "password_selector": None,
        "submit_selector": None,
        "crawler_exclude_patterns": None,
        "idor_candidate_ids": None,
        "requires_assisted_login": False,
        "admin_username": None,
        "admin_auth_type": "form_login",
        "admin_password_set": False,
        "admin_totp_secret_set": False,
        "normal_username": None,
        "normal_auth_type": "form_login",
        "normal_password_set": False,
        "normal_totp_secret_set": False,
        "scan_intensity": "standard",
        "allow_state_changing_probes": False,
        "created_at": now,
        "updated_at": now,
    }


def apply_fields(profile: dict, updates: dict) -> None:
    """Partial update -- the exact convention every other config
    endpoint in this codebase already uses (see `/api/config/target`,
    `/api/credentials` in `stof/ui/server.py`): a field absent from
    `updates` (or explicitly `None`) is left untouched; `""` on a
    clearable selector field resets it back to auto-detect."""
    for field in ("name", "app_type", "environment", "base_url", "login_url", "scan_intensity"):
        value = updates.get(field)
        if value:
            profile[field] = value
    if updates.get("requires_assisted_login") is not None:
        profile["requires_assisted_login"] = bool(updates["requires_assisted_login"])
    if updates.get("allow_state_changing_probes") is not None:
        profile["allow_state_changing_probes"] = bool(updates["allow_state_changing_probes"])
    # Clearable fields (string selectors + list fields share one rule):
    # `None` in updates means untouched; an empty string/list clears
    # back to the generic auto-detected default.
    for field in ("username_selector", "password_selector", "submit_selector", "crawler_exclude_patterns", "idor_candidate_ids"):
        if field in updates and updates[field] is not None:
            profile[field] = updates[field] or None
    profile["updated_at"] = _now()


def set_role_credentials(profile: dict, role: str, username: str | None, auth_type: str | None) -> None:
    """Sets username/auth_type for `role` ("admin" | "normal") on the
    profile. `username=""` clears that role's credentials entirely
    (username, auth_type reset to default, `password_set` reset to
    False) -- mirrors `DELETE /api/credentials/{role}`'s single-account
    support, just expressed as a value instead of a separate endpoint.
    The caller is still responsible for deleting the matching `.env`
    key via `env_key()`; this only updates the profile document."""
    if username is None and auth_type is None:
        return
    if username == "":
        profile[f"{role}_username"] = None
        profile[f"{role}_auth_type"] = "form_login"
        profile[f"{role}_password_set"] = False
        # Removing the account removes whatever MFA was configured for
        # it too -- a stale totp_secret_set flag with no username
        # behind it would silently keep referencing a `.env` key for an
        # account that no longer exists in this profile.
        profile[f"{role}_totp_secret_set"] = False
        profile["updated_at"] = _now()
        return
    if username is not None:
        profile[f"{role}_username"] = username
    if auth_type is not None:
        profile[f"{role}_auth_type"] = auth_type
    profile["updated_at"] = _now()


def mark_password_set(profile: dict, role: str) -> None:
    profile[f"{role}_password_set"] = True
    profile["updated_at"] = _now()


def set_role_totp_secret(profile: dict, role: str, totp_secret: str | None) -> None:
    """Sets/clears `role`'s TOTP-configured flag -- mirrors
    `mark_password_set`'s shape, but (unlike a password) TOTP is
    genuinely optional per account, so this also handles turning it
    back OFF. `totp_secret=None` (omitted from the request) leaves the
    flag untouched; `""` explicitly clears it (2FA turned off for this
    test account, or the operator made a mistake and wants to remove
    it); any other non-empty value marks it set. The caller is still
    responsible for writing the matching `.env` key via
    `totp_env_key()` -- this only updates the profile document, same
    division of responsibility as `set_role_credentials`/
    `mark_password_set`."""
    if totp_secret is None:
        return
    profile[f"{role}_totp_secret_set"] = bool(totp_secret)
    profile["updated_at"] = _now()


def target_block(profile: dict) -> dict:
    """The exact shape `config.json`'s `target` key needs, derived from
    a profile -- written by the caller into `CONFIG_PATH` on
    activation. Selector overrides are included only when actually
    set, matching `TargetConfig`'s own "unset means auto-detect"
    philosophy (`stof/config/schema.py`)."""
    block: dict[str, Any] = {
        "base_url": profile["base_url"],
        "login_url": profile["login_url"],
        "requires_assisted_login": bool(profile.get("requires_assisted_login", False)),
    }
    for field in ("username_selector", "password_selector", "submit_selector", "crawler_exclude_patterns", "idor_candidate_ids"):
        if profile.get(field):
            block[field] = profile[field]
    return block


def testing_block(profile: dict) -> dict:
    """The fields of `config.json`'s `testing` block this profile owns.
    Merged into whatever's already there (not a full replace) by the
    caller, since `testing` may hold other keys this module doesn't
    know about."""
    return {
        "allow_state_changing_probes": bool(profile.get("allow_state_changing_probes", False)),
        "scan_intensity": profile.get("scan_intensity", "standard"),
    }


def user_entries(profile: dict) -> list[dict]:
    """The `users` list `config/users.json` needs for this profile's
    roles -- a role is included only if it actually has a username
    configured (single-account targets are normal and already
    supported elsewhere in this codebase, see `server.py`'s
    `set_credentials`/`delete_credentials` docstrings)."""
    entries = []
    for role, default_id in _DEFAULT_IDS.items():
        username = profile.get(f"{role}_username")
        if not username:
            continue
        env_var = "ADMIN_PASSWORD" if role == "admin" else "USER_PASSWORD"
        entry = {
            "id": default_id,
            "role": role,
            "username": username,
            "password": f"{{{{env:{env_var}}}}}",
            "auth_type": profile.get(f"{role}_auth_type", "form_login"),
        }
        if profile.get(f"{role}_totp_secret_set"):
            totp_var = "ADMIN_TOTP_SECRET" if role == "admin" else "USER_TOTP_SECRET"
            entry["totp_secret"] = f"{{{{env:{totp_var}}}}}"
        entries.append(entry)
    return entries
