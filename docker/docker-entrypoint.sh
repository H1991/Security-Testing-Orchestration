#!/usr/bin/env bash
# STOF container entrypoint.
#
# Seeds a fresh, mounted config/ volume from the read-only reference
# copy baked into the image (config-defaults/ -- the static test
# catalog: testcases.json, test_catalog_summaries.json, auth_tests.json)
# WITHOUT ever overwriting a file the team has already put there --
# config.json/targets.json/users.json are target-specific and
# credential-bearing, so they only ever come from `stof configure`
# writing into the mounted volume, never from the image itself (see
# .dockerignore -- those three files are deliberately excluded from
# the build context).
set -euo pipefail

mkdir -p /opt/stof/config /opt/stof/data

for f in /opt/stof/config-defaults/*; do
  name="$(basename "$f")"
  if [ ! -e "/opt/stof/config/$name" ]; then
    cp "$f" "/opt/stof/config/$name"
  fi
done

# STOF reads `.env` from its current working directory by default (see
# `stof/config/loader.py`'s `load_dotenv()`), and `stof configure`
# writes it there too -- but CWD here is /opt/stof, which is NOT one of
# the two mounted volumes (config/, data/), so anything written there
# would silently vanish the next time this container is recreated.
# Symlink it into the persistent config/ volume, created once, so
# `stof configure` (or any scan) transparently persists credentials
# without the team needing a special --env-file flag on every command.
if [ ! -L /opt/stof/.env ] && [ ! -f /opt/stof/.env ]; then
  ln -s config/.env /opt/stof/.env
fi

exec "$@"
