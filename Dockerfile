# STOF -- Security Testing Orchestration Framework
#
# Plain python:3.11-slim base, not a pre-built Playwright browser image
# -- Microsoft's `playwright/python` images ship a fixed Python version
# per tag (3.10 as of the v1.61.0-jammy tag, checked live while
# building this image) that doesn't track this project's own
# `requires-python = ">=3.11"`. Installing Playwright from pip and then
# running its OWN `playwright install` immediately after is actually
# the more robust way to solve the "browser version pinning" problem
# STOF_TECHNICAL_OVERVIEW.md's Known Issues section flagged: the
# downloaded Chromium build is guaranteed to match whichever Playwright
# version pip just resolved, in the same build step, rather than
# depending on a separately-versioned upstream base image staying in
# sync with it.
FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="STOF" \
      org.opencontainers.image.description="Security Testing Orchestration Framework" \
      org.opencontainers.image.vendor="NuSummit"

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/stof-browsers

WORKDIR /opt/stof

# Dependencies first (better layer caching -- source changes far more
# often than pyproject.toml).
COPY pyproject.toml README.md ./
COPY stof ./stof

# `ui` extra pulls in FastAPI/uvicorn for the web console; `[dev]` test
# tooling is deliberately NOT installed here -- this is a runtime
# image, not a CI image. Editable install (`-e`), not a normal one:
# STOF's own code resolves several paths (config/testcases.json,
# data/stof.db, ...) relative to the REPO ROOT / current working
# directory, not the installed package location (see
# `stof/ui/server.py`'s `REPO_ROOT = Path(__file__).resolve().parent.
# parent.parent>` and the many bare `Path("config/...")`/`Path("data/
# ...")` literals throughout `stof/main.py`) -- a normal (non-editable)
# install would copy the package into site-packages and silently break
# every one of those lookups.
#
# `playwright install --with-deps chromium` runs as root (needs apt)
# in this same step, right after pip resolves the exact Playwright
# version -- see this block's own opening comment for why that
# ordering is what actually keeps the browser build in sync.
RUN pip install --no-cache-dir -e ".[ui]" \
    && playwright install --with-deps chromium

# Read-only reference copy of the static test-case catalog (never the
# real, credential-bearing config.json/targets.json/users.json -- see
# .dockerignore) -- the entrypoint seeds a fresh mounted config/ volume
# from this on first run, without ever overwriting what's already there.
COPY config ./config-defaults

RUN useradd --create-home --shell /bin/bash stof \
    && mkdir -p /opt/stof/config /opt/stof/data \
    && chown -R stof:stof /opt/stof /opt/stof-browsers

COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# config/ (target URL, credentials via .env, session state) and data/
# (scan reports, evidence, the SQLite findings/session/cleanup stores)
# are the only things a real engagement needs to persist across a
# container recreation -- mount both to a host directory or named
# volume. See STOF_TECHNICAL_OVERVIEW.md's own Known Issues section:
# SQLite's WAL mode needs a real filesystem, not container-overlay
# storage, for crash-resume to actually survive a restart.
VOLUME ["/opt/stof/config", "/opt/stof/data"]

USER stof

# The console (`stof/ui/server.py`) binds 127.0.0.1 by default when run
# directly -- inside a container that's unreachable from the host, so
# the console CMD below explicitly binds 0.0.0.0. Loopback-only was
# never a real security boundary once a container's network namespace
# is in the picture; use `docker run -p 127.0.0.1:8787:8787:...` (bind
# the HOST side to loopback) or STOF_CONSOLE_API_KEY (see the user
# guide) to actually restrict access, not the in-container bind address.
EXPOSE 8787

ENTRYPOINT ["docker-entrypoint.sh"]
# Default: the CLI's own --help. docker-compose.yml overrides this for
# the `scan`/`console` services with the actual commands.
CMD ["stof", "--help"]
