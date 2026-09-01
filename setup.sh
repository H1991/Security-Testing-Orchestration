#!/usr/bin/env bash
# One-time environment bootstrap for STOF on Linux.
#
# The .venv/ that may already exist in this checkout was created on
# Windows (its pyvenv.cfg points at a C:\... Python) and cannot run
# here -- this script removes it and creates a real Linux venv in its
# place, then installs this project's own dependencies and Playwright's
# Chromium browser into it.
#
# Usage:
#   chmod +x setup.sh   # once
#   ./setup.sh
set -euo pipefail

cd "$(dirname "$0")"

if [ -d .venv ]; then
    echo "Removing existing .venv/ (Windows-created, unusable on Linux)..."
    rm -rf .venv
fi

echo "Creating .venv/..."
python3 -m venv .venv

# shellcheck disable=SC1091
source .venv/bin/activate

echo "Upgrading pip..."
pip install --upgrade pip -q

echo "Installing STOF and its dependencies (pip install -e \".[dev]\")..."
pip install -e ".[dev]" -q

echo "Installing Playwright's Chromium browser (one-time, ~150-300MB download)..."
python -m playwright install chromium

echo
echo "Done. Activate this environment in new shells with:"
echo "  source .venv/bin/activate"
echo
echo "Then run the full scan with:"
echo "  python -m stof.main scan --config config/config.json --users config/users.json"
