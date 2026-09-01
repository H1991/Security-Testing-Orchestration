"""Manual smoke-test entry point for Layer 3A, ahead of Layer 15's `stof
record` CLI command: `python -m stof.recorder --output ... --users ...`.

Requires a Chrome/Edge instance already running with
`--remote-debugging-port=9222` (see README.md).
"""
from __future__ import annotations

import argparse
import asyncio

from stof.config import load_dotenv, load_users
from stof.core.logger import configure_logging

from .recorder import DEFAULT_CDP_ENDPOINT, record


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m stof.recorder",
        description="STOF Layer 3A manual smoke test: record a workflow from a "
        "real Chrome instance over CDP (run `google-chrome "
        "--remote-debugging-port=9222` first).",
    )
    parser.add_argument("--output", required=True, help="Path to write the workflow JSON")
    parser.add_argument("--cdp-endpoint", default=DEFAULT_CDP_ENDPOINT)
    parser.add_argument(
        "--users", default=None, help="Optional path to users.json for credential tokenisation"
    )
    return parser.parse_args()


async def _main() -> None:
    args = _parse_args()
    load_dotenv()
    configure_logging()
    users = load_users(args.users) if args.users else None
    await record(args.output, cdp_endpoint=args.cdp_endpoint, users=users)


if __name__ == "__main__":
    asyncio.run(_main())
