"""Layer 3A — shared CDP-attach conventions.

Extracted from `stof/ui/server.py`'s original Workflow Recording code
(same `RECORDING_CDP_PORT`/`_recording_cdp_host()`/
`_recording_cdp_endpoint()`/`_recording_launch_command()` this project
already relied on) so a second consumer -- `stof/main.py`'s assisted-
login path -- can connect to the exact same operator-run, debuggable
browser without forking a second, slightly-different implementation.
Both features share one debug port and one set of instructions on
purpose: an operator who has already started a debuggable Chrome for
one doesn't need a second one for the other.
"""
from __future__ import annotations

import os
import platform
import socket

CDP_PORT = 9222  # Chrome/Edge's own conventional --remote-debugging-port default

# A SEPARATE, dedicated port for the server-side assisted-login browser
# (`stof/ui/server.py`'s `AssistedLoginBrowserSession`) -- deliberately
# not the same 9222 as the operator-runs-their-own-Chrome flows above,
# so the two never collide if both happen to be in use at once. Always
# bound to 127.0.0.1 only (never 0.0.0.0/LAN) -- unlike Workflow
# Recording, both the FastAPI server AND the `stof scan` subprocess
# that later reconnects to this browser run on the SAME machine (the
# whole point of moving the browser server-side was to remove the
# cross-machine reachability problem a remote end user's own laptop
# would otherwise create), so there is never a reason to expose this
# one off localhost.
ASSISTED_LOGIN_CDP_PORT = 9223


def assisted_login_cdp_endpoint() -> str:
    return f"http://127.0.0.1:{ASSISTED_LOGIN_CDP_PORT}"


def cdp_host() -> str:
    """The address this process should use to reach the operator's
    Chrome debug port. `127.0.0.1` is wrong whenever the connecting
    process isn't in the exact same network namespace as the browser --
    e.g. the STOF server/scan subprocess running in a container/VM or
    on a genuinely different machine than the operator's own laptop.
    `STOF_RECORDING_CDP_HOST` overrides this outright for setups this
    heuristic can't guess. The heuristic: open a UDP "connection" (no
    packets actually sent) to a public address purely to ask the OS
    which local interface it would route through -- the standard
    no-DNS trick for finding a box's own LAN IP. Kept the same env var
    name as Workflow Recording (not a new one) -- one setting, two
    features that both need the same answer to the same question."""
    override = os.environ.get("STOF_RECORDING_CDP_HOST")
    if override:
        return override
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def cdp_endpoint() -> str:
    return f"http://{cdp_host()}:{CDP_PORT}"


def launch_command() -> dict:
    """OS-specific command to start a CDP-debuggable browser, shown to
    the operator before they start a recording or an assisted login.
    Two details matter here, not one:
    - A separate `--user-data-dir` (a throwaway scratch profile, not
      their normal one): Chrome silently REFUSES to enable remote
      debugging on an already-running instance using the default
      profile -- confirmed behavior, not a guess -- so a command that
      omits it "works" the first time someone has no Chrome open at
      all and mysteriously stops working the next time they already
      have a normal browsing session going.
    - `--remote-debugging-address=0.0.0.0`: Chrome's debug port binds
      to loopback ONLY by default, unreachable from outside the
      browser's own machine/namespace. The connecting process (STOF
      server, or a scan subprocess) may be reached over the LAN
      (`cdp_host()` above) precisely because it isn't sharing loopback
      with the browser, so the browser's debug port has to be opened
      to the network too, not just started."""
    system = platform.system()
    if system == "Darwin":
        return {
            "os": "macOS",
            "command": f'open -a "Google Chrome" --args --remote-debugging-port={CDP_PORT} --remote-debugging-address=0.0.0.0 --user-data-dir=/tmp/stof-chrome-debug',
        }
    if system == "Windows":
        return {
            "os": "Windows",
            "command": f'start chrome --remote-debugging-port={CDP_PORT} --remote-debugging-address=0.0.0.0 --user-data-dir=%TEMP%\\stof-chrome-debug',
        }
    return {
        "os": "Linux",
        "command": f"google-chrome --remote-debugging-port={CDP_PORT} --remote-debugging-address=0.0.0.0 --user-data-dir=/tmp/stof-chrome-debug &",
    }
