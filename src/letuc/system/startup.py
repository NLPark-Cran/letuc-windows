"""开机自启动 via the HKCU Run registry key.

A registry Run entry is the lightest way to launch letuc at logon: no
service, no admin rights, and it shows up in Task Manager's "Startup"
tab so the user can disable it there too.

We write the value under HKCU\\...\\Run so it only affects the current
user. The command line is the frozen exe itself, with --minimized so the
window does not pop up on boot — the tray icon is what the user interacts
with from then on.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

logger = logging.getLogger(__name__)

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "letuc"

# See system/proxy.py for why the flags matter: the frozen exe has no
# console, and a console tool spawned without CREATE_NO_WINDOW dies with
# 0xC0000142 before it can do anything.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _run(cmd, check):
    return subprocess.run(cmd, check=check, capture_output=True,
                          stdin=subprocess.DEVNULL, text=True,
                          creationflags=_NO_WINDOW)


def _exe_path():
    """The path that should be written into the Run key.

    When running from source (python main.py) this is the interpreter plus
    the script, so a dev install does not accidentally persist.
    """
    if getattr(sys, "frozen", False):
        return sys.executable
    return None  # not built: nothing to persist


def is_enabled():
    """Return True if letuc is set to start with the current user."""
    try:
        # Single backslash: reg.exe rejects "HKCU\\Software" as an
        # invalid key name.
        out = _run(["reg", "query",
                    "HKCU\\" + RUN_KEY,
                    "/v", VALUE_NAME], check=False).stdout
        return VALUE_NAME in out
    except Exception as e:
        logger.warning("startup query failed: %s", e)
        return False


def enable():
    """Register letuc to start with the current user."""
    exe = _exe_path()
    if exe is None:
        raise RuntimeError("not running from a frozen executable")
    cmd = '"%s" --minimized' % exe
    _run(["reg", "add",
          "HKCU\\" + RUN_KEY,
          "/v", VALUE_NAME, "/t", "REG_SZ", "/d", cmd, "/f"], check=True)
    logger.info("startup enabled: %s", cmd)


def disable():
    """Remove the letuc Run entry."""
    try:
        _run(["reg", "delete",
              "HKCU\\" + RUN_KEY,
              "/v", VALUE_NAME, "/f"], check=True)
    except subprocess.CalledProcessError as e:
        # "value not found" is exit code 1 and is not an error here.
        if e.returncode != 1:
            raise
    logger.info("startup disabled")


__all__ = ["is_enabled", "enable", "disable"]