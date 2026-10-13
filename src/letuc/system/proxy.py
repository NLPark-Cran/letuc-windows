"""System proxy management for Windows.

Two mechanisms, both optional:

1. WinHTTP transparent proxy — redirects traffic from terminal processes
   (cmd, powershell, git, curl) through our local proxy without those
   programs knowing about it.
2. Internet Options system proxy — what browsers read.

Both are best-effort: failures are logged and the client keeps working.
"""

from __future__ import annotations

import logging
import subprocess

logger = logging.getLogger(__name__)

# The frozen exe is a windowed process with no console. Console tools
# (reg.exe, netsh.exe) spawned from it inherit no usable console handles
# and die at startup with 0xC0000142 (STATUS_DLL_INIT_FAILED) — or worse,
# pop a modal "Application Error" that waits for a click while the event
# loop is blocked. CREATE_NO_WINDOW keeps them invisible and headless;
# DEVNULL gives stdin a valid handle.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _run(cmd):
    return subprocess.run(cmd, check=True, capture_output=True,
                          stdin=subprocess.DEVNULL,
                          creationflags=_NO_WINDOW)


def set_winhttp_proxy(host, port):
    """Sync the WinHTTP proxy from Internet Options settings.

    Terminal processes (cmd, git, curl) read WinHTTP, not Internet
    Options. The supported way to mirror the IE settings is
    `netsh winhttp import proxy source=ie`; setting it by hand needs
    a `proxy-server=` keyword the previous invocation was missing.
    Must run after set_internet_options_proxy().
    """
    try:
        _run(["netsh", "winhttp", "import", "proxy", "source=ie"])
        logger.info("winhttp proxy imported from ie settings")
    except Exception as e:
        logger.warning("failed to import winhttp proxy: %s", e)


def clear_winhttp_proxy():
    try:
        _run(["netsh", "winhttp", "reset", "proxy"])
        logger.info("winhttp proxy reset")
    except Exception as e:
        logger.warning("failed to reset winhttp proxy: %s", e)


def set_internet_options_proxy(host, port, exceptions=None):
    """Set the system-wide proxy that browsers and apps read.

    V2RayN style: a plain `host:port` ProxyServer value (no `http=`
    prefix), so every scheme routes through the mixed port, followed by
    a WinINet refresh broadcast so Explorer, browsers and the Settings
    app pick the change up without waiting for their own polling cycle.
    """
    exceptions = exceptions or (
        "localhost;127.*;10.*;172.*;192.168.*")
    proxy_value = "%s:%d" % (host, port)
    try:
        _run(["reg", "add",
              r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
              "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"])
        _run(["reg", "add",
              r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
              "/v", "ProxyServer", "/t", "REG_SZ", "/d", proxy_value, "/f"])
        _run(["reg", "add",
              r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
              "/v", "ProxyOverride", "/t", "REG_SZ",
              "/d", exceptions, "/f"])
        _notify_wininet_changed()
        logger.info("internet options proxy set to %s:%d", host, port)
    except Exception as e:
        logger.warning("failed to set internet options proxy: %s", e)


def clear_internet_options_proxy():
    try:
        _run(["reg", "add",
              r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
              "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"])
        _notify_wininet_changed()
        logger.info("internet options proxy cleared")
    except Exception as e:
        logger.warning("failed to clear internet options proxy: %s", e)


def _notify_wininet_changed():
    """Broadcast INTERNET_OPTION_SETTINGS_CHANGED / REFRESH.

    Registry writes alone leave the Settings UI and some apps showing
    stale state; WinINet listens for this broadcast.
    """
    import ctypes

    internet_set_option = ctypes.windll.wininet.InternetSetOptionW
    internet_set_option(None, 39, None, 0)  # SETTINGS_CHANGED
    internet_set_option(None, 37, None, 0)  # REFRESH


__all__ = [
    "set_winhttp_proxy", "clear_winhttp_proxy",
    "set_internet_options_proxy", "clear_internet_options_proxy",
]