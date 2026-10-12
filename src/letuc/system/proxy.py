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
    """Configure the WinHTTP proxy used by terminal processes."""
    try:
        _run(["netsh", "winhttp", "set", "proxy",
              f"{host}:{port}", ""])
        logger.info("winhttp proxy set to %s:%d", host, port)
    except Exception as e:
        logger.warning("failed to set winhttp proxy: %s", e)


def clear_winhttp_proxy():
    try:
        _run(["netsh", "winhttp", "set", "proxy", "", ""])
        logger.info("winhttp proxy cleared")
    except Exception as e:
        logger.warning("failed to clear winhttp proxy: %s", e)


def set_internet_options_proxy(host, port, exceptions=None):
    """Set the system-wide proxy that browsers and apps read.

    The ProxyServer value is `http=host:port`. The `=` is part of the
    value, but reg.exe treats `/d` as the start of a new switch whenever
    it sees one, so an unquoted value silently gets truncated — browsers
    then read a proxy with no port and fail to connect. Quote the value
    and escape any embedded quotes so the whole string survives.
    """
    exceptions = exceptions or (
        "localhost;127.*;10.*;172.*;192.168.*")
    proxy_value = '"http=%s:%d"' % (host, port)
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
        logger.info("internet options proxy set to %s:%d", host, port)
    except Exception as e:
        logger.warning("failed to set internet options proxy: %s", e)


def clear_internet_options_proxy():
    try:
        _run(["reg", "add",
              r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
              "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"])
        logger.info("internet options proxy cleared")
    except Exception as e:
        logger.warning("failed to clear internet options proxy: %s", e)


__all__ = [
    "set_winhttp_proxy", "clear_winhttp_proxy",
    "set_internet_options_proxy", "clear_internet_options_proxy",
]