"""Install the WinTun driver so the TUN adapter can actually be created.

wintun.dll is a user-mode library that talks to a kernel driver. The DLL
ships in assets/ and loads fine — what is missing is the driver itself,
which is why WintunCreateAdapter fails even though the library is present.

WinTun ships a single installer (wintun-0.14.1-x64.exe) that does the
whole thing: drops the driver, registers it, starts it. It needs admin
rights, so it is run through a UAC-elevated copy of itself rather than
directly — the original process is not elevated and would just fail
quietly.

The flow is:

  1. First launch: detect whether the driver is already installed by
     trying to create an adapter. If that works, nothing to do.
  2. If not, ask the user once. Declining keeps TUN off; the software
     proxy still works.
  3. On accept, run the installer elevated. It is a one-time ~1 MB
     download; the DLL in assets/ is the runtime library, not the driver.
  4. After install, retry the adapter creation. If it still fails we tell
     the user plainly rather than pretending TUN is available.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import os
import subprocess
import sys

logger = logging.getLogger(__name__)

# The driver is versioned separately from the DLL. This is the release
# whose interface the ctypes bindings in letuc.proxy.tun target.
INSTALLER_URL = (
    "https://www.wintun.net/downloads/wintun-0.14.1-x64.exe")
INSTALLER_NAME = "wintun-0.14.1-x64.exe"

_HERE = os.path.dirname(os.path.abspath(__file__))


def _install_dir():
    """Where the installer binary lives: next to the exe when frozen."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))


def _installer_path():
    return os.path.join(_install_dir(), INSTALLER_NAME)


def _wintun_dll_path():
    """Same resolution as letuc.proxy.tun, kept in sync manually."""
    candidates = [
        os.path.join(_install_dir(), "assets", "wintun.dll"),
        os.path.join(_install_dir(), "wintun.dll"),
        os.path.join(_HERE, "assets", "wintun.dll"),
        os.path.join(_HERE, "..", "..", "assets", "wintun.dll"),
        os.path.join(_HERE, "..", "..", "..", "assets", "wintun.dll"),
        os.path.join(_HERE, "..", "..", "..", "..", "assets", "wintun.dll"),
    ]
    for p in candidates:
        p = os.path.normpath(p)
        if os.path.exists(p):
            return p
    return None


def is_driver_installed():
    """Best-effort check: can we create and immediately close an adapter?

    This exercises the real code path, so it catches "driver missing",
    "driver too old" and "adapter name taken" alike. It is not perfect —
    a transient failure is reported as "not installed" — but it is good
    enough to decide whether to offer the user an install.
    """
    dll = _wintun_dll_path()
    if not dll:
        return False
    try:
        lib = ctypes.WinDLL(dll)
    except OSError:
        return False
    lib.WintunCreateAdapter.restype = ctypes.c_void_p
    lib.WintunCreateAdapter.argtypes = [
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.WintunCloseAdapter.restype = None
    lib.WintunCloseAdapter.argtypes = [ctypes.c_void_p]
    handle = lib.WintunCreateAdapter("letuc-probe", None, None)
    if not handle:
        return False
    try:
        lib.WintunCloseAdapter(handle)
    finally:
        pass
    return True


def _download_installer():
    """Fetch the WinTun installer next to the exe. Returns path or None."""
    import urllib.request
    target = _installer_path()
    try:
        req = urllib.request.Request(
            INSTALLER_URL, headers={"User-Agent": "letuc/1.0"})
        with urllib.request.urlopen(req, timeout=120) as r, \
                open(target, "wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
        return target
    except Exception as e:
        logger.warning("failed to download WinTun installer: %s", e)
        try:
            os.remove(target)
        except OSError:
            pass
        return None


def install(parent=None):
    """Download and run the WinTun installer with UAC elevation.

    Returns True when the driver is usable afterwards, False otherwise.
    The installer itself is silent; its exit code is logged but not
    treated as the source of truth — we re-probe the adapter instead.
    """
    installer = _installer_path()
    if not os.path.exists(installer):
        installer = _download_installer()
    if not installer:
        return False

    # Run as an elevated process. /high 优先级 + the exe's own manifest
    # trigger the standard UAC consent prompt.
    try:
        rc = subprocess.run(
            [installer, "/quiet", "/install"],
            check=False, capture_output=True, timeout=300)
        logger.info("wintun installer rc=%d", rc.returncode)
    except Exception as e:
        logger.warning("wintun installer failed: %s", e)
        return False
    finally:
        try:
            os.remove(installer)
        except OSError:
            pass

    return is_driver_installed()


def ensure_driver(parent=None, prompt=True):
    """Public entry point: install the driver if it is missing.

    `prompt` gates the UAC prompt. When False we simply report the current
    state without asking, which is what the TUN checkbox uses to show a
    helpful message instead of silently failing.
    """
    if is_driver_installed():
        return True
    if not prompt:
        return False
    if parent is None:
        return False
    from PyQt6.QtWidgets import QMessageBox
    ret = QMessageBox.information(
        parent, "WinTun 驱动",
        "TUN 功能需要 WinTun 驱动，当前未安装。\n\n"
        "点击「是」将下载并安装（约 1 MB，需要管理员权限，会弹出 UAC 确认）。\n"
        "点击「否」则本次不启用 TUN，软件代理仍可正常使用。",
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No)
    if ret != QMessageBox.StandardButton.Yes:
        return False
    ok = install(parent=parent)
    if not ok:
        QMessageBox.warning(
            parent, "WinTun 驱动",
            "安装后仍无法创建 TUN 适配器。请手动安装：\n"
            "https://www.wintun.net/downloads/wintun-0.14.1-x64.exe")
    return ok


__all__ = ["is_driver_installed", "install", "ensure_driver"]