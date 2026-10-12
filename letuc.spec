# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for letuc.

    pyinstaller letuc.spec
"""

import os

from PyInstaller.building.build_main import Analysis, COLLECT, EXE, PYZ

block_cipher = None

here = os.path.abspath(os.getcwd())
datas = [
    (os.path.join(here, "docs"), "docs"),
    (os.path.join(here, "src", "letuc", "rule"), "letuc/rule"),
]
# The community rule sets are plain-text files that can be many MB each,
# so they are bundled as data rather than embedded as code. The app
# refreshes them at runtime; this is the initial copy shipped with the exe.
_rule_data = os.path.join(here, "src", "letuc", "rule", "data")
if os.path.isdir(_rule_data):
    datas.append((_rule_data, "letuc/rule/data"))
_wintun = os.path.join(here, "assets", "wintun.dll")
if os.path.exists(_wintun):
    datas.append((_wintun, "assets"))

# Application icon, generated from the user's avatar by make_icon.py.
for _icon in ("letuc.png", "letuc.ico"):
    _p = os.path.join(here, "assets", _icon)
    if os.path.exists(_p):
        datas.append((_p, "assets"))

# Qt platform plugins (qwindows/qminimal/qoffscreen) are not auto-included
# by the PyQt6 hook in this build, and without them a GUI exe refuses to
# start with "no Qt platform plugin could be initialized".
import PyQt6
_qt_plugins = os.path.join(os.path.dirname(PyQt6.__file__), "Qt6", "plugins")
for _sub in ("platforms", "styles", "iconengines", "imageformats"):
    _p = os.path.join(_qt_plugins, _sub)
    if os.path.isdir(_p):
        datas.append((_p, os.path.join("PyQt6", "Qt6", "plugins", _sub)))

a = Analysis(
    [os.path.join(here, "main.py")],
    pathex=[here, os.path.join(here, "src")],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "PyQt6", "PyQt6.QtCore", "PyQt6.QtGui", "PyQt6.QtWidgets",
        "cryptography", "cryptography.hazmat.backends.openssl",
        "cryptography.hazmat.primitives.ciphers.aead",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # qasync imports every Qt binding it supports so it can pick one at
    # runtime; freezing must not follow those edges or PyInstaller aborts
    # on "multiple Qt bindings".
    excludes=["PySide6", "PySide2", "PyQt5"],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="letuc",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(here, "assets", "letuc.ico"),
)