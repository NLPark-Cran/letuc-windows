"""TUN device on Windows, backed by wintun.dll.

wintun is a single DLL exposing a small C interface (WintunCreateAdapter,
WintunStartSession, WintunReceivePacket/SendPacket). We load it through
ctypes, so no compilation is needed on the user side as long as
assets/wintun.dll is present next to the executable.

The wrapper below targets the 0.14.x interface (the header in
wintun-0.14.1.zip):

    WintunCreateAdapter(Name, TunnelType, GUID*)
    WintunOpenAdapter(Name)              <- only the name, no GUID
    WintunCloseAdapter(Adapter)
    WintunStartSession(Adapter, Capacity)
    WintunEndSession(Session)
    WintunReceivePacket(Session, DWORD*)  <- returns BYTE*, not BOOL
    WintunReleaseReceivePacket(Session, Packet)
    WintunAllocateSendPacket(Session, DWORD)
    WintunSendPacket(Session, Packet)

This module is intentionally thin: it wraps the handful of calls the rest
of the client needs (create, open, read, write, close). Higher-level
routing and packet dispatch live in letuc.system.tun_stack.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import os
import sys
import threading

from letuc.system.tun_stack import TunRouter

logger = logging.getLogger(__name__)

WINTUN_NAME = "letuc-tun"
WINTUN_GUID = "0x00000000-0000-0000-0000-000000000000"

# wintun.dll lives next to the executable (frozen), next to the source
# tree (dev), or in the repo's assets/ folder. Resolve all three so the
# same code works whether it is run from source, from a built exe, or
# from anywhere the user has dropped the project.
_HERE = os.path.dirname(os.path.abspath(__file__))
_WINTUN_PATHS = [
    os.path.join(_HERE, "assets", "wintun.dll"),
    os.path.join(_HERE, "wintun.dll"),
    os.path.join(_HERE, "..", "..", "assets", "wintun.dll"),
    os.path.join(_HERE, "..", "..", "..", "assets", "wintun.dll"),
    os.path.join(_HERE, "..", "..", "..", "..", "assets", "wintun.dll"),
    os.path.join(os.path.dirname(_HERE), "assets", "wintun.dll"),
    os.path.join(os.path.dirname(os.path.dirname(_HERE)), "assets", "wintun.dll"),
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(_HERE))), "assets", "wintun.dll"),
]
# When frozen, the exe's own directory is the natural place for it.
try:
    if getattr(sys, "frozen", False):
        _WINTUN_PATHS.insert(0, os.path.join(os.path.dirname(sys.executable), "wintun.dll"))
except Exception:
    pass


def _load_library():
    for path in _WINTUN_PATHS:
        path = os.path.normpath(path)
        if os.path.exists(path):
            try:
                lib = ctypes.WinDLL(path)
                return lib
            except OSError as e:
                logger.warning("failed to load %s: %s", path, e)
    return None


_lib = None
try:
    _lib = _load_library()
except Exception as e:
    logger.warning("wintun not available: %s", e)


if _lib is not None:
    # Adapter lifecycle
    _lib.WintunCreateAdapter.restype = ctypes.c_void_p
    _lib.WintunCreateAdapter.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p,
                                         ctypes.POINTER(ctypes.c_void_p)]
    _lib.WintunOpenAdapter.restype = ctypes.c_void_p
    _lib.WintunOpenAdapter.argtypes = [ctypes.c_wchar_p]
    _lib.WintunCloseAdapter.restype = None
    _lib.WintunCloseAdapter.argtypes = [ctypes.c_void_p]

    # Session lifecycle (0.14.x: StartSession / EndSession)
    _lib.WintunStartSession.restype = ctypes.c_void_p
    _lib.WintunStartSession.argtypes = [ctypes.c_void_p, wt.DWORD]
    _lib.WintunEndSession.restype = None
    _lib.WintunEndSession.argtypes = [ctypes.c_void_p]

    # Packet I/O
    _lib.WintunReceivePacket.restype = ctypes.c_void_p
    _lib.WintunReceivePacket.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
    _lib.WintunReleaseReceivePacket.restype = None
    _lib.WintunReleaseReceivePacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    _lib.WintunAllocateSendPacket.restype = ctypes.c_void_p
    _lib.WintunAllocateSendPacket.argtypes = [
        ctypes.c_void_p, wt.DWORD]
    _lib.WintunSendPacket.restype = None
    _lib.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]


class WintunAdapter:
    """A wintun virtual adapter.

    The read model is the 0.14.x one: WintunReceivePacket returns a BYTE*
    (NULL when nothing is queued) and the caller must release it with
    WintunReleaseReceivePacket.
    """

    def __init__(self, name=WINTUN_NAME, guid=None):
        self.name = name
        self.guid = guid
        self._handle = None
        self._session = None
        self._lock = threading.Lock()

    def create(self):
        if _lib is None:
            raise RuntimeError("wintun.dll not available")
        # RequestedGUID may be NULL; letting the system pick means we do
        # not have to hand out a GUID structure for the adapter.
        self._handle = _lib.WintunCreateAdapter(self.name, self.guid, None)
        if not self._handle:
            # An adapter with this name may already exist from a previous
            # run; fall back to opening it instead of failing the whole
            # startup. WintunOpenAdapter takes only the name.
            self._handle = _lib.WintunOpenAdapter(self.name)
        if not self._handle:
            raise OSError("WintunCreateAdapter / WintunOpenAdapter failed")

    def open(self):
        if _lib is None:
            raise RuntimeError("wintun.dll not available")
        if not self._handle:
            self._handle = _lib.WintunOpenAdapter(self.name)
        if not self._handle:
            raise OSError("WintunOpenAdapter failed")
        self._session = _lib.WintunStartSession(self._handle, 1 << 20)
        if not self._session:
            raise OSError("WintunStartSession failed")

    def read(self, timeout=1000):
        """Return a packet's bytes, or None when no packet is available.

        WintunReceivePacket is non-blocking: it returns NULL when the
        session has no packet queued. The caller keeps polling.
        """
        if not self._session:
            raise RuntimeError("session not open")
        with self._lock:
            size = wt.DWORD(0)
            pkt = _lib.WintunReceivePacket(self._session, ctypes.byref(size))
            if not pkt:
                return None
            try:
                data = ctypes.string_at(pkt, size.value)
            finally:
                _lib.WintunReleaseReceivePacket(self._session, pkt)
            return data

    def write(self, data):
        if not self._session:
            raise RuntimeError("session not open")
        with self._lock:
            buf = _lib.WintunAllocateSendPacket(self._session, wt.DWORD(len(data)))
            if not buf:
                raise OSError("WintunAllocateSendPacket failed")
            try:
                ctypes.memmove(buf, data, len(data))
            finally:
                _lib.WintunSendPacket(self._session, buf)

    def close(self):
        if self._session is not None:
            try:
                _lib.WintunEndSession(self._session)
            finally:
                self._session = None
        if self._handle is not None:
            try:
                _lib.WintunCloseAdapter(self._handle)
            finally:
                self._handle = None


class TunStack:
    """High-level TUN driver: routes packets to/from the mieru client.

    The stack is deliberately simple: every IP packet that arrives on the
    TUN device is checked against the rule engine, forwarded to the mieru
    client as a data segment only when the rule says `proxy`, and packets
    coming back are written back out. Routing decisions live in the rule
    engine and are applied here before anything touches the wire.

    The TUN read callback runs on a worker thread, but the mieru client is
    asyncio-only, so inbound packets are scheduled onto the client's event
    loop with run_coroutine_threadsafe rather than awaited directly.
    """

    def __init__(self, adapter=None, client=None, router=None, server_ip=None,
                 loop=None):
        self.adapter = adapter or WintunAdapter()
        self.client = client
        self.router = router or TunRouter(server_ip=server_ip)
        self.loop = loop
        self._tun_session = None  # (reader, writer) on the client loop
        self._running = False
        self._read_thread = None

    def start(self):
        self._running = True
        self.adapter.create()
        self.adapter.open()
        if self.client is not None and self.loop is not None:
            import asyncio
            asyncio.run_coroutine_threadsafe(
                self._open_tunnel(), self.loop)
        self._read_thread = threading.Thread(
            target=self._read_loop, daemon=True)
        self._read_thread.start()

    def _read_loop(self):
        while self._running:
            try:
                data = self.adapter.read()
            except Exception as e:
                logger.debug("TUN read error: %s", e)
                continue
            if data is None:
                continue
            try:
                self.feed_inbound(data)
            except Exception as e:
                logger.debug("TUN feed error: %s", e)

    def stop(self):
        self._tun_session = None
        self.adapter.close()

    async def _open_tunnel(self):
        self._tun_session = await self.client.open_tunnel()

    def feed_inbound(self, data):
        """Packet arriving from the TUN device -> send to the server."""
        if self.client is None or not self.client.connected:
            return
        if self.loop is None:
            return
        if self._tun_session is None:
            import asyncio
            asyncio.run_coroutine_threadsafe(
                self._open_tunnel(), self.loop)
            return
        if not self.router.should_forward(data):
            logger.debug("TUN packet dropped by rule: %d bytes", len(data))
            return
        _, writer = self._tun_session
        writer.write(data)
        import asyncio
        asyncio.run_coroutine_threadsafe(writer.drain(), self.loop)

    def feed_outbound(self, data):
        """Packet arriving from the server -> write back to TUN."""
        self.adapter.write(data)


__all__ = ["WintunAdapter", "TunStack", "WINTUN_NAME"]