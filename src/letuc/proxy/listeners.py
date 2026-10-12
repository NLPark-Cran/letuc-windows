"""Local proxy listeners for letuc.

The default port layout is a single mixed port plus a few auxiliary ports:

    20808  mixed      HTTP CONNECT + SOCKS5 on one port (auto-detected)
    3080   socks     dedicated SOCKS5
    20811  pac       Proxy Auto-Config script (mixed + 3)
    20812  xray_api  minimal Xray-style control API (mixed + 4)
    20813  mihomo_api minimal mihomo-style control API (mixed + 5)

The mixed port inspects the first bytes of each connection: a SOCKS5
greeting starts with 0x05, an HTTP request starts with a method token.
This keeps one port usable by both browsers and tools without per-tool
configuration.
"""

from __future__ import annotations

import asyncio
import json
import logging

from letuc.proxy.http import HttpProxyServer
from letuc.proxy.socks5 import Socks5Server

logger = logging.getLogger(__name__)

SOCKS5_VERSION = 0x05


class MixedProxyServer:
    """HTTP + SOCKS5 on a single port, chosen by peeking the first byte."""

    def __init__(self, host="127.0.0.1", port=20808, engine=None, client=None):
        self.host = host
        self.port = port
        self.engine = engine
        self.client = client
        self._server = None
        self.http = HttpProxyServer(host, port, engine, client)
        self.socks = Socks5Server(host, port, engine, client)

    async def start(self):
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        logger.info("mixed proxy listening on %s:%d", self.host, self.port)

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader, writer):
        try:
            first = await reader.readexactly(1)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            return
        if first[0] == SOCKS5_VERSION:
            # SOCKS5: push the byte back and let Socks5Server drive the rest
            await self.socks._negotiate(
                _PrependedReader(reader, first), writer)
        else:
            await self.http._serve(
                _PrependedReader(reader, first), writer)


class _PrependedReader:
    """An asyncio reader that yields one already-read byte first."""

    def __init__(self, reader, first):
        self._reader = reader
        self._buf = bytes([first])

    async def readexactly(self, n):
        while len(self._buf) < n:
            chunk = await self._reader.readexactly(n - len(self._buf))
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    async def read(self, n=-1):
        if self._buf:
            out, self._buf = self._buf, b""
            return out
        return await self._reader.read(n)

    async def readuntil(self, sep=b"\r\n"):
        while sep not in self._buf:
            chunk = await self._reader.readuntil(sep)
            self._buf += chunk
        idx = self._buf.index(sep) + len(sep)
        out, self._buf = self._buf[:idx], self._buf[idx:]
        return out


class PacServer:
    """Serves a Proxy Auto-Config script over HTTP."""

    TEMPLATE = """function FindProxyForURL(url, host) {{
    var socks = "SOCKS5 127.0.0.1:{socks}";
    var http = "PROXY 127.0.0.1:{mixed}";
    if (shExpMatch(host, "*.cn") || shExpMatch(host, "*.local") ||
        shExpMatch(host, "localhost") || /^10\\./.test(host) ||
        /^192\\.168\\./.test(host) || /^172\\.(1[6-9]|2\\d|3[01])\\./.test(host))
        return "DIRECT";
    return socks + "; " + http;
}}"""

    def __init__(self, host="127.0.0.1", port=20811, mixed=20808, socks=3080):
        self.host = host
        self.port = port
        self.mixed = mixed
        self.socks = socks
        self._server = None

    def script(self):
        return self.TEMPLATE.format(mixed=self.mixed, socks=self.socks)

    async def start(self):
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        logger.info("PAC server listening on %s:%d", self.host, self.port)

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            body = self.script().encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n"
                b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body))
            writer.write(body)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


class ControlApiServer:
    """Tiny REST-ish control API for Xray/mihomo compatibility.

    Both front-ends expose a handful of common endpoints. Responses are
    deliberately minimal — this client is not a full proxy router, it just
    needs to answer the probes that tools like mihomo/xray send on startup.
    """

    def __init__(self, host="127.0.0.1", port=20812, engine=None, client=None,
                 kind="xray"):
        self.host = host
        self.port = port
        self.engine = engine
        self.client = client
        self.kind = kind
        self._server = None

    async def start(self):
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        logger.info("%s API listening on %s:%d", self.kind, self.host, self.port)

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            line = head.split(b"\r\n", 1)[0].decode("latin-1")
            method, path, _ = line.split()
            body = await self._route(method, path)
            data = json.dumps(body).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                         b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(data))
            writer.write(data)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _route(self, method, path):
        if path in ("/version", "/api/version"):
            return {"version": "0.1.0", "kind": self.kind}
        if path in ("/proxies", "/api/proxies"):
            return {
                "proxies": [
                    {"name": "mixed", "type": "mixed", "port": 20808},
                    {"name": "socks", "type": "socks5", "port": 3080},
                ]}
        if path in ("/traffic", "/api/traffic"):
            return {"uplink": 0, "downlink": 0}
        return {"ok": True, "kind": self.kind}


__all__ = [
    "MixedProxyServer", "PacServer", "ControlApiServer",
    "SOCKS5_VERSION",
]