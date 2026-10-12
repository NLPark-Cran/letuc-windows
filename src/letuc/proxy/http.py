"""Local HTTP/HTTPS proxy.

A small subset of RFC 7230: CONNECT for HTTPS, plain GET/HEAD/POST/etc for
HTTP. CONNECT tunnels bytes through the mieru client; plain requests are
opened directly or proxied according to the rule engine.
"""

from __future__ import annotations

import asyncio
import logging

from letuc.rule.engine import RuleEngine

logger = logging.getLogger(__name__)


class HttpProxyServer:
    def __init__(self, host="127.0.0.1", port=8080, engine=None, client=None):
        self.host = host
        self.port = port
        self.engine = engine or RuleEngine()
        self.client = client
        self._server = None

    async def start(self):
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        logger.info("http proxy listening on %s:%d", self.host, self.port)

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader, writer):
        try:
            await self._serve(reader, writer)
        except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError):
            pass
        except Exception as e:
            logger.warning("http proxy error: %s", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _serve(self, reader, writer):
        request_line = await self._readline(reader)
        if not request_line:
            return
        parts = request_line.decode("latin-1").strip().split()
        if len(parts) != 3:
            return
        method, url, version = parts

        # read headers
        headers = {}
        while True:
            line = await self._readline(reader)
            if not line or line in (b"\r\n", b"\n"):
                break
            if b":" in line:
                k, v = line.decode("latin-1").split(":", 1)
                headers[k.strip().lower()] = v.strip()

        if method.upper() == "CONNECT":
            await self._tunnel(reader, writer, url)
            return

        if url.startswith("http://"):
            rest = url[len("http://"):]
        else:
            rest = url

        # Split authority from path BEFORE looking for the port. Parsing
        # "www.baidu.com/" by partitioning on ":" leaves the path glued to
        # the host, which then fails to resolve and the connection dies
        # with an empty reply.
        authority, _, path = rest.partition("/")
        path = "/" + path if path else "/"
        host, _, port = authority.partition(":")
        port = int(port) if port else 80

        outbound = self.engine.match(host, None)
        if outbound == "direct":
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
        elif outbound == "proxy" and self.client and self.client.connected:
            remote_reader, remote_writer = await self.client.connect(host, port)
        else:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        body = await self._read_body(reader, headers)
        if body:
            remote_writer.write(body)
            await remote_writer.drain()

        # Origin servers expect origin-form request targets, not the
        # absolute URI the client sent to us.
        request = f"{method} {path} {version}\r\n".encode()
        for k, v in headers.items():
            request += f"{k}: {v}\r\n".encode()
        request += b"\r\n"
        remote_writer.write(request)
        await remote_writer.drain()

        await asyncio.gather(
            self._copy(remote_reader, writer),
            self._copy(reader, remote_writer),
        )

    async def _tunnel(self, reader, writer, url):
        host, _, port = url.partition(":")
        port = int(port) if port else 443

        outbound = self.engine.match(host, None)
        if outbound == "direct":
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
        elif outbound == "proxy" and self.client and self.client.connected:
            remote_reader, remote_writer = await self.client.connect(host, port)
        else:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        await asyncio.gather(
            self._copy(reader, remote_writer),
            self._copy(remote_reader, writer),
        )

    @staticmethod
    async def _readline(reader):
        try:
            return await reader.readuntil(b"\r\n")
        except asyncio.IncompleteReadError:
            return b""

    @staticmethod
    async def _read_body(reader, headers):
        cl = headers.get("content-length")
        if cl is not None:
            try:
                return await reader.readexactly(int(cl))
            except (asyncio.IncompleteReadError, ValueError):
                return b""
        return b""

    @staticmethod
    async def _copy(reader, writer):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError):
            pass
        except Exception as e:
            logger.debug("http copy error: %s", e)
        finally:
            try:
                writer.close()
            except Exception:
                pass


__all__ = ["HttpProxyServer"]