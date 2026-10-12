"""Local socks5 proxy (RFC 1928, minimal subset).

Negotiates NOAUTH, handles CONNECT and UDP Associate. Each CONNECT is
dispatched through the rule engine: direct connections are opened straight
up, proxy connections go through the mieru client.
"""

from __future__ import annotations

import asyncio
import logging
import struct

from letuc.core import protocol as mieru
from letuc.rule.engine import RuleEngine

logger = logging.getLogger(__name__)

SOCKS5_VERSION = 0x05
NOAUTH = 0x00
CONNECT = 0x01
UDP_ASSOCIATE = 0x03


class Socks5Server:
    def __init__(self, host="127.0.0.1", port=1080, engine=None, client=None):
        self.host = host
        self.port = port
        self.engine = engine or RuleEngine()
        self.client = client  # MieruClient
        self._server = None

    async def start(self):
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        logger.info("socks5 listening on %s:%d", self.host, self.port)

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader, writer):
        try:
            await self._negotiate(reader, writer)
        except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError):
            pass
        except Exception as e:
            logger.warning("socks5 error: %s", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _negotiate(self, reader, writer):
        if (await reader.readexactly(1))[0] != SOCKS5_VERSION:
            raise ValueError("bad socks version")
        nmethods = (await reader.readexactly(1))[0]
        await reader.readexactly(nmethods)
        writer.write(bytes([SOCKS5_VERSION, NOAUTH]))
        await writer.drain()

        if (await reader.readexactly(1))[0] != SOCKS5_VERSION:
            raise ValueError("bad request version")
        cmd = (await reader.readexactly(1))[0]
        await reader.readexactly(1)  # rsv
        atype = (await reader.readexactly(1))[0]

        if atype == 0x01:
            addr = ".".join(str(b) for b in await reader.readexactly(4))
        elif atype == 0x03:
            ln = (await reader.readexactly(1))[0]
            addr = (await reader.readexactly(ln)).decode()
        elif atype == 0x04:
            addr = ":".join(
                f"{int.from_bytes(await reader.readexactly(2), 'big'):x}"
                for _ in range(8))
        else:
            raise ValueError(f"unsupported atype {atype}")

        port = struct.unpack(">H", await reader.readexactly(2))[0]

        if cmd == UDP_ASSOCIATE:
            await self._handle_udp_associate(reader, writer, addr, port)
        elif cmd == CONNECT:
            await self._handle_connect(reader, writer, addr, port)
        else:
            writer.write(bytes([SOCKS5_VERSION, 0x07, 0, 1, 0, 0, 0, 0, 0, 0]))
            await writer.drain()
            raise ValueError(f"unsupported cmd {cmd}")

    async def _handle_connect(self, reader, writer, addr, port):
        outbound = self.engine.match(addr, None)
        logger.info("CONNECT %s:%d -> %s", addr, port, outbound)

        if outbound == "block":
            writer.write(bytes([SOCKS5_VERSION, 0x05, 0, 1, 0, 0, 0, 0, 0, 0]))
            await writer.drain()
            return

        if outbound == "direct":
            remote_reader, remote_writer = await asyncio.open_connection(addr, port)
        else:
            if self.client is None or not self.client.connected:
                writer.write(bytes([SOCKS5_VERSION, 0x05, 0, 1, 0, 0, 0, 0, 0, 0]))
                await writer.drain()
                return
            remote_reader, remote_writer = await self.client.connect(addr, port)

        writer.write(bytes([SOCKS5_VERSION, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]))
        await writer.drain()

        await asyncio.gather(
            self._pipe(reader, remote_writer),
            self._pipe(remote_reader, writer),
        )

    async def _handle_udp_associate(self, reader, writer, addr, port):
        # UDP Associate over a TCP control channel: we can't actually relay
        # UDP without a UDP transport layer, which is out of scope for v0.1.
        # Reply with an unreachable relay so clients fall back to TCP.
        writer.write(bytes([SOCKS5_VERSION, 0x05, 0, 1, 0, 0, 0, 0, 0, 0]))
        await writer.drain()
        logger.info("UDP associate rejected (no UDP transport in v0.1): %s:%d", addr, port)

    @staticmethod
    async def _pipe(reader, writer):
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
            logger.debug("pipe error: %s", e)
        finally:
            try:
                writer.close()
            except Exception:
                pass


__all__ = ["Socks5Server", "SOCKS5_VERSION", "NOAUTH", "CONNECT", "UDP_ASSOCIATE"]