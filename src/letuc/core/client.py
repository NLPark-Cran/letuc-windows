"""mieru client: owns the control connection and multiplexes sessions.

One TCP connection carries every session. Encryption state lives at the
connection level (SendCipher/RecvCipher), not the session level: the
nonce chain belongs to the direction of the stream, and every session
multiplexed on it shares the same chain. Each session only tracks its
own id and sequence number.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import struct
import time

from letuc.core import protocol as mieru

logger = logging.getLogger(__name__)

# advertised per-segment receive window; the server uses this for flow
# control, a generous constant is fine for a minimal client
_WINDOW_SIZE = 65535


class MieruClient:
    def __init__(self, host, port, username, password, mtu=1400):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.mtu = mtu
        self._reader = None
        self._writer = None
        self._send = None  # SendCipher, created at start()
        self._recv = None  # RecvCipher, created at start()
        self._write_lock = asyncio.Lock()
        self._next_session_id = 1
        self._sessions = {}  # session_id -> _SessionState
        self._running = False
        self._drain_task = None

    @property
    def connected(self):
        return self._writer is not None and not self._writer.is_closing()

    async def start(self):
        key = mieru.derive_key(
            self.username, self.password, mieru.round_time(int(time.time())))
        self._reader, self._writer = await asyncio.open_connection(
            self.host, self.port)
        self._send = mieru.SendCipher(key, self.username)
        self._recv = mieru.RecvCipher(key)
        self._running = True
        self._drain_task = asyncio.create_task(self._drain())

    async def stop(self):
        self._running = False
        if self._drain_task:
            self._drain_task.cancel()
            self._drain_task = None
        for state in list(self._sessions.values()):
            await self._close_session(state)
        self._sessions.clear()
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass

    async def open_tunnel(self):
        """Open a session that carries raw IP packets for the TUN device."""
        state = await self._open_session(b"")
        return state.reader, _ProxyWriter(state, self)

    async def connect(self, host, port):
        """Open a proxied TCP connection. Returns (reader, writer).

        Upstream runs a socks5 server inside every session with client
        side authentication enabled, so there is no greeting exchange on
        the session at all: the openSessionRequest piggybacks the full
        RFC 1928 CONNECT request, and the server replies with a single
        socks5 response. We complete that handshake here so callers get
        a clean byte stream.
        """
        state = await self._open_session(
            b"\x05\x01\x00" + _encode_socks5_addr(host, port))

        head = await asyncio.wait_for(state.reader.readexactly(4), 15)
        if head[0] != 0x05 or head[1] != 0x00:
            raise ConnectionError(
                "connect %s:%d refused by remote socks5: rep=%d"
                % (host, port, head[1] if len(head) > 1 else -1))
        atyp = head[3]
        if atyp == 0x01:
            await state.reader.readexactly(4)
        elif atyp == 0x03:
            n = (await state.reader.readexactly(1))[0]
            await state.reader.readexactly(n)
        elif atyp == 0x04:
            await state.reader.readexactly(16)
        await state.reader.readexactly(2)

        return state.reader, _ProxyWriter(state, self)

    async def _open_session(self, payload):
        session_id = self._alloc_session_id()
        state = _SessionState(session_id)
        self._sessions[session_id] = state
        await self._send_segment(
            state, mieru.OPEN_SESSION_REQUEST, payload)
        info = await state.response
        if info.get("status", 0) != 0:
            self._sessions.pop(session_id, None)
            raise ConnectionError(
                f"openSession rejected: status={info.get('status')}")
        return state

    def _alloc_session_id(self):
        sid = self._next_session_id
        self._next_session_id += 1
        return sid

    async def _send_segment(self, state, protocol_type, payload=b""):
        """Encrypt and write one segment for a session.

        Session segments (open/close) take no prefix padding; data
        segments may carry both. Lengths are random in [0, 255] like
        upstream, so packet sizes don't fingerprint content length.
        """
        ts = int(time.time() // 60) & 0xFFFFFFFF
        suffix = _rand_padding()
        if protocol_type in (mieru.OPEN_SESSION_REQUEST,
                             mieru.CLOSE_SESSION_REQUEST):
            prefix = b""
            metadata = mieru.encode_session_metadata(
                protocol_type, ts, state.session_id, state.send_seq,
                0, len(payload), len(suffix))
        else:
            prefix = _rand_padding()
            metadata = mieru.encode_data_metadata(
                protocol_type, ts, state.session_id, state.send_seq,
                0, _WINDOW_SIZE, 0, len(prefix), len(payload), len(suffix))
        segment = self._send.encrypt_segment(metadata, payload, prefix, suffix)
        state.send_seq += 1
        async with self._write_lock:
            self._writer.write(segment)
            await self._writer.drain()

    async def _drain(self):
        while self._running:
            try:
                info = await self._recv.read_segment(self._reader)
            except (asyncio.IncompleteReadError, ConnectionResetError):
                break
            except Exception:
                logger.exception("segment decrypt/parse failed, stream dead")
                break
            logger.debug("rx segment type=%s sid=%s seq=%s plen=%s",
                         info["type"], info["session_id"],
                         info.get("sequence"), len(info.get("payload", b"")))
            self._dispatch(info)
        for state in list(self._sessions.values()):
            state.reader.feed_eof()

    def _dispatch(self, info):
        state = self._sessions.get(info["session_id"])
        if state is None:
            logger.debug("dropped segment for unknown session %s",
                         info["session_id"])
            return
        ptype = info["type"]
        if ptype == mieru.OPEN_SESSION_RESPONSE:
            if not state.response.done():
                state.response.set_result(info)
        elif ptype == mieru.CLOSE_SESSION_RESPONSE:
            self._sessions.pop(info["session_id"], None)
            state.reader.feed_eof()
        elif ptype == mieru.DATA_SERVER_TO_CLIENT:
            payload = info.get("payload", b"")
            if payload:
                state.reader.feed_data(payload)
        elif ptype == mieru.ACK_SERVER_TO_CLIENT:
            pass

    async def _close_session(self, state):
        if not self.connected:
            return
        try:
            await self._send_segment(state, mieru.CLOSE_SESSION_REQUEST)
        except Exception:
            pass


class _SessionState:
    def __init__(self, session_id):
        self.session_id = session_id
        self.send_seq = 0
        self.response = asyncio.get_event_loop().create_future()
        self.reader = _ProxyReader()


class _ProxyReader(asyncio.StreamReader):
    pass


class _ProxyWriter(asyncio.StreamWriter):
    def __init__(self, state, client):
        # StreamWriter.__del__ touches _transport; we bypass the real
        # transport, so give it a closed dummy to keep GC quiet
        self._transport = _ClosedTransport()
        self._state = state
        self._client = client

    def write(self, data):
        if not data:
            return
        for off in range(0, len(data), mieru.MAX_FRAGMENT_SIZE):
            chunk = data[off:off + mieru.MAX_FRAGMENT_SIZE]
            asyncio.get_event_loop().create_task(
                self._client._send_segment(
                    self._state, mieru.DATA_CLIENT_TO_SERVER, chunk))

    async def drain(self):
        await self._client._writer.drain()

    def close(self):
        asyncio.get_event_loop().create_task(
            self._client._close_session(self._state))

    def is_closing(self):
        return False

    async def wait_closed(self):
        pass


class _ClosedTransport:
    """Minimal stand-in so StreamWriter.__del__ stays silent."""

    def is_closing(self):
        return True

    def close(self):
        pass


def _rand_padding():
    """0..255 random bytes, matching upstream's maxPaddingSize of 255."""
    n = random.randint(0, 255)
    return os.urandom(n) if n else b""


def _encode_socks5_addr(host, port):
    """RFC 1928 address field: ATYP + ADDR + PORT, big-endian port."""
    try:
        import ipaddress
        ip = ipaddress.ip_address(host)
    except ValueError:
        host_bytes = host.encode()
        if len(host_bytes) > 255:
            raise ValueError("host too long")
        return b"\x03" + struct.pack(">B", len(host_bytes)) + host_bytes \
            + struct.pack(">H", port)
    if ip.version == 4:
        return b"\x01" + ip.packed + struct.pack(">H", port)
    return b"\x04" + ip.packed + struct.pack(">H", port)


__all__ = ["MieruClient"]
