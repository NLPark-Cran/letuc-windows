"""mieru client: owns the control connection and multiplexes streams.

One TCP control connection carries every session. Each proxied TCP
connection gets its own session id; data flows in both directions as a
pair of async pipes. Sessions are torn down when the pipes finish.
"""

from __future__ import annotations

import asyncio
import logging
import struct
import time

from letuc.core import protocol as mieru

logger = logging.getLogger(__name__)


class MieruClient:
    def __init__(self, host, port, username, password, mtu=1400):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.mtu = mtu
        self._reader = None
        self._writer = None
        self._next_session_id = 1
        self._sessions = {}  # session_id -> _SessionState
        self._lock = asyncio.Lock()
        self._running = False
        self._drain_task = None

    @property
    def connected(self):
        return self._writer is not None and not self._writer.is_closing()

    async def start(self):
        self._reader, self._writer = await asyncio.open_connection(
            self.host, self.port)
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
        """Open a session that carries raw IP packets for the TUN device.

        Unlike connect() there is no host/port to negotiate — the session
        is a bare pipe and every packet is just a data segment.
        """
        key = self._current_key()
        async with self._lock:
            session_id = self._next_session_id
            self._next_session_id += 1

        sess = mieru.Session(session_id, key, self.username)
        state = _SessionState(sess)
        self._sessions[session_id] = state

        segment = sess.encrypt(mieru.OPEN_SESSION_REQUEST, b"")
        self._writer.write(segment)
        await self._writer.drain()

        info = await state.response
        if info.get("status", 0) != 0:
            raise ConnectionError(
                f"tunnel session rejected: status={info.get('status')}")
        return _ProxyReader(state), _ProxyWriter(state, self, sess)

    async def connect(self, host, port):
        """Open a proxied TCP connection.

        Returns (reader, writer) usable like asyncio streams.
        """
        key = self._current_key()
        async with self._lock:
            session_id = self._next_session_id
            self._next_session_id += 1

        sess = mieru.Session(session_id, key, self.username)
        state = _SessionState(sess)
        self._sessions[session_id] = state

        payload = _encode_target(host, port)
        segment = sess.encrypt(mieru.OPEN_SESSION_REQUEST, payload)
        self._writer.write(segment)
        await self._writer.drain()

        info = await state.response
        if info.get("status", 0) != 0:
            raise ConnectionError(
                f"openSession rejected: status={info.get('status')}")

        reader = _ProxyReader(state)
        writer = _ProxyWriter(state, self, sess)
        return reader, writer

    def _current_key(self):
        rounded = round(int(time.time()) / mieru.TIME_SALT_INTERVAL) * mieru.TIME_SALT_INTERVAL
        return mieru.derive_key(self.username, self.password, rounded)

    async def _drain(self):
        while self._running:
            try:
                head = await self._reader.readexactly(8 + 24 + 48 + 4)
            except (asyncio.IncompleteReadError, ConnectionResetError):
                break
            info = self._decrypt_header(head)
            if info is None:
                continue
            tail_len = info.get("payload_length", 0) + 16 + info.get("suffix_length", 0)
            tail = b""
            if tail_len:
                try:
                    tail = await self._reader.readexactly(tail_len)
                except (asyncio.IncompleteReadError, ConnectionResetError):
                    break
            await self._dispatch(head + tail)

    def _decrypt_header(self, head):
        # head = padding0(8) + nonce(24) + encrypted_meta(48) + padding1(4)
        for sid, state in list(self._sessions.items()):
            try:
                return mieru.decrypt(state.sess.key, head, state.sess.username)
            except Exception:
                continue
        return None

    async def _dispatch(self, data):
        for sid, state in list(self._sessions.items()):
            try:
                info = mieru.decrypt(state.sess.key, data, state.sess.username)
            except Exception:
                continue
            ptype = info["type"]
            if ptype == mieru.OPEN_SESSION_RESPONSE:
                if not state.response.done():
                    state.response.set_result(info)
            elif ptype == mieru.CLOSE_SESSION_RESPONSE:
                self._sessions.pop(sid, None)
            elif ptype == mieru.DATA_SERVER_TO_CLIENT:
                state.reader._deliver(info.get("payload", b""))
            elif ptype == mieru.ACK_SERVER_TO_CLIENT:
                pass
            return
        logger.debug("dropped segment for unknown session")

    async def _send(self, sess, protocol_type, payload=b""):
        segment = sess.encrypt(protocol_type, payload)
        self._writer.write(segment)
        await self._writer.drain()

    async def _close_session(self, state):
        if not self.connected:
            return
        try:
            await self._send(state.sess, mieru.CLOSE_SESSION_REQUEST)
        except Exception:
            pass


class _SessionState:
    def __init__(self, sess):
        self.sess = sess
        self.response = asyncio.get_event_loop().create_future()
        self.reader = _ProxyReader(self)


class _ProxyReader(asyncio.StreamReader):
    def __init__(self, state):
        super().__init__()
        self._state = state

    def _deliver(self, data):
        if data:
            self.feed_data(data)
        else:
            self.feed_eof()


class _ProxyWriter(asyncio.StreamWriter):
    def __init__(self, state, client, sess):
        self._state = state
        self._client = client
        self._sess = sess

    def write(self, data):
        if not data:
            return
        for off in range(0, len(data), mieru.MAX_FRAGMENT_SIZE):
            chunk = data[off:off + mieru.MAX_FRAGMENT_SIZE]
            segment = self._sess.encrypt(mieru.DATA_CLIENT_TO_SERVER, chunk)
            self._client._writer.write(segment)

    async def drain(self):
        await self._client._writer.drain()

    def close(self):
        asyncio.get_event_loop().create_task(self._client._close_session(self._state))

    def is_closing(self):
        return False

    async def wait_closed(self):
        pass


def _encode_target(host, port):
    host_bytes = host.encode()
    if len(host_bytes) > 255:
        raise ValueError("host too long")
    return struct.pack(">B", len(host_bytes)) + host_bytes + struct.pack(">H", port)


__all__ = ["MieruClient"]