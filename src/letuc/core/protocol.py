"""mieru client protocol: key derivation, framing, encryption.

Reference: https://github.com/enfein/mieru (docs/protocol.md), archived in
docs/mieru-protocol.md. This is an independent implementation; it is not
derived from the mieru source tree.

Implemented: TCP segments, XChaCha20-Poly1305 AEAD, session/data/ack
metadata, socks5 UDP associate encapsulation.

Not implemented (out of scope for v0.1): low-entropy modes, UDP transport
layer (everything rides TCP for now).
"""

from __future__ import annotations

import hashlib
import os
import struct
import time

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ---------------------------------------------------------------------------
# protocol type constants
# ---------------------------------------------------------------------------

OPEN_SESSION_REQUEST = 2
OPEN_SESSION_RESPONSE = 3
CLOSE_SESSION_REQUEST = 4
CLOSE_SESSION_RESPONSE = 5
DATA_CLIENT_TO_SERVER = 6
DATA_SERVER_TO_CLIENT = 7
ACK_CLIENT_TO_SERVER = 8
ACK_SERVER_TO_CLIENT = 9

# largest payload we will ever put in a single fragment
MAX_FRAGMENT_SIZE = 32768
SESSION_PAYLOAD_MAX = 1024

# key derivation is pinned to a 2-minute grid; the server tolerates 4 minutes
# of skew and tries three time salts
TIME_SALT_INTERVAL = 120
MAX_TIME_SKEW = 240

_HCHACHACHA_CONST = b"expand 32-byte k"


# ---------------------------------------------------------------------------
# HChaCha20 / XChaCha20
# ---------------------------------------------------------------------------

def _quarter(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = ((d << 16) | (d >> 16)) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = ((b << 12) | (b >> 20)) & 0xFFFFFFFF
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = ((d << 8) | (d >> 24)) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = ((b << 7) | (b >> 25)) & 0xFFFFFFFF
    return a, b, c, d


def _hchacha20(key, nonce_prefix):
    """Derive a 32-byte sub-key from a 16-byte nonce prefix.

    XChaCha20(key, nonce24) == ChaCha20(sub_key, nonce24[16:24]).
    """
    state = list(struct.unpack("<16I", _HCHACHACHA_CONST + key + nonce_prefix))
    for _ in range(10):
        state[0], state[4], state[8], state[12] = _quarter(state[0], state[4], state[8], state[12])
        state[1], state[5], state[9], state[13] = _quarter(state[1], state[5], state[9], state[13])
        state[2], state[6], state[10], state[14] = _quarter(state[2], state[6], state[10], state[14])
        state[3], state[7], state[11], state[15] = _quarter(state[3], state[7], state[11], state[15])
        state[0], state[5], state[10], state[15] = _quarter(state[0], state[5], state[10], state[15])
        state[1], state[6], state[11], state[12] = _quarter(state[1], state[6], state[11], state[12])
        state[2], state[7], state[8], state[13] = _quarter(state[2], state[7], state[8], state[13])
        state[3], state[4], state[9], state[14] = _quarter(state[3], state[4], state[9], state[14])
    return struct.pack("<8I", state[0], state[1], state[2], state[3],
                       state[12], state[13], state[14], state[15])


def _aead_encrypt(key, nonce, plaintext, aad=b""):
    """XChaCha20-Poly1305. Returns ciphertext + 16-byte tag."""
    sub_key = _hchacha20(key, nonce[:16])
    return ChaCha20Poly1305(sub_key).encrypt(
        b"\x00\x00\x00\x00" + nonce[16:24], plaintext, aad)


def _aead_decrypt(key, nonce, ciphertext, aad=b""):
    """Inverse of _aead_encrypt. Raises InvalidTag on failure."""
    sub_key = _hchacha20(key, nonce[:16])
    return ChaCha20Poly1305(sub_key).decrypt(
        b"\x00\x00\x00\x00" + nonce[16:24], ciphertext, aad)


# ---------------------------------------------------------------------------
# key derivation
# ---------------------------------------------------------------------------

def round_time(unix_time):
    """Round to the 2-minute grid the way Go's time.Round does: half away
    from zero. Python's round() is banker's rounding and disagrees when
    unix_time % 120 == 60, which would pick the wrong key once every 120
    seconds on average."""
    return ((unix_time + TIME_SALT_INTERVAL // 2)
            // TIME_SALT_INTERVAL) * TIME_SALT_INTERVAL


def derive_key(username, password, unix_time):
    """PBKDF2-SHA256 key as specified by the mieru protocol."""
    hashed_password = hashlib.sha256(password.encode() + b"\x00" + username.encode()).digest()
    rounded = round_time(unix_time)
    time_salt = hashlib.sha256(struct.pack(">Q", rounded)).digest()
    return hashlib.pbkdf2_hmac("sha256", hashed_password, time_salt, 64, dklen=32)


def time_salt_candidates(username, password):
    """Three (rounded_time, key) pairs: previous grid, current, next grid."""
    now = int(time.time())
    out = []
    for delta in (-TIME_SALT_INTERVAL, 0, TIME_SALT_INTERVAL):
        rounded = round_time(now + delta)
        out.append((rounded, derive_key(username, password, rounded)))
    return out


def make_nonce():
    """A fresh 24-byte nonce. Pure random, like upstream."""
    return os.urandom(24)


def increment_nonce(nonce):
    """The nonce as a 24-byte big-endian integer, plus one.

    TCP carries the nonce only in the first segment of each direction;
    every AEAD operation after that (metadata and payload count
    separately) advances this counter. Carry starts at the last byte and
    walks backwards, including over the 4-byte user marker.
    """
    n = bytearray(nonce)
    for i in range(len(n) - 1, -1, -1):
        n[i] = (n[i] + 1) & 0xFF
        if n[i] != 0:
            break
    return bytes(n)


def stamp_nonce(username, nonce):
    """Replace the last 4 bytes with a username lookup marker."""
    marker = hashlib.sha256(username.encode() + nonce[:16]).digest()[:4]
    return nonce[:20] + marker


# ---------------------------------------------------------------------------
# metadata framing
# ---------------------------------------------------------------------------

def encode_session_metadata(protocol_type, timestamp, session_id, sequence,
                             status, payload_length, suffix_length):
    return struct.pack(
        ">BB I I I B H B 14x",
        protocol_type & 0xFF, 0,
        timestamp & 0xFFFFFFFF, session_id & 0xFFFFFFFF, sequence & 0xFFFFFFFF,
        status & 0xFF, payload_length & 0xFFFF, suffix_length & 0xFF,
    )


def encode_data_metadata(protocol_type, timestamp, session_id, sequence,
                         unack_sequence, window_size, fragment_number,
                         prefix_length, payload_length, suffix_length):
    return struct.pack(
        ">BB I I I I H B B H B 7x",
        protocol_type & 0xFF, 0,
        timestamp & 0xFFFFFFFF, session_id & 0xFFFFFFFF, sequence & 0xFFFFFFFF,
        unack_sequence & 0xFFFFFFFF, window_size & 0xFFFF,
        fragment_number & 0xFF, prefix_length & 0xFF,
        payload_length & 0xFFFF, suffix_length & 0xFF,
    )


def decode_metadata(raw):
    if len(raw) != 32:
        raise ValueError(f"metadata must be 32 bytes, got {len(raw)}")
    protocol_type = raw[0]
    timestamp = struct.unpack(">I", raw[2:6])[0]
    session_id = struct.unpack(">I", raw[6:10])[0]
    sequence = struct.unpack(">I", raw[10:14])[0]

    if protocol_type in (OPEN_SESSION_REQUEST, OPEN_SESSION_RESPONSE,
                         CLOSE_SESSION_REQUEST, CLOSE_SESSION_RESPONSE):
        return {
            "type": protocol_type,
            "timestamp": timestamp,
            "session_id": session_id,
            "sequence": sequence,
            "status": raw[14],
            "payload_length": struct.unpack(">H", raw[15:17])[0],
            "suffix_length": raw[17],
        }

    if protocol_type in (DATA_CLIENT_TO_SERVER, DATA_SERVER_TO_CLIENT,
                         ACK_CLIENT_TO_SERVER, ACK_SERVER_TO_CLIENT):
        return {
            "type": protocol_type,
            "timestamp": timestamp,
            "session_id": session_id,
            "sequence": sequence,
            "unack_sequence": struct.unpack(">I", raw[14:18])[0],
            "window_size": struct.unpack(">H", raw[18:20])[0],
            "fragment_number": raw[20],
            "prefix_length": raw[21],
            "payload_length": struct.unpack(">H", raw[22:24])[0],
            "suffix_length": raw[24],
        }

    raise ValueError(f"unknown protocol type: {protocol_type}")


# ---------------------------------------------------------------------------
# segment encrypt/decrypt — TCP wire format
#
# Layout (verified against enfein/mieru pkg/protocol/underlay_stream.go):
#
#   first segment per direction:
#       nonce(24) | encMetadata(32) | metaTag(16)
#       | [encPayload | payloadTag(16)] | padding2(suffixLen)
#   later session segments:
#       encMetadata(32) | metaTag(16) | [encPayload | tag] | padding2
#   data/ack segments:
#       encMetadata(32) | metaTag(16) | padding1(prefixLen)
#       | [encPayload | tag] | padding2(suffixLen)
#
# There is no padding before the nonce. The nonce appears on the wire once
# per direction; every AEAD operation afterwards (metadata and payload are
# separate operations) advances the implicit nonce by one.
# ---------------------------------------------------------------------------

class SendCipher:
    """Encrypts one direction of a TCP underlay connection.

    Connection-level, shared by every session multiplexed on the TCP
    stream: the nonce chain belongs to the direction, not the session.
    """

    def __init__(self, key, username=""):
        self.key = key
        self.username = username
        self._nonce = None

    def encrypt_segment(self, metadata, payload=b"", prefix=b"", suffix=b""):
        if self._nonce is None:
            self._nonce = stamp_nonce(self.username, make_nonce())
            wire_nonce = self._nonce
        else:
            self._nonce = increment_nonce(self._nonce)
            wire_nonce = b""
        out = wire_nonce + _aead_encrypt(self.key, self._nonce, metadata)
        if prefix:
            out += prefix
        if payload:
            self._nonce = increment_nonce(self._nonce)
            out += _aead_encrypt(self.key, self._nonce, payload)
        return out + suffix


class RecvCipher:
    """Decrypts one direction of a TCP underlay connection.

    Mirror of SendCipher: reads the nonce off the wire once, then tracks
    the same increment-per-AEAD-operation chain.
    """

    def __init__(self, key):
        self.key = key
        self._nonce = None

    async def read_segment(self, reader):
        """Read and decrypt one segment from an asyncio StreamReader.

        Returns the decoded metadata dict with a "payload" key. Raises
        IncompleteReadError / ConnectionResetError at EOF.
        """
        if self._nonce is None:
            head = await reader.readexactly(24 + 48)
            self._nonce = head[:24]
            meta_ct = head[24:]
        else:
            self._nonce = increment_nonce(self._nonce)
            meta_ct = await reader.readexactly(48)
        info = decode_metadata(_aead_decrypt(self.key, self._nonce, meta_ct))
        if info["type"] in (DATA_CLIENT_TO_SERVER, DATA_SERVER_TO_CLIENT,
                            ACK_CLIENT_TO_SERVER, ACK_SERVER_TO_CLIENT):
            prefix_len = info.get("prefix_length", 0)
            if prefix_len:
                await reader.readexactly(prefix_len)
        payload_len = info.get("payload_length", 0)
        if payload_len:
            self._nonce = increment_nonce(self._nonce)
            ct = await reader.readexactly(payload_len + 16)
            info["payload"] = _aead_decrypt(self.key, self._nonce, ct)
        else:
            info["payload"] = b""
        suffix_len = info.get("suffix_length", 0)
        if suffix_len:
            await reader.readexactly(suffix_len)
        return info


# ---------------------------------------------------------------------------
# socks5 UDP associate encapsulation
# ---------------------------------------------------------------------------

def encapsulate_udp(data):
    if len(data) > 0xFFFF:
        raise ValueError("UDP associate data too large")
    return b"\x00" + struct.pack(">H", len(data)) + data + b"\xff"


def decapsulate_udp(data):
    if len(data) < 4 or data[0] != 0x00 or data[-1] != 0xFF:
        raise ValueError("invalid UDP associate encapsulation")
    return data[3:3 + struct.unpack(">H", data[1:3])[0]]


__all__ = [
    "OPEN_SESSION_REQUEST", "OPEN_SESSION_RESPONSE",
    "CLOSE_SESSION_REQUEST", "CLOSE_SESSION_RESPONSE",
    "DATA_CLIENT_TO_SERVER", "DATA_SERVER_TO_CLIENT",
    "ACK_CLIENT_TO_SERVER", "ACK_SERVER_TO_CLIENT",
    "MAX_FRAGMENT_SIZE", "SESSION_PAYLOAD_MAX",
    "TIME_SALT_INTERVAL", "MAX_TIME_SKEW",
    "derive_key", "time_salt_candidates", "make_nonce", "stamp_nonce",
    "encode_session_metadata", "encode_data_metadata", "decode_metadata",
    "increment_nonce", "SendCipher", "RecvCipher",
    "encapsulate_udp", "decapsulate_udp",
]