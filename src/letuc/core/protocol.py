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

def derive_key(username, password, unix_time):
    """PBKDF2-SHA256 key as specified by the mieru protocol."""
    hashed_password = hashlib.sha256(password.encode() + b"\x00" + username.encode()).digest()
    rounded = round(unix_time / TIME_SALT_INTERVAL) * TIME_SALT_INTERVAL
    time_salt = hashlib.sha256(struct.pack(">Q", rounded)).digest()
    return hashlib.pbkdf2_hmac("sha256", hashed_password, time_salt, 64, dklen=32)


def time_salt_candidates(username, password):
    """Three (rounded_time, key) pairs: previous grid, current, next grid."""
    now = int(time.time())
    out = []
    for delta in (-TIME_SALT_INTERVAL, 0, TIME_SALT_INTERVAL):
        rounded = round((now + delta) / TIME_SALT_INTERVAL) * TIME_SALT_INTERVAL
        out.append((rounded, derive_key(username, password, rounded)))
    return out


def make_nonce(key, counter):
    """24-byte nonce. The low 4 bytes carry a user lookup marker."""
    nonce = os.urandom(24)
    nonce = (counter.to_bytes(4, "big") + nonce[4:]).ljust(24, b"\x00")[:24]
    return nonce


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
# segment encrypt/decrypt
# ---------------------------------------------------------------------------

class Session:
    """State for one direction of a TCP session."""

    def __init__(self, session_id, key, username=""):
        self.session_id = session_id
        self.key = key
        self.username = username
        self.send_seq = 0
        self.recv_seq = 0
        self.send_nonce_counter = 0
        self.recv_nonce_counter = 0

    def encrypt(self, protocol_type, payload=b"", suffix_length=0):
        timestamp = int(time.time() // 60) & 0xFFFFFFFF
        if protocol_type in (OPEN_SESSION_REQUEST, CLOSE_SESSION_REQUEST):
            metadata = encode_session_metadata(
                protocol_type, timestamp, self.session_id, self.send_seq,
                0, len(payload), suffix_length)
        else:
            metadata = encode_data_metadata(
                protocol_type, timestamp, self.session_id, self.send_seq,
                0, 0, 0, 0, len(payload), suffix_length)

        nonce = stamp_nonce(self.username, make_nonce(self.key, self.send_nonce_counter))
        self.send_nonce_counter += 1

        encrypted_meta = _aead_encrypt(self.key, nonce, metadata)
        encrypted_payload = _aead_encrypt(self.key, nonce, payload) if payload else b""
        segment = (
            os.urandom(8) + nonce + encrypted_meta
            + os.urandom(4) + encrypted_payload + os.urandom(suffix_length)
        )
        self.send_seq += 1
        return segment


def decrypt(key, data, username=""):
    """Decrypt one segment. Returns {metadata..., "payload": bytes}."""
    if len(data) < 8 + 24 + 48 + 4:
        raise ValueError("segment too short")
    nonce = data[8:32]
    info = decode_metadata(_aead_decrypt(key, nonce, data[32:80]))
    payload_start = 80 + 4
    payload_len = info.get("payload_length", 0)
    if payload_len:
        info["payload"] = _aead_decrypt(
            key, nonce, data[payload_start:payload_start + payload_len + 16])
    else:
        info["payload"] = b""
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
    "Session", "decrypt",
    "encapsulate_udp", "decapsulate_udp",
]