"""Protocol stack tests."""
import hashlib
import os
import struct

import pytest

from letuc.core import protocol as mieru


def test_derive_key_is_deterministic():
    k1 = mieru.derive_key("alice", "secret", 1000)
    k2 = mieru.derive_key("alice", "secret", 1000)
    assert k1 == k2
    assert len(k1) == 32


def test_derive_key_differs_by_username():
    assert mieru.derive_key("alice", "secret", 1000) != mieru.derive_key("bob", "secret", 1000)


def test_derive_key_differs_by_password():
    assert mieru.derive_key("alice", "secret", 1000) != mieru.derive_key("alice", "wrong", 1000)


def test_derive_key_matches_protocol_definition():
    username = "testuser"
    password = "testpass"
    unix_time = 1700000000
    hashed_password = hashlib.sha256(password.encode() + b"\x00" + username.encode()).digest()
    rounded = round(unix_time / mieru.TIME_SALT_INTERVAL) * mieru.TIME_SALT_INTERVAL
    time_salt = hashlib.sha256(struct.pack(">Q", rounded)).digest()
    expected = hashlib.pbkdf2_hmac("sha256", hashed_password, time_salt, 64, dklen=32)
    assert mieru.derive_key(username, password, unix_time) == expected


def test_time_salt_candidates_count():
    assert len(mieru.time_salt_candidates("alice", "secret")) == 3


def test_session_metadata_roundtrip():
    raw = mieru.encode_session_metadata(
        mieru.OPEN_SESSION_REQUEST, 12345, 42, 7, 0, 100, 8)
    assert len(raw) == 32
    info = mieru.decode_metadata(raw)
    assert info["type"] == mieru.OPEN_SESSION_REQUEST
    assert info["session_id"] == 42
    assert info["sequence"] == 7
    assert info["payload_length"] == 100
    assert info["suffix_length"] == 8


def test_data_metadata_roundtrip():
    raw = mieru.encode_data_metadata(
        mieru.DATA_CLIENT_TO_SERVER, 12345, 42, 7, 3, 100, 1, 2, 50, 4)
    assert len(raw) == 32
    info = mieru.decode_metadata(raw)
    assert info["type"] == mieru.DATA_CLIENT_TO_SERVER
    assert info["session_id"] == 42
    assert info["sequence"] == 7
    assert info["unack_sequence"] == 3
    assert info["window_size"] == 100
    assert info["payload_length"] == 50
    assert info["suffix_length"] == 4


def test_decode_metadata_unknown_type_raises():
    with pytest.raises(ValueError):
        mieru.decode_metadata(b"\xff" + b"\x00" * 31)


def test_aead_roundtrip():
    key = os.urandom(32)
    nonce = os.urandom(24)
    plaintext = b"hello mieru"
    ct = mieru._aead_encrypt(key, nonce, plaintext)
    assert ct != plaintext
    assert mieru._aead_decrypt(key, nonce, ct) == plaintext


def test_aead_tamper_fails():
    key = os.urandom(32)
    nonce = os.urandom(24)
    ct = bytearray(mieru._aead_encrypt(key, nonce, b"hello"))
    ct[0] ^= 0xFF
    with pytest.raises(Exception):
        mieru._aead_decrypt(key, nonce, bytes(ct))


def test_aead_wrong_key_fails():
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    nonce = os.urandom(24)
    ct = mieru._aead_encrypt(key1, nonce, b"hello")
    with pytest.raises(Exception):
        mieru._aead_decrypt(key2, nonce, ct)


def test_session_encrypt_decrypt_roundtrip():
    key = os.urandom(32)
    sess = mieru.Session(session_id=1, key=key)
    payload = b"x" * 100
    segment = sess.encrypt(mieru.OPEN_SESSION_REQUEST, payload, suffix_length=4)
    assert len(segment) > 48
    info = mieru.decrypt(key, segment)
    assert info["type"] == mieru.OPEN_SESSION_REQUEST
    assert info["session_id"] == 1
    assert info["payload"] == payload


def test_session_sequence_increments():
    key = os.urandom(32)
    sess = mieru.Session(session_id=1, key=key)
    s1 = sess.encrypt(mieru.DATA_CLIENT_TO_SERVER, b"a" * 10)
    s2 = sess.encrypt(mieru.DATA_CLIENT_TO_SERVER, b"b" * 10)
    i1 = mieru.decrypt(key, s1)
    i2 = mieru.decrypt(key, s2)
    assert i2["sequence"] == i1["sequence"] + 1


def test_udp_associate_encapsulate():
    data = b"hello udp"
    enc = mieru.encapsulate_udp(data)
    assert enc[0] == 0x00
    assert enc[-1] == 0xFF
    assert struct.unpack(">H", enc[1:3])[0] == len(data)
    assert mieru.decapsulate_udp(enc) == data


def test_udp_associate_empty():
    enc = mieru.encapsulate_udp(b"")
    assert enc == b"\x00\x00\x00\xff"
    assert mieru.decapsulate_udp(enc) == b""


def test_udp_associate_too_large():
    with pytest.raises(ValueError):
        mieru.encapsulate_udp(b"x" * 0x10000)


def test_udp_associate_invalid_marker():
    with pytest.raises(ValueError):
        mieru.decapsulate_udp(b"\x01\x00\x00ab\xff")