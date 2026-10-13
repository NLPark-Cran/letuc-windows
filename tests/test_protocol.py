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


def _recv_sync(recv_cipher, data):
    """Feed bytes into a StreamReader and read one segment synchronously."""
    import asyncio

    async def go():
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        return await recv_cipher.read_segment(reader)

    return asyncio.run(go())


def test_cipher_roundtrip_first_segment():
    key = os.urandom(32)
    send = mieru.SendCipher(key, username="alice")
    recv = mieru.RecvCipher(key)
    payload = b"x" * 100
    metadata = mieru.encode_session_metadata(
        mieru.OPEN_SESSION_REQUEST, 12345, 1, 0, 0, len(payload), 4)
    segment = send.encrypt_segment(metadata, payload, suffix=b"s" * 4)
    # first segment carries the full 24-byte nonce up front
    assert segment[:24] != b""
    info = _recv_sync(recv, segment)
    assert info["type"] == mieru.OPEN_SESSION_REQUEST
    assert info["session_id"] == 1
    assert info["payload"] == payload


def test_cipher_nonce_chain_across_segments():
    key = os.urandom(32)
    send = mieru.SendCipher(key, username="alice")
    recv = mieru.RecvCipher(key)
    wire = b""
    infos = []
    # second and later segments must NOT carry a nonce on the wire;
    # both sides advance the implicit nonce once per AEAD operation
    for i in range(3):
        metadata = mieru.encode_data_metadata(
            mieru.DATA_CLIENT_TO_SERVER, 12345, 1, i, 0, 65535, 0, 2, 10, 3)
        wire += send.encrypt_segment(metadata, b"p" * 10,
                                     prefix=b"q" * 2, suffix=b"r" * 3)
    import asyncio

    async def go():
        reader = asyncio.StreamReader()
        reader.feed_data(wire)
        reader.feed_eof()
        for _ in range(3):
            infos.append(await recv.read_segment(reader))

    asyncio.run(go())
    assert [i["sequence"] for i in infos] == [0, 1, 2]
    assert all(i["payload"] == b"p" * 10 for i in infos)


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