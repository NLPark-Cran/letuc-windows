"""UDP associate encapsulation tests."""
import struct

import pytest

from letuc.core import protocol as mieru


def test_encapsulate_roundtrip():
    data = b"hello udp"
    enc = mieru.encapsulate_udp(data)
    assert enc[0] == 0x00
    assert enc[-1] == 0xFF
    assert struct.unpack(">H", enc[1:3])[0] == len(data)
    assert mieru.decapsulate_udp(enc) == data


def test_empty():
    enc = mieru.encapsulate_udp(b"")
    assert enc == b"\x00\x00\x00\xff"
    assert mieru.decapsulate_udp(enc) == b""


def test_too_large():
    with pytest.raises(ValueError):
        mieru.encapsulate_udp(b"x" * 0x10000)


def test_invalid_marker():
    with pytest.raises(ValueError):
        mieru.decapsulate_udp(b"\x01\x00\x00ab\xff")