"""DNS resolver parsing tests."""
import pytest

from letuc.dns.resolver import _encode_query, _parse_response


def test_encode_query_has_header():
    q = _encode_query("example.com")
    assert len(q) >= 12
    import struct
    tid, flags, qd = struct.unpack(">HHH", q[:6])
    assert tid == 0xBEEF
    assert qd == 1
    assert b"\x07example\x03com\x00" in q


def test_parse_response_roundtrip():
    q = _encode_query("example.com")
    import struct
    name = b"\x07example\x03com\x00"
    answer = name + struct.pack(">HHIH", 1, 1, 300, 4) + b"\x01\x02\x03\x04"
    header = struct.pack(">HHHHHH", 0xBEEF, 0x8180, 1, 1, 0, 0)
    resp = header + q[12:] + answer
    out = _parse_response(resp)
    assert out
    assert out[0][3] == "1.2.3.4"
    assert out[0][2] == 300


def test_parse_response_bad_tid():
    import struct
    header = struct.pack(">HHHHHH", 0xDEAD, 0x8180, 0, 0, 0, 0)
    assert _parse_response(header) == []


def test_parse_response_truncated():
    assert _parse_response(b"\x00" * 5) == []