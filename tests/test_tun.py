"""TUN routing tests.

The router is pure logic — no wintun, no asyncio — so it is easy to test
in isolation. The tunnel session on the client is exercised through the
existing protocol round-trip.
"""

import pytest

from letuc.system.tun_stack import TunRouter
from letuc.rule.engine import RuleEngine


def _router():
    rules = [
        {"type": "domain_suffix", "domain_suffix": [".cn"], "outbound": "direct"},
        {"type": "ip_cidr", "ip_cidr": ["8.8.8.8/32"], "outbound": "proxy"},
        {"type": "default", "outbound": "proxy"},
    ]
    return TunRouter(RuleEngine(rules), server_ip="203.0.113.10")


def _ipv4(src, dst):
    """Minimal 20-byte IPv4 header: version/IHL at 0, src at 12..15, dst at 16..19."""
    return bytes([
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00,
    ]) + bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split("."))


def test_forward_when_rule_says_proxy():
    r = _router()
    assert r.should_forward(_ipv4("10.0.0.1", "8.8.8.8")) is True


def test_drop_private_traffic():
    r = _router()
    assert r.should_forward(_ipv4("10.0.0.1", "192.168.1.1")) is False
    assert r.should_forward(_ipv4("10.0.0.1", "127.0.0.1")) is False
    assert r.should_forward(_ipv4("10.0.0.1", "0.0.0.0")) is False


def test_drop_multicast_and_broadcast():
    r = _router()
    assert r.should_forward(_ipv4("10.0.0.1", "224.0.0.1")) is False
    assert r.should_forward(_ipv4("10.0.0.1", "255.255.255.255")) is False


def test_drop_server_itself():
    r = _router()
    assert r.should_forward(_ipv4("10.0.0.1", "203.0.113.10")) is False


def test_drop_malformed_packet():
    r = _router()
    assert r.should_forward(b"\x00" * 5) is False
    assert r.should_forward(b"") is False


def test_open_tunnel_session_method_exists():
    from letuc.core.client import MieruClient

    client = MieruClient("127.0.0.1", 1, "alice", "secret")
    assert hasattr(client, "open_tunnel")