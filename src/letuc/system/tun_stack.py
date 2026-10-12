"""TUN routing: decide which IP packets go through the tunnel.

The TUN device hands us every IP packet the OS wants to send from the
virtual interface. Not all of them should cross the wire — traffic to
private ranges, loopback, multicast and the mieru server itself is
handled locally or dropped, and only the rest is forwarded through the
tunnel session.

This module is deliberately stateless: it asks the rule engine for an
outbound decision the same way the proxy does, then the caller feeds
the packet in or discards it.
"""

from __future__ import annotations

import ipaddress
import logging

from letuc.rule.engine import RuleEngine

logger = logging.getLogger(__name__)

# Addresses that never leave the local machine, regardless of rules.
LOCAL_RANGES = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]


def _ip_version(data: bytes):
    if len(data) < 20:
        return None
    return (data[0] >> 4) & 0x0F


def _dst_ip(data: bytes):
    if len(data) < 20:
        return None
    if _ip_version(data) == 4:
        # IPv4 header is 20 bytes; source at 12..15, destination at 16..19
        return ".".join(str(b) for b in data[16:20])
    # IPv6: source at 24..39, destination at 40..55
    if len(data) < 56:
        return None
    return ":".join(f"{data[i]:02x}{data[i + 1]:02x}" for i in range(40, 56, 2))


class TunRouter:
    """Decides whether an IP packet should be forwarded through the tunnel."""

    def __init__(self, engine=None, server_ip=None):
        self.engine = engine or RuleEngine()
        self.server_ip = server_ip

    def should_forward(self, data: bytes):
        """Return True if the packet should be sent through the tunnel.

        Returns False for malformed packets, local/broadcast/multicast
        traffic, and traffic destined for the server itself.
        """
        if _ip_version(data) is None:
            return False
        dst = _dst_ip(data)
        if dst is None:
            return False
        try:
            ip_obj = ipaddress.ip_address(dst)
        except ValueError:
            return False
        for net in LOCAL_RANGES:
            if ip_obj in net:
                return False
        if self.server_ip and str(ip_obj) == self.server_ip:
            return False
        return self.engine.match(None, dst) == "proxy"


__all__ = ["TunRouter", "LOCAL_RANGES"]