"""Tiny DNS resolver used to answer lookups inside the client.

The client never lets a process's own DNS query reach the system resolver,
so we resolve here and hand the answer back. DoH is the primary upstream;
plain UDP 53 is the fallback. This is a minimal hand-rolled resolver, not a
general-purpose one: it answers A/AAAA queries and nothing else.
"""

from __future__ import annotations

import asyncio
import logging
import struct

logger = logging.getLogger(__name__)

DEFAULT_UPSTREAMS = [
    "https://dns.alidns.com/dns-query",
    "https://94.140.14.14/dns-query",
    "https://dns.google/dns-query",
    "https://cloudflare-dns.com/dns-query",
]


def _encode_query(name, qtype=1):
    """Build a wire-format DNS query for one name/type."""
    tid = 0xBEEF
    flags = 0x0100  # recursion desired
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    labels = b"".join(
        bytes([len(part)]) + part.encode() for part in name.rstrip(".").split("."))
    question = labels + b"\x00" + struct.pack(">HH", qtype, 1)
    return header + question


def _parse_response(data):
    """Return list of (name, type, ttl, rdata) from a DNS response."""
    if len(data) < 12:
        return []
    tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    if tid != 0xBEEF:
        return []
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off)
        off += 4
    out = []
    for _ in range(an):
        name, off = _read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == 1 and rdlen == 4:
            rdata = ".".join(str(b) for b in rdata)
        elif rtype == 28 and rdlen == 16:
            rdata = ":".join(
                f"{rdata[i]:02x}{rdata[i + 1]:02x}" for i in range(0, 16, 2))
        out.append((name, rtype, ttl, rdata))
    return out


def _skip_name(data, off):
    while True:
        if off >= len(data):
            return off
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1 + length


def _read_name(data, off):
    labels = []
    jumped = False
    end = off
    while True:
        if off >= len(data):
            break
        length = data[off]
        if length == 0:
            if not jumped:
                end = off + 1
            break
        if length & 0xC0 == 0xC0:
            if not jumped:
                end = off + 2
            off = ((length & 0x3F) << 8) | data[off + 1]
            jumped = True
            continue
        off += 1
        labels.append(data[off:off + length].decode("latin-1"))
        off += length
    return ".".join(labels), end


class DnsResolver:
    def __init__(self, upstreams=None, timeout=5.0):
        self.upstreams = list(upstreams or DEFAULT_UPSTREAMS)
        self.timeout = timeout

    async def resolve(self, name, qtype=1):
        query = _encode_query(name, qtype)
        last_error = None
        for upstream in self.upstreams:
            try:
                if upstream.startswith("https://"):
                    answers = await self._doh(query, upstream)
                else:
                    answers = await self._udp(query, upstream)
                if answers:
                    return [r for r in answers if r[1] == qtype]
            except Exception as e:
                last_error = e
                logger.debug("upstream %s failed: %s", upstream, e)
                continue
        if last_error:
            raise last_error
        return []


    async def _doh(self, query, url):
        # stdlib only: DoH is just HTTPS on a fixed path with application/dns-message
        import urllib.request
        req = urllib.request.Request(
            url, data=query,
            headers={"Content-Type": "application/dns-message"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = resp.read()
        return _parse_response(data)

    async def _udp(self, query, host):
        # host may be "ip:port" or just "ip"
        ip, _, port = host.partition(":")
        port = int(port) if port else 53
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), self.timeout)
        try:
            writer.write(query)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), self.timeout)
        finally:
            writer.close()
            await writer.wait_closed()
        return _parse_response(data)


__all__ = ["DnsResolver", "DEFAULT_UPSTREAMS"]