"""DNS leak detection.

Periodically queries a couple of public resolvers for a fixed set of names
and compares the answers against what our own resolver returns. A mismatch
means something else is answering for us, which is a leak.
"""

from __future__ import annotations

import asyncio
import logging

from letuc.dns.resolver import DnsResolver

logger = logging.getLogger(__name__)

LEAK_CHECK_NAMES = [
    "www.google.com",
    "www.cloudflare.com",
    "www.anthropic.com",
    "one.one.one.one",
]

# Public resolvers we probe directly; if they answer, DNS is leaking out.
LEAK_PROBES = [
    "8.8.8.8:53",
    "1.1.1.1:53",
    "9.9.9.9:53",
]


class LeakDetector:
    def __init__(self, resolver, names=None, probes=None, interval=60.0):
        self.resolver = resolver
        self.names = list(names or LEAK_CHECK_NAMES)
        self.probes = list(probes or LEAK_PROBES)
        self.interval = interval
        self._task = None
        self._running = False

    def start(self):
        self._running = True
        self._task = asyncio.create_task(self._run())

    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None

    async def _run(self):
        while self._running:
            try:
                await self._check_once()
            except Exception as e:
                logger.debug("leak check error: %s", e)
            await asyncio.sleep(self.interval)

    async def _check_once(self):
        for name in self.names:
            ours = await self._safe_resolve(name)
            if ours is None:
                continue
            for probe in self.probes:
                leaked = await self._safe_probe(name, probe)
                if leaked is None:
                    continue
                if set(ours) != set(leaked):
                    logger.warning(
                        "DNS leak suspected for %s: ours=%s probe(%s)=%s",
                        name, ours, probe, leaked)
                    return
        logger.debug("leak check clean")

    async def _safe_resolve(self, name):
        try:
            answers = await self.resolver.resolve(name)
            return tuple(a[3] for a in answers)
        except Exception:
            return None

    async def _safe_probe(self, name, probe):
        # query the public resolver directly with a plain UDP query
        from letuc.dns.resolver import _encode_query, _parse_response
        import asyncio
        import struct
        ip, _, port = probe.partition(":")
        port = int(port) if port else 53
        query = _encode_query(name)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), 5.0)
        except Exception:
            return None
        try:
            writer.write(query)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), 5.0)
        except Exception:
            return None
        finally:
            writer.close()
            await writer.wait_closed()
        answers = _parse_response(data)
        return tuple(a[3] for a in answers if a[1] == 1)


__all__ = ["LeakDetector", "LEAK_CHECK_NAMES", "LEAK_PROBES"]