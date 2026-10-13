"""Live probe: handshake with the real mieru server and fetch one HTTP page.

Run: python live_probe.py
Exits 0 on success (got an HTTP response through the tunnel).
"""
import asyncio
import sys

from letuc.core.client import MieruClient

HOST, PORT = "114.55.35.183", 33009
USER, PASS = "8c94fee1", "7d5ce5ba"


async def main():
    client = MieruClient(HOST, PORT, USER, PASS)
    await asyncio.wait_for(client.start(), timeout=10)
    print("[ok] TCP connected, ciphers initialised")

    reader, writer = await asyncio.wait_for(
        client.connect("example.com", 80), timeout=10)
    print("[ok] openSession accepted by server")

    writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    await writer.drain()

    data = await asyncio.wait_for(reader.read(4096), timeout=15)
    head = data.split(b"\r\n", 1)[0]
    print("[ok] got %d bytes, status line: %s" % (len(data), head.decode(errors="replace")))

    await client.stop()
    if b"HTTP/" not in data:
        print("[fail] response is not HTTP")
        return 1
    print("[pass] live tunnel works")
    return 0


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.DEBUG,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    sys.exit(asyncio.run(main()))
