"""Fake mieru server: emulate the server side with our own protocol.py and
let the OFFICIAL mieru client talk to us. If the official client can push a
full HTTP request through this script, our wire format is byte-compatible
in both directions.

Run: python fake_server.py   (listens on 127.0.0.1:13309)
"""
import asyncio
import struct
import time

from letuc.core import protocol as mieru

USER, PASS = "8c94fee1", "7d5ce5ba"
LISTEN = ("127.0.0.1", 13309)

_LOG = open(r"D:\workspace\letuc-windows\fake_server.log", "w", buffering=1)


def log(msg):
    _LOG.write(msg + "\n")


# redirect prints
import builtins
_orig_print = builtins.print
builtins.print = lambda *a, **k: log(" ".join(str(x) for x in a))


def now_ts():
    return int(time.time() // 60) & 0xFFFFFFFF


async def handle(reader, writer):
    # --- first segment: try the 3 time-salt keys, like the real server
    recv = None
    info = None
    head = await reader.readexactly(72)
    nonce = head[:24]
    marker_ok = mieru.stamp_nonce(USER, nonce[:20] + b"\x00" * 4)[20:24] == nonce[20:24]
    print("[srv] user hint marker match:", marker_ok)
    for rounded, key in mieru.time_salt_candidates(USER, PASS):
        try:
            meta = mieru.decode_metadata(mieru._aead_decrypt(key, nonce, head[24:72]))
            recv = mieru.RecvCipher(key)
            recv._nonce = nonce
            info = meta
            print("[srv] decrypted with rounded=%d" % rounded)
            break
        except Exception:
            continue
    if recv is None:
        print("[srv] FAIL: no key could decrypt first segment")
        writer.close()
        return

    # read rest of first segment per metadata
    plen = info.get("payload_length", 0)
    payload = b""
    if plen:
        recv._nonce = mieru.increment_nonce(recv._nonce)
        ct = await reader.readexactly(plen + 16)
        payload = mieru._aead_decrypt(recv.key, recv._nonce, ct)
    slen = info.get("suffix_length", 0)
    if slen:
        await reader.readexactly(slen)
    print("[srv] open request: type=%d sid=%d seq=%d status=%d payload=%s"
          % (info["type"], info["session_id"], info["sequence"],
             info["status"], payload.hex()))

    send = mieru.SendCipher(recv.key, "")

    def send_session(ptype, sid, seq, status=0, payload=b""):
        md = mieru.encode_session_metadata(ptype, now_ts(), sid, seq, status, len(payload), 0)
        writer.write(send.encrypt_segment(md, payload))

    def send_data(sid, seq, payload):
        md = mieru.encode_data_metadata(
            mieru.DATA_SERVER_TO_CLIENT, now_ts(), sid, seq, 0, 65535, 0, 0, len(payload), 0)
        writer.write(send.encrypt_segment(md, payload))

    sid = info["session_id"]
    send_session(mieru.OPEN_SESSION_RESPONSE, sid, info["sequence"])
    print("[srv] sent openSessionResponse")

    # server session send seq: openSessionResponse consumes seq 0
    # (upstream: seq = nextSend(0), then nextSend++), so data starts at 1
    sseq = 1
    print("[srv] open meta:", {k: v for k, v in info.items()})
    # payload = FULL socks5 CONNECT request (VER|CMD|RSV|ATYP|ADDR|PORT),
    # no greeting exchange on the session (client side auth mode)
    buf = bytearray(payload)
    while len(buf) < 4:
        seg = await recv.read_segment(reader)
        print("[srv] rx type=%d seq=%d payload=%s"
              % (seg["type"], seg.get("sequence"), seg["payload"].hex()))
        buf += seg["payload"]
    print("[srv] socks5 request head:", bytes(buf[:4]).hex())

    atyp = buf[3]
    if atyp == 1:
        need = 4 + 4 + 2
    elif atyp == 3:
        while len(buf) < 5:
            seg = await recv.read_segment(reader)
            buf += seg["payload"]
        need = 4 + 1 + buf[4] + 2
    else:
        need = 4 + 16 + 2
    while len(buf) < need:
        seg = await recv.read_segment(reader)
        print("[srv] rx type=%d seq=%d payload=%s"
              % (seg["type"], seg.get("sequence"), seg["payload"].hex()))
        buf += seg["payload"]
    req = bytes(buf[:need])
    buf = buf[need:]
    print("[srv] target addr spec:", req[3:].hex())
    if atyp == 1:
        host = ".".join(str(b) for b in req[4:8])
        port = struct.unpack(">H", req[8:10])[0]
    elif atyp == 3:
        host = req[5:5 + req[4]].decode()
        port = struct.unpack(">H", req[5 + req[4]:7 + req[4]])[0]
    else:
        host = "ipv6"
        port = struct.unpack(">H", req[20:22])[0]
    print("[srv] target: %s:%d" % (host, port))

    try:
        up_r, up_w = await asyncio.open_connection(host, port)
    except Exception as e:
        print("[srv] dial fail:", e)
        send_data(sid, sseq, b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
        writer.close()
        return
    # single socks5 CONNECT response; no greeting exchange on the session
    send_data(sid, sseq, b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    sseq += 1
    print("[srv] sent connect success, entering relay")

    seq_counter = [sseq]

    async def client_to_target():
        while True:
            try:
                seg = await recv.read_segment(reader)
            except Exception:
                break
            if seg["type"] == mieru.DATA_CLIENT_TO_SERVER and seg["payload"]:
                up_w.write(seg["payload"])
                await up_w.drain()
            elif seg["type"] in (mieru.CLOSE_SESSION_REQUEST, mieru.CLOSE_SESSION_RESPONSE):
                break
        try:
            up_w.close()
        except Exception:
            pass

    async def target_to_client():
        while True:
            data = await up_r.read(8192)
            if not data:
                break
            send_data(sid, seq_counter[0], data)
            seq_counter[0] += 1
            await writer.drain()

    await asyncio.gather(client_to_target(), target_to_client())
    writer.close()


async def main():
    server = await asyncio.start_server(handle, *LISTEN)
    print("[srv] listening on %s:%d" % LISTEN)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
