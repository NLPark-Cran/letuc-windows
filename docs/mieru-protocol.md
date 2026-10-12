# mieru protocol notes

Sourced from https://github.com/enfein/mieru (`docs/protocol.md`), fetched
2026-10-09. letuc is an independent implementation and is not derived from
the mieru source tree; mieru itself is GPL-3.0.

## 1. Overview

mieru offers TCP and UDP. UDP needs more decryption attempts; TCP is faster.
Default to TCP.

All multi-byte fields are big-endian.

## 2. Key generation

TCP and UDP share one key derivation.

1. `hashedPassword = SHA-256(password + 0x00 + username)`
2. `unixTime` = current seconds, **rounded to the nearest 2 minutes**,
   stored as an 8-byte uint64 string.
3. `timeSalt = SHA-256(uint64_string(unixTime))`
4. `key = PBKDF2(password=hashedPassword, salt=timeSalt, iterations=64,
   dklen=32, hash=SHA-256)`

Because the key depends on system time, client and server must not drift by
more than 4 minutes. The server tries up to three time salts.

## 3. Encryption

AEAD with a 24-byte nonce. Only XChaCha20-Poly1305 is used here.

To speed up user lookup, the last 4 bytes of the nonce are replaced with the
first 4 bytes of `SHA-256(username + nonce[:16])`.

## 4. Segments

```
padding 0 | nonce (0 or 24) | encrypted metadata (32) | auth tag (16)
| padding 1 | encrypted payload | auth tag (16) | padding 2
```

`encrypted metadata` and its tag are present in every segment.
`padding 0/1/2` are random non-encrypted bytes that pad the entropy.

### TCP

The nonce appears only in the first segment of each direction. After each
encryption the nonce is incremented by one. A single fragment is at most
32768 bytes.

### UDP

Every segment carries its own nonce. A segment must fit in one UDP packet,
so length is bounded by the path MTU.

## 5. Metadata (32 bytes fixed)

### Session metadata

| protocol type | unused | timestamp | session id | sequence | status | payload len | suffix len | unused |
|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 4 | 4 | 4 | 1 | 2 | 1 | 14 |

protocol types: `openSessionRequest`=2, `openSessionResponse`=3,
`closeSessionRequest`=4, `closeSessionResponse`=5. timestamp is minutes
since 1970-01-01. Session metadata carries at most 1024 bytes of payload.

### Data metadata

| protocol type | unused | timestamp | session id | sequence | unack seq | window | fragment num | prefix len | payload len | suffix len | unused |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 4 | 4 | 4 | 4 | 2 | 1 | 1 | 2 | 1 | 7 |

protocol types: `dataClientToServer`=6, `dataServerToClient`=7,
`ackClientToServer`=8, `ackServerToClient`=9. sequence / unack / window
implement flow control.

### Low entropy extension (not implemented)

| protocol type | low entropy mode | timestamp | session id | sequence | unack seq | window | fragment num | prefix len | payload len | suffix len | mask | extracted len | mask rotation |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 4 | 4 | 4 | 4 | 2 | 1 | 1 | 2 | 1 | 4 | 2 | 1 |

`dataClientToServerLowEntropy`=10, `dataServerToClientLowEntropy`=11.
Modes 1-4 pack 32/40/48/56 payload bits per 64-bit chunk.

## 6. UDP associate encapsulation

socks5 UDP Associate requests are carried over the proxy protocol wrapped
so UDP packet boundaries survive:

```
marker 1 (1) | data length (2) | data (X) | marker 2 (1)
```

marker 1 = `0x00`, marker 2 = `0xff`.

## 7. Client config format (JSON)

```json
{
  "profiles": [
    {
      "profileName": "default",
      "user": { "name": "your-username", "password": "your-password" },
      "servers": [
        {
          "ipAddress": "203.0.113.10",
          "domainName": "",
          "portBindings": [{ "port": 33009, "protocol": "TCP" }]
        }
      ],
      "mtu": 1400,
      "multiplexing": { "level": "MULTIPLEXING_LOW" },
      "handshakeMode": "HANDSHAKE_STANDARD"
    }
  ],
  "activeProfile": "default",
  "rpcPort": 8964,
  "socks5Port": 1080,
  "loggingLevel": "INFO",
  "socks5ListenLAN": false,
  "httpProxyPort": 8080,
  "httpProxyListenLAN": false
}
```

letuc stores a friendlier shape in `config.json`; the fields map onto this
structure.

## 8. Client commands

```sh
mieru apply config <FILE>     # merge
mieru replace config <FILE>   # replace
mieru describe config         # inspect
mieru start                   # start
mieru stop                    # stop
```

letuc exposes start/stop through the GUI and the system tray.

## License

mieru is GPL-3.0. This document is a summary of publicly documented
behaviour; letuc is independently implemented.