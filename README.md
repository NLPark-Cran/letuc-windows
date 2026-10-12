# letuc

A small, readable mieru client for Windows.

It is a from-scratch implementation: not a fork of the official mieru client,
not a wrapper around sing-box/mihomo. The goal is a client you can read in
twenty minutes, that starts a socks5/HTTP proxy, optionally opens a TUN
device, and keeps DNS and WebRTC from leaking while you use AI services.

## Server

letuc is a client only — bring your own mieru server. On first run the GUI
asks for the server address, port, username and password, and saves them to
`config.json` next to the executable.

## Install

```sh
pip install -r requirements.txt
python main.py
```

On first run the GUI asks for the server, credentials and the local listen
ports. Everything is saved to `config.json` next to the executable.

## Layout

```
letuc-windows/
├── main.py                # entry point
├── config.json            # your connection settings (created on first run)
├── requirements.txt
├── pyproject.toml
├── assets/
│   └── wintun.dll         # TUN backend (downloaded at build time)
├── docs/
│   ├── mieru-protocol.md  # protocol notes, sourced from enfein/mieru
│   ├── rules-design.md    # rule engine design
│   ├── anti-detection.md  # DNS / WebRTC / system proxy leak design
│   └── CHANGELOG.md
├── src/letuc/
│   ├── core/protocol.py   # key derivation, framing, XChaCha20-Poly1305
│   ├── core/client.py     # control connection, stream multiplexing
│   ├── rule/engine.py     # domain / suffix / keyword / cidr matching
│   ├── rule/rules.json    # default rules
│   ├── proxy/socks5.py    # local socks5 server
│   ├── proxy/http.py      # local HTTP/HTTPS proxy
│   ├── proxy/tun.py       # wintun-backed TUN device
│   ├── dns/resolver.py    # DoH / UDP resolver
│   ├── dns/leak.py        # leak detection
│   ├── system/proxy.py    # WinHTTP + Internet Options proxy
│   ├── util/config.py     # config read/write
│   └── ui/main.py         # PyQt6 GUI + tray
├── tests/
└── build/                 # PyInstaller output
```

## Features

- **mieru protocol stack** — PBKDF2 key derivation, XChaCha20-Poly1305,
  session/data/ack metadata, TCP segmentation, UDP associate encapsulation.
- **Local proxy** — socks5 on 1080, HTTP/HTTPS on 8080, both on 127.0.0.1
  by default. Direct/proxy/block decided by the rule engine per connection.
- **Rules** — `domain`, `domain_suffix`, `domain_keyword`, `ip_cidr`,
  `default`. First match wins. Editable from the GUI or by hand in
  `rules.json`.
- **TUN** — optional wintun virtual adapter so terminal processes route
  through the proxy without knowing it.
- **Anti-detection** — own DNS resolver (DoH primary, UDP 53 fallback),
  periodic leak checks against public resolvers, system proxy exception
  list, clock skew warning.

## Development

```sh
pip install -r requirements.txt
pip install -e .
pytest
```

The TUN backend (`assets/wintun.dll`) is fetched at build time; run
`python dl_wintun.py` if it is missing.

## Building a single-file exe

```sh
python dl_wintun.py        # fetch assets/wintun.dll (TUN backend)
python -m PyInstaller letuc.spec --noconfirm
```

The result is `dist/letuc.exe`, a single file (~42 MB) that launches on its
own: Qt platform plugins and `rules.json` are bundled inside, so there is no
`plugins/` folder to ship alongside it.

> If the exe is already running when you rebuild, PyInstaller cannot replace
> it. Kill any running `letuc.exe` first (`taskkill /F /IM letuc.exe`).

## License

MIT — Copyright (c) 2026 NLPark-Cran