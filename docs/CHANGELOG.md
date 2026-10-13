# Changelog

## v0.2.2 — 2026-10-13

### Fixed

- `src/letuc/core/protocol.py` — TCP wire format rewritten against
  enfein/mieru v3.38.1 ground truth (official client ↔ local fake server,
  and our client ↔ real server, both verified live). The nonce is a pure
  random 24-byte value stamped with a 4-byte user lookup marker, sent on
  the wire exactly once per direction; every AEAD operation after that
  (metadata and payload count separately) advances the nonce as one
  192-bit big-endian counter. The old format invented 8+4 random bytes
  around the nonce and reused one nonce for metadata and payload, so the
  server never decrypted a single segment.
- `src/letuc/core/client.py` — the session carries a full RFC 1928
  CONNECT request inside the openSessionRequest payload. Upstream runs
  the in-session socks5 server with client side authentication enabled
  (`ClientSideAuthentication: true` in the client daemon config), so
  there is no greeting exchange on the session at all; the server
  replies with a single 10-byte socks5 response. We used to send the
  3-byte greeting alone and wait for a 2-byte auth response, which
  deadlocked against the real server: it read our greeting as the start
  of a CONNECT request and blocked waiting for bytes that never came.
  Symptom on every live handshake: openSession accepted, then silence.
- `src/letuc/core/client.py` — data sequence numbers start at 1
  (openSessionResponse consumes seq 0); a `_ProxyWriter` no longer
  trips `StreamWriter.__del__` during GC.

### Added

- `fake_server.py`, `live_probe.py` — ground-truth harness: a minimal
  Python mieru server used to pin down the wire format against the
  official v3.38.1 client, and an end-to-end probe that fetches one HTTP
  page through the real relay.

## v0.2.1 — 2026-10-13

### Fixed

- `src/letuc/ui/main.py` — the asyncio loop was created but never pumped:
  `_on_start` ran `start_services` via `run_until_complete` and the loop
  stopped for good when it returned. Listeners showed LISTENING but nobody
  ever called accept, so every browser connection piled up in CLOSE_WAIT
  and new ones were refused. Qt and asyncio now share a qasync
  `QEventLoop`; slots schedule coroutines with `create_task` and surface
  failures in the log.
- `src/letuc/ui/main.py` — the tray's 停止代理并完全退出 entry was connected
  to a coroutine function directly, so it created the coroutine and never
  ran it: quitting left the system proxy pointing at a dead client and
  broke all browsing until the settings were reset by hand. It is now
  scheduled on the loop, stops services, and clears the system proxy.
- `src/letuc/system/proxy.py`, `src/letuc/system/startup.py`,
  `src/letuc/system/wintun_install.py` — console tools (reg.exe, netsh.exe)
  spawned from the windowed exe died at startup with 0xC0000142 and, on
  the way down, showed a modal Application Error that blocked the event
  loop until it was clicked. All subprocess calls now use
  CREATE_NO_WINDOW + stdin DEVNULL, and the start/exit paths run them on
  worker threads.
- `src/letuc/system/startup.py` — the Run key path was built as
  `HKCU\\Software...` (double backslash in a raw string), which reg.exe
  rejects as an invalid key name, so the autostart checkbox could never
  work. Single backslash now.
- `src/letuc/proxy/listeners.py` — the mixed port wrapped the peeked first
  byte as `bytes([first])`, but readexactly already returns bytes, so every
  mixed-port connection died with TypeError before dispatch. SOCKS5 on the
  mixed port was equally dead.
- `src/letuc/proxy/http.py` — plain-GET forwarding partitioned the target
  on ":" before splitting off the path, so "host/" was resolved as a
  hostname and every plain HTTP request failed; the forwarded request line
  also kept the absolute URI instead of origin-form.

### Changed

- `requirements.txt` — `pyqt6-asyncio` removed (it does not exist on PyPI;
  the dependency was aspirational and never installed). Replaced with
  `qasync>=0.27.0`, which provides the QEventLoop the code was designed
  around.

## v0.2.0 — 2026-10-12

### Added

- `src/letuc/rule/rulesets.py` — community rule sets (Loyalsoldier
  direct/proxy/reject, dnsmasq-china-list, chnroute, HaGeZi) downloaded at
  runtime with conditional requests, merged into the engine as
  block → private/DNS → direct → proxy → default.
- `src/letuc/rule/data/` — bundled initial copy of the rule sets so the exe
  works offline on first launch.
- `gen_rules.py` / `gen_chnroute.py` — build-time regeneration of
  `rules.json` and the Chinese IPv4 CIDR list (APNIC-derived, with mirrors
  and a pre-derived fallback).
- `src/letuc/system/wintun_install.py` — one-click WinTun driver install
  (download + elevated quiet install) offered when TUN is enabled without
  the driver present.

### Fixed

- `src/letuc/ui/main.py` — window and tray icon were blank in the frozen
  exe: the icon was only searched next to the executable, while PyInstaller
  onefile unpacks it under `sys._MEIPASS`. Both locations are searched now.
- `src/letuc/ui/main.py` + `src/letuc/system/proxy.py` — the active server
  address is appended to the system-proxy bypass list at connect time, so
  the server's own traffic never loops into the tunnel; the default bypass
  list no longer hardcodes any server.

### Changed

- No server presets ship with the public codebase. Servers live in
  `config.json` next to the executable (gitignored); defaults are empty and
  the GUI asks on first run.
- `build.bat` removed; `letuc.spec` is the single source of truth for the
  exe build.

## v0.1.0 — 2026-10-10

### Added

- `src/letuc/core/protocol.py` — mieru protocol stack
  - PBKDF2 key derivation on a 2-minute grid
  - XChaCha20-Poly1305 AEAD via HChaCha20 sub-key derivation
  - session / data / ack metadata encode and decode
  - TCP segment encrypt and decrypt
  - socks5 UDP associate encapsulation
- `src/letuc/core/client.py` — control connection with stream multiplexing
- `src/letuc/rule/engine.py` + `src/letuc/rule/rules.json` — rule engine
  - `domain` / `domain_suffix` / `domain_keyword` / `ip_cidr` / `default`
  - first match wins, `proxy` as final fallback
- `src/letuc/proxy/socks5.py` — local socks5 server (CONNECT, UDP Associate)
- `src/letuc/proxy/http.py` — local HTTP/HTTPS proxy
- `src/letuc/proxy/tun.py` — wintun-backed TUN device
- `src/letuc/dns/resolver.py` — DoH / UDP resolver
- `src/letuc/dns/leak.py` — DNS leak detector
- `src/letuc/system/proxy.py` — WinHTTP and Internet Options proxy control
- `src/letuc/util/config.py` — JSON config read/write
- `src/letuc/ui/main.py` — PyQt6 GUI with system tray
- `tests/` — protocol, rule engine, DNS parsing, config, UDP associate, GUI smoke
- `tests/test_gui_smoke.py` — headless GUI smoke test
- `docs/` — protocol notes, rule design, anti-detection design, FEATURES
- `docs/FEATURES.md` — feature registry with status and add date
- `letuc.spec` — PyInstaller spec for single-file exe build
- `build.bat` — one-shot build script (fetches wintun.dll, runs pyinstaller)
- `README.md`, `LICENSE`, `pyproject.toml`, `requirements.txt`, `.gitignore`
- `AGENTS.md`, `PRD.md`

### Fixed

- `src/letuc/core/protocol.py` — HChaCha20 round function was unpacking
  slices instead of passing the four state words directly, so the derived
  sub-key did not depend on the input key. Corrected to call `_quarter`
  with explicit arguments.
- `src/letuc/core/client.py` — inbound drain loop now reads the segment
  tail after decrypting the header, instead of assuming a fixed size.
- `src/letuc/ui/main.py` — `_on_apply_rules` opened a `QMessageBox.critical`
  on bad JSON, which blocks the Qt event loop in headless mode and froze
  the GUI smoke test. Errors are now reported through the log line and the
  status bar instead.
- `src/letuc/ui/main.py` — config path resolves next to the executable when
  frozen, and to the repo root when running from source.
- `src/letuc/system/tun_stack.py` — new module. `TunRouter` decides whether a
  raw IP packet is forwarded through the tunnel: malformed packets, private
  ranges, loopback, link-local, multicast, broadcast, and the server IP are
  dropped; everything else is delegated to the rule engine. IPv4 and IPv6
  header offsets are handled explicitly, including the IPv6 destination at
  bytes 40..55.
- `src/letuc/core/client.py` — added `open_tunnel()`, which opens a bare
  session with no host/port negotiation so the TUN device can send raw IP
  packets as data segments.
- `src/letuc/proxy/tun.py` — `TunStack` now owns a dedicated TUN session, a
  worker read thread, and an asyncio bridge (`run_coroutine_threadsafe`)
  so the wintun callback can feed packets onto the client event loop.
- `src/letuc/ui/main.py` — `start_services` creates the `TunStack` when the
  `tun.enabled` config flag is set and tears it down on stop.
- `letuc.spec` — Qt platform plugins (platforms/styles/iconengines/
  imageformats) are now bundled as datas; without them a GUI exe refuses
  to start with "no Qt platform plugin could be initialized". rules.json is
  also bundled so the frozen exe can load the default rule set.
- `tests/test_tun.py` — 6 new tests covering TunRouter decisions and the
  `open_tunnel` helper.

### v0.1.1 — 2026-10-10

#### Fixed

- `src/letuc/ui/main.py` — the GUI log widget was never wired to the stdlib
  logger, so every warning (system proxy setup, TUN failure, bind errors)
  was invisible. A `_QtLogHandler` now pumps records into the 日志 tab.
- `src/letuc/ui/main.py` — system proxy was never set on start. The
  Internet Options (`ProxyEnable` / `ProxyServer` / `ProxyOverride`) and
  WinHTTP entries are now written when the client starts, and cleared on
  stop. Verified end-to-end against the registry.
- `src/letuc/proxy/tun.py` — `WintunCreateAdapter` failed when a stale
  adapter from a previous run was still present, which crashed the whole
  TUN startup. It now falls back to `WintunOpenAdapter` and the GUI keeps
  running without TUN instead of exiting.
- `src/letuc/system/tun_stack.py` — IPv6 destination was read at bytes
  24..39 instead of 40..55, so every IPv6 packet was misrouted.

#### Added

- `src/letuc/proxy/listeners.py` — new listener set with the port layout the
  user asked for: a single mixed port (HTTP + SOCKS5 auto-detected), a
  dedicated SOCKS port, a PAC script server, and Xray / mihomo control APIs.
- `src/letuc/ui/main.py` — server presets (configurable from the dropdown,
  with a "(直连) 香港精品 - 韩国落地" entry at 203.0.113.20), an advanced
  settings panel collapsed by default (MTU + all local ports), and a natural
  rule syntax: `google.com 走代理`, `*.cn 需要直连`,
  `192.168.0.0/16 需要屏蔽`.
- `tests/test_rule_syntax.py` — 9 tests for the natural rule parser and the
  round-trip renderer.

### Notes

- TUN and UDP transport are present as scaffolding; the full packet path is
  not wired end-to-end in v0.1.
- wintun.dll is fetched at build time via `python dl_wintun.py`.
- The single-file exe (`dist/letuc.exe`, ~42 MB) launches, sets the system
  proxy, and shows the connection / rules / log tabs. It has not been tested
  against the live mieru server; credentials in the default config are the
  repo's own.