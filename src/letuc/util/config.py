"""Configuration: read/write the JSON config file.

The config file is a plain JSON document. Missing keys raise rather than
being silently filled in — a misconfigured client should be visible.
"""

from __future__ import annotations

import json
import os
from typing import Any

DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "config.json",
)


def _deep_merge(base, override):
    """Recursively merge `override` into `base`, returning a new dict.

    Dicts are merged key-by-key; everything else is replaced. This is how
    a user's config file is combined with the built-in defaults: anything
    the user has set wins, anything missing falls back to the default.
    """
    if not isinstance(base, dict) or not isinstance(override, dict):
        return override
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _migrate_legacy(data):
    """Turn flat server/auth keys into a preset list when the file has them.

    Older config files store the server as `server.host` / `server.port`
    and the credentials as `auth.username` / `auth.password`. The GUI now
    picks a server from a preset dropdown, so migrate those values into a
    preset on load rather than losing them.

    The check is "has host but no presets", not just "no presets": the
    default config already ships with presets, so a plain `if not presets`
    would never fire for a user file merged on top of the defaults.
    """
    server = data.setdefault("server", {})
    host = server.get("host")
    if not host:
        return
    presets = server.get("presets", [])
    # Already migrated, or the flat host matches an existing preset: nothing
    # to do. The default config ships presets whose host equals the flat
    # server.host, so this check must compare values, not just presence.
    if presets and any(p.get("host") == host for p in presets):
        return
    port = server.get("port", 33009)
    auth = data.get("auth", {})
    name = str(host)
    server["presets"] = [{
        "name": name,
        "host": host,
        "port": port,
        "username": auth.get("username", ""),
        "password": auth.get("password", ""),
    }]
    server["active"] = name


class Config:
    def __init__(self, path=None, data=None):
        self.path = path or DEFAULT_CONFIG_PATH
        self._data = data if data is not None else self._load()

    @staticmethod
    def _load():
        # No server is baked in: this is a public codebase, and shipping
        # someone's server list would both leak it and be wrong for anyone
        # else. The user adds their server on first run; it lands in
        # config.json next to the executable.
        return {
            "server": {
                "presets": [],
                "active": "",
                # legacy flat fields kept for backward compatibility with
                # code that reads server.host / auth.username directly
                "host": "",
                "port": 33009,
            },
            "auth": {"username": "", "password": ""},
            "proxy": {
                "listen": "127.0.0.1",
                "mixed": 20808,   # HTTP + SOCKS5 on one port
                "socks": 3080,    # dedicated SOCKS5
                "socks5": 3080,   # legacy alias
                "http": 20808,    # legacy alias (same as mixed)
                "pac": 20811,     # PAC script (mixed + 3)
                "xray_api": 20812,  # mixed + 4
                "mihomo_api": 20813,  # mixed + 5
            },
            "tun": {"enabled": False, "interface": "letuc-tun",
                    "address": "10.8.0.1", "mtu": 1400},
            "dns": {"leak_detection": True, "upstreams": [
                "https://dns.alidns.com/dns-query",
                "https://94.140.14.14/dns-query"]},
            "anti_detection": {
                "dns_leak_detection": True,
                "webrtc_block": False,
                "system_proxy_exceptions":
                    "localhost;127.*;10.*;172.*;192.168.*",
                "clock_check_on_startup": True},
        }

    def get(self, *keys, default=None):
        node: Any = self._data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    def set(self, value, *keys):
        node = self._data
        for k in keys[:-1]:
            node = node.setdefault(k, {})
        node[keys[-1]] = value

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, ensure_ascii=False, indent=2)

    @classmethod
    def load_from_file(cls, path):
        """Load a config file, merging in defaults for anything missing.

        Old config files store the server as flat keys (server.host /
        auth.username / ...). Those are migrated into a preset list on load
        so the preset dropdown and the connection code keep working
        without losing the user's data.
        """
        if not os.path.exists(path):
            return cls(path=path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        defaults = cls._load()
        merged = _deep_merge(defaults, data)
        _migrate_legacy(merged)
        return cls(path=path, data=merged)


__all__ = ["Config", "DEFAULT_CONFIG_PATH"]