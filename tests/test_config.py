"""Config tests."""

import os

import pytest

from letuc.util.config import Config


def test_defaults_present():
    c = Config()
    # The public build ships no server presets — the user adds their own
    # on first run, and they land in config.json.
    presets = c.get("server", "presets", default=[])
    assert presets == []
    assert c.get("server", "port") == 33009
    assert c.get("proxy", "mixed") == 20808
    assert c.get("proxy", "socks") == 3080
    assert c.get("proxy", "pac") == 20811
    assert c.get("proxy", "xray_api") == 20812
    assert c.get("proxy", "mihomo_api") == 20813


def test_legacy_flat_server_migrates_to_preset():
    c = Config(data={
        "server": {"host": "203.0.113.10", "port": 33009},
        "auth": {"username": "u", "password": "p"},
    })
    from letuc.util.config import _migrate_legacy
    _migrate_legacy(c._data)
    presets = c.get("server", "presets")
    assert len(presets) == 1
    assert presets[0]["host"] == "203.0.113.10"
    assert presets[0]["username"] == "u"
    assert c.get("server", "active") == "203.0.113.10"


def test_set_and_get():
    c = Config()
    c.set("new-host", "server", "host")
    assert c.get("server", "host") == "new-host"


def test_missing_returns_default():
    c = Config()
    assert c.get("nope", "nope", default="x") == "x"


def test_save_and_reload(tmp_path):
    path = str(tmp_path / "cfg.json")
    c = Config(path=path)
    c.set("changed", "server", "host")
    c.save()
    assert os.path.exists(path)
    c2 = Config.load_from_file(path)
    assert c2.get("server", "host") == "changed"