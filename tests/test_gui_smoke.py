"""GUI smoke test: build the widget tree headless and exercise the rules
tab round-trip. Runs under the Qt minimal platform so no display is needed.

The previous version hung because `_on_apply_rules` opened a
`QMessageBox.critical` on bad JSON; a modal dialog blocks the event loop
in headless mode. Errors are now reported through the log line instead.
"""

import os

import pytest


@pytest.fixture(autouse=True)
def _offscreen():
    os.environ.setdefault("QT_QPA_PLATFORM", "minimal")


def _stub():
    from letuc.rule.engine import RuleEngine
    from letuc.util.config import Config

    class Stub:
        pass

    la = Stub()
    la.config = Config()
    la.user_rules = []
    la.community_rules = []
    la.engine = RuleEngine()
    la.client = None
    la.socks5 = None
    la.http = None
    la.loop = None
    la.window = None

    def _rebuild():
        la.engine = RuleEngine(la.user_rules + la.community_rules)

    la.rebuild_engine = _rebuild
    return la


def test_gui_builds_and_rules_roundtrip():
    from PyQt6.QtWidgets import QApplication
    from letuc.ui.main import MainWindow

    app = QApplication.instance() or QApplication([])

    w = MainWindow(_stub())
    w.show()
    app.processEvents()

    assert w.centralWidget().count() == 3
    assert w.centralWidget().tabText(0) == "连接"
    assert w.centralWidget().tabText(1) == "规则"
    assert w.centralWidget().tabText(2) == "日志"

    # The rules tab lists the user's custom rules only (community coverage
    # is a status line, not 380k list entries), so a fresh stub starts empty.
    assert w.rule_list.count() == 0
    assert w.rule_value is not None
    assert w.rule_outbound is not None

    # Adding a rule works without crashing the app. The value field feeds
    # the parser now, not a hardcoded dummy string.
    before = w.rule_list.count()
    w.rule_value.setText("example.com")
    w.rule_outbound.setCurrentIndex(1)
    w._on_add_rule()
    app.processEvents()
    assert w.rule_list.count() == before + 1
    assert "example.com" in w.rule_list.item(0).text()

    # Deleting a rule works.
    w._on_del_rule()
    app.processEvents()
    assert w.rule_list.count() == before

    # Editing the selected rule and applying it works.
    w._on_add_rule()
    w.rule_value.setText("google.com")
    w.rule_outbound.setCurrentIndex(1)  # 代理
    w._on_apply_rule_edit()
    app.processEvents()
    assert w.rule_list.count() == before + 1


def test_connection_tab_reads_config():
    from PyQt6.QtWidgets import QApplication
    from letuc.ui.main import MainWindow

    app = QApplication.instance() or QApplication([])

    w = MainWindow(_stub())
    # No server ships with the public build: the fields start empty and
    # carry their defaults as placeholder text.
    assert w.host_edit.text() == ""
    assert w.port_edit.text() == ""
    assert w.port_edit.placeholderText() == "33009"
    assert w.user_edit.text() == ""
    assert w.mixed_edit.text() == "20808"
    assert w.socks_edit.text() == "3080"
    assert w.tun_check.isChecked() is False
    assert w.leak_check.isChecked() is True
    # advanced settings are collapsed by default
    assert w.proxy_box.isVisible() is False
    assert w.mtu_edit.isVisible() is False


def test_toggle_advanced_settings():
    from PyQt6.QtWidgets import QApplication
    from letuc.ui.main import MainWindow

    app = QApplication.instance() or QApplication([])

    w = MainWindow(_stub())
    w.show()
    app.processEvents()
    w.advanced_btn.setChecked(True)
    w._toggle_advanced()
    app.processEvents()
    assert w.proxy_box.isVisible() is True
    assert w.mtu_edit.isVisible() is True
    assert "▾" in w.advanced_btn.text()


def test_legacy_config_migrates_to_presets(tmp_path):
    """Old flat-key configs must still load and populate the preset dropdown."""
    from PyQt6.QtWidgets import QApplication
    from letuc.rule.engine import RuleEngine
    from letuc.util.config import Config
    from letuc.ui.main import MainWindow

    path = str(tmp_path / "old.json")
    with open(path, "w", encoding="utf-8") as f:
        f.write('{"server": {"host": "1.2.3.4", "port": 1234}, '
                '"auth": {"username": "u", "password": "p"}}')

    app = QApplication.instance() or QApplication([])

    la = _stub()
    la.config = Config.load_from_file(path)
    la.engine = RuleEngine()

    w = MainWindow(la)
    assert w.host_edit.text() == "1.2.3.4"
    assert w.port_edit.text() == "1234"
    assert w.user_edit.text() == "u"
    assert w.preset_combo.count() == 1