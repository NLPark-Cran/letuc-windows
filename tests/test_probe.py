import os

import pytest


@pytest.fixture(autouse=True)
def _offscreen():
    os.environ.setdefault("QT_QPA_PLATFORM", "minimal")


def test_instance_has_attributes():
    from PyQt6.QtWidgets import QApplication
    from letuc.rule.engine import RuleEngine
    from letuc.util.config import Config
    from letuc.ui.main import MainWindow

    app = QApplication.instance() or QApplication([])

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

    w = MainWindow(la)
    for name in ("status_label", "tun_check", "host_edit", "mixed_edit",
                 "rule_list", "rule_value", "rule_outbound",
                 "advanced_btn", "proxy_box", "mtu_edit"):
        assert hasattr(w, name), name