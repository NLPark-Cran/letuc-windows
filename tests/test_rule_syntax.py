"""Tests for the natural rule syntax used by the GUI rules tab.

Each line reads like a sentence: "<value> 需要直连" / "走代理" / "需要屏蔽".
The value is auto-classified as domain / domain_suffix / ip_cidr.
"""

from letuc.ui.main import _parse_rules, _rules_to_text


def test_parse_domain_proxy_and_direct():
    rules, err = _parse_rules(
        "google.com 走代理\n"
        "baidu.com 需要直连\n"
        "8.8.8.8 需要屏蔽")
    assert err is None
    assert len(rules) == 3
    assert rules[0] == {"type": "domain", "domain": ["google.com"],
                        "outbound": "proxy"}
    assert rules[1]["outbound"] == "direct"
    assert rules[2]["type"] == "ip_cidr"
    assert rules[2]["ip_cidr"] == ["8.8.8.8/32"]


def test_parse_suffix_and_cidr():
    rules, err = _parse_rules(
        "*.cn 需要直连\n"
        "192.168.0.0/16 要直连")
    assert err is None
    assert rules[0]["type"] == "domain_suffix"
    assert rules[0]["domain_suffix"] == [".cn"]
    assert rules[1]["ip_cidr"] == ["192.168.0.0/16"]


def test_parse_proxy_word_variants():
    for word in ("走代理", "要代理", "代理"):
        rules, err = _parse_rules("google.com %s" % word)
        assert err is None, word
        assert rules[0]["outbound"] == "proxy"


def test_parse_direct_word_variants():
    for word in ("需要直连", "要直连", "直连"):
        rules, err = _parse_rules("google.com %s" % word)
        assert err is None, word
        assert rules[0]["outbound"] == "direct"


def test_parse_block_word_variants():
    for word in ("需要屏蔽", "屏蔽", "拦截"):
        rules, err = _parse_rules("8.8.8.8 %s" % word)
        assert err is None, word
        assert rules[0]["outbound"] == "block"


def test_parse_ignores_comments_and_blanks():
    rules, err = _parse_rules(
        "# a comment\n\n   \n"
        "google.com 走代理")
    assert err is None
    assert len(rules) == 1


def test_parse_missing_outbound():
    _, err = _parse_rules("google.com")
    assert err is not None
    assert "直连" in err or "代理" in err or "屏蔽" in err


def test_parse_missing_value():
    _, err = _parse_rules("走代理")
    assert err is not None


def test_parse_empty():
    _, err = _parse_rules("# only comments")
    assert err is not None


def test_roundtrip_text():
    rules, _ = _parse_rules(
        "google.com 走代理\n"
        "*.cn 需要直连\n"
        "192.168.0.0/16 需要屏蔽")
    text = _rules_to_text(rules)
    rules2, err = _parse_rules(text)
    assert err is None
    assert rules2 == rules