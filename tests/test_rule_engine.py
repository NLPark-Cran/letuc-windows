"""Rule engine tests."""
import pytest

from letuc.rule.engine import RuleEngine


@pytest.fixture
def engine():
    rules = [
        {"type": "domain", "domain": ["www.google.com"], "outbound": "proxy"},
        {"type": "domain_suffix", "domain_suffix": [".cn"], "outbound": "direct"},
        {"type": "domain_keyword", "domain_keyword": ["baidu"], "outbound": "direct"},
        {"type": "ip_cidr", "ip_cidr": ["10.0.0.0/8", "192.168.0.0/16"], "outbound": "direct"},
        {"type": "default", "outbound": "proxy"},
    ]
    return RuleEngine(rules)


def test_domain_match(engine):
    assert engine.match("www.google.com", "1.2.3.4") == "proxy"


def test_domain_suffix_match(engine):
    assert engine.match("www.baidu.com", "1.2.3.4") == "direct"
    assert engine.match("example.cn", "1.2.3.4") == "direct"


def test_domain_keyword_match(engine):
    assert engine.match("m.baidu.com", "1.2.3.4") == "direct"


def test_ip_cidr_match(engine):
    assert engine.match("anything.local", "10.0.0.1") == "direct"
    assert engine.match("anything.local", "192.168.1.1") == "direct"


def test_default_fallback(engine):
    assert engine.match("unknown.example", "8.8.8.8") == "proxy"


def test_first_match_wins(engine):
    assert engine.match("baidu.cn", "1.2.3.4") == "direct"


def test_load_default_rules():
    """The shipped rule set is 广告屏蔽 / 境内直连 / 保留地址直连 / 其余代理.

    8.8.8.8 is a routable public address, so it goes direct even though
    the domain is google.com — the IP rule beats the domain rule.
    """
    e = RuleEngine()
    assert e.match("www.baidu.com", "1.2.3.4") == "direct"
    assert e.match("www.google.com", "8.8.8.8") == "direct"
    assert e.match("localhost", "127.0.0.1") == "direct"
    # Public DNS resolvers bypass the proxy so name resolution itself
    # never loops through the tunnel.
    assert e.match("x", "223.5.5.5") == "direct"
    # A foreign domain with no IP is resolved through the default rule and
    # goes proxy; the catch-all 255.0.0.0/8 only fires when an IP is given.
    assert e.match("www.youtube.com", None) == "proxy"
    assert e.match("ads.google.com", "1.2.3.4") == "block"


def test_empty_domain_with_ip(engine):
    assert engine.match("", "10.0.0.5") == "direct"


def test_invalid_ip(engine):
    assert engine.match("x", "not-an-ip") == "proxy"