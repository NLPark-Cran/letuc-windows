"""Download and merge community rule sets into the local rules.json.

Why this exists
---------------
The hand-written default rules cover the obvious cases (CN domains, private
CIDRs, a few ad keywords), but a proxy client is only as good as its rule
list, and the rule list is only as good as its coverage. The V2Ray / sing-box
ecosystem has spent years curating exactly this data, so rather than
reinvent it we pull from the same sources and merge into our own format.

Sources (all plain text, no protobuf, no external dependencies):

  direct-list.txt    Loyalsoldier/v2ray-rules-dat   CN + Apple-CN domains
  proxy-list.txt     Loyalsoldier/v2ray-rules-dat   geolocation-!cn
  reject-list.txt    Loyalsoldier/v2ray-rules-dat   category-ads-all
  accelerated-...    felixonmars/dnsmasq-china-list Chinese domains
  china.txt          mayaxcn/china-ip-list         Chinese IPv4
  pro.txt            HaGeZi/dns-blocklists          ad + tracker blocklist

All of them are plain text: one entry per line, `#` starts a comment.
That is the only format our engine needs, so no conversion is required.

Caching
-------
Each file is cached under letuc/rule/data/<name> next to the source tree.
On update we send a HEAD with If-Modified-Since (the local mtime) and only
re-download on a 200. Any failure — 404, timeout, DNS failure — falls back
to the cached copy silently so a bad network day never breaks the client.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Iterable

logger = logging.getLogger(__name__)

_HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(_HERE, "data")

# When frozen, the bundled data dir is extracted to PyInstaller's temp
# directory (sys._MEIPASS), not next to the exe. Resolve it the same way
# the icon loader does so the cached rule sets are found regardless of
# how the client was launched.
if getattr(sys, "frozen", False):
    _meipass = getattr(sys, "_MEIPASS", None)
    if _meipass:
        _candidate = os.path.join(_meipass, "letuc", "rule", "data")
        if os.path.isdir(_candidate):
            DATA_DIR = _candidate

# name -> (url, kind, outbound, update_seconds)
#   kind: "domain" entries are treated as domain_suffix (suffix match is the
#         right semantics for a curated list where every line is a domain
#         that should be matched exactly or as a subdomain).
#   kind: "cidr" entries are ip_cidr.
#   update_seconds: how often to re-check; ad lists change most often.
SOURCES = {
    "direct-list.txt": (
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat"
        "/release/direct-list.txt",
        "domain", "direct", 86400),
    "proxy-list.txt": (
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat"
        "/release/proxy-list.txt",
        "domain", "proxy", 86400),
    "reject-list.txt": (
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat"
        "/release/reject-list.txt",
        "domain", "block", 86400),
    "accelerated-domains.china.conf": (
        "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list"
        "/master/accelerated-domains.china.conf",
        "domain", "direct", 86400),
    "chnroute.txt": (
        # mayaxcn/china-ip-list publishes chnroute.txt, not china.txt. The
        # filename is the only thing that changed between versions; the
        # content is the same APNIC-sourced Chinese IPv4 list.
        "https://raw.githubusercontent.com/mayaxcn/china-ip-list"
        "/master/chnroute.txt",
        "cidr", "direct", 86400),
    "pro.txt": (
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest"
        "/dnsmasq/pro.txt",
        "domain", "block", 604800),
}

# Ad keywords we keep in the hand-written rules even when the lists above
# are present: the curated lists are domain-based and miss the substring
# style matches that catch ad-tech hostnames we do not have a list for.
_FALLBACK_ADS = [
    "ads", "ad", "adservice", "adserver", "adsystem", "adtech",
    "advertising", "analytics", "track", "tracker", "telemetry",
    "beacon", "ping", "stat", "metrics", "measure",
    "doubleclick", "googlesyndication", "google-analytics",
    "facebook", "fbcdn", "twimg", "t.co", "bit.ly", "goo.gl",
    "cloudflare", "akamai", "fastly", "cdn", "cnd",
]

# Private / special-use ranges. Hard-coded: no external data source covers
# these reliably, and they never change.
_PRIVATE_CIDRS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
    "198.51.100.0/24", "203.0.113.0/24",
    "::1/128", "fc00::/7", "fe80::/10", "::ffff:0:0/96",
]

# Public DNS resolvers that should never be proxied — if we proxy the very
# resolver the client uses, nothing resolves at all.
_DNS_CIDRS = [
    "1.1.1.1/32", "8.8.8.8/32", "8.8.4.4/32", "9.9.9.9/32",
    "149.112.112.112/32", "223.5.5.5/32", "223.6.6.6/32",
    "114.114.114.114/32", "114.114.115.115/32", "180.76.76.76/32",
    "119.29.29.29/32", "119.28.28.28/32",
]


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _writable_dir():
    """Where downloaded rule sets are cached for updates.

    The bundled copy under DATA_DIR ships read-only inside the exe, so
    writing updated lists there would fail. Cache next to the config
    file instead — the same place the user's own settings live.
    """
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
    return os.path.join(base, "rule_data")


def _cache_path(name):
    """Return the path where a rule set is read from.

    Reads prefer the writable cache (updated at runtime) and fall back to
    the bundled copy shipped with the exe on first launch.
    """
    cached = os.path.join(_writable_dir(), name)
    if os.path.exists(cached):
        return cached
    return os.path.join(DATA_DIR, name)


def _read_lines(path):
    """Yield non-empty, non-comment lines from a rule-set text file."""
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                yield line


def _etag_path(target):
    """Sidecar file holding the ETag of the cached rule set.

    Last-Modified is stored implicitly in the file mtime, but some mirrors
    (GitHub raw included) send an ETag that is the real freshness signal
    and rotate Last-Modified on every deploy. Persisting it lets a later
    HEAD compare against the exact value the server sent.
    """
    return target + ".etag"


def _read_etag(target):
    p = _etag_path(target)
    if not os.path.exists(p):
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return f.read().strip() or None
    except OSError:
        return None


def _write_etag(target, etag):
    if not etag:
        return
    try:
        with open(_etag_path(target), "w", encoding="utf-8") as f:
            f.write(etag)
    except OSError:
        pass


def _head(url, since=None):
    """Send a conditional HEAD. Returns (status, last_modified, etag)."""
    import urllib.request
    req = urllib.request.Request(url, method="HEAD",
                                 headers={"User-Agent": "letuc/1.0"})
    if since:
        req.add_header("If-Modified-Since", since)
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status, r.headers.get("Last-Modified"), r.headers.get("ETag")


def _get(url):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "letuc/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def fetch_one(name, force=False):
    """Download one rule set, caching it on disk.

    Returns the local path on success (possibly the existing cache when the
    remote has not changed), or None when the download failed and there is
    no cached copy to fall back to.

    The conditional-GET dance has a deliberate fallback: some mirrors
    (GitHub raw included) answer HEAD with a truncated TLS session that
    then breaks the GET. When the HEAD itself fails we do a plain GET and
    compare ETag / Last-Modified against the cache, which costs a little
    bandwidth on a flaky link but never loses the update.
    """
    url, kind, _out, _ttl = SOURCES[name]
    target = _cache_path(name)
    _ensure_dir()

    cached_etag = _read_etag(target)
    cached_lm = None
    if os.path.exists(target) and not force:
        cached_lm = time.strftime(
            "%a, %d %b %Y %H:%M:%S GMT", time.gmtime(os.path.getmtime(target)))

    etag = None
    try:
        status, lm, etag = _head(url, since=cached_lm)
        if status == 304:
            return target
        if status == 200 and etag and etag == cached_etag:
            return target
        if status == 200 and lm and lm == cached_lm:
            return target
    except Exception as e:
        logger.debug("rule set %s: HEAD failed (%s), trying GET", name, e)

    try:
        data = _get(url)
    except Exception as e:
        logger.warning("rule set %s: download failed (%s), using cache",
                       name, e)
        return target if os.path.exists(target) else None

    with open(target, "wb") as f:
        f.write(data)
    _write_etag(target, etag)
    logger.info("rule set %s: downloaded %d bytes", name, len(data))
    return target


def fetch_all(force=False):
    """Fetch every configured rule set. Returns {name: path_or_None}."""
    out = {}
    for name in SOURCES:
        out[name] = fetch_one(name, force=force)
    return out


def build_rules():
    """Assemble the full rule list from cached files + hand-written defaults.

    Order matters: the engine is first-match-wins, so put the most specific
    rules first (blocklist, private ranges, CN) and leave the catch-all
    proxy last.

    Returns a list of rule dicts ready for RuleEngine.
    """
    rules = []

    # 1. Blocklist first so nothing ad-related ever slips through.
    block_keywords = list(_FALLBACK_ADS)
    block_suffixes = []
    for name in ("reject-list.txt", "pro.txt"):
        path = _cache_path(name)
        if os.path.exists(path):
            block_suffixes.extend(_read_lines(path))
    if block_suffixes:
        rules.append({"type": "domain_suffix",
                      "domain_suffix": block_suffixes,
                      "outbound": "block"})
    if block_keywords:
        rules.append({"type": "domain_keyword",
                      "domain_keyword": block_keywords,
                      "outbound": "block"})

    # 2. Private ranges and public DNS never leave the machine.
    rules.append({"type": "ip_cidr", "ip_cidr": _PRIVATE_CIDRS,
                  "outbound": "direct"})
    rules.append({"type": "ip_cidr", "ip_cidr": _DNS_CIDRS,
                  "outbound": "direct"})

    # 3. CN domains and Chinese IPs are direct.
    direct_suffixes = []
    for name in ("direct-list.txt", "accelerated-domains.china.conf"):
        path = _cache_path(name)
        if os.path.exists(path):
            direct_suffixes.extend(_read_lines(path))
    if direct_suffixes:
        rules.append({"type": "domain_suffix",
                      "domain_suffix": direct_suffixes,
                      "outbound": "direct"})
    china_path = _cache_path("china.txt")
    if os.path.exists(china_path):
        cidrs = list(_read_lines(china_path))
        if cidrs:
            rules.append({"type": "ip_cidr", "ip_cidr": cidrs,
                          "outbound": "direct"})

    # 4. Everything else goes through the proxy.
    proxy_path = _cache_path("proxy-list.txt")
    if os.path.exists(proxy_path):
        suffixes = list(_read_lines(proxy_path))
        if suffixes:
            rules.append({"type": "domain_suffix",
                          "domain_suffix": suffixes,
                          "outbound": "proxy"})

    rules.append({"type": "default", "outbound": "proxy"})
    return rules


def write_rules(path=None):
    """Persist the assembled rules to a JSON file (default: rules.json)."""
    import json
    if path is None:
        path = os.path.join(_HERE, "rules.json")
    rules = build_rules()
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"rules": rules}, f, ensure_ascii=False, indent=2)
    return path, len(rules)


def cached_files():
    """Return {name: path} for every rule set currently on disk."""
    out = {}
    for name in SOURCES:
        p = _cache_path(name)
        if os.path.exists(p):
            out[name] = p
    return out


def cache_size():
    """Total bytes of cached rule sets, for the status line."""
    n = 0
    for p in cached_files().values():
        try:
            n += os.path.getsize(p)
        except OSError:
            pass
    return n


__all__ = [
    "fetch_all", "fetch_one", "build_rules", "write_rules",
    "cached_files", "cache_size", "DATA_DIR",
]