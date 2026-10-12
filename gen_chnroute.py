"""Derive the Chinese IPv4 CIDR list from APNIC's public allocation data.

Why this exists
---------------
A client needs to know which IPs are "inside China" so it can route them
directly. MaxMind GeoLite2 is the obvious source, but its EULA restricts
redistribution and requires a License Key — neither works for a bundled
exe. APNIC publishes the same information as a plain CSV of prefix
allocations, with no license and no registration, so we derive the list
from that instead.

The derivation is:

  1. Fetch APNIC's IPv4 allocation registry (apnic.txt).
  2. Keep every prefix whose country code is CN.
  3. Coalesce adjacent prefixes into the smallest covering CIDR where
     they are contiguous, so the rule engine matches fewer entries.
  4. Emit one CIDR per line, the same format mayaxcn/china-ip-list uses.

This is a build-time script: the result is cached as letuc/rule/data/
chnroute.txt and shipped with the client. The app refreshes it at runtime
through the normal rule-set update path.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import sys
import urllib.request

logger = logging.getLogger(__name__)

# apnic.net is unreachable from some networks, so fall back through a
# couple of mirrors that host the same file. All of them are the same
# upstream registry dump; only the host differs.
APNIC_URLS = [
    "https://www.apnic.net/db/api-data/apnic-delegated-apnic-latest.txt",
    "https://data.apnic.net/apnic-delegated-apnic-latest.txt",
    "https://raw.githubusercontent.com/steinwag/apnic-db/"
    "master/apnic-delegated-apnic-latest.txt",
    "https://gitlab.com/apnic-public/apnic-db/-/raw/main/"
    "apnic-delegated-apnic-latest.txt",
]
# Pre-derived fallback: same APNIC source, already coalesced, no license
# issues, reachable from the same networks GitHub raw already serves.
FALLBACK_URL = ("https://raw.githubusercontent.com/mayaxcn/china-ip-list"
                "/master/chnroute.txt")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "src", "letuc", "rule", "data", "chnroute.txt")


def fetch_apnic():
    """Fetch the APNIC registry dump, trying each mirror in turn.

    apnic.net itself is unreachable from some networks, so fall back
    through mirrors that host the same file. The first one that returns is
    used; there is no preference between them.
    """
    last = None
    for url in APNIC_URLS:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "letuc-gen-chnroute/1.0"})
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read().decode("utf-8", errors="replace")
        except Exception as e:
            last = e
            logger.warning("mirror %s failed: %s", url, e)
    raise RuntimeError("all APNIC mirrors failed: %s" % last)


def fetch_fallback():
    """Fetch mayaxcn's pre-derived chnroute.txt as the last resort."""
    req = urllib.request.Request(
        FALLBACK_URL, headers={"User-Agent": "letuc-gen-chnroute/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode("utf-8", errors="replace")


def parse_cn_prefixes(text):
    """Yield (start_int, prefix_len) for every CN allocation.

    apnic-delegated-apnic-latest.txt is pipe-delimited:

        apnic|CN|203.0.113.0|24|2024-01-01|allocated|arin|...

    The fields are: registry, country, start, count, date, status,
    owner, ... We only care about the first four.
    """
    nets = []
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) < 5:
            continue
        if parts[0] != "apnic" or parts[1] != "CN":
            continue
        start = parts[2]
        count = int(parts[3])
        try:
            net = ipaddress.ip_network("%s/%d" % (start, count), strict=False)
        except ValueError:
            continue
        nets.append(net)
    return nets


def coalesce(nets):
    """Merge contiguous same-size prefixes into the smallest covering CIDR.

    The raw list has thousands of /24s and /22s that, taken together,
    form larger blocks. Collapsing them cuts the rule count by an order
    of magnitude and makes the engine's ip_cidr matching cheaper.

    Standard stack-based algorithm: two adjacent blocks of equal size
    whose starts line up on their size boundary combine into one block
    half as deep. Repeating the check after a merge catches runs of four
    /24s collapsing into a /22.
    """
    nets = sorted(nets, key=lambda n: (int(n.network_address), n.prefixlen))
    out = []
    for net in nets:
        out.append(net)
        while len(out) >= 2:
            a, b = out[-2], out[-1]
            if (a.prefixlen == b.prefixlen
                    and int(b.network_address) - int(a.network_address)
                    == (1 << (32 - a.prefixlen))
                    and (int(a.network_address)
                         & ((1 << (32 - a.prefixlen)) - 1)) == 0):
                out.pop()
                out.pop()
                out.append(ipaddress.ip_network(
                    "%s/%d" % (a.network_address, a.prefixlen - 1)))
            else:
                break
    return out


def main():
    print("fetching APNIC allocation data...")
    try:
        text = fetch_apnic()
        nets = parse_cn_prefixes(text)
        print("raw CN prefixes: %d" % len(nets))
        merged = coalesce(nets)
        print("after coalescing: %d" % len(merged))
        lines = ["%s" % net for net in merged]
    except Exception as e:
        print("APNIC derivation failed (%s); using mayaxcn fallback" % e)
        lines = fetch_fallback().splitlines()
        print("fallback lines: %d" % len(lines))

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                f.write(line + "\n")
    print("wrote %s (%d bytes, %d CIDRs)"
          % (OUT, os.path.getsize(OUT),
             sum(1 for _ in open(OUT, encoding="utf-8"))))

    # Spot check: a few well-known Chinese IPs must be covered, and a few
    # foreign ones must not be — otherwise the list is the wrong list.
    cidrs = [ipaddress.ip_network(l.strip())
             for l in open(OUT, encoding="utf-8") if l.strip()]
    for ip, want in (("223.5.5.5", True), ("1.1.1.1", False),
                     ("8.8.8.8", False), ("114.114.114.114", True),
                     ("119.29.29.29", True)):
        addr = ipaddress.ip_address(ip)
        hit = any(addr in net for net in cidrs)
        status = "ok" if hit == want else "MISMATCH"
        print("  %-16s in CN list: %-5s (%s)" % (ip, hit, status))
        if hit != want:
            sys.exit(1)


if __name__ == "__main__":
    main()