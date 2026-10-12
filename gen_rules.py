"""Generate the default rules.json from the community rule sets.

Run this once before the first release to seed letuc/rule/data/ with the
curated lists, and letuc/rule/rules.json with the merged result. After
that, the app updates the data files itself at runtime.

    python gen_rules.py            # download + merge
    python gen_rules.py --verify   # download + merge + assert coverage

The China IP list is derived from APNIC's CIDR allocation data, which is
public and free of the MaxMind licensing issues that make GeoLite2
unsuitable for a bundled client. The derivation is a pure-Python script
(no external database) so it stays reproducible on any machine.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
from letuc.rule import rulesets  # noqa: E402

# Sanity checks that would otherwise only surface at runtime, on a user's
# machine, with a user's network. Catch them here, at release time.
MIN_ENTRIES = {
    "direct-list.txt": 1000,
    "accelerated-domains.china.conf": 1000,
    "reject-list.txt": 100,
    "pro.txt": 1000,
    "chnroute.txt": 100,
}


def main():
    verify = "--verify" in sys.argv
    print("downloading rule sets...")
    results = rulesets.fetch_all(force=True)
    for name, path in results.items():
        if path is None or not os.path.exists(path):
            print("  MISSING", name)
            if verify:
                sys.exit(1)
            continue
        n = sum(1 for _ in rulesets._read_lines(path))
        print("  %-40s %8d entries" % (name, n))
        if verify and n < MIN_ENTRIES.get(name, 0):
            print("  !! %s has only %d entries, expected >= %d"
                  % (name, n, MIN_ENTRIES[name]))
            sys.exit(1)

    path, count = rulesets.write_rules()
    print("wrote %s: %d rules" % (path, count))

    # The default rules.json must not be empty: a missing file means the
    # engine silently falls back to "everything goes proxy".
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert data.get("rules"), "rules.json has no rules"
    assert data["rules"][-1].get("type") == "default", \
        "last rule must be the catch-all default"

    if verify:
        # And the engine must classify the obvious cases the way a user
        # would expect, otherwise the merge silently produced a broken list.
        from letuc.rule.engine import RuleEngine
        e = RuleEngine(data["rules"])
        checks = [
            ("baidu.com", None, "direct"),
            ("google.com", None, "proxy"),
            ("192.168.1.1", None, "direct"),
            ("8.8.8.8", None, "direct"),
            ("1.1.1.1", None, "direct"),
            ("example.com", None, "proxy"),
        ]
        for domain, ip, want in checks:
            got = e.match(domain, ip)
            assert got == want, "%s -> %s, expected %s" % (domain, got, want)
        print("coverage checks passed")


if __name__ == "__main__":
    main()