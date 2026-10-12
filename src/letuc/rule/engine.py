"""Rule engine: map a destination to an outbound decision.

Matching types:
  domain         exact domain match
  domain_suffix  suffix match (a domain matches its own suffix too)
  domain_keyword substring match
  ip_cidr        CIDR match
  default        unconditional fallback

Outbounds: direct / proxy / block. First matching rule wins.
"""

from __future__ import annotations

import ipaddress
import json
import os
from typing import Iterable

# rules.json lives next to this module
_RULES_PATH = os.path.join(os.path.dirname(__file__), "rules.json")


def load_rules(path=None):
    with open(path or _RULES_PATH, encoding="utf-8") as f:
        return json.load(f).get("rules", [])


class RuleEngine:
    def __init__(self, rules=None):
        self._rules = rules if rules is not None else load_rules()
        self._compiled = []
        for r in self._rules:
            try:
                self._compiled.append(self._compile(r))
            except ValueError:
                logger.warning("rule skipped: %r", r)

    @staticmethod
    def _compile(rule):
        rtype = rule.get("type", "default")
        outbound = rule.get("outbound", "proxy")
        if rtype == "ip_cidr":
            patterns = []
            for cidr in rule.get("ip_cidr", []):
                try:
                    patterns.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass
        elif rtype in ("domain", "domain_suffix", "domain_keyword"):
            # Normalise suffixes up front so ".cn" and "cn" behave the same
            # in match(), and strip accidental whitespace that would otherwise
            # make a keyword like " bilibili" silently miss everything.
            patterns = [p.strip().lstrip(".") for p in rule.get(rtype, [])]
        else:
            patterns = rule.get(rtype, [])
        return rtype, patterns, outbound

    def match(self, domain, ip=None):
        domain = (domain or "").lower()
        ip_obj = None
        # A bare IP passed as the domain is an IP destination, not a DNS
        # name: parse it here so the ip_cidr rules get a chance to match
        # before the default rule sends it to proxy.
        if not ip:
            try:
                ip_obj = ipaddress.ip_address(domain)
            except ValueError:
                ip_obj = None
        if ip:
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                ip_obj = None

        for rtype, patterns, outbound in self._compiled:
            if rtype == "default":
                return outbound
            if rtype == "domain":
                if domain in [p.lower() for p in patterns]:
                    return outbound
            elif rtype == "domain_suffix":
                # Patterns are normalised at compile time, so ".cn" and
                # "cn" are identical here. A suffix matches the domain
                # itself and any subdomain.
                for p in patterns:
                    pl = p.lower()
                    if domain == pl or domain.endswith("." + pl):
                        return outbound
            elif rtype == "domain_keyword":
                # Patterns are normalised at compile time, so " bilibili"
                # and "bilibili" are identical here.
                for p in patterns:
                    if p.lower() in domain:
                        return outbound
            elif rtype == "ip_cidr":
                if ip_obj is not None:
                    for net in patterns:
                        if ip_obj in net:
                            return outbound
        return "proxy"


__all__ = ["RuleEngine", "load_rules"]