# rule engine design

## 1. Goal

Rules are readable and editable JSON. Matching logic stays small enough to
hold in your head. First matching rule wins; a `default` rule at the end
catches everything else.

v1 does not depend on external GeoIP/GeoSite databases. The built-in set is
a hand-written starter that covers the common cases.

## 2. Rule format

```json
{
  "rules": [
    {
      "type": "domain",
      "domain": ["www.google.com"],
      "outbound": "proxy"
    },
    {
      "type": "domain_suffix",
      "domain_suffix": [".cn"],
      "outbound": "direct"
    },
    {
      "type": "domain_keyword",
      "domain_keyword": ["baidu"],
      "outbound": "direct"
    },
    {
      "type": "ip_cidr",
      "ip_cidr": ["10.0.0.0/8", "192.168.0.0/16"],
      "outbound": "direct"
    },
    {
      "type": "default",
      "outbound": "proxy"
    }
  ]
}
```

## 3. Matching types

| type | field | meaning |
|---|---|---|
| `domain` | `domain[]` | exact domain match |
| `domain_suffix` | `domain_suffix[]` | suffix match (a domain matches its own suffix too) |
| `domain_keyword` | `domain_keyword[]` | substring match |
| `ip_cidr` | `ip_cidr[]` | CIDR match |
| `default` | — | unconditional fallback |

## 4. Flow

```
for rule in rules:
    if rule.type == "default":
        return rule.outbound
    for pattern in rule.patterns:
        if match(pattern, dest):
            return rule.outbound
return "proxy"  # final fallback
```

## 5. Outbounds

| outbound | meaning |
|---|---|
| `direct` | connect straight to the target, bypass the proxy |
| `proxy` | route through the mieru client |
| `block` | refuse the connection |

## 6. Built-in default rules

```
1. domain_suffix: .cn / .中国 / .公司 / .网络  -> direct
2. domain_keyword: baidu, alibaba, weibo, qq, ... -> direct
3. ip_cidr: private ranges, loopback, link-local, multicast -> direct
4. ip_cidr: 203.0.113.10 (the server itself) -> direct
5. default -> proxy
```

## 7. Sources

- `D:\v2rayN-windows-64\guiConfigs\pac.txt` — domain allow list
- `D:\v2rayN-windows-64\binConfigs\configPre.json` — sing-box `dns.rules`
- `D:\v2rayN-windows-64\guiConfigs\guiNConfig.json` —
  `SystemProxyItem.SystemProxyExceptions`