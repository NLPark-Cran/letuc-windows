# PRD — letuc

版本：v0.1（草案）
作者：NLPark-Cran
状态：已实现 v0.1

---

## 1. 产品定位

**一句话**：个人代理服务的专用 Windows 客户端 —— 简易、轻量、可读、可开 TUN、对 AI 服务探测不敏感。

**不是什么**：
- 不是 mieru 官方客户端的 fork。
- 不是 sing-box / mihomo / v2rayN 的套壳。
- 不做订阅管理、不做节点测速、不做订阅链接解析。

**目标用户**：我自己（小 crina），以及可能借用同一套配置的朋友。

**服务端**：`203.0.113.10:33009`（mieru / TCP）
**账号**：`your-username` / `your-password`

---

## 2. 用户需求（原话整理）

1. "界面要尽可能简易好开发"
2. "实现也尽量简单"
3. "具备正常的规则代理功能"
4. "或许需要 TUN？因为我的朋友可能需要能在终端当中被正常代理"
5. "在使用 Anthropic 的 AI 服务时不被各种侦测探测恶心到（比如 DNS 泄露？比如 WebRTC 探测？）"
6. "规则可以学习我本地的 D:\v2rayN-windows-64 里面的"

---

## 3. 功能清单

### 3.1 核心协议（MVP，必须）

| 编号 | 功能 | 说明 |
| |------|------|
| F1 | mieru 客户端协议栈 | 实现 openSession / data / ack / closeSession 四种元数据类型，XChaCha20-Poly1305 加密，key 由 username+password+时间（2 分钟粒度）派生 |
| F2 | TCP 代理 | socks5 + HTTP/HTTPS 本地监听 |
| F3 | UDP 代理 | socks5 UDP Associate（含 mieru 自身的 UDP 封装） |
| F4 | 配置管理 | JSON 配置文件：server、user、portBindings、mtu、本地监听端口 |

### 3.2 规则引擎（MVP，必须）

| 编号 | 功能 | 说明 |
| |------|------|
| F5 | 规则匹配 | domain / domain_suffix / domain_keyword / ip_cidr / default，首个命中为准 |
| F6 | 规则文件 | `rules.json`，格式参考 v2rayN 的 pac.txt + sing-box 的 rule_set |
| F7 | 出站决策 | 匹配 -> direct / proxy / block，按顺序，首个命中为准 |
| F8 | 默认规则 | 中国域名直连、私有地址直连、其余走代理 |

### 3.3 TUN（V1，需要）

| 编号 | 功能 | 说明 |
| |------|------|
| F9 | TUN 虚拟网卡 | 基于 wintun.dll，创建虚拟适配器 |
| F10 | 路由表 | 按规则把流量导向 TUN 或跳过 |
| F11 | 终端进程代理 | 通过 TUN 让 cmd/powershell/git 等无感知地走代理 |

### 3.4 防探测（V1，需要）

| 编号 | 功能 | 说明 |
| |------|------|
| F12 | DNS 防泄漏 | 所有 DNS 请求强制走本客户端解析，不泄漏到系统 DNS；支持 DoH/DoT |
| F13 | DNS 劫持防护 | 检测并拦截 DNS 劫持（异常响应、TTL 异常） |
| F14 | WebRTC 防护 | 禁用浏览器 WebRTC 或拦截本地 IP 泄漏（需配合浏览器扩展或策略） |
| F15 | 系统代理泄漏防护 | 确保直连域名不走系统代理；例外列表可配 |
| F16 | 时钟偏移防护 | 客户端与服务端时间差 > 4 分钟时告警并拒绝连接 |

### 3.5 界面（MVP，必须）

| 编号 | 功能 | 说明 |
| |------|------|
| F17 | 主窗口 | 服务器/端口/账号显示、启停按钮、状态指示、流量统计 |
| F18 | 规则编辑 | 可查看/编辑 rules.json |
| F19 | 配置编辑 | 可编辑连接参数 |
| F20 | 日志 | 实时滚动日志，可筛选级别 |
| F21 | 系统托盘 | 最小化到托盘，右键启停 |

### 3.6 工程（非功能但必须）

| 编号 | 要求 |
| |------|
| F22 | 单元测试：协议编解码、规则匹配、TUN 路由 |
| F23 | PyInstaller 单文件 exe 打包 |
| F24 | GitHub 托管 + MIT License |
| F25 | CHANGELOG / Release Notes |

---

## 4. 非目标（明确不做）

- 不做节点订阅、节点管理、延迟测速
- 不做分流规则的 GUI 可视化编排（只提供 JSON 编辑）
- 不做浏览器插件（WebRTC 防护靠系统策略 + 提示用户）
- 不做 macOS / Linux 版本（第一版只 Windows）
- 不做多用户、多配置文件切换
- 不做流量统计图表（只保留启停和实时速率）

---

## 5. 规则引擎设计

### 5.1 规则格式（参考 v2rayN pac.txt + sing-box rule_set）

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
      "domain_suffix": [".cn", ".cn"],
      "outbound": "direct"
    },
    {
      "type": "domain_keyword",
      "domain_keyword": ["baidu", "alibaba"],
      "outbound": "direct"
    },
    {
      "type": "ip_cidr",
      "ip_cidr": ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"],
      "outbound": "direct"
    },
    {
      "type": "default",
      "outbound": "proxy"
    }
  ]
}
```

### 5.2 匹配优先级

按数组顺序，**首个命中为准**。`default` 规则放在最后兜底。

### 5.3 出站

- `direct` — 直连，不走代理，不走系统代理
- `proxy` — 走 mieru 代理
- `block` — 直接拒绝

### 5.4 默认规则集（内置，可覆盖）

```
1. domain_suffix: .cn / .中国 / .公司 / .网络  -> direct
2. domain_keyword: baidu, alibaba, weibo, qq, ... -> direct
3. ip_cidr: 私有地址                            -> direct
4. ip_cidr: 127.0.0.1                          -> direct
5. ip_cidr: 203.0.113.10 (服务端自身)          -> direct
6. default                                     -> proxy
```

---

## 6. 防探测设计

### 6.1 DNS 泄漏

- **所有域名解析由本客户端接管**：进程发出的 DNS 请求被 TUN/系统 DNS 劫持层截获，走客户端内置 resolver。
- **内置 resolver**：优先 DoH（`dns.alidns.com` / `94.140.14.14`），fallback 直连 UDP 53。
- **泄漏检测**：周期性向 `dns.google` / `cloudflare` 发起查询，比对响应 IP 是否与客户端解析结果一致；不一致则告警。
- **配置项**：`dns.leak_detection` 开关、`dns.upstream` 列表。

### 6.2 WebRTC 泄漏

- **不实现浏览器插件**（非目标）。
- **提供系统级防护**：通过 Windows 策略 / 组策略提示关闭 WebRTC，或在 TUN 模式下拦截 `127.0.0.1` / 局域网 IP 的 STUN 请求。
- **文档**：`docs/anti-detection.md` 给出各浏览器的 WebRTC 关闭步骤。

### 6.3 系统代理泄漏

- 直连规则的域名**不写入系统代理**，由客户端直接建立连接。
- 例外列表（`SystemProxyItem.SystemProxyExceptions`，参考 v2rayN guiNConfig.json）：`localhost;127.*;10.*;172.*;192.168.*;203.0.113.10;...`

### 6.4 时钟偏移

- 客户端启动时检查与 NTP 的时间差，> 4 分钟时弹窗提示同步时钟（mieru 协议要求时间差 < 4 分钟）。

---

## 7. 技术选型

| 层 | 选型 | 理由 |
|---|---|---|
| 语言 | Python 3.11+ | 开发快、跨平台、社区库多 |
| 协议实现 | 自研（纯 Python） | mieru 协议不复杂，自研可控、无 GPL 传染 |
| 加密 | `cryptography` 库的 XChaCha20-Poly1305 | AEAD，协议要求 24 字节 nonce |
| TUN | `wintun.dll`（随仓库发布） | 微软官方，免费、稳定 |
| GUI | PyQt6 | 界面简易、原生观感、系统托盘支持好 |
| 打包 | PyInstaller | 单文件 exe |
| 测试 | pytest | 见 `tests/` |

---

## 8. 里程碑

| 阶段 | 内容 | 交付 |
| |------|------|
| M0 | PRD 评审 + 仓库骨架 + AGENTS.md | 本文件 |
| M1 | mieru 协议实现 + 单元测试 | `src/letuc/core/protocol.py` + `tests/test_protocol.py` |
| M2 | socks5/HTTP 代理 + 规则引擎 | `src/letuc/proxy/*` + `src/letuc/rule/*` |
| M3 | TUN + 路由 | `src/letuc/proxy/tun.py` |
| M4 | DNS 防泄漏 + WebRTC 防护 | `src/letuc/dns/*` + `docs/anti-detection.md` |
| M5 | GUI + 系统托盘 | `src/letuc/ui/main.py` |
| M6 | 打包 + GitHub Release | `build/*.exe` |

---

## 9. 验收标准

1. `python main.py` 启动，GUI 显示连接状态。
2. 本地 socks5（默认 1080）可用，浏览器走代理访问 google.com。
3. `.cn` 域名直连，不走代理。
4. TUN 模式下 `cmd` 里 `curl google.com` 走代理。
5. DNS 泄漏测试：客户端解析结果与泄漏检测一致。
6. `pytest tests/` 全部通过。
7. `pyinstaller` 打出单文件 exe，双击可运行。

---

## 10. 附录

### A. mieru 协议要点（来自 enfein/mieru）

- 加密：XChaCha20-Poly1305，nonce 24 字节。
- key 生成：`PBKDF2(SHA-256(password\0+username), SHA-256(uint64(unixTime rounded to 2 min)), 64, 32)`。
- 客户端/服务端时间差必须 < 4 分钟，服务端最多尝试 3 个 timeSalt。
- 分段：padding0 + nonce + encrypted_metadata(32) + auth(16) + padding1 + payload + auth(16) + padding2。
- TCP：nonce 只在每个方向的第一个 segment 出现，之后每次加密 nonce +1。
- UDP：每个 segment 都带 nonce。
- 元数据类型：openSession=2, openSessionResponse=3, closeSession=4, closeSessionResponse=5, dataClientToServer=6, dataServerToClient=7, ackClientToServer=8, ackServerToClient=9。
- UDP Associate 封装：`0x00 + len(2) + data + 0xff`。

### B. v2rayN 规则来源

- `guiConfigs/pac.txt`：域名白名单列表（直连/代理）。
- `binConfigs/configPre.json`：sing-box 配置，含 `dns.rules`（domain / domain_suffix / rule_set）。
- `guiConfigs/guiNConfig.json`：`SystemProxyItem.SystemProxyExceptions` 例外列表。

### C. 服务端信息

```
ip: 203.0.113.10
port: 33009
protocol: TCP
user: your-username
password: your-password
```