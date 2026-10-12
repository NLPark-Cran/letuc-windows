# Features

| # | feature | status | added |
|---|---------|--------|-------|
| F1 | mieru 客户端协议栈（key derivation / XChaCha20-Poly1305 / 元数据编解码 / TCP 分段 / UDP associate） | done | 2026-10-10 |
| F2 | TCP 代理：socks5 + HTTP/HTTPS 本地监听 | done | 2026-10-10 |
| F3 | UDP 代理：socks5 UDP Associate 封装 | done | 2026-10-10 |
| F4 | JSON 配置文件读写 | done | 2026-10-10 |
| F5 | 规则匹配（domain / domain_suffix / domain_keyword / ip_cidr / default） | done | 2026-10-10 |
| F6 | rules.json 规则文件 + 默认规则集 | done | 2026-10-10 |
| F7 | 出站决策 direct / proxy / block | done | 2026-10-10 |
| F8 | TUN 虚拟网卡（wintun 后端） | scaffold | 2026-10-10 |
| F9 | 终端进程代理（TUN 路由） | scaffold | 2026-10-10 |
| F8b | TUN 路由决策（TunRouter）：私有/广播/组播/服务端直弃，其余按规则出站 | done | 2026-10-10 |
| F8c | TUN 会话承载（client.open_tunnel）+ 读写线程与 asyncio 桥接 | done | 2026-10-10 |
| F10 | DNS 防泄漏（DoH / UDP 解析器 + 泄漏检测） | done | 2026-10-10 |
| F11 | DNS 劫持防护 | todo | — |
| F12 | WebRTC 防护（系统策略 + 文档） | doc | 2026-10-10 |
| F13 | 系统代理泄漏防护 + 例外列表 | done | 2026-10-10 |
| F14 | 时钟偏移告警 | done | 2026-10-10 |
| F15 | PyQt6 GUI：连接 / 规则 / 日志三页签 + 系统托盘 | done | 2026-10-10 |
| F16 | 规则编辑往返校验 | done | 2026-10-10 |
| F17 | 单元测试（pytest，40 条） | done | 2026-10-10 |
| F18 | PyInstaller 单文件 exe 打包 | done | 2026-10-10 |
| F18b | 打包内嵌 Qt platform 插件（qwindows/qminimal/qoffscreen），exe 双击可启动 | done | 2026-10-10 |
| F18c | 打包内嵌 rules.json，冻结态下路径解析正确 | done | 2026-10-10 |
| F19 | GitHub 仓库 + Release | todo | — |