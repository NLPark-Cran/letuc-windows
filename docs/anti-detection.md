# anti-detection design

Goal: use AI services without being bitten by DNS leaks, WebRTC probes, or
system proxy leakage.

## 1. DNS leak protection

### 1.1 The problem

Browsers and the OS can resolve names directly, bypassing the proxy and
leaking the real IP.

### 1.2 What letuc does

- All name resolution is done by the client's own resolver.
- Primary upstream is DoH (`dns.alidns.com`, `94.140.14.14`); plain UDP 53
  is the fallback.
- A background checker periodically queries public resolvers for a fixed
  set of names and compares answers against the client's own results. A
  mismatch is a suspected leak and gets logged.

### 1.3 Config

```json
{
  "dns": {
    "leak_detection": true,
    "upstreams": [
      "https://dns.alidns.com/dns-query",
      "https://94.140.14.14/dns-query"
    ]
  }
}
```

## 2. WebRTC leak protection

### 2.1 The problem

WebRTC's STUN handshake can expose local addresses even when a proxy is
active.

### 2.2 What letuc does

- No browser extension (out of scope for v1).
- When TUN is on, STUN traffic to ports 3478/3479 can be intercepted.
- A short guide below for disabling WebRTC per browser.

### 2.3 Manual steps

- **Chrome / Edge**: `chrome://flags` → search "WebRTC" → disable
  "WebRTC Pipewire" / use an extension that blocks non-proxied ICE candidates.
- **Firefox**: `about:config` → `media.peerconnection.enabled` → false.
- **Safari**: System Settings → Privacy → uncheck "Share my location" and
  disable WebRTC where exposed.

## 3. System proxy leakage

### 3.1 The problem

A domain marked `direct` in the rules must not be written into the system
proxy, or it will be routed through the proxy anyway.

### 3.2 What letuc does

- Direct domains are connected straight up; they never touch the system
  proxy.
- The system proxy exception list mirrors v2rayN's
  `SystemProxyItem.SystemProxyExceptions`:
  ```
  localhost;127.*;10.*;172.*;192.168.*;203.0.113.10
  ```

## 4. Clock skew

The mieru key is derived from a 2-minute time grid and the server tolerates
4 minutes of drift. On startup letuc checks the offset against a public NTP
source and warns if it is out of range.

### 4.1 Config

```json
{
  "anti_detection": {
    "dns_leak_detection": true,
    "webrtc_block": false,
    "system_proxy_exceptions": "localhost;127.*;10.*;172.*;192.168.*;203.0.113.10",
    "clock_check_on_startup": true
  }
}
```