<p align="center">
  <img src="ui/img/avalanche-k2.gif" width="150" alt="rxvpn">
</p>

<h1 align="center">rxvpn</h1>

<p align="center">
  <a href="README.md">Русский</a> · <b>English</b>
</p>

<p align="center">
  <b>An open internet — with one button.</b><br>
  A Windows VPN client that gets around censorship by itself.
</p>

<p align="center">
  <a href="https://github.com/rxsk7/rxVPN/releases/latest"><b>⬇ Download the latest version</b></a>
</p>

<p align="center">
  <img src="docs/img/rxvpn-main.png" width="760" alt="rxvpn main window">
</p>

## Features

**Connecting**
- Modern protocols: **VLESS + Reality**, xHTTP, VMess, Trojan, Shadowsocks, **Hysteria2**.
- Subscriptions from Marzban, Remnawave, 3x-ui and any VPN provider — with remaining traffic and expiry date.
- **⚡ Auto** picks the fastest stable server and switches if it goes down.
- Modes: **Browser** (system proxy), **Whole PC** (TUN — games and any app) and **No VPN**.

**Getting around blocks**
- Route only blocked sites through the VPN, or everything except local sites.
- **YouTube and Discord without a VPN** via zapret (DPI bypass): faster and uses no VPN traffic. rxvpn picks the strategy for you.
- **Telegram without a VPN** with one switch — Telegram opens with “Connect proxy” by itself.
- **“Why won't this site open?”** checks in 10 seconds what your ISP did to a site and suggests the fix.
- **Whitelist mode**: when the mobile network only lets allowed sites through, rxvpn switches to the right server.

**Protection**
- **Kill switch**: if the VPN drops, the internet closes — no app reaches the network with your real IP.
- Tamper-free DNS, leak checks for IP, DNS and IPv6.
- **Your own VPN server in five minutes**: give rxvpn your VPS address and password — it installs and hardens the VPN.
- Signed updates, server passwords encrypted with your Windows account key, no telemetry.

## Getting started

1. [Download](https://github.com/rxsk7/rxVPN/releases/latest) `rxvpn-portable-*.zip` and unpack it anywhere — `D:\rxvpn`, the desktop, a USB stick. Just not into `Program Files`.
2. Run `rxvpn.exe`. Windows may show “Windows protected your PC” — the app isn't code-signed yet: **More info → Run anyway**.
3. Paste a server link or subscription → press the mountain. Done.

<p align="center">
  <img src="docs/img/rxvpn-welcome.png" width="640" alt="First run: three steps">
</p>

rxvpn is **portable**: everything lives in the `data` folder next to it. Move it to another PC by copying the folder (or a backup); remove it by deleting the folder. Updates arrive by themselves: once a day rxvpn checks for a new version and installs it on your click — only if the signature matches.

The interface is in Russian and English; it follows your Windows language, or pick one in Settings.

## FAQ

**My antivirus flags zapret.** Windows Defender labels the WinDivert driver a “hacktool”. rxvpn downloads only the official zapret and checks it by hash. If Defender removes the files, add the `data\zapret` folder to exclusions.

**Why administrator rights?** Only for Whole PC mode, zapret and tamper-free DNS — they change networking for the whole computer. Browser mode works without them.

**Can rxvpn see my traffic?** No. The VPN and Telegram encrypt traffic themselves; rxvpn collects nothing and sends nothing anywhere.

## For developers

Rust (all logic) + Tauri 2 (window) + [Xray-core](https://github.com/XTLS/Xray-core) (protocols). Architecture, building, tests and security details (in Russian) — [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## License and thanks

rxvpn is licensed under [GPL-3.0](LICENSE).

[Xray-core](https://github.com/XTLS/Xray-core) (MPL-2.0) · [zapret](https://github.com/bol-van/zapret) and [Flowseal strategies](https://github.com/Flowseal/zapret-discord-youtube) (MIT) · [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) (MIT) · [Arti](https://gitlab.torproject.org/tpo/core/arti) · [runetfreedom lists](https://github.com/runetfreedom/russia-v2ray-rules-dat) · [Wintun](https://www.wintun.net/)
