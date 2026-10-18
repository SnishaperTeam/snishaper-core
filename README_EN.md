# snishaper-core

[中文](README.md) | [English](README_EN.md) | [Русский](README_RU.md)

[![Go Version](https://img.shields.io/badge/Go-1.27%2B-00ADD8?style=flat&logo=go)](https://golang.org) [![License](https://img.shields.io/badge/License-AGPL--3.0-blue?style=flat&logo=open-source-initiative)](LICENSE) [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/SnishaperTeam/snishaper-core/build.yml?style=flat&logo=githubactions&label=CI)](https://github.com/SnishaperTeam/snishaper-core/actions) [![GitHub last commit](https://img.shields.io/github/last-commit/SnishaperTeam/snishaper-core?style=flat&logo=git&label=last%20commit)](https://github.com/SnishaperTeam/snishaper-core/commits/main) [![GitHub contributors](https://img.shields.io/github/contributors/SnishaperTeam/snishaper-core?style=flat&label=contributors)](https://github.com/SnishaperTeam/snishaper-core/graphs/contributors)

**snishaper-core** is the core proxy library shared by [SniShaper](https://github.com/SnishaperTeam/SniShaper) and [FlowWeaver](https://github.com/SnishaperTeam/FlowWeaver), providing an embeddable, testable Go data plane for hostile network environments through a **hybrid-port proxy**, **rule engine with MITM**, **ECH injection**, **TLS fragmentation**, **DoH resolution**, and a **TUN dataplane**.

The library has zero global mutable state: silent by default, no environment reads, no `os.Exit` — every behavior is injected via functional options.

---

## Downstream projects

This library is embedded by two applications; all three are maintained in parallel:

| | [SniShaper](https://github.com/SnishaperTeam/SniShaper) | [FlowWeaver](https://github.com/SnishaperTeam/FlowWeaver) | snishaper-core (this repo) |
|---|---|---|---|
| Role | Lightweight proxy server (GUI + CLI) | Full-featured client / gateway | Embeddable Go core library |
| Key capabilities | UI, system proxy, tray, evolution mode | Clash subscriptions, multi-protocol nodes, WireGuard, TUN gateway | ProxyServer, RuleManager, DoH, certificates, TUN dataplane |
| Audience | End users | End users | Go developers |

Both applications depend on this library directly; the product name is injected via `config.Brand` (SniShaper uses the default `SniShaper`, FlowWeaver injects `FlowWeaver`). Rule file formats and configuration semantics stay consistent across all three.

---

## Features

- **Hybrid-port proxy**: HTTP CONNECT and SOCKS5 on a single port.
- **Rule engine with MITM**: site groups, multiple modes (MITM / Transparent / TLS-RF / QUIC / Migration / Direct), on-demand certificate minting.
- **Subscriptions & node protocols**: Clash subscription parsing, outbound node protocols (vmess / vless / trojan / shadowsocks / hysteria / tuic / wireguard, etc.), rules can bind to subscription node groups.
- **ECH injection**: DoH discovery, hot reload and recovery.
- **TLS fragmentation**: ClientHello splitting with OOB delivery.
- **Smart routing**: GFWList suffix matching and auto routing.
- **Encrypted DNS**: multi-node DoH failover resolution.
- **Cloudflare IP pool**: health checks, latency tests, NAT64.
- **TUN dataplane**: transparent hijacking based on sing-tun (Handler / Manager split).
- **Zero global state**: no `init()`, no package-level mutable state; multi-instance and concurrency safe.

---

## Quick Start

```go
rm := proxy.NewRuleManager(
    filepath.Join(dir, "config", "settings.json"),
    filepath.Join(dir, "rules", "config.json"),
)
if err := rm.LoadConfig(); err != nil { /* ... */ }

p := proxy.NewProxyServer("127.0.0.1:8080",
    proxy.WithRuleManager(rm),
    proxy.WithLogger(corelog.Std), // silent by default; inject to get logs
)
p.Start()
```

Runnable version: the [`examples/basic`](examples/basic) sample in this repo:

```powershell
go run ./examples/basic 8080
```

---

## Packages

| Package | Description |
|---------|-------------|
| `proxy` | ProxyServer (hybrid port), RuleManager (rule engine), AutoRouter, MITM, upstream dialing |
| `subscription` | Clash subscription download/parsing, node storage and protocol outbound (mihomo adapters) |
| `dohresolver` | Multi-node DoH failover with ECH config hot repair |
| `cfpool` | Cloudflare preferred-IP pool |
| `netiface` | Physical interface selection and outbound binding (`Selector`) |
| `tlsfrag` | TLS ClientHello fragmentation and OOB delivery |
| `gfwlist` | GFWList domain suffix matching |
| `certmanager` | CA generation, MITM certificate minting, system trust installation |
| `singtun` | sing-tun based TUN dataplane |
| `config` | Shared configuration types (`CertVerifyConfig` etc.) |
| `log` | `Logger` interface with `Nop` / `Std` / `Func` adapters |

---

## Documentation

- **[docs/DESIGN.md](docs/DESIGN.md)** — library design, package boundaries and de-globalization conventions.
- **[examples/basic](examples/basic)** — minimal embedder sample.
- **[SniShaper Wiki](https://github.com/SnishaperTeam/SniShaper/wiki)** — core modes, custom rules and other app-level docs.
- **[FlowWeaver Wiki](https://github.com/SnishaperTeam/FlowWeaver/wiki)** — subscription import, node protocols and client-side docs.

---

## Build & Development

The library is written in **Go**, minimum version **1.27**. Pre-commit gates:

```powershell
go build ./...
go vet ./...
go test ./...
```

`proxy/proxy_integration_test.go` is an end-to-end smoke test that uses exported APIs only.

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for contribution guidelines.

---

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0). This library derives from SniShaper; derivatives and distributions must follow the same license.
