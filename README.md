# snishaper-core

[中文](README.md) | [English](README_EN.md) | [Русский](README_RU.md)

[![Go Version](https://img.shields.io/badge/Go最低版本-1.27%2B-00ADD8?style=flat&logo=go)](https://golang.org) [![License](https://img.shields.io/badge/许可证-AGPL--3.0-blue?style=flat&logo=open-source-initiative)](LICENSE) [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/SnishaperTeam/snishaper-core/build.yml?style=flat&logo=githubactions&label=持续集成)](https://github.com/SnishaperTeam/snishaper-core/actions) [![GitHub last commit](https://img.shields.io/github/last-commit/SnishaperTeam/snishaper-core?style=flat&logo=git&label=最后提交)](https://github.com/SnishaperTeam/snishaper-core/commits/main) [![GitHub contributors](https://img.shields.io/github/contributors/SnishaperTeam/snishaper-core?style=flat&label=总贡献者)](https://github.com/SnishaperTeam/snishaper-core/graphs/contributors)

**snishaper-core** 是 [SniShaper](https://github.com/SnishaperTeam/SniShaper) 的核心代理库，通过 **混合端口代理**、**规则引擎与 MITM**、**ECH 注入**、**TLS 分片**、**DoH 解析** 与 **TUN 数据面** 等能力，为复杂网络环境提供可嵌入、可测试的 Go 数据面。

本库零全局可变状态：默认零日志、不读环境变量、不调用 `os.Exit`，全部行为通过 functional options 注入。

---

## 与 SniShaper 的关系

[SniShaper](https://github.com/SnishaperTeam/SniShaper) 是基于本库构建的 Windows / Linux 桌面应用（GUI + CLI），两者**并行维护**：

| | [SniShaper](https://github.com/SnishaperTeam/SniShaper) | snishaper-core（本仓库） |
|---|---|---|
| 定位 | 桌面应用（GUI + CLI） | 可嵌入的 Go 核心库 |
| 核心能力 | 界面、系统代理、托盘、进化模式 | ProxyServer、RuleManager、DoH、证书、TUN 数据面 |
| 面向对象 | 最终用户 | Go 开发者 |

SniShaper 直接依赖本库；规则文件格式与配置语义在两者间保持一致。

---

## 特性

- **混合端口代理**：单端口同时提供 HTTP CONNECT 与 SOCKS5。
- **规则引擎与 MITM**：站点分组、多模式（MITM / Transparent / TLS-RF / QUIC / Migration / Direct）、按需证书签发。
- **订阅与节点协议**：Clash 订阅解析，节点协议出站（vmess / vless / trojan / shadowsocks / hysteria / tuic / wireguard 等），规则可绑定订阅节点组。
- **ECH 注入**：DoH 发现、热更新与恢复。
- **TLS 分片**：ClientHello 分片与 OOB 发送。
- **智能分流**：GFWList 后缀匹配与自动路由。
- **加密 DNS**：多节点 DoH 故障切换解析。
- **Cloudflare 优选 IP 池**：健康检查、测速与 NAT64。
- **TUN 数据面**：基于 sing-tun 的透明劫持（Handler / Manager 分离）。
- **零全局状态**：无 `init()`、无包级可变状态，可多实例、可并发嵌入。

---

## 快速开始

```go
rm := proxy.NewRuleManager(
    filepath.Join(dir, "config", "settings.json"),
    filepath.Join(dir, "rules", "config.json"),
)
if err := rm.LoadConfig(); err != nil { /* ... */ }

p := proxy.NewProxyServer("127.0.0.1:8080",
    proxy.WithRuleManager(rm),
    proxy.WithLogger(corelog.Std), // 库默认静默，注入才有日志
)
p.Start()
```

可运行版本见本仓库示例 [`examples/basic`](examples/basic)：

```powershell
go run ./examples/basic 8080
```

---

## 包一览

| 包 | 说明 |
|----|------|
| `proxy` | ProxyServer（混合端口）、RuleManager（规则引擎）、AutoRouter、MITM、上游拨号 |
| `subscription` | Clash 订阅下载解析、节点存储与协议出站（mihomo 适配器） |
| `dohresolver` | DoH 多节点故障切换与 ECH 配置热修复 |
| `cfpool` | Cloudflare 优选 IP 池 |
| `netiface` | 物理网卡选择与出站绑定（`Selector`） |
| `tlsfrag` | TLS ClientHello 分片与 OOB 发送 |
| `gfwlist` | GFWList 域名后缀匹配 |
| `certmanager` | CA 生成、MITM 证书签发、系统信任安装 |
| `singtun` | 基于 sing-tun 的 TUN 数据面 |
| `config` | 跨包共享配置类型（`CertVerifyConfig` 等） |
| `log` | `Logger` 接口与 `Nop` / `Std` / `Func` 适配器 |

---

## 文档

- **[docs/DESIGN.md](docs/DESIGN.md)** — 库设计、包边界与去全局化约定。
- **[examples/basic](examples/basic)** — 最小嵌入示例。
- **[SniShaper Wiki](https://github.com/SnishaperTeam/SniShaper/wiki)** — 核心模式、规则自定义等应用层文档。

---

## 构建与开发

本库使用 **Go** 开发，最低版本 **1.27**。提交前门槛：

```powershell
go build ./...
go vet ./...
go test ./...
```

`proxy/proxy_integration_test.go` 提供仅使用导出 API 的端到端冒烟测试。

贡献指南见 **[CONTRIBUTING.md](CONTRIBUTING.md)**。

---

## 许可

[GNU Affero General Public License v3.0](LICENSE)（AGPL-3.0）。本库衍生自 SniShaper，衍生与分发须遵循同一许可证。
