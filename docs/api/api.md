# snishaper-core API 文档

`snishaper-core` 是 SnishaperTeam 全系产品（SniShaper 桌面版、Lumine Android 版等）共用的 Go 核心库。本页是全量中文 API 参考，按包分页组织。

> 模块路径：`github.com/SnishaperTeam/snishaper-core`
>
> 引入方式：`go get github.com/SnishaperTeam/snishaper-core`

## 包总览

### 核心引擎

| 包 | 作用 |
|----|------|
| [proxy](proxy.md) | 代理引擎：MITM/SOCKS5 服务器、TLS 分片、QUIC 重建、规则匹配（RuleManager / ProxyServer） |
| [evolution](evolution.md) | 规则演化：tester / generator / analyzer，用真实连通性数据自动进化分流规则 |

### 流量处理

| 包 | 作用 |
|----|------|
| [tlsfrag](tlsfrag.md) | TLS 记录分片（TLS-RF），把 Client Hello 拆分为多个记录绕过 DPI |
| [quicrewrite](quicrewrite.md) | QUIC 连接重写的底层支撑件 |
| [singtun](singtun.md) | 基于 sing-tun 的 TUN 虚拟网卡接入，全局流量接管 |

### 证书与域名

| 包 | 作用 |
|----|------|
| [certmanager](certmanager.md) | MITM CA 证书生成、管理与安装向导 |
| [dohresolver](dohresolver.md) | DoH（DNS over HTTPS）解析器 |
| [cfpool](cfpool.md) | Cloudflare IP 池拉取与延迟测速，优选最快节点 |
| [gfwlist](gfwlist.md) | GFWList 被封锁域名列表加载 |

### 系统集成

| 包 | 作用 |
|----|------|
| [sysproxy](sysproxy.md) | 系统代理设置（Windows 注册表等平台的进程级封装） |
| [netiface](netiface.md) | 网卡枚举与默认路由查询 |
| [subscription](subscription.md) | 订阅链接抓取与解析 |
| [config](config.md) | 统一配置模型 |
| [log](log.md) | 日志门面，供宿主应用注入自身日志实现 |
| [openutil](openutil.md) | 跨平台"用系统默认程序打开文件/URL"工具 |
| [atomicfile](atomicfile.md) | 原子写文件（写临时文件后 rename），避免半写状态 |

## 快速上手

```bash
go get github.com/SnishaperTeam/snishaper-core
```

```go
package main

import (
    "fmt"
    "os"
    "os/signal"
    "syscall"

    corelog "github.com/SnishaperTeam/snishaper-core/log"
    "github.com/SnishaperTeam/snishaper-core/proxy"
)

func main() {
    // RuleManager 读取设置与规则文件；文件不存在时生成默认配置。
    rm := proxy.NewRuleManager("config/settings.json", "rules/config.json")
    if err := rm.LoadConfig(); err != nil {
        panic(err)
    }

    p := proxy.NewProxyServer("127.0.0.1:8080",
        proxy.WithRuleManager(rm),
        proxy.WithLogger(corelog.Std), // 库默认静默，显式注入才有日志
    )
    if err := p.Start(); err != nil {
        panic(err)
    }
    fmt.Println("listening on 127.0.0.1:8080 (HTTP + SOCKS5)")

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
    <-sig
    if err := p.Stop(); err != nil {
        panic(err)
    }
}
```

> 完整可运行版本见 [examples/basic](https://github.com/SnishaperTeam/snishaper-core/tree/main/examples/basic)，各构造参数以 [proxy](proxy.md) 页为准。

## 设计约定

- **零全局可变状态**：所有引擎组件都是实例化对象，可随宿主应用生命周期启停，可多实例共存。
- **日志注入**：组件不直接打日志到全局 logger，统一通过构造函数注入 `log.Logger`。
- **functional options**：可配置组件的构造函数采用 options 模式（`WithXxx`），未指定的项走默认值。
- **平台隔离**：平台相关实现（Windows 注册表、TUN 等）封装在独立包内，接口保持跨平台一致。

## 其他资源

- GitHub：[SnishaperTeam/snishaper-core](https://github.com/SnishaperTeam/snishaper-core)
- 设计文档：[docs/DESIGN.md](https://github.com/SnishaperTeam/snishaper-core/blob/main/docs/DESIGN.md)
- pkg.go.dev：[github.com/SnishaperTeam/snishaper-core](https://pkg.go.dev/github.com/SnishaperTeam/snishaper-core)
