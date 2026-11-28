# dohresolver 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/dohresolver`

## 概述

`dohresolver` 实现带节点故障转移的 DoH（DNS over HTTPS）解析器。按启用节点顺序查询，主节点失败时并发转移其余节点；支持 ECH（Encrypted Client Hello）与 QUIC（HTTP/3）节点、ECH 配置自动恢复/刷新、A/AAAA 双栈并发查询、解析结果正缓存（2 分钟新鲜 + 24 小时 stale-while-revalidate）与失败负缓存（15 秒，吸收死域名重试风暴）、同域名解析 singleflight（并发调用只发一次真实查询）。DoH 客户端按节点配置指纹缓存复用（上限 16 个，LRU 淘汰）。

DoH 请求携带浏览器形态的 User-Agent（共享前缀 + 产品名 token），因为有些解析器直接拒绝非浏览器客户端。

## 类型别名

### CertVerifyConfig

```go
type CertVerifyConfig = config.CertVerifyConfig
```

重新导出 `config` 包的证书校验配置类型（类型别名），方便调用方只 import 本包。

## DNSNode

一个 DoH 上游节点。

```go
type DNSNode struct {
    Name          string           `json:"name"`
    URL           string           `json:"url"`            // DoH 服务地址
    SNI           string           `json:"sni"`            // 自定义 SNI
    ECHEnabled    bool             `json:"ech_enabled"`    // 节点是否启用 ECH
    ECHProfileID  string           `json:"ech_profile_id"` // ECH 配置档案 ID
    QUIC          bool             `json:"quic"`           // 是否走 QUIC/HTTP3
    IPs           []string         `json:"ips"`            // 预置的节点 IP
    CertVerify    CertVerifyConfig `json:"cert_verify"`    // 证书校验策略
    ECHAutoUpdate bool             `json:"ech_auto_update"`
    Enabled       bool             `json:"enabled"`        // 是否启用
}
```

## Rule

DoH 解析时按域名应用的策略。

```go
type Rule struct {
    SniFake       string
    ECHEnabled    bool
    ECHProfileID  string
    CertVerify    CertVerifyConfig
    ECHAutoUpdate bool
}
```

## ProxyServer

抽象接口，表达 DoH 模块对代理底层网络传输和安全状态的依赖。由宿主应用的代理服务器实现。

```go
type ProxyServer interface {
    DialWithRule(ctx context.Context, network, addr string, rule Rule) (net.Conn, error)
    GetUConn(conn net.Conn, sni, verifyName string, rule Rule, allowUnknownAuthority bool, alpn string, ech []byte) *utls.UConn
    ResolveRuleECHConfig(host string, rule Rule) []byte
    UpdateECHProfileConfig(profileID string, configBytes []byte)
    // GetPhysicalBinding 返回与目标地址 IP 族匹配的出站网卡绑定信息。
    // TUN 模式下用于把 QUIC/UDP socket 绑到物理网卡，绕过 TUN 避免流量回环。
    GetPhysicalBinding(targetAddr string) (netiface.Binding, bool)
}
```

## Option

`NewFailoverResolver` 的函数式选项。

```go
type Option func(*FailoverResolver)
```

### WithLogger

注入用于 DoH 握手恢复跟踪的 logger（默认 `log.Nop`：未配置的解析器保持静默）。

```go
func WithLogger(l corelog.Logger) Option
```

### WithBrand

声明嵌入应用，为 DoH User-Agent 提供产品 token。

```go
func WithBrand(b config.Brand) Option
```

## FailoverResolver

带节点故障转移的 DoH 解析器。用 `NewFailoverResolver` 构造。

### NewFailoverResolver

```go
func NewFailoverResolver(proxy ProxyServer, getNodes func() []DNSNode, opts ...Option) *FailoverResolver
```

基于代理适配器和 `getNodes` 返回的 DNS 节点创建故障转移解析器。`getNodes` 在每次查询时调用，节点配置可动态变化。

```go
r := dohresolver.NewFailoverResolver(
    proxyServer,
    func() []dohresolver.DNSNode { return nodes },
    dohresolver.WithBrand(config.Brand{}),
    dohresolver.WithLogger(log.Std),
)
defer r.Close()
```

### 方法总览

| 方法 | 作用 |
|---|---|
| `Exchange(ctx, msg)` | 按启用节点顺序执行 DNS 报文交换，失败时自动转移到下一节点 |
| `ExchangeSafe(ctx, msg)` | 只用未启用 ECH 的节点执行 DNS 查询 |
| `ResolveIPs(ctx, domain)` | 解析域名返回 IP 字符串列表（带缓存） |
| `ResolveIPAddrs(ctx, domain)` | 解析域名返回 `[]net.IP`（A/AAAA 并发查询，不带缓存） |
| `ResolveECH(ctx, domain)` | 通过 TypeHTTPS (65) 记录获取域名的 ECH 配置 |
| `ResolveECHSafe(ctx, domain)` | 通过标准（无 ECH）节点获取域名的 ECH 配置 |
| `TestNode(ctx, node)` | 用解析 cloudflare.com 的方式探测节点，返回解析到的 A 记录 |
| `Close()` | 释放所有缓存的 DoH 客户端 |

### 方法签名

```go
func (r *FailoverResolver) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
func (r *FailoverResolver) ExchangeSafe(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
func (r *FailoverResolver) ResolveIPs(ctx context.Context, domain string) ([]string, error)
func (r *FailoverResolver) ResolveIPAddrs(ctx context.Context, domain string) ([]net.IP, error)
func (r *FailoverResolver) ResolveECH(ctx context.Context, domain string) ([]byte, error)
func (r *FailoverResolver) ResolveECHSafe(ctx context.Context, domain string) ([]byte, error)
func (r *FailoverResolver) TestNode(ctx context.Context, node DNSNode) ([]string, error)
func (r *FailoverResolver) Close()
```

### Exchange

先串行试主节点，失败后并发其余启用节点，任一成功即返回。所有节点失败时返回聚合错误。

```go
msg := new(dns.Msg)
msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
resp, err := r.Exchange(ctx, msg)
```

### ResolveIPs

解析域名并返回 IP 字符串列表。先查正缓存（新鲜直接返回；过期但未超 24 小时返回旧值并后台刷新），再走 singleflight 真实解析；真实失败写入 15 秒负缓存（调用方被取消不写），期间重试立即失败。

```go
ips, err := r.ResolveIPs(ctx, "example.com")
```

### ResolveIPAddrs

解析域名并返回 `net.IP` 列表。并发查询 A 与 AAAA，IPv4 结果在前，调用方按 dns_mode 自行排序/过滤。不经过缓存。

```go
ipAddrs, err := r.ResolveIPAddrs(ctx, "example.com")
```

### TestNode

用解析 `cloudflare.com` 的方式探测节点（无视 `Enabled` 字段直接使用传入节点），返回解析到的 A 记录。用于设置界面的节点连通性测试。

```go
ips, err := r.TestNode(ctx, node)
```

### Close

释放所有缓存的 DoH 客户端：关闭 QUIC 连接、其底层 UDP socket 以及 TCP 空闲连接。停止代理或切换 TUN 模式（出站绑定网卡变化）后必须调用，否则连接与 goroutine 会泄漏。

### ECH 解析

```go
echConfig, err := r.ResolveECH(ctx, "cloudflare-ech.com")
// 若 ECH 节点自身握手失败，可用安全节点获取 ECH 配置：
echConfig, err = r.ResolveECHSafe(ctx, "cloudflare-ech.com")
```
