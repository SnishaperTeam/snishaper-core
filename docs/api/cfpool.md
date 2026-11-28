# cfpool 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/cfpool`

## 概述

`cfpool` 维护一个带健康检查的 Cloudflare 边缘 IP 池，供 MITM/代理出站直连 Cloudflare 时优选 IP。核心能力：

- 通过 wetest.vip 的 API 拉取优选边缘 IP（`FetchCloudflareIPs` / `FetchCDNIPs`）；
- 后台健康检查协程每 10 分钟全量测活（TCP 拨 443 端口测延迟），连接失败达阈值时触发增量重查；
- 「最快 IP」缓存 5 分钟，`DialParallel` 并发竞速（Happy Eyeballs）选最快可用 IP 并缓存赢家；
- 支持 NAT64：IPv4 地址可按前缀合成 IPv6 地址（`config.MapNAT64Addr`），纯 IPv6 环境下也能直连；
- 所有状态由 `sync.RWMutex` 保护，可并发使用。

## IP 拉取

### FetchCloudflareIPs

从配置的 IP 来源 API（wetest.vip）拉取 Cloudflare 边缘 IP。

```go
func FetchCloudflareIPs(apiKey string) ([]string, error)
```

```go
ips, err := cfpool.FetchCloudflareIPs("your-api-key")
if err == nil {
    pool.UpdateIPs(ips)
    pool.SetLastFetchTime(time.Now())
}
```

### FetchCDNIPs

按 CDN 名称拉取优选边缘 IP。没有拉取源的 CDN 会返回错误——调用方应把它当作「只能手动填 IP 的池」，而不是致命错误。apiKey 为空时使用内置默认 key。

```go
func FetchCDNIPs(cdn string, apiKey string) ([]string, error)
```

### CDNFetchEndpoints

```go
var CDNFetchEndpoints = map[string]string{
    "cloudflare": "get_cloudflare_ip",
}
```

变量：映射「受支持的 CDN 名 → wetest.vip 拉取端点」。不在此映射中的 CDN 没有自动拉取源，只能手动填充 IP。

## CloudflarePool

健康检查的 Cloudflare 边缘 IP 池。用 `NewCloudflarePool` 构造。

### NewCloudflarePool

```go
func NewCloudflarePool(ips []string) *CloudflarePool
```

用给定 IP 作为种子创建池，并把「上次拉取时间」设为当前时间。

```go
pool := cfpool.NewCloudflarePool(ips)
pool.Start()
defer pool.Stop()
```

### 方法总览

| 方法 | 作用 |
|---|---|
| `Start()` | 启动后台健康检查循环（每 10 分钟一轮） |
| `Stop()` | 停止后台健康检查循环，等待协程退出 |
| `TriggerHealthCheck()` | 唤醒后台循环立即执行一轮健康检查 |
| `UpdateIPs(ips []string)` | 替换池成员，保留已知 IP 及其统计 |
| `GetAllIPs() []string` | 返回池中全部 IP，最优在前 |
| `GetAllIPsWithStats() []*IPStats` | 返回全部 IP 及其统计（快照拷贝） |
| `HasIPs() bool` | 池中是否有任何 IP |
| `IsStale(maxAge time.Duration) bool` | 距上次拉取是否超过 maxAge |
| `SetLastFetchTime(t time.Time)` | API 拉取成功后更新拉取时间戳 |
| `SetNAT64Prefix(prefix string)` | 设置合成 NAT64 地址使用的前缀 |
| `DialParallel(ctx, network, port, nat64Prefix)` | 并发建连竞速并缓存最快 IP |
| `CandidateAddrs(port, nat64Prefix string) []string` | 返回可用候选地址（已做 NAT64 映射），不拨号 |
| `ReportFailure(ip string)` | 记录某 IP 连接失败 |
| `ReportSuccess(ip string)` | 记录某 IP 连接成功 |
| `RemoveInvalidIPs() int` | 移除健康检查失败的 IP，返回移除数量 |

### 关键方法签名

```go
func (p *CloudflarePool) Start()
func (p *CloudflarePool) Stop()
func (p *CloudflarePool) TriggerHealthCheck()
func (p *CloudflarePool) UpdateIPs(ips []string)
func (p *CloudflarePool) GetAllIPs() []string
func (p *CloudflarePool) GetAllIPsWithStats() []*IPStats
func (p *CloudflarePool) HasIPs() bool
func (p *CloudflarePool) IsStale(maxAge time.Duration) bool
func (p *CloudflarePool) SetLastFetchTime(t time.Time)
func (p *CloudflarePool) SetNAT64Prefix(prefix string)
func (p *CloudflarePool) DialParallel(ctx context.Context, network string, port string, nat64Prefix string) (net.Conn, string, error)
func (p *CloudflarePool) CandidateAddrs(port string, nat64Prefix string) []string
func (p *CloudflarePool) ReportFailure(ip string)
func (p *CloudflarePool) ReportSuccess(ip string)
func (p *CloudflarePool) RemoveInvalidIPs() int
```

### DialParallel

并发建连竞速并缓存最快 IP。缓存的最快 IP 未过期（5 分钟）时优先单点连接；失败则清空缓存进入竞速。返回建立的连接、实际拨的地址（`ip:port`）及错误。竞速输家的连接会被关闭，不泄漏 FD。

```go
conn, addr, err := pool.DialParallel(ctx, "tcp", "443", nat64Prefix)
if err != nil {
    return err
}
defer conn.Close()
```

### CandidateAddrs

返回池中可用 IP 候选（已完成 NAT64 映射），未过期的最快 IP 排首位。与 `DialParallel` 的区别：只挑地址不拨号，供自带 Happy Eyeballs 竞速的调用方使用（例如 MITM 在 ClientHello 回调里自己竞速并完成 TLS 握手），否则会出现「池里选一个再重拨一次」。

```go
addrs := pool.CandidateAddrs("443", nat64Prefix)
```

### GetAllIPs

返回池中全部 IP，最优在前：活跃 IP 按实测延迟排序，其后是未检查或失败的 IP。串行拨号方必须能从一个不可达的 IP 移到下一个，所以返回整个池而不是截断的头部。

### GetAllIPsWithStats

返回的是快照拷贝：调用方会在锁外读取这些结构体（如 JSON 序列化），而健康检查协程会并发更新原对象的字段，直接共享指针会构成数据竞争。

```go
for _, s := range pool.GetAllIPsWithStats() {
    fmt.Printf("%s latency=%s failures=%d\n", s.IP, s.Latency, s.Failures)
}
```

### 上报连接结果

```go
conn, addr, err := pool.DialParallel(ctx, "tcp", "443", "")
if err != nil {
    return err
}
// 之后对该连接的失败也可上报：host 会被从 addr 中拆出
pool.ReportSuccess(addr)
```

## IPStats

池中一个 IP 及其延迟与健康检查统计。

```go
type IPStats struct {
    IP            string        `json:"ip"`
    Latency       string        `json:"latency"`
    Failures      int           `json:"failures"`
    LastCheck     string        `json:"last_check"`
    LatencyVal    time.Duration // 延迟原始值（失败时为 0）
    LastCheckTime time.Time     // 上次检查时间
}
```
