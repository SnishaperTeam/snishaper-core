# netiface 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/netiface`

netiface 选出拥有系统默认路由的物理网卡，并把出站 socket 绑定到它。

设计要点：

- **按默认路由而非接口枚举选择**：遍历 `net.Interfaces()` 选网卡是错的——枚举顺序按接口索引而非路由优先级，碰巧索引更小的虚拟网卡（VMware VMnet、Hyper-V vEthernet、WSL、遗留 TAP）会压过真正承载流量的网卡；双栈主机上第一个枚举出的 IPv6 地址往往还是链路本地 `fe80::`，无法跨链路路由。本包实现与 sing-box / mihomo 相同的规则：先问内核哪块网卡拥有默认路由，内核不回答时才回退到枚举启发式。
- **零可变全局状态**：单体版的路由快照与选择日志状态原为包级全局，本包改为 `Selector` 实例持有，调用方显式隔离或共享缓存。
- **平台支持差异**：路由表读取在 Windows 与 Linux 有原生实现（`route_windows.go` / `route_linux.go`），其余平台没有可移植的路由表读取器——但选择仍然工作，内核源地址探测直接问操作系统出站流量会用哪个源地址；按接口绑定 socket 在 Windows/Linux/macOS 有原生实现，其他平台 `Binding.Control` 返回 nil（no-op），调用方无需 build tag。
- **两级虚拟网卡处置**：`DefaultExcludedNames` 黑名单内的接口在自动选择中被直接排除；`virtualNameMarkers` 命中的接口只降权、不排除（唯一上联就是虚拟网卡的主机——云 VM、VPN-only 机器——必须仍能工作）。

## 常量

```go
const (
	FamilyIPv4 = iota
	FamilyIPv6
)
```

`Select` 接受的地址族。

## 变量

```go
var DefaultExcludedNames = []string{ ... }
```

`DefaultExcludedNames` 是绝不应承载出站流量的接口内建黑名单：容器网桥、虚拟机宿主适配器、隧道设备等纯软件接口——它们没有任何物理介质存在，向其发送流量要么黑洞要么灌回隧道。条目支持 `"name*"` 前缀 glob 与全名匹配。

与只降权的 `virtualNameMarkers` 不同，此名单在自动选择中被直接排除。用户可通过 `TUNConfig.OutboundInterfaceExclude` 扩展该列表。

（完整条目见 `netiface/netiface.go`：`tun2proxy*`、`utun*`、`tun*`、`tap*`、`docker*`、`veth*`、`vmnet*`、`br-*`、`kube*`、`tailscale*`、`wg*`、`lo`、`mihomo`、`sing-box*`、`SingTun*` 等隧道、容器/VM、集群 overlay 与各类虚拟设备。）

## 辅助函数

```go
func FamilyOf(addr string) int
```

`FamilyOf` 返回 addr 的地址族（`FamilyIPv4` / `FamilyIPv6`）；addr 不是 IP 字面量时默认 IPv4。兼容 `"host:port"` 形式。

```go
family := netiface.FamilyOf("2001:db8::1") // FamilyIPv6
```

```go
func IsOwnTunnel(name string) bool
```

`IsOwnTunnel` 判断 name 是否属于参考产品（SniShaper）的 TUN 设备。为自己品牌化适配器的嵌入方应改调 `IsOwnTunnelOf`。

```go
func IsOwnTunnelOf(brand config.Brand, name string) bool
```

`IsOwnTunnelOf` 判断 name 是否属于 brand 所标识应用创建的 TUN 设备。

```go
if netiface.IsOwnTunnelOf(brand, name) { /* 不可作为出站上联 */ }
```

```go
func IsVirtualAdapter(name string) bool
```

`IsVirtualAdapter` 判断 name 看起来是虚拟/隧道适配器而非物理上联（只降权、不封禁）。

```go
if netiface.IsVirtualAdapter(name) { ... }
```

## Config

`Config` 调整接口选择。零值即生产默认值。

```go
type Config struct {
	// Brand 标识嵌入应用：其产品名决定哪些接口算"自己的 TUN"而绝不
	// 被选为出站上联。零值为参考产品。
	Brand config.Brand

	// ForceInterface 把选择钉死到指定接口；空为自动选择；
	// 以 "*" 结尾的条目为前缀 glob。
	ForceInterface string

	// ExcludeInterfaces 丢弃名称匹配这些条目的接口；
	// 比较不区分大小写，"name*" 为前缀 glob。
	ExcludeInterfaces []string

	// ExcludeAddresses 丢弃携带这些 CIDR 块或字面地址内
	// 地址的接口。
	ExcludeAddresses []string
}
```

```go
cfg := netiface.Config{ExcludeInterfaces: []string{"docker*"}}
```

## Binding

`Binding` 是一块已解析、可发出站流量的物理网卡。

```go
type Binding struct {
	InterfaceIndex int         // OS 接口索引，用于 IP_UNICAST_IF 与 SO_BINDTOIFINDEX
	InterfaceName  string      // OS 接口名
	Address        netip.Addr  // 该接口上请求地址族的可用源地址；仅链路本地时无效
	DefaultRoute   bool        // 该接口是否拥有默认路由
	Metric         uint32      // 接口 + 路由 metric，越小越好
	Virtual        bool        // 适配器是否像虚拟设备（降权，非封禁）
	Reason         string      // 选择原因，供日志与测试
}
```

构造方式：由 `Selector.Select` / `SelectForTarget` 返回。

| 方法 | 作用 | 备注 |
|------|------|------|
| `Control(family int) func(network, address string, c syscall.RawConn) error` | 返回把 socket 绑定到 b 的 `net.Dialer.Control` 钩子 | 不支持按接口绑定 socket 的平台返回 nil（no-op），调用方无需 build tag |
| `Describe() string` | 渲染绑定的诊断描述 | |
| `LocalTCPAddr() *net.TCPAddr` | 返回该绑定的 TCP 本地地址 | 无可用源地址时返回 nil |
| `LocalUDPAddr() *net.UDPAddr` | 返回该绑定的 UDP 本地地址 | 无可用源地址时返回 nil |

```go
binding, err := selector.Select(netiface.FamilyIPv4, cfg, logf)
if err != nil { ... }
dialer := &net.Dialer{Control: binding.Control(netiface.FamilyIPv4)}
conn, err := dialer.Dial("tcp", "example.com:443")
```

## Descriptor

`Descriptor` 为设置界面概述一块适配器。

```go
type Descriptor struct {
	Name            string   `json:"name"`
	Index           int      `json:"index"`
	Up              bool     `json:"up"`
	Physical        bool     `json:"physical"`
	DefaultRoute    bool     `json:"default_route"`
	IPv4            []string `json:"ipv4"`
	IPv6            []string `json:"ipv6"`
	Usable          bool     `json:"usable"`          // 能否承载流量（up、非环回、非自身隧道）
	Selected        bool     `json:"selected"`        // 用户是否在配置中钉死了该适配器
	CurrentOutbound bool     `json:"current_outbound"` // 自动选择当前会选中该适配器（设置页标注"使用中"）
	Excluded        bool     `json:"excluded"`         // 当前配置是否排除该适配器
	ExcludeReason   string   `json:"exclude_reason,omitempty"`
}
```

由 `Selector.List` / `DescribeAll` 返回。

## Selector

`Selector` 缓存路由快照与选择日志状态。可显式创建多个实例以隔离（或共享）缓存。

### 构造

```go
func NewSelector() *Selector
```

```go
selector := netiface.NewSelector()
```

### 选择

```go
func (s *Selector) Select(family int, cfg Config, logf func(string)) (Binding, error)
```

`Select` 返回拥有 family 默认路由、优先有可用源地址的物理网卡。

`logf` 只在选择结果**发生变化**时调用：数据面上每条出站连接都会走一次 Select，逐次打印会在高 QPS 下刷满日志缓冲、冲掉真正的故障信息。

```go
binding, err := selector.Select(netiface.FamilyIPv4, netiface.Config{}, logf)
if err != nil { ... }
```

```go
func (s *Selector) SelectForTarget(addr string, cfg Config, logf func(string)) (Binding, error)
```

`SelectForTarget` 从 addr 推断地址族再选择绑定。

```go
binding, err := selector.SelectForTarget("example.com:443", netiface.Config{}, logf)
```

### 枚举与诊断

| 方法 | 作用 |
|------|------|
| `List(cfg Config) []Descriptor` | 返回全部适配器及其地址、物理/虚拟判定、默认路由归属、是否被当前配置排除；设置页渲染它提供手动网卡选择 |
| `DescribeAll() []Descriptor` | 用默认（未过滤）配置返回全部适配器 |
| `Explain(cfg Config) []string` | 返回逐地址族的排名轨迹，用于诊断与缺陷报告 |

```go
for _, d := range selector.List(netiface.Config{}) {
	logf(d.Name)
}
```

### 缓存管理

```go
func (s *Selector) Invalidate()
```

`Invalidate` 丢弃缓存的路由快照。TUN 启停之后必须调用——那些时点适配器集合会变化。

```go
selector.Invalidate()
```
