# subscription 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/subscription`

subscription 负责订阅的下载、解析、持久化与节点拨号：把 Clash 订阅 YAML 解析为规范化的节点/分组/规则模型，把订阅文件与当前激活项持久化到磁盘，并通过 mihomo（Clash core）适配器或少量内建拨号器把流量送入订阅节点。

设计要点：

- **mihomo 适配器为唯一主路径**：从订阅解析出的节点携带原始 Clash YAML 映射（`Node.Raw`），拨号走 mihomo 核心的 `adapter.ParseProxy`——与 Clash 自身加载配置完全相同的代码路径，因此覆盖核心能解析的一切协议与选项（vmess/vless/trojan/ss/tuic/hysteria2、ws/grpc 传输、REALITY、uTLS client-fingerprint 等）。手工构造、没有 Raw 配置的节点退回到包内的小型标准协议拨号器（wireguard/socks5/http）。
- **无进程级副作用**：库承诺没有 `init()` 副作用；mihomo 核心日志在首次使用时才被静默。`Store` 为实例级状态（内部锁保护），可多实例共存。
- **依赖环规避**：`SiteGroup` 镜像 `proxy.SiteGroup` 的字段但不导入 proxy 包，保持无依赖环。
- **functional options**：`WithBrand` / `WithProductName` 声明嵌入方产品名，用于订阅请求的 User-Agent。
- **内存防护**：`MaxPayloadBytes` 限制单次订阅下载体积；WireGuard 隧道按进程/按 Store 池化，可显式释放。

## 常量

```go
const DefaultSubscriptionID = "builtin-default"
```

`DefaultSubscriptionID` 是内建订阅条目的 ID。该条目保留随应用发布的内置规则，不提供节点选择；激活它即恢复内置规则。

```go
const MaxPayloadBytes = 8 << 20
```

`MaxPayloadBytes`（8 MiB）封顶单次订阅下载体积，防止恶意或配置错误的订阅端点耗尽内存。

## 顶层函数

### Fetch

下载订阅载荷并读取流量配额响应头（如存在）。`proxyURL` 非空时先经该 HTTP 代理请求、失败回退直连；订阅提供方域名经常无法直连，Clash 客户端同样经由自身代理更新订阅。

```go
func Fetch(rawURL string, proxyURL string, opts ...Option) ([]byte, UserInfo, error)
```

```go
payload, info, err := subscription.Fetch(subURL, "http://127.0.0.1:8080")
if err != nil { ... }
```

### ParseSubscriptionUserInfo

解码 Clash 的 `subscription-userinfo` 响应头，形如 `upload=1; download=2; total=3; expire=1590000000`。

```go
func ParseSubscriptionUserInfo(header string) UserInfo
```

```go
info := subscription.ParseSubscriptionUserInfo("upload=1; download=2; total=3; expire=1590000000")
```

### ParseClash

解码 Clash YAML 订阅载荷，返回规范化结果。

```go
func ParseClash(payload []byte) (*ParsedConfig, error)
```

```go
cfg, err := subscription.ParseClash(payload)
if err != nil { ... }
for _, n := range cfg.Nodes { ... }
```

### ConvertRules

把 Clash 规则行映射为站点分组（`[]SiteGroup`）。Clash 规则目标（代理组名、DIRECT、REJECT）在此刻意不绑定具体节点：节点选择发生在 UI，代理层在拨号时解析组名。

```go
func ConvertRules(cfg *ParsedConfig) []SiteGroup
```

```go
groups := subscription.ConvertRules(cfg)
```

### NodeHTTPClient

构造一个 TLS 连接经由给定节点隧穿的 HTTP 客户端——Clash Verge 的 URL-test 语义：请求从节点出去、由节点服务器解析目标域名，因此被污染的本地 DNS 不会影响测速结果。timeout 整体约束拨号、握手与响应头。

```go
func NodeHTTPClient(node Node, timeout time.Duration) *http.Client
```

```go
client := subscription.NodeHTTPClient(node, 10*time.Second)
resp, err := client.Get("https://www.gstatic.com/generate_204")
```

### EncodeSocks5Addr

按 SOCKS5 地址格式渲染地址：`ATYP(1) ADDR DST.PORT`。不含 SOCKS5 请求头的 VER/CMD/RSV 字节，由调用方自行前置。ATYP `0x01` 为 IPv4、`0x03` 为域名、`0x04` 为 IPv6；host 非字面 IP 时优先用域名，让域名完整到达代理并由出口解析。

```go
func EncodeSocks5Addr(host string, port int) ([]byte, error)
```

```go
addr, err := subscription.EncodeSocks5Addr("example.com", 443)
```

### ReadSocks5Addr

解析完整的 SOCKS5 地址（VER + ATYP + ADDR + PORT）。

```go
func ReadSocks5Addr(r io.Reader) (string, error)
```

```go
host, err := subscription.ReadSocks5Addr(conn)
```

### ReadSocks5AddrBody

解析 ATYP + ADDR + PORT，供已消费 VER 字节的调用方使用。

```go
func ReadSocks5AddrBody(r io.Reader) (string, error)
```

```go
host, err := subscription.ReadSocks5AddrBody(conn)
```

### SplitHostPort

容忍缺省端口号的 `net.SplitHostPort` 薄封装：无端口时返回 `defaultPort`。

```go
func SplitHostPort(addr string, defaultPort int) (string, int)
```

```go
host, port := subscription.SplitHostPort("example.com", 443)
```

### ReleaseWireguardDialers（包级）

关闭进程内所有池化的 WireGuard 隧道。在进程退出时调用；只持有进程一部分的嵌入方应改用 `Store.ReleaseWireguardDialers`。

```go
func ReleaseWireguardDialers()
```

```go
defer subscription.ReleaseWireguardDialers()
```

## 配置选项（Option）

`Option` 是 `NewStore` 与 `Fetch` 接受的 functional option。

```go
type Option func(*options)
```

| 函数 | 作用 |
|------|------|
| `WithBrand(b config.Brand) Option` | 声明嵌入本库的应用，为订阅 User-Agent 提供产品令牌；零值保持参考产品名 |
| `WithProductName(name string) Option` | 只需产品名时的 `WithBrand` 简化形式 |

```go
store := subscription.NewStore(path, logf, subscription.WithProductName("MyApp"))
```

## 核心类型

### Node

单个代理节点，从 Clash 订阅解析而来。

```go
type Node struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Server     string            `json:"server"`
	Port       int               `json:"port"`
	ServerName string            `json:"server_name,omitempty"`
	UDP        bool              `json:"udp"`
	Options    map[string]string `json:"options,omitempty"`
	// Raw 是节点的原始 Clash YAML 映射，逐字保留，使 mihomo 适配器
	// 看到与 Clash 自身加载完全一致的配置——扁平 Options 装不下的
	// ws-opts/reality-opts/grpc-ots 等嵌套块在这里存活。
	Raw map[string]any `json:"raw,omitempty"`
}
```

构造方式：通常由 `ParseClash` / `Store` 产出，也可手工构造（手工节点无 Raw，走内建 legacy 拨号器）。

| 方法 | 作用 | 备注 |
|------|------|------|
| `Dial(targetHost string, targetPort int) (net.Conn, error)` | 以默认超时打开到目标的隧道 | `DialTimeout` 的简写 |
| `DialTimeout(targetHost string, targetPort int, timeout time.Duration) (net.Conn, error)` | 打开到 `targetHost:targetPort` 的隧道 | 返回的 `net.Conn` 承载隧道字节流，调用方在其上照常讲应用协议（TLS、HTTP……）；有 Raw 时走 mihomo 适配器，否则仅支持 wireguard/socks5/http/https |
| `ListenPacketUDP(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error)` | 经该节点打开到 destination 的 UDP 隧道 | 返回 sing 的 `N.PacketConn`（`github.com/sagernet/sing/common/network`）：数据报目的地保持类型化 `M.Socksaddr`，缓冲按指针移动，同时满足 `net.PacketConn` |
| `MihomoProxy() (C.Proxy, error)` | 从 Raw 配置构建 Clash-core 代理对象 | 节点无 Raw 配置时返回错误（手工节点走 legacy 拨号器）；`C` 为 `github.com/metacubex/mihomo/constant` |
| `Supported() bool` | 该节点的协议能否拨号 | Raw 节点恒为 true（mihomo 适配器覆盖核心能解析的全部协议）；手工节点仅 wireguard/socks5/http/https 及白名单协议名 |
| `UDPSupported() bool` | 该节点当前能否承载 UDP | |
| `URLTest(ctx context.Context, testURL string) (uint16, error)` | 运行 Clash-core 延迟测试 | 与 mihomo `/proxies/:name/delay` 端点同一实现；返回毫秒延迟，0 表示失败（与核心 REST 语义一致） |

```go
conn, err := node.DialTimeout("example.com", 443, 10*time.Second)
if err != nil { ... }
defer conn.Close()
// 在 conn 上照常进行 TLS 握手等
```

```go
delay, err := node.URLTest(ctx, "https://www.gstatic.com/generate_204")
```

### Group

Clash 的 proxy-group。

```go
type Group struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Members  []string `json:"members"`
	Selected string   `json:"selected,omitempty"`
}
```

由 `ParseClash` 产出，通常经 `Entry.Groups` 读取。

### SiteGroup

镜像 `proxy.SiteGroup` 的站点分组结构（不导入 proxy 包以避免依赖环）。字段与 `rules/config.json` 的 `site_groups` 条目对应。

```go
type SiteGroup struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Mode       string   `json:"mode"`
	DNSMode    string   `json:"dns_mode,omitempty"`
	SniFake    string   `json:"sni_fake,omitempty"`
	Domains    []string `json:"domains"`
	ECHEnabled bool     `json:"ech_enabled"`
	UseCFPool  bool     `json:"use_cf_pool"`
	CertVerify struct {
		Mode  string   `json:"mode"`
		Names []string `json:"names,omitempty"`
	} `json:"cert_verify"`
	Website  string `json:"website,omitempty"`
	Enabled  bool   `json:"enabled"`
	Upstream string `json:"upstream,omitempty"`
}
```

由 `ConvertRules` 产出，或经 `Store.ActiveSiteGroups` / `Entry.SiteGroups` 读取。

### ParsedConfig

Clash 订阅载荷的规范化解析结果。

```go
type ParsedConfig struct {
	Nodes      []Node            `json:"nodes"`
	Groups     []Group           `json:"groups"`
	Rules      []string          `json:"rules"`
	RawRuleMap map[string]string `json:"-"`
}
```

由 `ParseClash` 构造。

### Entry

一条已存储的订阅。

```go
type Entry struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	URL        string            `json:"url"`
	Builtin    bool              `json:"builtin"`
	UpdatedAt  int64             `json:"updated_at"`
	UserInfo   UserInfo          `json:"user_info"`
	NodeCount  int               `json:"node_count"`
	RuleCount  int               `json:"rule_count"`
	Groups     []Group           `json:"groups"`
	Nodes      []Node            `json:"nodes"`
	SiteGroups []SiteGroup       `json:"site_groups"`
	Selection  map[string]string `json:"selection"`
	Error      string            `json:"error,omitempty"`
}
```

由 `Store` 的 `Add` / `Update` 构造，经 `Store.List` / `Get` / `ActiveEntry` 读取（均返回副本或快照）。

### UserInfo

订阅提供方公布的流量配额与到期信息。

```go
type UserInfo struct {
	Upload     int64 `json:"upload"`
	Download   int64 `json:"download"`
	Total      int64 `json:"total"`
	ExpireTime int64 `json:"expire_time"`
}
```

由 `Fetch` / `ParseSubscriptionUserInfo` 构造。

| 方法 | 作用 |
|------|------|
| `ExpireDate() time.Time` | 到期时间；未设置时为零值 |
| `Left() int64` | 剩余流量（字节）；配额未知时为负 |
| `Used() int64` | 已消耗流量（字节） |

```go
if info.Left() >= 0 && info.Left() < 1<<30 { /* 配额不足 1 GiB */ }
```

## Store

`Store` 持久化订阅并跟踪激活项。内部互斥锁保护全部状态；对外的读取方法（`List`、`Get`、`ActiveEntry` 等）返回副本/快照，因此 `Update` / `Add` 可并发修改活条目而不引发竞争。

### 构造

```go
func NewStore(path string, logf func(string), opts ...Option) *Store
```

从磁盘加载订阅存储；文件不存在时得到一个只含内建默认条目的 Store。`opts`（如 `WithBrand`）配置嵌入方行为。

```go
store := subscription.NewStore(filepath.Join(cfgDir, "subscriptions.json"),
	log.Default().Printf, subscription.WithBrand(brand))
```

### 订阅管理

| 方法 | 作用 | 备注 |
|------|------|------|
| `Add(name, url string) (*Entry, error)` | 下载并解析后注册新订阅 | |
| `Update(id string) (*Entry, error)` | 重新下载已有订阅 | |
| `Delete(id string) error` | 删除订阅 | 内建条目不可删除 |
| `Get(id string) *Entry` | 按 id 返回订阅副本 | |
| `List() []*Entry` | 返回全部订阅，内建条目在前 | 返回副本；Update/Add 并发修改活条目，发放指针会与下次刷新竞争 |
| `Reload() error` | 重读存储文件，拾取另一进程（GUI）写入的变更 | 读取/解析成功后替换条目列表与激活 id；任何失败时内存态保持不变 |
| `SetActive(id string) error` | 选定激活订阅 | 选内建条目恢复内置规则；其他条目加载该订阅的规则 |
| `ActiveID() string` | 当前选定的订阅 id | |
| `ActiveEntry() *Entry` | 激活订阅的快照 | 在存储锁内复制，锁外可安全读取 |
| `ActiveSiteGroups() []SiteGroup` | 激活订阅的规则集 | 应使用内置规则时返回 nil |
| `ActiveNode() (Node, bool)` | 第一个携带可用选组的节点 | Clash 把激活订阅视为一个 proxy-group，此即"当前出口"；内置规则激活或无可用节点时 ok=false |

```go
if _, err := store.Add("我的订阅", subURL); err != nil { ... }
if err := store.SetActive(subID); err != nil { ... }
```

### 节点选择

| 方法 | 作用 |
|------|------|
| `NodeByID(subscriptionID, nodeName string) (Node, bool)` | 按名称解析某订阅的一个节点 |
| `SelectNode(subscriptionID, group, node string) error` | 记录某分组选定的节点 |

```go
if err := store.SelectNode(subID, "自动选择", "香港-01"); err != nil { ... }
```

### 下载代理

```go
func (s *Store) SetFetchProxy(proxyURL string)
```

让订阅下载优先经给定 HTTP 代理（通常为运行中的本地代理），失败回退直连；空串表示仅直连。

```go
store.SetFetchProxy("http://127.0.0.1:8080")
```

### 资源释放

```go
func (s *Store) ReleaseWireguardDialers()
```

关闭**本 Store** 拨出的 WireGuard 隧道，不动进程中属于其他 Store 的隧道。

```go
store.ReleaseWireguardDialers()
```

### 测试辅助方法

以下方法服务于嵌入本包的包（如 proxy）在测试中演练激活路径，无需网络或 HTTP 服务器：

| 方法 | 作用 |
|------|------|
| `AddEntryForTest(name, url string) *Entry` | 不访问网络注册一条订阅 |
| `SetGroupsForTest(id string, groups []Group)` | 替换 `AddEntryForTest` 条目的代理分组列表 |
| `SetNodesForTest(id string, nodes []Node)` | 替换 `AddEntryForTest` 条目的节点列表 |
| `SetSiteGroupsForTest(id string, groups []SiteGroup)` | 替换 `AddEntryForTest` 条目的规则集；代理层只需 domains 与 mode，其他包可经回调提供自己的 SiteGroup 类型 |
