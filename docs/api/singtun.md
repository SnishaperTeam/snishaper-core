# singtun 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/singtun`

singtun 基于 sing-tun 实现 TUN 设备的创建、系统流量接管与转发：`Manager` 管理 TUN 设备生命周期，`Handler` 实现 sing-tun 的 Handler 接口、把 TUN 流量转发到嵌入方自己的代理，`FakeIPStore` 维护 fake-ip 映射，另含自包含的 TLS ClientHello SNI/ECH 嗅探解析器。

设计要点：

- **品牌隔离**：`NewManagerFor` 让 TUN 网卡默认名与残留网卡清理按嵌入方品牌匹配，避免两个嵌入方互删对方网卡。Windows 上残留网卡清理（`SetupAPI`）严格限定在本项目自建适配器：sing-tun 与 sing-box / mihomo 共用同一 Wintun 驱动，仅凭 "sing-tun" 描述匹配会误删并发运行的 sing-box 网卡；非 Windows 平台该清理为 no-op。
- **依赖方向受控**：`SetUDPRelay` / `SetQUICRewrite` 以接口/钩子注入 UDP 隧道与 QUIC 重写策略——本包不依赖订阅栈，否则形成 import 环；实现由代理层提供。
- **关闭路径分级**：`Stop` 是可重复调用的运行时停止；`Release` 回收存量连接但不置终态标记（Start 失败回滚无需重建 Handler）；`Shutdown` 是进程退出路径上的终态销毁。
- **SNI 嗅探自包含**（设计决策 D2）：`ParseClientHelloRecord` / `SniffClientHello` 是 singtun 内自包含的 TLS 解析器，不扩展 tlsfrag——tlsfrag 面向分片偏移，本模块面向结构化 SNI/ECH 信息，消费者不同。
- 日志经 `logf func(string)` 注入，同时桥接为 `slog.Logger` 供 sing-tun 栈使用。

## Manager

`Manager` 管理 TUN 设备的生命周期与流量处理。

### 构造

```go
func NewManager(resolver *dohresolver.FailoverResolver, logf func(string)) *Manager
```

创建一个属于参考产品的 TUN 管理器。

```go
func NewManagerFor(brand config.Brand, resolver *dohresolver.FailoverResolver, logf func(string)) *Manager
```

创建属于 brand 所标识应用的 TUN 管理器：TUN 网卡默认名与残留网卡清理都按该品牌匹配，避免两个嵌入方互相删除对方的网卡。

```go
mgr := singtun.NewManagerFor(brand, resolver, logf)
```

### 生命周期

```go
func (m *Manager) Start(cfg proxy.TUNConfig, proxyAddr string) (err error)
```

启动 TUN 设备并接管系统流量。启动前先执行显式残留清理（设计决策 D7）：清掉上次运行的残留资源与遗留虚拟网卡后才创建新设备；创建中途失败会自动回滚已建资源。

```go
if err := mgr.Start(tunCfg, "127.0.0.1:8080"); err != nil { ... }
```

| 方法 | 作用 | 备注 |
|------|------|------|
| `Stop() error` | 停止 TUN 并释放全部资源 | 可重复调用的运行时停止，不是终态 |
| `Shutdown() error` | 进程退出路径上的终态销毁 | 与 `Stop` 的区别是会一并关闭 Handler，使 Stop 之后才被派发的残留连接无法再生效 |
| `Status() proxy.TUNStatus` | 返回当前 TUN 状态 | |

```go
if err := mgr.Stop(); err != nil { ... }
defer mgr.Shutdown()
```

### 注入（须在 Start 之前）

```go
func (m *Manager) SetUDPRelay(relay UDPRelay)
```

注入 UDP 隧道（订阅节点）；传 nil 表示 UDP 只走直连。由代理层实现：本包不能依赖订阅栈，否则会形成 import 环。已启动时立即生效，重连订阅节点无需重启 TUN。

```go
func (m *Manager) SetQUICRewrite(hook QUICRewriteFunc)
```

注入按域名查策略的 QUIC Initial 重写钩子（TUN fake-ip UDP 路径）。传 nil 恢复丢弃 fake-ip UDP、等浏览器回退 TCP 的旧行为。由代理层实现（通常是 `RuleManager.MatchQUICStrategies` 的适配闭包）；已启动时立即生效，改规则无需重启 TUN。

```go
mgr.SetUDPRelay(relayImpl)
mgr.SetQUICRewrite(quicHook)
```

## Handler

`Handler` 实现 sing-tun 的 Handler 接口，负责将 TUN 流量转发到嵌入方自己的代理。

### 构造

```go
func NewHandler(proxyAddr string, resolver *dohresolver.FailoverResolver, logf func(string)) *Handler
```

```go
handler := singtun.NewHandler("127.0.0.1:8080", resolver, logf)
```

### sing-tun Handler 接口方法

| 方法 | 作用 |
|------|------|
| `NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc)` | 处理新的 TCP 连接 |
| `NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc)` | 处理新的 UDP 连接；53 端口由本层接管 DNS |
| `NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter)` | 处理 TUN 捕获的原始 DNS 请求报文 |
| `JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict` | 对 TUN 流量返回处理判定（当前一律放行） |

（`M` 为 `github.com/sagernet/sing/common/metadata`、`N` 为 `github.com/sagernet/sing/common/network` 的惯用别名，`tun` 为 `github.com/sagernet/sing-tun`。）

### 配置与注入

| 方法 | 作用 |
|------|------|
| `SetInterfaceConfig(cfg netiface.Config)` | 设置出站流量绑定的网卡配置 |
| `SetUDPRelay(relay UDPRelay)` | 注入把 UDP 经代理节点隧穿的解析器；传 nil 恢复仅直连 UDP |
| `SetQUICRewrite(hook QUICRewriteFunc)` | 安装 fake-ip UDP 路径上按域名的 QUIC Initial 重写钩子；传 nil 恢复丢弃并回退 TCP |

### 生命周期

| 方法 | 作用 |
|------|------|
| `Close()` | 终态：置 closed 后拒绝新连接并回收全部存量连接；调用后 Handler 不可复用 |
| `Release()` | 回收全部存量连接并等待转发 goroutine 退出，但不复用 closed 标记——Manager 的 releaseLocked 走这条路径：设备已关闭但 Handler 语义上仍可继续接收派发，Start 失败回滚时也无需重建 Handler。因为不置 closed，snapshot 之后仍可能有新连接被 track，所以按轮次收敛：每轮重新快照并关闭，直到某轮快照为空；最多 releaseMaxRounds 轮 |

```go
handler.Close()      // 终态
```

## FakeIPStore

`FakeIPStore` 维护域名与 fake IP 的双向映射，超限按 FIFO 淘汰。

### 构造

```go
func NewFakeIPStore() *FakeIPStore
```

```go
store := singtun.NewFakeIPStore()
```

| 方法 | 作用 |
|------|------|
| `Create(domain string) (netip.Addr, bool)` | 为域名分配一个假 IPv4 地址（去重）；返回 `(ip, isNew)`，isNew=true 表示本次新建，false 表示命中缓存 |
| `CreateIPv6(domain string) (netip.Addr, bool)` | 为域名分配一个假 IPv6 地址（去重）；返回值语义同上 |
| `Lookup(ip netip.Addr) (string, bool)` | 通过假 IP 反查域名 |
| `Contains(ip netip.Addr) bool` | 检查 IP 是否在 fake-ip 范围内 |

```go
ip, _ := store.Create("example.com")
if domain, ok := store.Lookup(ip); ok { _ = domain }
```

## SNI 嗅探

### SNIInfo

`SNIInfo` 是一次 ClientHello 嗅探的结果。

```go
type SNIInfo struct {
	IsTLS  bool   // 首字节是否 TLS handshake record
	SNI    string // 外层 server_name（可空；ECH 场景即外层 SNI，D4 降级用）
	HasECH bool   // 是否存在 ECH（encrypted_client_hello）扩展
	Err    error  // 畸形/读取失败原因（任何输入不 panic）
}
```

### ParseClientHelloRecord

```go
func ParseClientHelloRecord(record []byte) (SNIInfo, error)
```

解析单条完整 TLS record（含 5 字节 record 头），纯函数。畸形输入（非握手 record / 截断 / 长度越界 / 空 server_name 列表）返回错误而非 panic；ClientHello 横跨多条 record 时返回明确错误，由 `SniffClientHello` 的流式路径负责重组。

```go
info, err := singtun.ParseClientHelloRecord(record)
```

### SniffClientHello

```go
func SniffClientHello(conn net.Conn, timeout time.Duration) (SNIInfo, net.Conn)
```

从连接读取首个 ClientHello 并解析 SNI。

关键保证：已消费的字节通过返回的连接完整回放——嗅探对连接数据零丢失。超时 / 非 TLS / 畸形：返回对应 `SNIInfo`（`IsTLS=false` 或 `Err` 非空），返回的连接仍然可用；读超时在返回前恢复（清零 deadline）。ClientHello 横跨多条 record 时继续读取重组（尽力解析，总长度有上限）。

```go
info, conn := singtun.SniffClientHello(conn, 5*time.Second)
if info.IsTLS && info.SNI != "" { /* 用 SNI 做分流 */ }
```

## 扩展点

### UDPRelay

```go
type UDPRelay interface {
	// OpenUDP returns a packet conn carrying traffic to destination, or
	// ok=false when no relay applies and the caller should dial directly.
	OpenUDP(ctx context.Context, destination M.Socksaddr) (conn N.PacketConn, ok bool, err error)
}
```

`UDPRelay` 为目标地址解析出一条 UDP 隧道，由代理层实现以使本包不依赖订阅栈。返回 sing 的 `N.PacketConn` 而非 `net.PacketConn`：目的地以类型化 `M.Socksaddr` 携带、按 sing buf.Buffer 值移动，保持地址类型化并避免每数据报一次拷贝。

```go
type myRelay struct{}
func (myRelay) OpenUDP(ctx context.Context, dest M.Socksaddr) (N.PacketConn, bool, error) { ... }
mgr.SetUDPRelay(myRelay{})
```

### QUICRewriteFunc

```go
type QUICRewriteFunc func(domain string) (quicrewrite.Strategies, bool)
```

`QUICRewriteFunc` 报告某域名的 QUIC Initial 重写策略（`github.com/SnishaperTeam/snishaper-core/quicrewrite`）。`ok=false`（或 nil 函数）保持旧的 fake-ip UDP 行为：丢弃数据报、让客户端回退 TCP。

```go
mgr.SetQUICRewrite(func(domain string) (quicrewrite.Strategies, bool) {
	return ruleManager.MatchQUICStrategies(domain)
})
```

## 辅助函数

```go
func AsNetIP(addr netip.Addr) net.IP
```

`AsNetIP` 将 `netip.Addr` 转换为 `net.IP`。

```go
func TUNGateway4() string
```

`TUNGateway4` 返回 TUN 的 IPv4 网关地址（`198.18.0.1`）。它是 TUN 地址的唯一来源，外部（如 app 的数据面自检）必须经此读取，不得再硬编码 `"198.18.0.1"`。

```go
gw := singtun.TUNGateway4()
```
