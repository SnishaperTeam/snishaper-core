# tlsfrag 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/tlsfrag`

## 概述

`tlsfrag` 实现针对 TLS ClientHello 的流量整形与改写（TLS-RF 分片、CircumVolve 论文策略）：

- **发送侧**：`SendRecords` 按配置把 ClientHello 拆成多条 TLS record / 多个 TCP segment 发送（TLS-RF 分片），支持带外字节、版本字节改写、握手头内分片等变体；
- **改写侧**：一组「解析 → 修改 → 修复长度字段」的 ClientHello 重建工具（`AppendPaddingExtension`、`RemoveSNIExtension`、`ReplaceSNIName`、`TrailingDotSNI` 等 CircumVolve 策略）；
- **读取侧**：`ReadInitialTLSRecord` 读取连接上的第一条完整 TLS record。

重建工具的输入必须满足结构前提：ClientHello 是 record 中唯一的握手消息、extensions 块恰好填满握手消息，否则返回错误。

## 常量

```go
const (
    TlsRecordHeaderLen       = 5                  // TLS record 头长度（字节）
    TlsHandshakeRecord       = 22                 // 握手类型的 record 类型值
    TlsFragmentReadWait      = 10 * time.Second   // 读取首条 record 的超时
    DefaultTLSRFNumRecords   = 4                  // 默认分片 record 数
    DefaultTLSRFNumSegments  = 1                  // 默认 segment 数
    DefaultTLSRFSendInterval = 50 * time.Millisecond // 默认发送间隔
    DefaultTLSRFModMinorVer  = true               // 默认改写版本次字节
    DefaultTLSRFOOB          = false              // 默认首段带外发送
    DefaultTLSRFOOBEx        = false              // 默认 20 字节带外前缀
    DefaultTLSRFHeaderSplit  = false              // 默认不在握手头内分片
    DefaultTLSRFAltRecordVer = false              // 默认不改写每 record 版本
)
```

## 发送与连接辅助

### ReadInitialTLSRecord

```go
func ReadInitialTLSRecord(conn net.Conn) ([]byte, error)
```

读取连接上的第一条完整 TLS record（读超时 `TlsFragmentReadWait`）。

```go
record, err := tlsfrag.ReadInitialTLSRecord(conn)
if err != nil {
    return err
}
```

### SendRecords

```go
func SendRecords(conn net.Conn, clientHello []byte, offset, length, records, segments int, oob, oobex, modMinorVer, headerSplit, altRecordVer bool, interval time.Duration) error
```

把 ClientHello 按配置的 record 数 / segment 数分片发送。`offset`/`length` 是 SNI 主机名在 record 内的位置（来自 `ParseClientHello`），分片以 SNI 中的最后一个点为切分点。各布尔开关：

- `modMinorVer`：把 record 版本次字节改为 0x04；
- `oob`：首个包附带一个 MSG_OOB 带外字节发送；
- `oobex`：把前 20 字节按 TLS-RF 的带外变体发送（第 16 字节作为 OOB 字节，两段 `SendWithOOB`）；
- `headerSplit`：把第一条 record 边界放在 4 字节握手头内部（首条 record 载荷 < 4 字节）；
- `altRecordVer`：首条 record 版本发 0x0303、其余发 0x0301。

`headerSplit` 与 `altRecordVer` 都是 CircumVolve（CCS'26）策略：重新组帧但不改握手内容，且仅在 `records >= 2` 时生效。

```go
err := tlsfrag.SendRecords(conn, record,
    sniPos, sniLen,
    tlsfrag.DefaultTLSRFNumRecords, tlsfrag.DefaultTLSRFNumSegments,
    tlsfrag.DefaultTLSRFOOB, tlsfrag.DefaultTLSRFOOBEx,
    tlsfrag.DefaultTLSRFModMinorVer,
    tlsfrag.DefaultTLSRFHeaderSplit, tlsfrag.DefaultTLSRFAltRecordVer,
    tlsfrag.DefaultTLSRFSendInterval)
```

### SendWithOOB

```go
func SendWithOOB(conn net.Conn, data []byte, oob byte) error
```

发送 data 外加一个 urgent MSG_OOB 字节（Windows 用 `WSASend`，Unix 用 `send(MSG_OOB)`）。

```go
err := tlsfrag.SendWithOOB(conn, []byte{0x16, 0x03}, 0x00)
```

### GetRawConn

```go
func GetRawConn(conn net.Conn) (syscall.RawConn, error)
```

把 conn 解包为 `syscall.RawConn`；连接不支持原始访问时报错。

### IsUseOfClosedConn

```go
func IsUseOfClosedConn(err error) bool
```

判断 err 是否为「use of closed connection」类错误。

```go
if tlsfrag.IsUseOfClosedConn(err) {
    return // 连接已被关闭，静默退出
}
```

## ClientHello 解析

### ParseClientHello

```go
func ParseClientHello(data []byte) (prtVer []byte, sniPos int, sniLen int, hasKeyShare bool, err error)
```

从 ClientHello 中提取协议版本、SNI 位置与 key_share 扩展是否存在。无 SNI 时 `sniPos` 为 -1。

```go
prtVer, sniPos, sniLen, hasKeyShare, err := tlsfrag.ParseClientHello(record)
```

### FindLastDot

```go
func FindLastDot(data []byte, sniPos, sniLen int) (offset int, found bool)
```

返回 SNI 主机名内最后一个点的偏移；找不到时返回区间中点、false。

## ClientHelloLayout

定位原位重建 ClientHello record 所需的全部长度字段。偏移量是 record 内的绝对位置。

```go
type ClientHelloLayout struct {
    RecordLenAt    int // 2 字节 record 长度字段（恒为 3）
    HandshakeLenAt int // 3 字节握手长度字段（恒为 6）
    RecordEnd      int // 5 + record 长度
    ExtTotalLenAt  int // 2 字节扩展总长字段（缺失时 -1）
    ExtBlockStart  int
    PrtVer         []byte
    HasKeyShare    bool
    SniExtStart    int // server_name 扩展类型字段的偏移（缺失时 -1）
    SniExtLen      int // 完整扩展大小（含 type+length 头）
    SniNameAt      int
    SniNameLen     int
}
```

### ParseClientHelloLayout

```go
func ParseClientHelloLayout(data []byte) (ClientHelloLayout, error)
```

遍历一条 TLS record，返回重建所需的每个字段的字节偏移。接受与 `ParseClientHello` 相同的输入，报告相同的错误。

```go
layout, err := tlsfrag.ParseClientHelloLayout(record)
if err != nil || layout.SniExtStart == -1 {
    return // 无 SNI，跳过改写
}
```

## ClientHello 重建策略

以下函数均接受完整 TLS record（ClientHello 必须独占 record），返回新的 record 并自动修复 record、握手、扩展块、SNI 列表及名称长度字段。

### AppendPaddingExtension

```go
func AppendPaddingExtension(record []byte, n int) ([]byte, error)
```

向 ClientHello 追加含 n 个零字节的 RFC 7685 padding 扩展，迫使 record 变大让 TCP 必须分段（CircumVolve "padding" 策略）。n 会被限制以保证 record 不超过 TLS record 尺寸上限。

```go
record, err = tlsfrag.AppendPaddingExtension(record, 512)
```

### RemoveSNIExtension

```go
func RemoveSNIExtension(record []byte) ([]byte, error)
```

从 ClientHello 中移除 server_name 扩展（CircumVolve "hidden SNI" 策略）。服务器回退到默认证书；只对无 SNI 也提供正确证书的部署有效——论文中验证过 Cloudflare 与 Google。

### ReplaceSNIName

```go
func ReplaceSNIName(record []byte, name []byte) ([]byte, error)
```

把 SNI 主机名替换为 name，并按大小差值修复 record、握手、扩展、SNI 列表和名称长度字段。用于 QUIC punycode SNI 策略。

```go
record, err = tlsfrag.ReplaceSNIName(record, []byte("xn--65736e69"))
```

### TrailingDotSNI

```go
func TrailingDotSNI(record []byte) ([]byte, error)
```

向 SNI 主机名追加尾部点号，使精确匹配的 SNI 黑名单漏掉 FQDN（CircumVolve "trailing dot" 策略）。

```go
record, err = tlsfrag.TrailingDotSNI(record)
```
