# quicrewrite 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/quicrewrite`

## 概述

`quicrewrite` 在线改写客户端 QUIC v1 Initial 数据报，是 TLS-RF 的 QUIC 对应物：用 DCID 派生的密钥解密 Initial，把 CircumVolve 论文的 ClientHello 策略应用到 CRYPTO 流，再重新加密封包。不是可改写的客户端 Initial 的数据报原样放行（fail-open），输入永远不会被修改。

## Strategies

选择应用哪些 CircumVolve QUIC 技术。全部相互独立、可组合，唯独 `DoubleHello` 涵盖（吞并）`FragmentCrypto` 与 `PunycodeSNI`。

```go
type Strategies struct {
    ReservedBits   bool // 把长头部保留位 (0x0C) 置为 11
    PrependACK     bool // 在 CRYPTO 帧前预置一个伪造的 ACK 帧
    DecoyCrypto    bool // 在超大流偏移处预置一个诱饵 CRYPTO 帧
    FragmentCrypto bool // 拆分承载 ClientHello 的 CRYPTO 帧
    DoubleHello    bool // 真实 CH（无 SNI）+ 第二个带 SNI 的极简 CH
    PunycodeSNI    bool // 把 SNI 改写为 xn--<hex> 形式
}
```

### AnyEnabled

```go
func (s Strategies) AnyEnabled() bool
```

报告是否至少启用了一个策略。

```go
s := quicrewrite.Strategies{ReservedBits: true, PrependACK: true}
fmt.Println(s.AnyEnabled()) // true
```

## RewriteInitial

```go
func RewriteInitial(datagram []byte, s Strategies) ([]byte, bool)
```

把 s 应用到一个客户端 QUIC v1 Initial 数据报。返回改写后的数据报和 true；以下情况返回 `(nil, false)`，表示数据报必须原样转发：未启用任何策略、不是 QUIC v1 Initial、无法解密、或 CRYPTO 偏移 0 处没有 ClientHello。输入永不被修改；允许数据报因新增帧而变大，永不缩小。Initial 之后合并发送（coalesced）的其他包原样透传。

```go
n, err := conn.Read(buf)
if err != nil {
    return err
}
if out, ok := quicrewrite.RewriteInitial(buf[:n], strategies); ok {
    _, err = conn.Write(out)
} else {
    _, err = conn.Write(buf[:n]) // 原样转发
}
```
