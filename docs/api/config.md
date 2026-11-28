# config 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/config`

## 概述

`config` 存放被 snishaper-core 多个包（proxy、dohresolver、singtun、cfpool、certmanager）共享的配置类型与小型网络辅助函数。这些类型放在这个不依赖其他内部包的叶子包里，是为了在消费方之间避免导入环。

## 常量

### DefaultProductName

```go
const DefaultProductName = "SniShaper"
```

未显式声明品牌时 snishaper-core 假定的产品名。参考应用 SniShaper 使用默认值；其他嵌入方（例如 FlowWeaver）传入自己的名字，使用户可见产物——TUN 适配器、安装的 CA、残留适配器清理——带上自己的品牌而不是库的参考产品。

## Brand

标识嵌入 snishaper-core 的应用。零值合法，表示 `DefaultProductName`。

```go
type Brand struct {
    // Name 是展示给用户的产品名，例如 "SniShaper" 或 "FlowWeaver"。
    // 空字符串表示 DefaultProductName。
    Name string
}
```

### 方法

```go
func (b Brand) Resolve() Brand
func (b Brand) Display() string
func (b Brand) OwnNames() []string
func (b Brand) Tunnels() []string
```

| 方法 | 作用 |
|---|---|
| `Resolve()` | 返回产品名已默认化并去除首尾空格的 Brand；读取 Name 前应先调用（其余方法会替你调用） |
| `Display()` | 返回解析后的产品名 |
| `OwnNames()` | 返回小写的、专属于本产品的接口名（产品名及其 dashed 形式）；判定「某物可否被删除/是否属于本产品」时使用 |
| `Tunnels()` | 返回本产品自有 TUN 设备可能使用的接口名（小写）：OwnNames 加上共享的 sing-tun 驱动名 |

匹配必须精确（外加尾部数字后缀），绝不能子串匹配：仅仅包含这些名字的名字（如 "Tundra"）必须保持无关。`OwnNames` 排除了所有 sing-tun 应用共享的名字——描述里含 "sing-tun" 什么也证明不了：sing-box 和 mihomo 用同一个 Wintun 驱动，按那个名字行事会拆掉别的应用的适配器。

```go
b := config.Brand{Name: "FlowWeaver"}
fmt.Println(b.Display())        // FlowWeaver
fmt.Println(b.OwnNames())       // [flowweaver flow-weaver]
fmt.Println(b.Tunnels())        // [flowweaver flow-weaver singtun sing-tun]
```

## CertVerifyConfig

描述上游或 DoH 节点的 TLS 证书校验方式。零值表示「默认校验」。

```go
type CertVerifyConfig struct {
    Mode                  string   `json:"mode,omitempty"`
    Names                 []string `json:"names,omitempty"`
    Suffixes              []string `json:"suffixes,omitempty"`
    SPKISHA256            []string `json:"spki_sha256,omitempty"`
    AllowUnknownAuthority bool     `json:"allow_unknown_authority,omitempty"`
}
```

### IsZero

报告是否未设置任何校验选项。

```go
func (c CertVerifyConfig) IsZero() bool
```

```go
var c config.CertVerifyConfig
fmt.Println(c.IsZero()) // true
```

## 辅助函数

### Dashed

把 CamelCase 产品名转为小写 dashed 形式：`"SniShaper"` → `"sni-shaper"`，`"FlowWeaver"` → `"flow-weaver"`。不含大写字母的名字原样返回。

```go
func Dashed(name string) string
```

```go
config.Dashed("SniShaper")   // "sni-shaper"
config.Dashed("HTTPProxy")   // "httpproxy"（大写连续串视为一个词）
```

### HalfClose

关闭 `conn` 的写半边、保持读半边打开，让对端仍能冲刷它那一半会话。无法半关闭的连接会被整个关闭。

```go
func HalfClose(conn net.Conn)
```

```go
config.HalfClose(clientConn) // 请求已写完，继续读响应
```

### MapNAT64Addr

把 IPv4 地址映射进给定 NAT64 前缀。空前缀或无法解析的输入原样返回；第二个返回值报告输入是否为 IPv4 地址（非 IPv4 在有前缀时返回 false）。

```go
func MapNAT64Addr(ipStr string, prefix string) (string, bool)
```

```go
mapped, ok := config.MapNAT64Addr("1.1.1.1", "64:ff9b::")
// mapped == "64:ff9b::101:101", ok == true
```

### VerifyChainOnly

校验对端证书链是否可由系统根信任，不匹配主机名。用于 SNI 可能被主动伪造的场景：只要求对方持有一张可信 CA 签发的证书。

```go
func VerifyChainOnly(peerCerts []*x509.Certificate) error
```

```go
tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
    return config.VerifyChainOnly(cs.PeerCertificates)
}
```
