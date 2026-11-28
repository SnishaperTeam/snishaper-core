# gfwlist 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/gfwlist`

## 概述

`gfwlist` 加载并提供 GFWList 格式的域名黑名单（每行一个域名，跳过 `#` / `!` 注释行及 `Source:`、`---` 开头的行），匹配采用后缀匹配：主机名本身或其任一父域名在列表中即视为被屏蔽。全部状态由 `sync.RWMutex` 保护，可并发使用。

`IsBlocked` 的父域名遍历用字符串切片而不是 split/join：启用自动路由时它对每个请求的每个主机名都会执行，运行在请求路径上。

## GFWList

已加载的域名黑名单。零值不可用，必须用 `NewGFWList` 构造。

### NewGFWList

```go
func NewGFWList(opts ...Option) *GFWList
```

创建一个空的 GFWList。

```go
g := gfwlist.NewGFWList(gfwlist.WithLogger(log.Std))
if _, err := g.LoadFromFile("gfwlist.txt"); err != nil {
    return err
}
if g.IsBlocked("blocked.example.com") {
    // 走代理
}
```

### 方法总览

| 方法 | 作用 |
|---|---|
| `LoadFromReader(r io.Reader) (int, error)` | 用从 r 解析出的域名替换黑名单内容，返回加载数量 |
| `LoadFromFile(path string) (int, error)` | 用 path 文件中的域名替换黑名单内容 |
| `IsBlocked(host string) bool` | 检查主机名（或其任一父域名）是否在列表中 |
| `Count() int` | 返回已加载的域名数量 |
| `LastLoadTime() time.Time` | 返回上次成功加载的时间（从未加载为零值） |

### 方法签名

```go
func (g *GFWList) LoadFromReader(r io.Reader) (int, error)
func (g *GFWList) LoadFromFile(path string) (int, error)
func (g *GFWList) IsBlocked(host string) bool
func (g *GFWList) Count() int
func (g *GFWList) LastLoadTime() time.Time
```

### LoadFromReader / LoadFromFile

整体替换列表内容（非追加），加载成功后更新 `LastLoadTime` 并向注入的 logger 打印加载数量。

```go
n, err := g.LoadFromReader(resp.Body)
// 或
n, err := g.LoadFromFile("gfwlist.txt")
```

### IsBlocked

先精确匹配，再逐级去掉最左侧标签做后缀匹配（`a.b.example.com` → `b.example.com` → `example.com` → `com`）。主机名为空或列表为空时返回 false。

```go
g.IsBlocked("www.example.com") // example.com 在列表中则为 true
```

## Option

`NewGFWList` 的函数式选项。

```go
type Option func(*GFWList)
```

### WithLogger

```go
func WithLogger(l log.Logger) Option
```

注入列表加载时使用的 logger（默认 `log.Nop`）。
