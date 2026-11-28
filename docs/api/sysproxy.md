# sysproxy 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/sysproxy`

## 概述

`sysproxy` 提供「系统代理开关」能力，把各桌面系统的系统级代理设置统一为同一套实例化 API：

- **Windows**：读写注册表 Internet Settings（`ProxyEnable` / `ProxyServer` / `ProxyOverride`），并通过 `InternetSetOptionW` 通知系统立即生效；
- **macOS**：通过 `networksetup` 修改各网络服务的 HTTP/HTTPS 代理；
- **Linux**：通过 `gsettings` 修改 GNOME 的 `org.gnome.system.proxy` 配置。

所有可变状态（原始代理快照、状态查询缓存）都保存在 `Manager` 实例中，包内不存在包级可变状态，因此同一进程内可以安全地创建多个互不影响的 Manager。

修改系统代理通常需要管理员（Windows）或 root（Linux）权限；本包只负责写入设置，不负责提权。

## Manager

系统代理管理器。每个实例各自持有原始代理快照与状态查询缓存，不依赖包级全局状态，因此同一进程内可以安全地创建多个互不影响的 Manager。用 `New` 构造。

### New

```go
func New(opts ...Option) *Manager
```

创建一个新的系统代理管理器。

```go
m := sysproxy.New()
if err := m.SaveOriginal(); err != nil {
    // 处理错误
}
if err := m.Enable(8080); err != nil {
    // 处理错误
}
// ... 使用代理 ...
_ = m.RestoreOriginal()
```

### 方法总览

| 方法 | 作用 |
|---|---|
| `Enable(port int) error` | 在本机回环地址的给定端口上启用系统代理 |
| `Disable() error` | 关闭系统代理 |
| `Set(enable bool, server string) error` | 按给定状态写入系统代理设置 |
| `Status() SystemProxyStatus` | 返回当前系统代理状态（缓存 2 秒） |
| `SaveOriginal() error` | 记录当前系统代理状态，供 `RestoreOriginal` 恢复 |
| `RestoreOriginal() error` | 把系统代理恢复为 `SaveOriginal` 记录的状态 |
| `Manual() error` | 打开系统代理设置界面 |

### 方法签名

```go
func (m *Manager) Enable(port int) error
func (m *Manager) Disable() error
func (m *Manager) Set(enable bool, server string) error
func (m *Manager) Status() SystemProxyStatus
func (m *Manager) SaveOriginal() error
func (m *Manager) RestoreOriginal() error
func (m *Manager) Manual() error
```

### Enable / Disable

`Enable` 的端口必须位于 1..65535，代理地址固定为 `127.0.0.1:<port>`。

```go
if err := m.Enable(8080); err != nil { return err }
defer m.RestoreOriginal()
```

### Set

启用代理时 `server` 必须是非空的 `host:port` 地址；启用时固定把 ProxyOverride 写为 `"<local>"`，与旧实现保持一致。Windows 上启用时会同时清掉 `AutoConfigURL`——PAC 存在时 WinInet 优先走 PAC 而忽略 ProxyServer。

```go
if err := m.Set(true, "192.168.1.2:8080"); err != nil { return err }
```

### Status

查询结果缓存 2 秒，避免频繁读取注册表；写入设置后缓存立即失效。

```go
status := m.Status()
if status.Enabled {
    fmt.Println("proxy:", status.Server, "override:", status.Override)
}
```

### SaveOriginal / RestoreOriginal

`RestoreOriginal` 在未调用过 `SaveOriginal` 时为空操作。恢复时会把 `SaveOriginal` 记录的 PAC 地址（AutoConfigURL）原样写回。

## SystemProxyStatus

描述当前系统代理的状态。

```go
type SystemProxyStatus struct {
    // Enabled 表示系统代理是否已启用。
    Enabled bool
    // Server 是代理服务器地址，格式为 host:port。
    Server string
    // Override 是代理绕过列表；本包启用代理时固定写入 "<local>"。
    Override string
    // AutoConfigURL 是 WinInet 的 PAC 地址（AutoConfigURL 注册表值）。
    // PAC 存在时 WinInet 优先走 PAC 而忽略 ProxyServer，因此启用代理前
    // 必须先清掉它，恢复时原样写回。
    AutoConfigURL string
}
```

## Option

调整 Manager 的可选行为。

```go
type Option func(*Manager)
```

### WithRunAsUser

```go
func WithRunAsUser(user string) Option
```

指定以 root 运行时把系统命令切换到哪个原始用户（仅 Linux 生效）。库本身不读环境变量：调用方若通过 sudo 启动，应显式传入 `os.Getenv("SUDO_USER")`；传空字符串表示直接在当前用户下执行。

```go
m := sysproxy.New(sysproxy.WithRunAsUser(os.Getenv("SUDO_USER")))
```
