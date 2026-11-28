# certmanager 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/certmanager`

## 概述

`certmanager` 管理宿主应用的 MITM 根 CA 证书与私钥：加载或生成 CA（RSA 2048，10 年有效期）、将其安装到各平台信任库、枚举/卸载本应用安装过的证书、导出 PEM。CA 主题中的组织名与通用名由 `config.Brand` 决定（`"<Product>"` / `"<Product> CA"`），因此不同品牌的应用各自安装可识别的根证书，而不是共享（或互相卸载）同一个。

设计要点：

- CA 证书与私钥通过 `atomicfile` 以「临时文件 + rename」方式落盘，崩溃或并发写入不会留下截断文件；私钥固定 0600 权限。
- 证书加载失败（文件损坏）时保留原文件为 `.corrupt.bak` 以备取证，并自动重新生成 CA，通过注入的 logger 发出警告。
- 安装状态查询有 5 分钟缓存（避免昂贵的 PowerShell/certutil 调用），写入操作后缓存立即失效。
- 平台实现：Windows 用 `certutil` 写 CurrentUser/LocalMachine 的 Root/CA 存储区；macOS 用 `security` CLI 写入登录钥匙串（会弹窗请求授权）；Linux（非 Android）将 CA 复制到发行版 anchor 目录并调用 `update-ca-certificates` 等命令发布；Android 通过脚本方式处理。
- 每个信任库中的证书都用 SHA-1 指纹（大写十六进制）寻址。

## 构造函数

### InitCertManager

为参考产品（`config.DefaultProductName`，即 SniShaper）加载或创建 `certDir` 下的 CA，返回可直接使用的 CertManager。内部使用 `certDir/ca.crt` 与 `certDir/ca.key` 两个固定文件名；目录不存在时自动创建。

```go
func InitCertManager(certDir string, opts ...Option) (*CertManager, error)
```

```go
cm, err := certmanager.InitCertManager("C:\\Users\\me\\.snishaper\\certs",
    certmanager.WithLogger(log.Std))
if err != nil {
    return err
}
```

### InitCertManagerFor

同 `InitCertManager`，但由 `brand` 决定 CA 主题与「哪些证书属于本应用」的判定。加载失败时把旧文件改名为 `.corrupt.bak` 并自动生成新 CA。

```go
func InitCertManagerFor(brand config.Brand, certDir string, opts ...Option) (*CertManager, error)
```

```go
cm, err := certmanager.InitCertManagerFor(
    config.Brand{Name: "FlowWeaver"}, certDir)
```

### NewCertManager

创建一个读写指定路径 CA 的 CertManager，CA 主题使用参考产品名。不加载也不生成 CA，需要随后调用 `LoadCA` / `GenerateCA`。

```go
func NewCertManager(caPath, keyPath string) *CertManager
```

### NewCertManagerFor

同 `NewCertManager`，但 CA 主题与信任库搜索使用给定品牌。

```go
func NewCertManagerFor(brand config.Brand, caPath, keyPath string) *CertManager
```

```go
cm := certmanager.NewCertManagerFor(config.Brand{},
    filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
if err := cm.LoadCA(); err != nil {
    return err
}
```

## Option

自定义 CertManager 初始化的函数式选项。

```go
type Option func(*CertManager)
```

### WithLogger

注入接收「损坏 CA 恢复警告」的 logger；不注入时 `InitCertManagerFor` 中的 CA 重新生成会静默发生。

```go
func WithLogger(l log.Logger) Option
```

## CertManager

MITM CA 证书与私钥的管理器。通过 `NewCertManager` / `NewCertManagerFor` / `InitCertManager` / `InitCertManagerFor` 构造，无需显式初始化锁等字段，构造后即可并发使用（内部用 RWMutex 保护）。

### 方法总览

| 方法 | 作用 |
|---|---|
| `Brand() config.Brand` | 返回本管理器签发证书所用的产品品牌 |
| `LoadCA() error` | 从磁盘加载 CA 证书与私钥，缺失时自动生成新 CA |
| `GenerateCA() error` | 生成新的 CA 证书与私钥并保存到磁盘 |
| `RegenerateCA() error` | 卸载旧证书、生成全新 CA 并安装 |
| `GetCACertPath() string` | 返回 CA 证书文件路径 |
| `GetCACert() *x509.Certificate` | 返回已加载的 CA 证书，未加载时为 nil |
| `GetCAKey() interface{}` | 返回 CA 私钥，未加载时为 nil |
| `GetCACertPEM() string` | 返回 PEM 形式的 CA 证书，未加载时为空字符串 |
| `ExportCert() ([]byte, error)` | 以 PEM 编码返回 CA 证书 |
| `IsCAInstalled() bool` | CA 是否已安装到平台信任库 |
| `GetCAInstallStatus() CAInstallStatus` | 返回缓存或新鲜的 CA 安装状态 |
| `InstallCA() error` | 卸载旧代 CA 后把当前 CA 安装到平台信任库 |
| `GetInstalledCertificates() ([]InstalledCert, error)` | 列出本应用在信任库中拥有的证书 |
| `UninstallCertificate(thumbprint string) error` | 按指纹或存储令牌卸载已安装的证书 |
| `OpenCertDir() error` | 在系统文件管理器中打开 CA 所在目录 |
| `OpenCAFile() error` | 在系统文件管理器中显示 CA 证书文件 |
| `SetLogger(l log.Logger)` | 注入接收损坏 CA 恢复警告的 logger |

### 常用方法签名与示例

```go
func (cm *CertManager) LoadCA() error
func (cm *CertManager) GenerateCA() error
func (cm *CertManager) RegenerateCA() error
func (cm *CertManager) InstallCA() error
func (cm *CertManager) GetCACertPath() string
func (cm *CertManager) GetCACert() *x509.Certificate
func (cm *CertManager) GetCAKey() interface{}
func (cm *CertManager) GetCACertPEM() string
func (cm *CertManager) ExportCert() ([]byte, error)
func (cm *CertManager) IsCAInstalled() bool
func (cm *CertManager) GetCAInstallStatus() CAInstallStatus
func (cm *CertManager) GetInstalledCertificates() ([]InstalledCert, error)
func (cm *CertManager) UninstallCertificate(thumbprint string) error
func (cm *CertManager) Brand() config.Brand
func (cm *CertManager) OpenCertDir() error
func (cm *CertManager) OpenCAFile() error
func (cm *CertManager) SetLogger(l log.Logger)
```

安装与状态查询：

```go
if !cm.IsCAInstalled() {
    if err := cm.InstallCA(); err != nil {
        return err
    }
}
status := cm.GetCAInstallStatus()
fmt.Println(status.Installed, status.InstallHelp)
```

导出与枚举：

```go
pemBytes, err := cm.ExportCert()
certs, err := cm.GetInstalledCertificates()
for _, c := range certs {
    _ = cm.UninstallCertificate(c.Token) // Token 或 Thumbprint 均可
}
```

## CAInstallStatus

描述 CA 是否已安装以及如何安装。

```go
type CAInstallStatus struct {
    Installed   bool   // 是否已安装
    Platform    string // 平台名（runtime.GOOS）
    CertPath    string // CA 证书文件路径
    InstallHelp string // 平台相关的安装指引文本
}
```

## InstalledCert

描述本应用安装到平台信任库中的一张证书。

```go
type InstalledCert struct {
    Subject       string `json:"subject"`
    Thumbprint    string `json:"thumbprint"`
    NotAfter      string `json:"notAfter"`
    StoreName     string `json:"storeName"`
    StoreLocation string `json:"storeLocation"`
    Token         string `json:"token"` // StoreLocation|StoreName|Thumbprint 组成的卸载令牌
}
```
