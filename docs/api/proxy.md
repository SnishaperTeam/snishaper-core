# proxy 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/proxy`

`proxy` 包是 SniShaper 的本地代理核心库：内置 HTTP（CONNECT）与 SOCKS5 混合监听端口，按站点规则对每个连接执行 MITM 解密、TLS 记录分片（TLS-RF）、ECH 注入、QUIC 重建、SNI 伪装、Cloudflare IP 池、NAT64 等处理策略，并管理规则配置的加载、分层合并、热更新与订阅。

设计要点：

- **实例持有状态，无包级可变全局**：所有运行状态（规则、连接注册表、IP 池、网卡选择器）都挂在 `ProxyServer` / `RuleManager` 实例上，同一进程可并存多个互不干扰的实例（唯一例外：WireGuard 隧道池是进程级的，`Stop` 只释放本实例拨过的隧道）。
- **日志注入**：通过 `WithLogger(l log.Logger)` 注入日志器，默认 `log.Nop`——未配置的库保持静默。
- **构造期选项**：`NewProxyServer` / `NewRuleManager` 使用 functional options（`Option`），与构造后再 `SetXxx` 等价。
- **规则匹配单一事实来源**：`SetRules` 建立的规则集由真实连接路径（`matchRuleDetailed`）与解释器（`ExplainMatch`）共用，保证解释不偏离引擎。

## 目录

- [快速上手](#快速上手)
- [构造选项（Option）](#构造选项option)
- [RuleManager —— 规则与配置管理](#rulemanager--规则与配置管理)
- [ProxyServer —— 代理服务器](#proxyserver--代理服务器)
- [AutoRouter —— 自动路由](#autorouter--自动路由)
- [规则与配置类型](#规则与配置类型)
- [匹配与调试](#匹配与调试)
- [配置导入导出与迁移](#配置导入导出与迁移)
- [TUN 辅助类型](#tun-辅助类型)
- [端口与进程辅助函数](#端口与进程辅助函数)
- [错误值](#错误值)

## 快速上手

```go
package main

import (
	"log"

	"github.com/SnishaperTeam/snishaper-core/proxy"
)

func main() {
	// 1. 规则与设置管理器（settings.json + rules/config.json）
	rm := proxy.NewRuleManager("config/settings.json", "rules/config.json",
		proxy.WithLogger(log.New(log.Writer(), "", log.LstdFlags)))
	if err := rm.LoadConfig(); err != nil {
		log.Fatal(err)
	}

	// 2. 代理服务器：混合 HTTP/SOCKS5 端口
	srv := proxy.NewProxyServer("127.0.0.1:8080", proxy.WithRuleManager(rm))
	if err := srv.Start(); err != nil {
		log.Fatal(err)
	}
	defer srv.Stop()
	select {} // 阻塞，实际应用中等待退出信号
}
```

`Start` 前必须设置 `RuleManager`（`WithRuleManager` 或 `SetRuleManager`），否则返回错误 `proxy: rule manager not set`。

---

## 构造选项（Option）

```go
type Option func(*options)
```

`Option` 是 `NewProxyServer` 与 `NewRuleManager` 共同接受的构造期选项；与具体构造器无关的选项会被忽略。

| 选项函数 | 作用 |
|---|---|
| `WithListenAddr(addr string) Option` | 覆盖 `ProxyServer` 的初始监听地址（host:port） |
| `WithRuleManager(rm *RuleManager) Option` | 构造时挂载 `RuleManager`，免去之后调用 `SetRuleManager` |
| `WithCertGenerator(cg CertGenerator) Option` | 设置 MITM 模式使用的 CA 证书生成器 |
| `WithLogger(l log.Logger) Option` | 注入 `ProxyServer` / `RuleManager` 使用的日志器，默认 `log.Nop` |
| `WithOnStop(cb func(error)) Option` | 注册 `ProxyServer` 意外停止时的回调（与 `OnStop` 字段同一钩子） |
| `WithRouterDebug(enabled bool) Option` | 在 `RuleManager` 上启用逐请求路由决策日志（替代单仓版的 `SNISHAPER_ROUTER_DEBUG=1` 环境变量） |
| `WithBrand(b config.Brand) Option` | 声明嵌入本库的应用品牌：决定默认 TUN 适配器名、出站选择时哪些网卡算自家隧道、证书管理器的 CA 主题；零值保持参考产品名 |
| `WithProductName(name string) Option` | 只改产品名的 `WithBrand` 简写（等价于 `WithBrand(config.Brand{Name: name})`） |

```go
srv := proxy.NewProxyServer("127.0.0.1:8080",
	proxy.WithRuleManager(rm),
	proxy.WithCertGenerator(certGen),
	proxy.WithLogger(myLogger),
	proxy.WithOnStop(func(err error) { log.Printf("server stopped: %v", err) }),
)
```

---

## RuleManager —— 规则与配置管理

```go
type RuleManager struct{ /* 均为未导出字段 */ }
```

`RuleManager` 负责站点规则与各项配置的加载、保存和热更新。它同时是 settings.json（应用设置）与 rules 配置文件（站点分组、上游、DNS 节点、ECH/NAT64 档案）的唯一读写入口。

### 构造

```go
func NewRuleManager(settingsPath, rulesPath string, opts ...Option) *RuleManager
```

创建一个把设置持久化到 `settingsPath`、规则持久化到 `rulesPath` 的管理器。可用选项：`WithLogger`、`WithRouterDebug`、`WithBrand`/`WithProductName`。默认值：`closeToTray=true`、`autoStartMethod="task"`、`showMainOnAutoStart=true`、`language="zh"`、`theme="dark"`。

```go
rm := proxy.NewRuleManager("config/settings.json", "rules/config.json",
	proxy.WithRouterDebug(true))
```

### 生命周期

| 方法 | 签名 | 作用 |
|---|---|---|
| `LoadConfig` | `func (rm *RuleManager) LoadConfig() error` | 从磁盘加载配置，文件缺失时使用默认值 |
| `LoadConfigWithMigration` | `func (rm *RuleManager) LoadConfigWithMigration() (MigrationReport, error)` | 与 `LoadConfig` 相同，但返回 [`MigrationReport`](#migrationreport) |
| `SaveConfig` | `func (rm *RuleManager) SaveConfig() error` | 将当前配置写回磁盘 |
| `RulesPath` | `func (rm *RuleManager) RulesPath() string` | 返回规则配置文件路径 |
| `WatchRulesFile` | `func (rm *RuleManager) WatchRulesFile(onChange func()) (func(), error)` | 任一规则文件（生效的 config.json 或上游备份 config.upstream.json）变化时调用 `onChange`，返回停止函数 |
| `SetOnConfigSaved` | `func (r *RuleManager) SetOnConfigSaved(cb func())` | 设置配置保存成功后的回调（在独立 goroutine 中触发，内部有 panic 保护） |

```go
if err := rm.LoadConfig(); err != nil {
	return err
}
stop, err := rm.WatchRulesFile(func() { log.Println("rules changed on disk") })
if err != nil {
	return err
}
defer stop()
```

### 规则集与匹配

#### SetRules（核心）

```go
func (r *RuleManager) SetRules(rules []Rule)
```

替换手动规则集。切片按原样存储：**调用方之后不得再改动它**——`matchRuleDetailed` 在读锁下读取该切片，且此处构建的域名索引会失效。应构建新切片并再次调用 `SetRules`，而不是原地修改。内部按规则域名模式建立加速索引（`ruleIndex`），域名形模式按归一化域分桶，正则/关键字等任意匹配模式留在线性扫描列表。

```go
rm.SetRules([]proxy.Rule{
	{Domain: "example.com", Mode: "tls-rf", Enabled: true},
	{Domain: "*.example.org", Mode: "direct", Enabled: true},
})
```

| 方法 | 签名 | 作用 |
|---|---|---|
| `HasProcessRules` | `func (r *RuleManager) HasProcessRules() bool` | 是否存在带进程过滤的启用规则；调用方用它跳过无规则需要时的进程查找开销 |
| `MatchQUICStrategies` | `func (r *RuleManager) MatchQUICStrategies(host string) (quicrewrite.Strategies, bool)` | 返回匹配 `host` 的规则的 QUIC Initial 重写策略（TUN fake-ip UDP 路径消费）；`ok=false` 表示该主机的 QUIC 必须保持原样：丢弃数据报让客户端回退 TCP |
| `SetRouteEventCallback` | `func (r *RuleManager) SetRouteEventCallback(cb func(domain, mode string))` | 设置路由模式变化时的回调 |
| `ExplainMatch` | `func (rm *RuleManager) ExplainMatch(host, mode, process string) MatchExplanation` | 解释规则引擎在给定全局模式与客户端进程名（`""` = 未知/任意）下将如何处理 `host` |

#### ExplainMatch（核心）

复用真实匹配管线——同样的评分、同样的进程规则优先级、同样的自动路由回退、同样的 MITM 降级——所以解释不可能偏离引擎；它只是跳过路由事件发送，避免模拟查询污染实时路由流。

```go
exp := rm.ExplainMatch("www.example.com", "mitm", "chrome.exe")
fmt.Println(exp.Mode, exp.Source, exp.RuleDomain)
for _, c := range exp.Candidates {
	fmt.Printf("  candidate %s score=%d\n", c.Domain, c.Score)
}
```

返回类型见 [`MatchExplanation`](#matchexplanation--matchcandidate)。

### 站点分组（SiteGroup）

| 方法 | 签名 | 作用 |
|---|---|---|
| `GetSiteGroups` | `func (rm *RuleManager) GetSiteGroups() []SiteGroup` | 返回全部站点分组 |
| `AddSiteGroup` | `func (rm *RuleManager) AddSiteGroup(sg SiteGroup) error` | 新增一个站点分组 |
| `UpdateSiteGroup` | `func (rm *RuleManager) UpdateSiteGroup(sg SiteGroup) error` | 按 ID 更新站点分组 |
| `DeleteSiteGroup` | `func (rm *RuleManager) DeleteSiteGroup(id string) error` | 按 ID 删除站点分组 |
| `RevertSiteGroupToUpstream` | `func (rm *RuleManager) RevertSiteGroupToUpstream(id string) error` | 丢弃站点分组的用户层状态，恢复上游定义：覆盖回落到随包副本、已删除（打墓碑）的上游分组被还原、用户自建分组被移除 |

### 上游（Upstream）

| 方法 | 签名 | 作用 |
|---|---|---|
| `GetUpstreams` | `func (rm *RuleManager) GetUpstreams() []Upstream` | 返回全部上游配置 |
| `AddUpstream` | `func (rm *RuleManager) AddUpstream(u Upstream) error` | 新增一个上游 |
| `UpdateUpstream` | `func (rm *RuleManager) UpdateUpstream(u Upstream) error` | 按 ID 更新上游 |
| `DeleteUpstream` | `func (rm *RuleManager) DeleteUpstream(id string) error` | 按 ID 删除上游 |
| `RevertUpstreamConfigToUpstream` | `func (rm *RuleManager) RevertUpstreamConfigToUpstream(id string) error` | 上游（代理服务器）定义版的 `RevertSiteGroupToUpstream` |

### DNS 节点（DNSNode）

| 方法 | 签名 | 作用 |
|---|---|---|
| `GetDNSNodes` | `func (rm *RuleManager) GetDNSNodes() []DNSNode` | 返回全部 DoH 上游节点 |
| `AddDNSNode` | `func (rm *RuleManager) AddDNSNode(n DNSNode) error` | 新增一个 DNS 节点 |
| `UpdateDNSNode` | `func (rm *RuleManager) UpdateDNSNode(n DNSNode) error` | 按 ID 更新 DNS 节点 |
| `DeleteDNSNode` | `func (rm *RuleManager) DeleteDNSNode(id string) error` | 按 ID 删除 DNS 节点 |
| `SetDNSNodePriority` | `func (rm *RuleManager) SetDNSNodePriority(id string, targetIndex int) error` | 把指定 ID 的节点移动到目标下标（0 起）实现重排；节点按列表顺序被查询 |

### ECH 配置档案

| 方法 | 签名 | 作用 |
|---|---|---|
| `GetECHProfiles` | `func (rm *RuleManager) GetECHProfiles() []ECHProfile` | 返回全部 ECH 配置档案 |
| `UpsertECHProfile` | `func (rm *RuleManager) UpsertECHProfile(p ECHProfile) error` | 新增或更新一个 ECH 配置档案 |
| `DeleteECHProfile` | `func (rm *RuleManager) DeleteECHProfile(id string) error` | 按 ID 删除 ECH 配置档案 |
| `GetBinaryECHConfig` | `func (r *RuleManager) GetBinaryECHConfig(id string) []byte` | 按 ID 返回 ECH 配置的二进制数据 |
| `UpdateECHProfileConfig` | `func (r *RuleManager) UpdateECHProfileConfig(profileID string, configBytes []byte) error` | 更新档案对应的 ECH 二进制配置 |

### NAT64 配置档案

| 方法 | 签名 | 作用 |
|---|---|---|
| `GetNAT64Profiles` | `func (rm *RuleManager) GetNAT64Profiles() []NAT64Profile` | 返回全部 NAT64 配置档案 |
| `AddNAT64Profile` | `func (rm *RuleManager) AddNAT64Profile(p NAT64Profile) error` | 新增一个 NAT64 配置档案 |
| `UpdateNAT64Profile` | `func (rm *RuleManager) UpdateNAT64Profile(p NAT64Profile) error` | 按 ID 更新 NAT64 配置档案 |
| `DeleteNAT64Profile` | `func (rm *RuleManager) DeleteNAT64Profile(id string) error` | 按 ID 删除 NAT64 配置档案 |
| `GetNAT64PrefixByID` | `func (rm *RuleManager) GetNAT64PrefixByID(id string) string` | 按 ID 返回 NAT64 前缀 |

### 自动路由

| 方法 | 签名 | 作用 |
|---|---|---|
| `GetAutoRouter` | `func (rm *RuleManager) GetAutoRouter() *AutoRouter` | 返回自动路由器实例 |
| `InitAutoRouter` | `func (rm *RuleManager) InitAutoRouter(resolver *dohresolver.FailoverResolver)` | 用给定解析器初始化自动路由器 |
| `GetAutoRoutingConfig` | `func (rm *RuleManager) GetAutoRoutingConfig() AutoRoutingConfig` | 返回自动路由配置 |
| `UpdateAutoRoutingConfig` | `func (rm *RuleManager) UpdateAutoRoutingConfig(cfg AutoRoutingConfig) error` | 更新自动路由配置 |
| `GetAutoRoutingStatus` | `func (rm *RuleManager) GetAutoRoutingStatus() GFWListStatus` | 返回 GFW 列表的加载状态 |

### 配置导入导出

| 方法 | 签名 | 作用 |
|---|---|---|
| `ExportConfig` | `func (rm *RuleManager) ExportConfig() (string, error)` | 把当前规则与设置序列化为 JSON 字符串 |
| `ImportConfig` | `func (rm *RuleManager) ImportConfig(content string) error` | 从 JSON 字符串替换当前配置 |
| `ImportConfigWithSummary` | `func (rm *RuleManager) ImportConfigWithSummary(content string) (ImportSummary, error)` | 导入配置并报告变更统计 |

```go
data, err := rm.ExportConfig()
if err != nil {
	return err
}
if err := os.WriteFile("backup.json", []byte(data), 0o644); err != nil {
	return err
}
```

### 远程规则合并（分层规则）

#### MergeRemoteRules（核心）

```go
func (rm *RuleManager) MergeRemoteRules(remote RulesConfig, remoteHash string) (RulesMergeSummary, error)
```

应用一版远程规则（issue #172，v0.7 起）：原始上游备份（rules/config.upstream.json）被整体替换；先从替换前的生效状态推导用户差异层，再把生效状态重建为"新上游 + 推导出的用户差异"（冲突时用户赢），并重写 rules/config.json。因此对工作文件的手工编辑与 GUI 编辑一样能在更新后幸存。

```go
summary, err := rm.MergeRemoteRules(remote, remoteHash)
if err != nil {
	return err
}
if summary.Changed() {
	log.Printf("rules updated: +%d groups, ~%d groups", summary.AddedGroups, summary.UpdatedGroups)
}
```

| 方法 | 签名 | 作用 |
|---|---|---|
| `RemoteRulesHash` | `func (rm *RuleManager) RemoteRulesHash() string` | 上次应用的规则版本哈希，调用方据此在上游无变化时跳过整个合并 |
| `CurrentRulesHash` | `func (rm *RuleManager) CurrentRulesHash() string` | 内存中当前规则的哈希（两个分层文件按最后一次写入的组合哈希） |
| `GetRulesLayerInfo` | `func (rm *RuleManager) GetRulesLayerInfo() RulesLayerInfo` | 描述每个生效站点分组/上游所属层（"upstream"/"override"/"user"）及被打墓碑的上游 ID；用户差异按需从生效状态与上游备份推导 |

### 订阅管理

| 方法 | 签名 | 作用 |
|---|---|---|
| `SetSubscriptionStore` | `func (rm *RuleManager) SetSubscriptionStore(store *subscription.Store)` | 挂载订阅存储并应用活动订阅的规则 |
| `GetSubscriptionStore` | `func (rm *RuleManager) GetSubscriptionStore() *subscription.Store` | 返回已挂载的存储（可能为 nil） |
| `ApplyActiveSubscriptionRules` | `func (rm *RuleManager) ApplyActiveSubscriptionRules()` | 从活动订阅重建运行时规则集；内置默认订阅恢复随包规则。池化的 WireGuard 隧道在此被丢弃：节点集变化后残留隧道会继续占用设备、IP 栈与 UDP socket |
| `ListSubscriptions` | `func (rm *RuleManager) ListSubscriptions() []*subscription.Entry` | 列出全部已知订阅 |
| `AddSubscription` | `func (rm *RuleManager) AddSubscription(name, url string) (*subscription.Entry, error)` | 从 Clash URL 注册新订阅 |
| `UpdateSubscription` | `func (rm *RuleManager) UpdateSubscription(id string) (*subscription.Entry, error)` | 重新下载订阅并在活动时刷新规则 |
| `DeleteSubscription` | `func (rm *RuleManager) DeleteSubscription(id string) error` | 删除订阅，必要时恢复默认 |
| `ActivateSubscription` | `func (rm *RuleManager) ActivateSubscription(id string) error` | 切换活动订阅并重载规则 |
| `SelectSubscriptionNode` | `func (rm *RuleManager) SelectSubscriptionNode(subscriptionID, group, node string) error` | 记录订阅分组中选定的节点 |

### 应用设置（getter / setter）

以下方法读写 settings.json 中的应用级设置，均持久化到磁盘（setter 返回 `error` 的会立即保存；`SetListenPort` 例外，只改内存值）。

| 方法 | 签名 | 作用 |
|---|---|---|
| `GetListenPort` | `func (rm *RuleManager) GetListenPort() string` | 返回本地监听端口 |
| `SetListenPort` | `func (rm *RuleManager) SetListenPort(port string)` | 设置本地监听端口 |
| `GetListenAddress` | `func (rm *RuleManager) GetListenAddress() string` | 返回本地监听地址（空值表示默认 127.0.0.1） |
| `SetListenAddress` | `func (rm *RuleManager) SetListenAddress(addr string) error` | 设置本地监听地址；空串合法（重置为默认 127.0.0.1），非 IP 格式返回错误 |
| `GetCloseToTray` | `func (rm *RuleManager) GetCloseToTray() bool` | 关闭窗口时是否最小化到托盘 |
| `SetCloseToTray` | `func (rm *RuleManager) SetCloseToTray(enabled bool) error` | 设置关闭窗口时是否最小化到托盘 |
| `GetHibernateOnClose` | `func (rm *RuleManager) GetHibernateOnClose() bool` | 关闭时是否休眠 |
| `SetHibernateOnClose` | `func (rm *RuleManager) SetHibernateOnClose(enabled bool) error` | 设置关闭时是否休眠 |
| `GetAutoStart` | `func (rm *RuleManager) GetAutoStart() bool` | 是否开机自启 |
| `SetAutoStart` | `func (rm *RuleManager) SetAutoStart(enabled bool) error` | 设置是否开机自启 |
| `GetAutoStartMethod` | `func (rm *RuleManager) GetAutoStartMethod() string` | 开机自启的注册方式（task/service/registry）；空值或未知值按 "task"（任务计划程序）处理，具体分发由各平台实现 |
| `SetAutoStartMethod` | `func (rm *RuleManager) SetAutoStartMethod(method string) error` | 设置开机自启的注册方式（task/service/registry） |
| `GetShowMainWindowOnAutoStart` | `func (rm *RuleManager) GetShowMainWindowOnAutoStart() bool` | 自启时是否显示主窗口 |
| `SetShowMainWindowOnAutoStart` | `func (rm *RuleManager) SetShowMainWindowOnAutoStart(enabled bool) error` | 设置自启时是否显示主窗口 |
| `GetAutoEnableProxyOnAutoStart` | `func (rm *RuleManager) GetAutoEnableProxyOnAutoStart() bool` | 自启时是否自动启动代理内核 |
| `SetAutoEnableProxyOnAutoStart` | `func (rm *RuleManager) SetAutoEnableProxyOnAutoStart(enabled bool) error` | 设置自启时是否自动启动代理内核 |
| `GetAutoEnableSysProxyOnAutoStart` | `func (rm *RuleManager) GetAutoEnableSysProxyOnAutoStart() bool` | 自启时是否自动设置系统代理 |
| `SetAutoEnableSysProxyOnAutoStart` | `func (rm *RuleManager) SetAutoEnableSysProxyOnAutoStart(enabled bool) error` | 设置自启时是否自动设置系统代理 |
| `GetAutoUpdateRules` | `func (rm *RuleManager) GetAutoUpdateRules() bool` | 是否自动更新规则 |
| `SetAutoUpdateRules` | `func (rm *RuleManager) SetAutoUpdateRules(enabled bool) error` | 设置是否自动更新规则 |
| `GetLanguage` | `func (r *RuleManager) GetLanguage() string` | 返回界面语言 |
| `SetLanguage` | `func (r *RuleManager) SetLanguage(lang string) error` | 设置界面语言 |
| `GetTheme` | `func (r *RuleManager) GetTheme() string` | 返回界面主题 |
| `SetTheme` | `func (r *RuleManager) SetTheme(theme string) error` | 设置界面主题 |
| `GetAppearanceMode` | `func (r *RuleManager) GetAppearanceMode() string` | 返回浅色/深色模式（"light"/"dark"/"system"）；从未设置过时返回空串，让前端保留本地缓存的上一选择 |
| `SetAppearanceMode` | `func (r *RuleManager) SetAppearanceMode(mode string) error` | 设置外观模式 |
| `GetCloudflareConfig` | `func (rm *RuleManager) GetCloudflareConfig() CloudflareConfig` | 返回 Cloudflare IP 池配置 |
| `UpdateCloudflareConfig` | `func (rm *RuleManager) UpdateCloudflareConfig(cfg CloudflareConfig) error` | 更新 Cloudflare IP 池配置 |
| `GetIPPoolsConfig` | `func (rm *RuleManager) GetIPPoolsConfig() []IPPoolConfig` | 返回全部命名 IP 池配置（cloudfront、自定义 CDN 等） |
| `UpdateIPPoolsConfig` | `func (rm *RuleManager) UpdateIPPoolsConfig(pools []IPPoolConfig) error` | 覆盖保存全部命名 IP 池配置 |
| `GetTUNConfig` | `func (rm *RuleManager) GetTUNConfig() TUNConfig` | 返回 TUN 配置 |
| `UpdateTUNConfig` | `func (rm *RuleManager) UpdateTUNConfig(cfg TUNConfig) error` | 更新 TUN 配置 |
| `GetFragmentConfig` | `func (rm *RuleManager) GetFragmentConfig() FragmentConfig` | 返回 TLS 分片配置 |
| `SetFragmentConfig` | `func (rm *RuleManager) SetFragmentConfig(cfg FragmentConfig) error` | 更新 TLS 分片配置 |
| `GetMigrationEnabled` | `func (rm *RuleManager) GetMigrationEnabled() bool` | 是否启用会话迁移 |
| `SetMigrationEnabled` | `func (rm *RuleManager) SetMigrationEnabled(enabled bool) error` | 设置是否启用会话迁移 |
| `GetMigrationServer` | `func (rm *RuleManager) GetMigrationServer() string` | 返回会话迁移服务器地址 |
| `SetMigrationServer` | `func (rm *RuleManager) SetMigrationServer(server string) error` | 设置会话迁移服务器地址 |
| `GetUpdateChannel` | `func (rm *RuleManager) GetUpdateChannel() string` | 返回当前更新通道 |
| `SetUpdateChannel` | `func (rm *RuleManager) SetUpdateChannel(channel string) error` | 设置更新通道 |
| `GetDownloadSource` | `func (rm *RuleManager) GetDownloadSource() string` | 返回下载源设置 |
| `SetDownloadSource` | `func (rm *RuleManager) SetDownloadSource(src string) error` | 设置下载源 |
| `GetCustomDownloadSource` | `func (rm *RuleManager) GetCustomDownloadSource() string` | 返回自定义下载源前缀 |
| `SetCustomDownloadSource` | `func (rm *RuleManager) SetCustomDownloadSource(prefix string) error` | 设置自定义下载源前缀 |

---

## ProxyServer —— 代理服务器

```go
type ProxyServer struct {
	Server      *http.Server // Start 后可用的底层 HTTP 服务器（Stop 后置 nil）
	Fingerprint string       // 指纹字段（由嵌入方使用）
	OnStop      func(error)  // 服务器意外停止时的回调钩子
	// 其余均为未导出字段
}
```

`ProxyServer` 是本地代理服务器核心：单一混合端口同时接受 HTTP（含 CONNECT）与 SOCKS5 连接，按 `RuleManager` 的逐域名规则分发处理。

### 构造

```go
func NewProxyServer(addr string, opts ...Option) *ProxyServer
```

创建监听 `addr` 的 `ProxyServer`。可选设置通过 functional options 应用（`WithLogger`、`WithRuleManager` 等）。

```go
srv := proxy.NewProxyServer("127.0.0.1:8080",
	proxy.WithRuleManager(rm),
	proxy.WithProductName("MyApp"))
```

### 生命周期

#### Start（核心）

```go
func (p *ProxyServer) Start() error
```

启动代理监听器与后台工作协程。要求已设置 `RuleManager`。混合端口无鉴权：绑定非回环地址时记录警告（本机网络可达一个开放代理）。重复调用是幂等的（已运行则直接返回 nil）。

#### Stop（核心）

```go
func (p *ProxyServer) Stop() error
```

关闭监听器与后台工作协程：停止证书缓存清理协程、关闭 SOCKS5 跟踪器、停止 CF/命名 IP 池、只释放本服务器拨过的 WireGuard 隧道（隧道池是进程级的，其他嵌入的服务器可能仍在运行）、关闭 DoH 解析器以释放 QUIC transport 与空闲连接。未运行时返回 nil，可安全重复调用。

```go
if err := srv.Start(); err != nil {
	return err
}
defer srv.Stop()
```

| 方法 | 签名 | 作用 |
|---|---|---|
| `IsRunning` | `func (p *ProxyServer) IsRunning() bool` | 服务器是否正在运行 |

### 监听地址与模式

| 方法 | 签名 | 作用 |
|---|---|---|
| `GetListenAddr` | `func (p *ProxyServer) GetListenAddr() string` | 返回当前本地监听地址 |
| `SetListenAddr` | `func (p *ProxyServer) SetListenAddr(addr string) error` | 设置监听地址；运行期间拒绝修改 |
| `GetMode` | `func (p *ProxyServer) GetMode() string` | 返回当前服务器模式 |
| `SetMode` | `func (p *ProxyServer) SetMode(mode string) error` | 设置服务器模式，未知值返回错误 |
| `SetTUNMode` | `func (p *ProxyServer) SetTUNMode(enabled bool)` | 设置 TUN 模式标记，启用后出站连接绑定物理网卡 |

```go
if err := srv.SetListenAddr("127.0.0.1:9090"); err != nil {
	// 运行中或不合法的地址
	return err
}
```

### 日志

| 方法 | 签名 | 作用 |
|---|---|---|
| `SetLogCallback` | `func (p *ProxyServer) SetLogCallback(cb func(string))` | 设置接收日志行的回调函数 |
| `SetLogger` | `func (p *ProxyServer) SetLogger(l log.Logger)` | 注入未设置日志回调时使用的后备日志器 |

### 组件注入

| 方法 | 签名 | 作用 |
|---|---|---|
| `SetRuleManager` | `func (p *ProxyServer) SetRuleManager(rm *RuleManager)` | 挂载用于逐域名决策的规则管理器 |
| `SetCertGenerator` | `func (p *ProxyServer) SetCertGenerator(cg CertGenerator)` | 挂载 MITM 证书生成器 |
| `SetSubscriptionDialer` | `func (p *ProxyServer) SetSubscriptionDialer(store *subscription.Store)` | 把拨号器接到订阅存储（按订阅节点拨号） |

### 连接查看与统计

| 方法 | 签名 | 作用 |
|---|---|---|
| `ActiveConnections` | `func (p *ProxyServer) ActiveConnections() []ConnInfo` | 返回当前被跟踪连接的快照（最新在前），任意 goroutine 可安全调用 |
| `GetStats` | `func (p *ProxyServer) GetStats() (int64, int64, int64)` | 返回下行与上行字节计数（第三个返回值保留，恒为 0） |
| `ClearCertCache` | `func (p *ProxyServer) ClearCertCache()` | 清除全部缓存的 MITM 叶子证书 |

```go
down, up, _ := srv.GetStats()
log.Printf("down=%d up=%d, active=%d", down, up, len(srv.ActiveConnections()))
```

### 拨号、TLS 与 DoH

| 方法 | 签名 | 作用 |
|---|---|---|
| `DialWithRule` | `func (p *ProxyServer) DialWithRule(ctx context.Context, network, addr string, rule Rule) (net.Conn, error)` | 按规则拨号（内部 `dialWithRule` 的导出包装） |
| `EstablishUpstreamConn` | `func (p *ProxyServer) EstablishUpstreamConn(host string, rule Rule, dialCandidates []string, initialALPN string) (net.Conn, string, error)` | 建立到上游的连接（内部 `establishUpstreamConn` 的导出包装） |
| `GetUConn` | `func (p *ProxyServer) GetUConn(conn net.Conn, sni string, verifyName string, rule Rule, allowInsecure bool, alpn string, echConfig []byte) *utls.UConn` | 按规则、ALPN 与 ECH 配置把 `conn` 包装成 uTLS `UConn` |
| `NewQUICRoundTripper` | `func (p *ProxyServer) NewQUICRoundTripper(host string, rule Rule) (*http3.Transport, error)` | 创建按规则拨号（含 NAT64 映射）的 HTTP/3 transport |
| `FetchECH` | `func (p *ProxyServer) FetchECH(ctx context.Context, domain string, dohURL string) ([]byte, error)` | 通过 DoH 获取域名的 ECH 配置；`dohURL` 非空时直连该 URL |
| `GetDoHResolver` | `func (p *ProxyServer) GetDoHResolver() *dohresolver.FailoverResolver` | 返回 DoH 故障转移解析器 |
| `UpdateECHProfileConfig` | `func (p *ProxyServer) UpdateECHProfileConfig(profileID string, configBytes []byte)` | 把新的 ECH 配置字节存到匹配该档案的规则上 |

```go
conn, err := srv.DialWithRule(ctx, "tcp", "example.com:443", proxy.Rule{
	Mode:       "tls-rf",
	ECHEnabled: true,
	Enabled:    true,
})
```

### Cloudflare IP 池

#### UpdateCloudflareIPPool（核心）

```go
func (p *ProxyServer) UpdateCloudflareIPPool(ips []string)
```

把一组 Cloudflare IP 应用到池（首次使用时创建池）。它是所有池更新的唯一入口：GUI 启动路径、核心运行时、规则文件监听器与 API 刷新都走这里。空列表保持现有池不变。

历史注记：曾经存在第二个由 `CloudflareConfig.AutoUpdate` 门控的入口，核心运行时用的是那一个——在自动更新关闭（固定了自选 IP 的用户的常态）时该路径从不创建池，导致所有 `use_cf_pool` 规则静默回落 DNS，而 GUI 那份池看起来很健康。单一入口杜绝了两份拷贝再次不一致的可能；`AutoUpdate` 现在只决定是否从 API 拉取新 IP。

```go
srv.UpdateCloudflareIPPool([]string{"104.16.1.1", "104.16.1.2"})
```

| 方法 | 签名 | 作用 |
|---|---|---|
| `GetCFPool` | `func (p *ProxyServer) GetCFPool() *cfpool.CloudflarePool` | 返回 Cloudflare IP 池，需要时创建 |
| `CFPoolUsable` | `func (p *ProxyServer) CFPoolUsable() bool` | 池存在、有 IP 且不陈旧（>1 天）时返回 true；陈旧时在后台触发异步刷新 |
| `SetCFPoolFetchTime` | `func (p *ProxyServer) SetCFPoolFetchTime(t time.Time)` | 记录 IP 列表最后拉取时间 |
| `SetCFRefreshCallback` | `func (p *ProxyServer) SetCFRefreshCallback(cb func())` | 设置池刷新完成后调用的函数 |
| `TriggerCFHealthCheck` | `func (p *ProxyServer) TriggerCFHealthCheck()` | 立即启动一轮池健康检查 |
| `RemoveInvalidCFIPs` | `func (p *ProxyServer) RemoveInvalidCFIPs() int` | 从池中剔除失败 IP 并返回剔除数量 |
| `GetAllCFIPsWithStats` | `func (p *ProxyServer) GetAllCFIPsWithStats() []*cfpool.IPStats` | 返回池内每个 IP 及其统计 |

### 命名 IP 池（cloudfront / 自定义 CDN）

| 方法 | 签名 | 作用 |
|---|---|---|
| `UpdateIPPool` | `func (p *ProxyServer) UpdateIPPool(name string, ips []string)` | 把一组 IP 应用到命名池（首次使用时创建）；空列表保持现有池不变 |
| `GetIPPool` | `func (p *ProxyServer) GetIPPool(name string) *cfpool.CloudflarePool` | 返回命名池，不存在时返回 nil |
| `IPPoolNames` | `func (p *ProxyServer) IPPoolNames() []string` | 返回全部命名池的名字 |
| `IPPoolUsable` | `func (p *ProxyServer) IPPoolUsable(name string) bool` | 命名池存在、有 IP 且不陈旧（>1 天）时返回 true |
| `RemoveIPPool` | `func (p *ProxyServer) RemoveIPPool(name string)` | 停止并丢弃命名池；仍引用它的规则回落到普通 DNS 拨号 |
| `GetIPPoolStats` | `func (p *ProxyServer) GetIPPoolStats(name string) []*cfpool.IPStats` | 返回命名池内每个 IP 及其统计 |
| `SetIPPoolFetchTime` | `func (p *ProxyServer) SetIPPoolFetchTime(name string, t time.Time)` | 记录命名池 IP 列表最后拉取时间 |
| `TriggerIPPoolHealthCheck` | `func (p *ProxyServer) TriggerIPPoolHealthCheck(name string)` | 立即启动命名池的一轮健康检查 |
| `RemoveInvalidIPPoolIPs` | `func (p *ProxyServer) RemoveInvalidIPPoolIPs(name string) int` | 从命名池剔除失败 IP 并返回剔除数量 |

```go
srv.UpdateIPPool("cloudfront", []string{"13.32.1.1", "13.32.1.2"})
if srv.IPPoolUsable("cloudfront") {
	srv.TriggerIPPoolHealthCheck("cloudfront")
}
```

### TUN 数据面

#### PlanTUNFlow（核心）

```go
func (p *ProxyServer) PlanTUNFlow(flow TUNFlow) TUNFlowPlan
```

计算给定 TUN 流的处理方案：命中哪个规则、生效模式、上游、拨号候选、UDP 策略、能否 MITM、是否需要嗅探等。嵌入方用它驱动 TUN 数据面（例如 singtun 集成）。

```go
plan := srv.PlanTUNFlow(proxy.TUNFlow{Protocol: "tcp", Host: "example.com", DestPort: 443})
log.Printf("mode=%s effective=%s upstream=%s", plan.RuleMode, plan.EffectiveMode, plan.Upstream)
```

| 方法 | 签名 | 作用 |
|---|---|---|
| `OpenUDP` | `func (p *ProxyServer) OpenUDP(ctx context.Context, destination M.Socksaddr) (N.PacketConn, bool, error)` | 实现 `singtun.UDPRelay`；未绑定节点时返回 `ok=false`，TUN 层据此回落到直连 socket |

---

## AutoRouter —— 自动路由

```go
type AutoRouter struct{ /* 均为未导出字段 */ }
```

`AutoRouter` 为未被手动 `SiteGroup` 规则覆盖的域名做逐请求路由决策（GFWList 匹配 + Cloudflare 识别）。

```go
func NewAutoRouter(config AutoRoutingConfig, dohResolver *dohresolver.FailoverResolver, opts ...Option) *AutoRouter
```

按给定预设创建 `AutoRouter`。可选的 `dohResolver` 用于识别 Cloudflare 域名。

```go
ar := proxy.NewAutoRouter(proxy.AutoRoutingConfig{Mode: proxy.AutoRoutingDefault}, resolver)
defer ar.Stop()

rule := ar.Decide("blocked.example.com")
log.Println(rule.Mode) // 未命中 GFWList 时为 "direct"
```

| 方法 | 签名 | 作用 |
|---|---|---|
| `Decide` | `func (ar *AutoRouter) Decide(host string) Rule` | 为 GFWList 命中的域名返回合成 `Rule`；域名不在 GFW 列表时返回 "direct" 规则 |
| `GetConfig` | `func (ar *AutoRouter) GetConfig() AutoRoutingConfig` | 返回当前自动路由配置 |
| `UpdateConfig` | `func (ar *AutoRouter) UpdateConfig(config AutoRoutingConfig)` | 替换自动路由配置 |
| `GetGFWList` | `func (ar *AutoRouter) GetGFWList() *gfwlist.GFWList` | 返回已加载的 GFW 域名列表 |
| `GetStatus` | `func (ar *AutoRouter) GetStatus() GFWListStatus` | 返回暴露给前端的自动路由状态 |
| `IsCloudflare` | `func (ar *AutoRouter) IsCloudflare(host string) bool` | 经 DoH 解析 host 并检查返回的 IP 是否落在 Cloudflare CIDR 内；结果按 `cfCacheTTL`（30 分钟）缓存，并发查询按主机去重（singleflight） |
| `Stop` | `func (ar *AutoRouter) Stop()` | 停止自动路由器及其后台工作协程；可安全调用两次 |

### 自动路由配置类型

```go
type AutoRoutingConfig struct {
	Mode AutoRoutingMode `json:"mode"`
}
```

`AutoRoutingConfig` 持久化在 settings.json 中。

```go
type AutoRoutingMode string
```

`AutoRoutingMode` 定义自动路由预设：

```go
const (
	AutoRoutingOff     AutoRoutingMode = ""        // 关闭
	AutoRoutingDefault AutoRoutingMode = "default" // ECH / TLS-RF / direct
)
```

```go
type GFWListStatus struct {
	Enabled     bool   `json:"enabled"`
	Mode        string `json:"mode"`
	DomainCount int    `json:"domain_count"`
}
```

`GFWListStatus` 是返回给前端的 GFWList 状态。

---

## 规则与配置类型

### Rule

```go
type Rule struct {
	Domain             string           `json:"domain"`
	Upstream           string           `json:"upstream,omitempty"`
	Upstreams          []string         `json:"upstreams,omitempty"`
	DNSMode            string           `json:"dns_mode,omitempty"`
	Mode               string           `json:"mode"` // "mitm", "transparent", "tls-rf", "quic", "direct"
	SniFake            string           `json:"sni_fake,omitempty"`
	ConnectPolicy      string           `json:"connect_policy,omitempty"`
	SniPolicy          string           `json:"sni_policy,omitempty"`
	Enabled            bool             `json:"enabled"`
	SiteID             string           `json:"site_id,omitempty"`
	ECHEnabled         bool             `json:"ech_enabled"`
	ECHProfileID       string           `json:"ech_profile_id,omitempty"`
	UseCFPool          bool             `json:"use_cf_pool"`
	ECHDiscoveryDomain string           `json:"ech_discovery_domain,omitempty"`
	ECHDoHUpstream     string           `json:"ech_doh_upstream,omitempty"`
	CertVerify         CertVerifyConfig `json:"cert_verify,omitempty"`
	ECHAutoUpdate      bool             `json:"ech_auto_update"`
	AutoRouted         bool             `json:"auto_routed,omitempty"`
	NAT64Enabled       bool             `json:"nat64_enabled"`
	NAT64ProfileID     string           `json:"nat64_profile_id,omitempty"`
	IPPool             string           `json:"ip_pool,omitempty"` // 命名池：cloudfront 或用户自定义；优先于 UseCFPool
	Process            string           `json:"process,omitempty"`
	Frag               *FragmentConfig  `json:"frag,omitempty"`
	QUIC               *QUICRewriteConfig `json:"quic,omitempty"`
}
```

`Rule` 定义一个域名/站点组的代理策略。关键字段：

- `Domain`：域名模式，支持 `~regex`、`*keyword*` 子串、`*.wildcard`、普通后缀域与 `exact.$` 终结符（评分语义见 [`MatchDomainScore`](#matchdomainscore)）。
- `Mode`：处理模式，`"mitm"`、`"transparent"`、`"tls-rf"`、`"quic"`、`"direct"` 之一。
- `Process`：把规则限定到客户端进程基名列表（逗号分隔，如 `"chrome.exe,msedge.exe"`）。进程规则优先于纯域名规则；空值表示任意进程。
- `Frag`：本规则自己的分片参数（仅 `tls-rf` 模式使用），`nil` 表示跟随全局。
- `QUIC`：本规则的 QUIC Initial 重写开关（TUN fake-ip UDP 路径），`nil` 或全关表示不重写（丢弃 fake-ip UDP，浏览器回退 TCP）。
- `IPPool`：命名 IP 池（cloudfront 或用户自定义 CDN），优先于 `UseCFPool`。

### SiteGroup

```go
type SiteGroup struct {
	ID                 string           `json:"id"`
	Name               string           `json:"name"`
	Mode               string           `json:"mode"`
	DNSMode            string           `json:"dns_mode,omitempty"`
	SniFake            string           `json:"sni_fake,omitempty"`
	ConnectPolicy      string           `json:"connect_policy,omitempty"`
	SniPolicy          string           `json:"sni_policy,omitempty"`
	Domains            []string         `json:"domains"`
	ECHEnabled         bool             `json:"ech_enabled"`
	ECHProfileID       string           `json:"ech_profile_id,omitempty"`
	UseCFPool          bool             `json:"use_cf_pool"`
	ECHDiscoveryDomain string           `json:"ech_discovery_domain,omitempty"`
	ECHDoHUpstream     string           `json:"ech_doh_upstream,omitempty"`
	CertVerify         CertVerifyConfig `json:"cert_verify,omitempty"`
	Website            string           `json:"website,omitempty"`
	Enabled            bool             `json:"enabled"`
	Upstream           string           `json:"upstream,omitempty"`
	Upstreams          []string         `json:"upstreams,omitempty"`
	ECHDomain          string           `json:"ech_domain,omitempty"`
	NAT64Enabled       bool             `json:"nat64_enabled"`
	NAT64ProfileID     string           `json:"nat64_profile_id,omitempty"`
	IPPool             string           `json:"ip_pool,omitempty"`
	Process            string           `json:"process,omitempty"` // 限定客户端进程基名（逗号分隔），见 Rule.Process
	Frag               *FragmentConfig  `json:"frag,omitempty"`   // 站点组自己的分片参数（仅 tls-rf），nil 跟随全局
	QUIC               *QUICRewriteConfig `json:"quic,omitempty"` // QUIC Initial 重写开关（TUN fake-ip UDP 路径）
}
```

`SiteGroup` 把共享同一规则的站点归为一组，是 rules 配置文件中规则的持久化形态（运行时经 `SetRules` 变为 `Rule` 切片）。

### FragmentConfig（TLS 记录分片）

```go
type FragmentConfig struct {
	NumRecords   int   `json:"num_records"`
	NumSegments  int   `json:"num_segments"`
	IntervalMs   *int  `json:"interval_ms,omitempty"`
	ModMinorVer  *bool `json:"mod_minor_ver,omitempty"`
	OOB          *bool `json:"oob,omitempty"`
	OOBEx        *bool `json:"oob_ex,omitempty"`
	HeaderSplit  *bool `json:"header_split,omitempty"`
	AltRecordVer *bool `json:"alt_record_ver,omitempty"`
	PaddingLen   *int  `json:"padding_len,omitempty"`
	TrailingDot  *bool `json:"trailing_dot,omitempty"`
	HideSNI      *bool `json:"hide_sni,omitempty"`
}
```

`FragmentConfig` 持有 TLS 记录分片设置。注意各开关的 nil 语义不同：`ModMinorVer` 为 nil 时视为**开启**，其余开关 nil 时视为关闭。

```go
func DefaultFragmentConfig() FragmentConfig
```

返回归一化后的默认分片设置。

```go
cfg := proxy.DefaultFragmentConfig()
cfg.NumRecords = 2
cfg.NumSegments = 2
if err := rm.SetFragmentConfig(cfg); err != nil {
	return err
}
```

| 方法 | 签名 | 作用 |
|---|---|---|
| `ModMinorVerEnabled` | `func (c FragmentConfig) ModMinorVerEnabled() bool` | TLS 次版本号修改是否开启（nil = 开启） |
| `OOBEnabled` | `func (c FragmentConfig) OOBEnabled() bool` | 首字节带外（out-of-band）技巧是否开启 |
| `OOBExEnabled` | `func (c FragmentConfig) OOBExEnabled() bool` | 扩展带外模式是否开启 |
| `HeaderSplitEnabled` | `func (c FragmentConfig) HeaderSplitEnabled() bool` | 首个记录边界是否落在握手头内（CircumVolve header split） |
| `AltRecordVerEnabled` | `func (c FragmentConfig) AltRecordVerEnabled() bool` | 记录是否携带逐记录版本字节（先 0x0303 后 0x0301） |
| `PaddingLenInt` | `func (c FragmentConfig) PaddingLenInt() int` | 附加到 ClientHello 的 RFC 7685 padding 大小（nil 或负数返回 0） |
| `TrailingDotEnabled` | `func (c FragmentConfig) TrailingDotEnabled() bool` | 是否在 SNI 后追加尾点 |
| `HideSNIEnabled` | `func (c FragmentConfig) HideSNIEnabled() bool` | 是否移除 server_name 扩展 |
| `Interval` | `func (c FragmentConfig) Interval() time.Duration` | 分片记录间的发送延迟；`IntervalMs` 为 nil 时取 `tlsfrag.DefaultTLSRFSendInterval` |
| `IntervalMillis` | `func (c FragmentConfig) IntervalMillis() int` | 记录间延迟的毫秒值（nil 时取默认值的毫秒数） |

### QUICRewriteConfig（QUIC Initial 重写）

```go
type QUICRewriteConfig struct {
	ReservedBits   *bool `json:"reserved_bits,omitempty"`
	PrependACK     *bool `json:"prepend_ack,omitempty"`
	DecoyCrypto    *bool `json:"decoy_crypto,omitempty"`
	FragmentCrypto *bool `json:"fragment_crypto,omitempty"`
	DoubleHello    *bool `json:"double_hello,omitempty"`
	PunycodeSNI    *bool `json:"punycode_sni,omitempty"`
}
```

`QUICRewriteConfig` 持有按站点的 QUIC Initial 重写开关（CircumVolve QUIC rewrite，作用于 TUN fake-ip UDP 路径）。每个开关对应一个 `quicrewrite.Strategies` 标志，nil 表示关闭；全部开关关闭的配置原样放行 Initial 包。

| 方法 | 签名 | 作用 |
|---|---|---|
| `AnyEnabled` | `func (c *QUICRewriteConfig) AnyEnabled() bool` | 至少一个重写开关开启时返回 true；nil 配置不启用任何东西 |
| `Strategies` | `func (c *QUICRewriteConfig) Strategies() quicrewrite.Strategies` | 把开关转换为 `quicrewrite.Strategies`；nil 配置得到全关策略 |

```go
q := &proxy.QUICRewriteConfig{DoubleHello: &on}
fmt.Println(q.AnyEnabled(), q.Strategies())
```

### TUNConfig（TUN 设置）

```go
type TUNConfig struct {
	Enabled               bool     `json:"enabled"`
	MTU                   int      `json:"mtu,omitempty"`
	DNSHijack             bool     `json:"dns_hijack,omitempty"`
	AutoRoute             bool     `json:"auto_route,omitempty"`
	StrictRoute           bool     `json:"strict_route,omitempty"`
	InterfaceName         string   `json:"interface_name,omitempty"`
	ExcludeInterfaces     []string `json:"exclude_interface,omitempty"`
	RouteExcludeAddresses []string `json:"route_exclude_address,omitempty"`
	Stack                 string   `json:"stack,omitempty"`
	AdapterName           string   `json:"adapter_name,omitempty"`
}
```

`TUNConfig` 持有 TUN 模式设置。

| 方法 | 签名 | 作用 |
|---|---|---|
| `InterfaceConfig` | `func (c TUNConfig) InterfaceConfig() netiface.Config` | 把 TUN 设置转换为出站网卡选择配置。注意：`RouteExcludeAddresses` **不能**参与网卡选择——它是"不要把这些网段路由进 TUN"的路由排除（例如把内网 192.168.0.0/16 留在物理网卡上），而 `netiface` 的 `ExcludeAddresses` 语义是"持有这些地址的网卡不得作为出站网卡"。两者混用时，用户为放行内网而填的 192.168.0.0/16 会把唯一一张家用路由网卡直接排除掉，表现为 TUN 启动后所有出站连接失败 |
| `InterfaceConfigFor` | `func (c TUNConfig) InterfaceConfigFor(brand config.Brand) netiface.Config` | 品牌化嵌入方的 `InterfaceConfig`：品牌决定哪些网卡被认作自家 TUN 设备、因而不被用作出站上联 |
| `RouteExcludePrefixes` | `func (c TUNConfig) RouteExcludePrefixes() ([]netip.Prefix, []netip.Prefix)` | 把 `RouteExcludeAddresses` 解析为 IPv4 与 IPv6 前缀 |

### SettingsConfig（应用设置）

```go
type SettingsConfig struct {
	ConfigVersion                 int               `json:"config_version,omitempty"`
	ListenPort                    string            `json:"listen_port"`
	ListenAddress                 string            `json:"listen_address,omitempty"`
	CloseToTray                   *bool             `json:"close_to_tray,omitempty"`
	HibernateOnClose              *bool             `json:"hibernate_on_close,omitempty"`
	AutoStart                     *bool             `json:"auto_start,omitempty"`
	AutoStartMethod               string            `json:"auto_start_method,omitempty"`
	ShowMainWindowOnAutoStart     *bool             `json:"show_main_window_on_auto_start,omitempty"`
	AutoEnableProxyOnAutoStart    *bool             `json:"auto_enable_proxy_on_auto_start,omitempty"`
	AutoEnableSysProxyOnAutoStart *bool             `json:"auto_enable_sysproxy_on_auto_start,omitempty"`
	AutoUpdateRules               *bool             `json:"auto_update_rules,omitempty"`
	AutoRouting                   AutoRoutingConfig `json:"auto_routing,omitempty"`
	TUN                           TUNConfig         `json:"tun,omitempty"`
	Fragment                      FragmentConfig    `json:"fragment,omitempty"`
	Language                      string            `json:"language,omitempty"`
	Theme                         string            `json:"theme,omitempty"`
	AppearanceMode                string            `json:"appearance_mode,omitempty"`
	CloudflareConfig              CloudflareConfig  `json:"cloudflare_config,omitempty"`
	IPPools                       []IPPoolConfig    `json:"ip_pools,omitempty"`
	MigrationEnabled              *bool             `json:"migration_enabled,omitempty"`
	MigrationServer               string            `json:"migration_server,omitempty"`
	UpdateChannel                 string            `json:"update_channel,omitempty"`
	DownloadSource                string            `json:"download_source,omitempty"`
	CustomDownloadSource          string            `json:"custom_download_source,omitempty"`
}
```

`SettingsConfig` 持有应用级设置（settings.json 的完整结构）。`ConfigVersion` 是显式配置模式版本（缺失 = 0，legacy），与 `RulesConfig` 的同名字段语义一致。

### RulesConfig / UserRulesConfig / RulesLayerInfo（分层规则）

```go
type RulesConfig struct {
	ConfigVersion int            `json:"config_version,omitempty"`
	SiteGroups    []SiteGroup    `json:"site_groups"`
	Upstreams     []Upstream     `json:"upstreams"`
	DNSNodes      []DNSNode      `json:"dns_nodes,omitempty"`
	ECHProfiles   []ECHProfile   `json:"ech_profiles,omitempty"`
	NAT64Profiles []NAT64Profile `json:"nat64_profiles,omitempty"`
}
```

`RulesConfig` 是规则配置文件的完整 JSON 结构。`ConfigVersion` 是显式配置模式版本（缺失 = 0，legacy）：由本构建在保存时写为 `CurrentConfigVersion`；更高版本拒绝加载。

```go
type UserRulesConfig struct {
	SiteGroups            []SiteGroup    `json:"site_groups,omitempty"`
	Upstreams             []Upstream     `json:"upstreams,omitempty"`
	DNSNodes              []DNSNode      `json:"dns_nodes,omitempty"`
	ECHProfiles           []ECHProfile   `json:"ech_profiles,omitempty"`
	NAT64Profiles         []NAT64Profile `json:"nat64_profiles,omitempty"`
	DeletedSiteGroups     []string       `json:"deleted_site_groups,omitempty"`
	DeletedUpstreams      []string       `json:"deleted_upstreams,omitempty"`
	DeletedDNSNodes       []string       `json:"deleted_dns_nodes,omitempty"`
	DeletedECHProfiles    []string       `json:"deleted_ech_profiles,omitempty"`
	DeletedNAT64Profiles  []string       `json:"deleted_nat64_profiles,omitempty"`
}
```

`UserRulesConfig` 是内存中的用户差异层：与上游条目同 ID 的条目覆盖上游条目；没有上游对应物的条目独立存在（即使上游之后删除原件，覆盖也保持存活）。`Deleted*` 列表是被用户删除的上游条目的墓碑：它们隐藏上游条目，直到 `RevertSiteGroupToUpstream` / `RevertUpstreamConfigToUpstream` 移除。它也是已退役的 v0.6 config.user.json 的结构，只在迁移时读取。

```go
type RulesLayerInfo struct {
	SiteGroupLayers    map[string]string `json:"site_group_layers,omitempty"`
	UpstreamLayers     map[string]string `json:"upstream_layers,omitempty"`
	DeletedSiteGroups  []string          `json:"deleted_site_groups,omitempty"`
	DeletedUpstreams   []string          `json:"deleted_upstreams,omitempty"`
	UpstreamRulesPath  string            `json:"upstream_rules_path,omitempty"`
}
```

`RulesLayerInfo` 报告每个生效规则所属的层（`SiteGroupLayers`/`UpstreamLayers` 的值为 `"upstream"`、`"override"`（用户层，存在上游对应物）或 `"user"`（用户自建）），让 GUI 能标记用户编辑并提供"恢复到上游"。

### RulesMergeSummary（合并统计）

```go
type RulesMergeSummary struct {
	AddedGroups        int      `json:"added_groups"`
	UpdatedGroups      int      `json:"updated_groups"`
	KeptGroups         int      `json:"kept_groups"`
	RemovedGroups      int      `json:"removed_groups"`
	AddedUpstreams     int      `json:"added_upstreams"`
	UpdatedUpstreams   int      `json:"updated_upstreams"`
	KeptUpstreams      int      `json:"kept_upstreams"`
	RemovedUpstreams   int      `json:"removed_upstreams"`
	AddedDNSNodes      int      `json:"added_dns_nodes"`
	AddedECHProfiles   int      `json:"added_ech_profiles"`
	AddedNAT64         int      `json:"added_nat64_profiles"`
	Details            []string `json:"details,omitempty"`
}
```

`RulesMergeSummary` 统计一次规则合并（`MergeRemoteRules`）应用的变更。

| 方法 | 签名 | 作用 |
|---|---|---|
| `Changed` | `func (s RulesMergeSummary) Changed() bool` | 合并是否新增或更新了任何东西 |

### 证书类型

```go
type CertGenerator interface {
	GetCACert() *x509.Certificate
	GetCAKey() interface{}
	IsCAInstalled() bool
}
```

`CertGenerator` 提供 MITM 叶子证书签发所需的 CA 材料。

```go
type CertVerifyConfig = config.CertVerifyConfig
```

`CertVerifyConfig` 是 `config` 包证书校验类型的再导出（类型别名）。

### 上游与 IP 池类型

```go
type Upstream struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Type      string   `json:"type"` // "cf_preferred"
	Addresses []string `json:"addresses"`
	Enabled   bool     `json:"enabled"`
	Address   string   `json:"address,omitempty"`
}
```

`Upstream` 定义一个上游代理服务器。

```go
type CloudflareConfig struct {
	PreferredIPs []string  `json:"preferred_ips"`
	AutoUpdate   bool      `json:"auto_update"`
	APIKey       string    `json:"api_key"`
	DNSNodes     []DNSNode `json:"dns_nodes,omitempty"`
}
```

`CloudflareConfig` 持有 Cloudflare IP 池设置。

```go
type IPPoolConfig struct {
	Name         string   `json:"name"`
	PreferredIPs []string `json:"preferred_ips"`
	AutoUpdate   bool     `json:"auto_update"`
	APIKey       string   `json:"api_key,omitempty"`
}
```

`IPPoolConfig` 持有命名 IP 池（cloudfront 或用户自定义 CDN 池）的设置。没有拉取端点的池只能手动维护。

### DNS 节点与 ECH/NAT64 档案

```go
type DNSNode struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	URL           string           `json:"url"`
	SNI           string           `json:"sni,omitempty"`
	IPs           []string         `json:"ips,omitempty"`
	ECHEnabled    bool             `json:"ech_enabled"`
	ECHProfileID  string           `json:"ech_profile_id,omitempty"`
	ECHAutoUpdate bool             `json:"ech_auto_update"`
	QUIC          bool             `json:"quic"`
	Enabled       bool             `json:"enabled"`
	CertVerify    CertVerifyConfig `json:"cert_verify,omitempty"`
}
```

`DNSNode` 描述一个 DoH 上游节点（可选 SNI 伪装、ECH、QUIC、静态 IP）。

```go
type ECHProfile struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Config          string `json:"config"`
	DiscoveryDomain string `json:"discovery_domain,omitempty"`
	DoHUpstream     string `json:"doh_upstream,omitempty"`
	AutoUpdate      bool   `json:"auto_update"`
}
```

`ECHProfile` 存储一个持久化的 ECH 配置档案。

```go
type NAT64Profile struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Prefix string `json:"prefix"`
}
```

`NAT64Profile` 存储一个 NAT64 前缀配置。

---

## 匹配与调试

### MatchDomainScore（核心）

```go
func MatchDomainScore(host, domain string) int
```

报告规则域名模式对 `host` 的匹配程度：分数越高越优先，`-1` 表示不匹配。模式支持 `~regex`、`*keyword*` 子串、`*.wildcard`、普通后缀域与 `exact.$` 终结符。正则模式每次调用都重新编译，热路径请优先用 `RuleManager`。它存在的意义是让嵌入方可以用数据面使用的精确语义审计规则数据。

```go
if proxy.MatchDomainScore("api.example.com", "*.example.com") > proxy.MatchDomainScore("api.example.com", "example.com") {
	// 更具体的模式胜出
}
```

### MatchExplanation / MatchCandidate

```go
type MatchExplanation struct {
	Simulated  bool             `json:"simulated"`
	Host       string           `json:"host"`
	Mode       string           `json:"mode"`
	Source     string           `json:"source"` // "manual", "auto" or "default"
	SiteID     string           `json:"site_id,omitempty"`
	RuleDomain string           `json:"rule_domain,omitempty"`
	DNSMode    string           `json:"dns_mode,omitempty"`
	Upstream   string           `json:"upstream,omitempty"`
	SniFake    string           `json:"sni_fake,omitempty"`
	ECHEnabled bool             `json:"ech_enabled"`
	UseCFPool  bool             `json:"use_cf_pool"`
	Downgraded bool             `json:"downgraded"`
	Candidates []MatchCandidate `json:"candidates,omitempty"`
	Notes      []string         `json:"notes,omitempty"`
}
```

`MatchExplanation` 是对一个主机的模拟决策，由处理真实连接的同一代码路径（`matchRuleDetailed`）产生。`Simulated` 恒为 true：它描述的是"将会发生什么"，绝不是"已经发生了什么"。

```go
type MatchCandidate struct {
	Domain  string `json:"domain"`
	SiteID  string `json:"site_id,omitempty"`
	Mode    string `json:"mode"`
	Process string `json:"process,omitempty"`
	Score   int    `json:"score"`
}
```

`MatchCandidate` 是同样匹配了查询主机的一条规则加上决定胜负的优先级分数。精确匹配 1000+ 分、正则模式 900+ 分、关键字匹配 800+ 分、后缀匹配按模式长度计分；最高分获胜——这就是更长（更具体）的规则能击败更宽泛规则的原因。

---

## 配置导入导出与迁移

### ConfigFile / ConfigRule / ImportSummary

```go
type ConfigFile struct {
	Version string       `json:"version"`
	Type    string       `json:"type"`
	Rules   []ConfigRule `json:"rules"`
}
```

`ConfigFile` 是导出的配置文件（`ExportConfig` 的产物）的 JSON 结构。

```go
type ConfigRule struct {
	Name           string           `json:"name"`
	Website        string           `json:"website,omitempty"`
	Mode           string           `json:"mode,omitempty"`
	Enabled        bool             `json:"enabled"`
	Domains        []string         `json:"domains"`
	Upstream       string           `json:"upstream,omitempty"`
	Upstreams      []string         `json:"upstreams,omitempty"`
	DNSMode        string           `json:"dns_mode,omitempty"`
	SniFake        string           `json:"sni_fake,omitempty"`
	ConnectPolicy  string           `json:"connect_policy,omitempty"`
	SniPolicy      string           `json:"sni_policy,omitempty"`
	ECHEnabled     bool             `json:"ech_enabled,omitempty"`
	ECHProfileID   string           `json:"ech_profile_id,omitempty"`
	ECHDomain      string           `json:"ech_domain,omitempty"`
	UseCFPool      bool             `json:"use_cf_pool,omitempty"`
	IPPool         string           `json:"ip_pool,omitempty"`
	CertVerify     CertVerifyConfig `json:"cert_verify,omitempty"`
	NAT64Enabled   bool             `json:"nat64_enabled,omitempty"`
	NAT64ProfileID string           `json:"nat64_profile_id,omitempty"`
}
```

`ConfigRule` 是导出配置中的单条规则。

```go
type ImportSummary struct {
	Total       int `json:"total"`
	Added       int `json:"added"`
	Overwritten int `json:"overwritten"`
	Skipped     int `json:"skipped"`
}
```

`ImportSummary` 统计一次导入（`ImportConfigWithSummary`）应用的分组与条目数量。

### MigrationReport 与配置版本

```go
const CurrentConfigVersion = 1
```

`CurrentConfigVersion` 是本构建理解并写出的配置模式版本。历史文件缺少 `config_version` 字段时按 0（legacy）处理，加载时补写当前版本号。

```go
type MigrationReport struct {
	FromRulesVersion    int      `json:"from_rules_version"`
	FromSettingsVersion int      `json:"from_settings_version"`
	ToVersion           int      `json:"to_version"`
	Changes             []string `json:"changes,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
	Errors              []string `json:"errors,omitempty"`
	BackupPaths         []string `json:"backup_paths,omitempty"`
}
```

`MigrationReport` 描述一次配置加载（`LoadConfigWithMigration`）中发生的迁移与校验结果，供 App 层展示给用户：`Changes` 是已应用的修改；`Warnings` 是不影响加载但用户应知道的问题；`Errors` 非空表示配置无法安全迁移、已保持原样。

```go
func IsKnownTopLevelKey(key string) bool
```

`IsKnownTopLevelKey` 报告 `key` 是否为 settings/rules 配置的已知顶层键。

---

## TUN 辅助类型

```go
type TUNFlow struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host,omitempty"`
	SNI      string `json:"sni,omitempty"`
	DestAddr string `json:"dest_addr,omitempty"`
	DestPort int    `json:"dest_port,omitempty"`
}
```

`TUNFlow` 描述一个待规划的 TUN 流。

```go
type TUNFlowPlan struct {
	Protocol       string   `json:"protocol"`
	Host           string   `json:"host,omitempty"`
	MatchHost      string   `json:"match_host,omitempty"`
	RuleMode       string   `json:"rule_mode"`
	EffectiveMode  string   `json:"effective_mode"`
	Upstream       string   `json:"upstream,omitempty"`
	DialCandidates []string `json:"dial_candidates,omitempty"`
	UDPStrategy    string   `json:"udp_strategy,omitempty"`
	CanMITM        bool     `json:"can_mitm"`
	NeedsSniffing  bool     `json:"needs_sniffing"`
	Notes          []string `json:"notes,omitempty"`
}
```

`TUNFlowPlan` 描述代理将如何处理一个 TUN 流（`PlanTUNFlow` 的返回值）。

```go
type TUNStatus struct {
	Supported bool   `json:"supported"`
	Running   bool   `json:"running"`
	Enabled   bool   `json:"enabled"`
	Driver    string `json:"driver,omitempty"`
	Message   string `json:"message,omitempty"`
}
```

`TUNStatus` 报告 TUN 设备的当前状态。

---

## 端口与进程辅助函数

### EnsurePortAvailable（核心）

```go
func EnsurePortAvailable(port int, selfNames []string) (int, error)
```

检查端口占用：1. 如果被 `selfNames` 列表中的进程占用，尝试 Kill；2. 如果被其他进程占用或 Kill 失败，则返回错误，不再自动跳端口。返回实际可用的端口。

```go
port, err := proxy.EnsurePortAvailable(8080, []string{"snishaper.exe", "MyApp.exe"})
if err != nil {
	return err
}
```

| 函数 | 签名 | 作用 |
|---|---|---|
| `FindProcessByPort` | `func FindProcessByPort(port int) (int, error)` | 返回占用指定端口的 PID（目前仅支持 TCP） |
| `GetProcessNameByPID` | `func GetProcessNameByPID(pid int) (string, error)` | 获取指定 PID 的进程名 |
| `KillProcessByPID` | `func KillProcessByPID(pid int) error` | 强制终止指定 PID 及其子进程 |
| `IsPortInExcludedRange` | `func IsPortInExcludedRange(port int) bool` | 检查端口是否落在 Windows 系统排除端口范围（Hyper-V/WSL/Docker/WinNAT 等保留段）。落在其中的端口 bind 会报 WSAEACCES（forbidden by its access permissions），且 netstat 查不到占用进程 |
| `ProcessRoutingSupported` | `func ProcessRoutingSupported() bool` | 当前平台能否解析本地 TCP 连接背后的进程（Windows/Linux/macOS 为 true，其余平台 false） |

---

## 连接信息

```go
type ConnInfo struct {
	ID         uint64    `json:"id"`
	Protocol   string    `json:"protocol"`              // "https"（CONNECT 隧道）或 "socks5"
	Host       string    `json:"host,omitempty"`        // 请求的主机（域名或字面 IP）
	DstAddr    string    `json:"dst_addr,omitempty"`    // 拨号目的地 ip:port（已知时）
	Rule       string    `json:"rule,omitempty"`        // 命中规则的站点分组 ID
	RuleDomain string    `json:"rule_domain,omitempty"` // 命中的域名模式
	Mode       string    `json:"mode"`                  // 生效的代理模式
	Source     string    `json:"source,omitempty"`      // "manual"、"auto" 或 "default"
	State      string    `json:"state"`                 // 隧道打开期间为 "active"
	StartedAt  time.Time `json:"started_at"`
	BytesUp    int64     `json:"bytes_up"`   // 客户端 → 远端
	BytesDown  int64     `json:"bytes_down"` // 远端 → 客户端
}
```

`ConnInfo` 是 `ProxyServer.ActiveConnections` 返回的活动连接快照中的单条。代理无法知道的字段留空：UI 必须把空字段呈现为"不可用"，绝不能当作已确认的数据。

---

## 错误值

```go
var ErrIPv6Required = errors.New("rule requires IPv6 but no usable IPv6 address was resolved (current network may be IPv4-only)")
```

`ErrIPv6Required` 表明规则要求 IPv6，但当前网络无法提供可用的 IPv6 候选。这是一个配置与网络不匹配的错误（`dns_mode = ipv6_only` 或启用了 NAT64），而不是一次传输故障：它不会被静默降级为 IPv4，否则规则的地址族约束会被悄悄稀释——用户会以为 `ipv6_only` 生效了，实际走的是 IPv4。

```go
conn, err := srv.DialWithRule(ctx, "tcp", "example.com:443", rule)
if errors.Is(err, proxy.ErrIPv6Required) {
	// 提示用户当前网络无 IPv6，而非重试
}
```
