# evolution 包

> 导入路径：`github.com/SnishaperTeam/snishaper-core/evolution`

evolution 提供规则进化（rule evolution）能力：对目标域名使用多种代理模式探测可达性，并依据探测结果生成临时站点分组规则。

探测主体是 `Tester`：先直连，失败后做 TCPing（必要时回退到 NAT64 映射地址），再按域名类型分流——Cloudflare 域名依次尝试 ECH、QUIC、TLS 分片，常规域名依次尝试域前置、TLS 分片、QUIC。命中的方法经 `GenerateRule` 生成 `TempRule`，由 `ToSiteGroup` 转换为应用侧站点分组配置。

设计要点：

- **测试即服务**：`Tester.StartTest` 异步启动任务并立即返回快照，进度经 `Snapshot` / `GetTask` 轮询；内部状态由 `sync.RWMutex` 保护，可被并发读取。
- **内存有界**：每次启动新任务清空历史结果与临时规则，避免长时间运行导致内存增长。
- **依赖注入**：`NewTester` 注入 `RuleManager`（NAT64 映射）、`ProxyServer`（上游连接与 QUIC 传输）、`FailoverResolver`（域名解析）、`AutoRouter`（Cloudflare 域名判定）与日志回调，测试日志可转发给调用方。

## Tester

`Tester` 协调域名探测任务：对每个域名依次尝试多种代理模式，记录每一步的结果并生成临时规则。

### 构造

```go
func NewTester(ruleManager *proxy.RuleManager, proxyServer *proxy.ProxyServer, dohResolver *dohresolver.FailoverResolver, autoRouter *proxy.AutoRouter, logCallback func(string)) *Tester
```

`ruleManager` 提供 NAT64 映射配置，`proxyServer` 负责建立上游连接与 QUIC 传输，`dohResolver` 提供域名解析，`autoRouter` 用于判定 Cloudflare 域名；`logCallback` 用于把测试日志转发给调用方，可为 nil。

```go
tester := evolution.NewTester(ruleManager, proxyServer, dohResolver, autoRouter, logf)
```

### 任务控制

```go
func (t *Tester) StartTest(domains []string, config TestConfig) (*TestTask, error)
```

异步启动一次测试任务并立即返回任务快照。已有任务处于运行状态时返回错误；启动时会清空历史结果与临时规则。

```go
task, err := tester.StartTest([]string{"example.com", "www.example.org"}, evolution.DefaultTestConfig())
if err != nil { /* 已有任务在运行 */ }
```

| 方法 | 作用 |
|------|------|
| `StopTest()` | 停止当前运行中的测试任务，并把任务状态置为失败 |

```go
tester.StopTest()
```

### 结果与规则读取

| 方法 | 作用 | 备注 |
|------|------|------|
| `Snapshot() *TestTask` | 返回当前任务字段的安全副本（浅拷贝），供外部在持锁之外读取进度/状态/结果等展示数据，避免与后台写入发生数据竞争 | 展示用途建议用它而非 `GetTask` |
| `GetTask() *TestTask` | 返回当前任务指针 | 返回值会随后台测试协程推进而变化 |
| `GetAllResults() []DomainTestResult` | 返回最近一次任务的全部域名结果副本 | |
| `GetTempRules() []*TempRule` | 返回当前所有临时规则的切片 | |
| `GetTempRule(ruleID string) *TempRule` | 返回指定 ID 的临时规则 | 不存在时返回 nil |
| `MarkRuleApplied(ruleID string) bool` | 在规则被应用到正式配置后移除对应临时规则 | 返回是否移除成功 |

```go
task := tester.Snapshot()
fmt.Println(task.Status, task.Progress, "/", task.Total)
for _, rule := range tester.GetTempRules() {
	sg := rule.ToSiteGroup() // 写入应用侧规则文件
	tester.MarkRuleApplied(rule.ID)
}
```

## 结果类型

### TestTask

一次测试任务及其进度与结果。

```go
type TestTask struct {
	ID        string             `json:"id"`
	Domains   []string           `json:"domains"`
	Status    TestStatus         `json:"status"`
	Config    TestConfig         `json:"config"`
	Results   []DomainTestResult `json:"results"`
	StartTime time.Time          `json:"start_time,omitempty"`
	EndTime   time.Time          `json:"end_time,omitempty"`
	Progress  int                `json:"progress"`
	Total     int                `json:"total"`
}
```

由 `StartTest` 构造，经 `Snapshot` / `GetTask` 读取。

### DomainTestResult

单个域名的完整测试结果，包含各步骤明细与生成的规则。

```go
type DomainTestResult struct {
	Domain        string        `json:"domain"`
	Reachable     bool          `json:"reachable"`
	Method        TestMethod    `json:"method,omitempty"`
	ResolvedIPs   []string      `json:"resolved_ips,omitempty"`
	BestIP        string        `json:"best_ip,omitempty"`
	IsCloudflare  bool          `json:"is_cloudflare"`
	Delay         time.Duration `json:"delay"`
	Error         string        `json:"error,omitempty"`
	Timestamp     time.Time     `json:"timestamp"`
	StepResults   []StepResult  `json:"step_results"`
	GeneratedRule *TempRule     `json:"generated_rule,omitempty"`
}
```

由 Tester 后台任务产出，经 `TestTask.Results` / `GetAllResults` 读取。

### StepResult

测试流程中单个步骤的执行结果。

```go
type StepResult struct {
	StepName  string        `json:"step_name"`
	Success   bool          `json:"success"`
	Delay     time.Duration `json:"delay"`
	Error     string        `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}
```

### TCPingResult

单个 IP 的 TCP 连通性探测结果。

```go
type TCPingResult struct {
	IP      string        `json:"ip"`
	Success bool          `json:"success"`
	Delay   time.Duration `json:"delay"`
	Error   string        `json:"error,omitempty"`
}
```

## 临时规则

### TempRule

探测过程中生成的临时站点分组规则，应用后转为正式规则。

```go
type TempRule struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Domain         string     `json:"domain"`
	Mode           string     `json:"mode"`
	SniFake        string     `json:"sni_fake,omitempty"`
	ECHEnabled     bool       `json:"ech_enabled"`
	Method         TestMethod `json:"method"`
	CreatedAt      time.Time  `json:"created_at"`
	IsApplied      bool       `json:"is_applied"`
	UseCFPool      bool       `json:"use_cf_pool"`
	NAT64Enabled   bool       `json:"nat64_enabled"`
	NAT64ProfileID string     `json:"nat64_profile_id,omitempty"`
}
```

### GenerateRule

```go
func GenerateRule(domain string, method TestMethod, sniFake string, echEnabled bool) *TempRule
```

根据域名与命中的测试方法生成临时规则。`method` 决定规则的代理模式：`domain_fronting` → `mitm`（携带 sniFake）、`tls_fragment` → `tls-rf`、`ech` → `mitm` + `ech_enabled`、`quic` → `quic`；`sniFake` 与 `echEnabled` 仅在对应方法下生效。规则 ID 形如 `evolution-<domain>-<method>`。

```go
rule := evolution.GenerateRule("example.com", evolution.MethodTLSFragment, "", false)
```

### ToSiteGroup

```go
func (r *TempRule) ToSiteGroup() map[string]interface{}
```

把临时规则转换为站点分组配置（map 结构与 `rules/config.json` 的 `site_groups` 条目一致），供应用侧直接写入规则文件。`sni_fake`、`ech_enabled`、`use_cf_pool`、`nat64_enabled`/`nat64_profile_id` 仅在规则启用对应项时出现。

```go
sg := rule.ToSiteGroup()
```

## 测试配置

### TestConfig

```go
type TestConfig struct {
	EnableIPv6         bool          `json:"enable_ipv6"`
	DomainFrontingSNIs []string      `json:"domain_fronting_snis"`
	Timeout            time.Duration `json:"timeout"`
	Concurrency        int           `json:"concurrency"`
}
```

控制一次测试任务的行为（IPv6、域前置 SNI 列表、超时与并发）。

### DefaultTestConfig

```go
func DefaultTestConfig() TestConfig
```

返回默认测试配置：不启用 IPv6，域前置 SNI 为 `apple.com`/`app-com`，单步超时 3 秒，并发数 10。

```go
cfg := evolution.DefaultTestConfig()
```

## 方法与状态枚举

### TestMethod

```go
type TestMethod string
```

探测域名时使用的代理/传输方法。

| 常量 | 值 | 含义 |
|------|----|------|
| `MethodDirect` | `"direct"` | 直连（TLS 直连并发送 HTTP/1.1 请求） |
| `MethodDomainFronting` | `"domain_fronting"` | MITM 域前置，通过伪造 SNI 建立连接 |
| `MethodTLSFragment` | `"tls_fragment"` | TLS 记录分片（tls-rf 模式） |
| `MethodECH` | `"ech"` | Cloudflare ECH（Encrypted Client Hello） |
| `MethodQUIC` | `"quic"` | QUIC/HTTP3 传输 |

### TestStatus

```go
type TestStatus string
```

单个进化测试任务的状态。

| 常量 | 值 | 含义 |
|------|----|------|
| `StatusPending` | `"pending"` | 测试任务尚未开始 |
| `StatusRunning` | `"running"` | 测试任务正在执行 |
| `StatusCompleted` | `"completed"` | 测试任务已全部执行完毕 |
| `StatusFailed` | `"failed"` | 测试任务失败或被手动停止 |

```go
if task.Status == evolution.StatusCompleted { ... }
```

## 辅助函数

```go
func GetDefaultConcurrency() int
```

返回推荐的测试并发数：CPU 核数的两倍；CPU 数异常时回退为 10。

```go
cfg := evolution.DefaultTestConfig()
cfg.Concurrency = evolution.GetDefaultConcurrency()
```
