# snishaper-core 抽取设计

## 目标与边界

把 SniShaper 单仓中的核心代理能力抽取为独立 Go module
`github.com/SnishaperTeam/snishaper-core`（go 1.27），原仓库只保留
CLI/GUI 装配逻辑（`app/`、`cli/`、`core/`、`evolution/`、`main.go`、
`pkg/sysproxy` 等）。

库的职责：混合端口代理（HTTP CONNECT + SOCKS5）、规则引擎与 MITM、
DoH 解析、ECH/TLS 分片、GFWList 分流、TUN（sing-tun）、网卡选择、
证书管理。

不属于库的职责（留在原项目）：Wails GUI、托盘、系统代理注册表写入、
core 进程 RPC、规则演化测试器。

## 包布局

| 包 | 来源 | 说明 |
|----|------|------|
| `proxy/` | 原 `proxy/` | ProxyServer、RuleManager、AutoRouter、MITM、SOCKS5、端口混合分发 |
| `subscription/` | FlowWeaver `pkg/subscription` | Clash 订阅解析、节点存储、协议出站（mihomo 适配器、WireGuard 池化拨号器） |
| `dohresolver/` | 原 `pkg/dohresolver` | FailoverResolver（DoH 故障切换、ECH 热修复） |
| `cfpool/` | 原 `pkg/cfpool` | Cloudflare IP 池 |
| `netiface/` | 原 `pkg/netiface` | 物理网卡选择与绑定 |
| `tlsfrag/` | 原 `pkg/tlsfrag` | TLS 记录分片/OOB |
| `gfwlist/` | 原 `pkg/rules` | GFWList 后缀匹配（包名 rules→gfwlist，避免与 proxy 规则混淆） |
| `certmanager/` | 原 `pkg/certmanager` | CA 生成与系统证书信任 |
| `singtun/` | 原 `pkg/singtun` | sing-tun 数据面（Handler/Manager） |
| `config/` | 原 `common` 中的共享类型 | `CertVerifyConfig`、`MapNAT64Addr`、`HalfClose`、`VerifyChainOnly` |
| `log/` | 新增 | `Logger` 接口 + `Nop`/`Std`/`Func` |
| `internal/openutil/` | 原 `common/open_*.go` | shell 打开/资源管理器定位（certmanager 内部用） |

依赖方向：`singtun → proxy → dohresolver → netiface`，`config` 与 `log`
为叶子包，无循环依赖。原 `core/coreRuntime` 是装配代码，留在原项目。

## 去全局化决策

单仓实现中的包级可变状态，库内全部实例化或注入：

1. **日志**：所有 `log.Printf` 改走注入的 `log.Logger`（默认 `Nop`，
   未配置即静默）。注入点：`proxy.WithLogger`（ProxyServer/RuleManager 共用
   同一 `Option`）、`dohresolver.WithLogger`、`gfwlist.WithLogger`。
   原 `tracef` 语义保留：`logCallback` 优先，其次注入的 logger。
2. **`netiface` 路由快照缓存**（包级 cache + log key）→ `Selector` 实例
   （`NewSelector()`，方法 `Select/SelectForTarget/List/Explain/DescribeAll/
   Invalidate`）。`ProxyServer`、`singtun.Manager`、`singtun.Handler` 各持
   有实例；Manager 把自己的实例共享给 Handler，保证 TUN 启停后的缓存失效
   对数据面立即生效。跨实例的缓存不再共享，10s TTL 兜底陈旧窗口。
3. **`SNISHAPER_ROUTER_DEBUG` 环境变量门控**（原包级 `routerDebugEnabled`）
   → `proxy.WithRouterDebug(bool)` 选项；读环境变量的决定权交还嵌入方。
4. **`singtun.udpIdleSessionTTL`**（init 设置 120s 的包级 atomic）→
   Handler 字段，`NewHandler` 中初始化。
5. **IPv6 出口探测缓存**（包级 ipv6Egress* 变量）→ Handler 字段
   （`ipv6EgressAvailable`/`invalidateIPv6Egress` 改为方法）。
6. 保留的包级 `var` 全部为只读数据（前缀表、正则、syscall 惰性绑定、
   `tunnelBufPool` 缓冲池、`log.Nop/Std`），无 init()、无 os.Exit、
   无 flag、无硬编码环境变量读取。

## 导出面

- 构造函数统一 functional options：`NewProxyServer(addr, ...Option)`、
  `NewRuleManager(settingsPath, rulesPath, ...Option)`、
  `NewFailoverResolver(proxy, getNodes, ...Option)`、
  `NewAutoRouter(config, dohResolver, ...Option)`。
- `proxy.MatchDomainScore(host, domain) int`：导出域名匹配打分
  （`~regex`/`*.wildcard`/后缀/`exact.$` 四种模式），供嵌入方对规则数据
  做守卫测试——规则数据文件随应用仓库，不随库分发。
- `dohresolver.CertVerifyConfig = config.CertVerifyConfig` 等类型别名
  保持既有引用路径可用。

## 原项目改造

1. `go.mod`：`require github.com/SnishaperTeam/snishaper-core` +
   `replace => ../Snishaper-core`（发布时推送远端并移除 replace）。
2. import 机械改写（13 个文件），删除 8 个已迁出目录。
3. `common` 包：`CertVerifyConfig`/`MapNAT64Addr`/`HalfClose`/
   `VerifyChainOnly` 改为库 `config` 的别名；RingLogWriter、路径、
   crashlog、open* 留在原地。
4. 行为等价注入（三个 `NewRuleManager` 调用点、两个 `NewProxyServer`
   调用点）：
   - `proxy.WithLogger(corelog.Std)` —— 库内日志回到 std log，被原有的
     `log.SetOutput` 捕获链（gatedLogWriter / MultiWriter）原样接住；
   - `proxy.WithRouterDebug(os.Getenv("SNISHAPER_ROUTER_DEBUG") == "1")`
     —— 还原原来的环境变量门控。
5. `App`/`coreRuntime` 各持有 `netiface.Selector` 供 UI 列举与配置变更后
   的缓存失效。
6. 规则数据守卫测试（`TestBuiltinRulesCoverDownloadDomains`、
   `TestBuiltinGitHubAssetsUseTencentReverseProxy`）迁至
   `internal/rulesguard/`，用导出的 `proxy.MatchDomainScore` 复用数据面
   匹配语义。

## 测试与门槛

- 库：`go build ./... && go vet ./... && go test ./...` 全绿；
  `proxy/proxy_integration_test.go` 是外部包集成冒烟（仅导出 API 完成
  路由→拨号→隧道全链路）。
- 原项目：同上门槛 + `go build -tags with_gvisor ./...` +
  Linux headless 交叉构建（`GOOS=linux go build -tags "headless
  with_gvisor" ./cli`）。
- 已知既有问题（非本次引入）：`TestBuiltinRulesCoverDownloadDomains`
  在基线即失败（rules/config.json 未覆盖 ghcr.io 等 4 个下载域名）；
  Windows 下 `go build -tags "headless with_gvisor"` 在基线同样失败
  （`RebuildSystemTray`/`BuildSystemTray` 未定义）。两者均已用
  git stash 对照干净基线验证。
