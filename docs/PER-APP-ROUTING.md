# Per-Application Routing (按应用分流)

按应用分流的规则：为指定进程（如 `telegram.exe`）的连接指定处理模式（direct / mitm / block / …），独立于域名规则。

## 规则模型

`site_groups[]` 新增可选字段 `process`：

```json
{
  "id": "g-telegram",
  "name": "Telegram",
  "mode": "block",
  "process": "telegram.exe,discord.exe",
  "domains": [],
  "enabled": true
}
```

- `process`：逗号分隔的进程可执行文件基名列表，大小写不敏感（`chrome.exe` = `CHROME.EXE`）。
- `domains` 可为空：表示该进程的**所有**目标都走此规则（构建时合成为 `Domain="*"`）。
- `domains` 非空时表示"该进程访问这些域名时才命中"（进程 + 域名双条件，比仅进程规则更具体）。

## 优先级

进程规则在域名匹配得分之上叠加固定加权（`processRuleBonus = 1<<20`）：

1. 进程 + 域名规则（最具体）
2. 仅进程规则
3. 域名规则（按既有域名得分排序）
4. 自动分流 / 默认直连

进程规则的进程不匹配、或进程无法识别时**一律不参与匹配（fail closed）**——不会因识别失败而误伤其它流量。

## 平台支持

| 平台 | 支持 | 识别机制 | 说明 |
|------|------|----------|------|
| Windows | ✅ | `GetExtendedTcpTable`（iphlpapi）+ `QueryFullProcessImageName` | 按连接远端（客户端 127.0.0.1:port）在系统 TCP 表中查 OWNER PID，精确、无额外依赖 |
| Linux | ✅ | `/proc/net/tcp{,6}` → socket inode → `/proc/<pid>/fd` → `/proc/<pid>/comm` | 纯文件系统读取，无 cgo |
| macOS | ✅ | `lsof -iTCP@<endpoint> -sTCP:ESTABLISHED`（结果缓存 10s） | 无公开 API 可查连接归属；lsof 每次调用约 100ms，按客户端端点缓存 10s 控制成本 |
| 其它 (BSD 等) | ❌ | — | 规则加载正常但永不命中；`ProcessRoutingSupported()` 返回 false |

跨平台约束：**所有平台编译均不引入 cgo**（headless Linux 构建要求 `CGO_ENABLED=0`）。macOS 用 lsof 而非 libproc/cgo 即为此约束。

## 性能设计

进程查表有真实成本（Windows ~1ms，Linux 数 ms，macOS ~100ms），因此是**惰性触发**：

- `RuleManager.HasProcessRules()`：只有存在至少一条**启用**的进程规则时，请求路径才调用 `findProcessName`。
- 无进程规则的部署（绝大多数）零开销——`clientProcess()` 直接返回空串。
- Windows 按缓存 PID 缓存进程名；macOS 按客户端端点缓存 10s；Linux 每次 /proc 扫描本身开销可接受。

## API

```go
// 平台是否支持按应用分流（UI 据此提示，而非让用户以为规则生效）
proxy.ProcessRoutingSupported() bool

// 连接跟踪条目中的来源进程（无法识别时为空）
proxy.ConnInfo.Process

// 模拟解释查询（第三个参数为进程名，空 = 模拟"未知进程"）
rm.ExplainMatch(host, mode, process string) MatchExplanation
```

## 规则匹配解释

`ExplainMatch` 与真实匹配共用 `matchRuleDetailed`（单一事实来源），候选列表（`MatchCandidate`）含 `Process` 字段，模拟查询不会触发路由事件。

## UI 暴露（由各 App 层负责）

App 层应：

1. 以 `ProcessRoutingSupported()` 控制规则的显示与提示（不支持的平台标注"进程规则在此平台不会生效"）。
2. 进程未知时（连接查看器中 `process` 为空且平台支持）不隐藏行，仅留空并提示。
