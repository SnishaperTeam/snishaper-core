# Proxy Performance Benchmarks

可重复的性能基准，位于 `proxy/bench_test.go`。用于跨版本对比验证性能改动，**单次运行结果不作结论**（见「统计方法」）。

## 运行方法

```bash
# 全部基准（proxy 包内）
go test ./proxy/ -run '^$' -bench 'Benchmark' -benchmem -count 10 > new.txt

# 快速冒烟（开发迭代用，结果不作对比依据）
go test ./proxy/ -run '^$' -bench 'Benchmark' -benchmem -benchtime 100x
```

`-count 10` 生成用于 benchstat 对比的样本；`-benchmem` 必开（内存分配是数据面回归的主要信号）。

## 基准清单

| 基准 | 测量内容 | 对应工作负载 |
|------|----------|--------------|
| `BenchmarkRuleMatch/rules=100\|1000` | 每请求规则决策耗时（轻/重规则集） | 所有 CONNECT/SOCKS5 请求的必经热路径 |
| `BenchmarkRuleMatchProcess` | 含按应用规则时的决策耗时 | 启用按应用分流的部署 |
| `BenchmarkFindProcessName` | OS 级客户端进程识别（Windows 为 TCP 表扫描；macOS 含首次 lsof，后续命中缓存） | 仅启用进程规则时触发 |
| `BenchmarkNormalizeHost` | 请求 host 归一化 | 每请求一次 |
| `BenchmarkProcessNameInList` | 进程规则列表比对 | 每条进程规则每请求一次 |
| `BenchmarkConnRegistryRegisterRemove` | 连接跟踪登记/注销（注册表满载，含逐出路径） | 每隧道开关一次 |
| `BenchmarkConnRegistrySnapshot` | 连接查看器快照（满载 4096 条） | UI 轮询间隔支付一次 |
| `BenchmarkTunnelThroughput` | direct 模式 CONNECT 隧道持续 64 KiB 往返吞吐 | 持续传输（大文件下载/上传） |
| `BenchmarkTunnelShortConnections` | 隧道建立 + 小载荷 + 拆除 | 短连接高频请求（API 密集型） |
| `BenchmarkTunnelConcurrent` | 多并发隧道小往返（`RunParallel`） | 大量并发连接 |
| `BenchmarkSOCKS5ShortConnections` | SOCKS5 握手 + 小往返 + 拆除 | SOCKS5 客户端的短连接churn |

覆盖的代理路径：HTTP CONNECT 与 SOCKS5 两个入口、direct 模式全链路（路由 → 拨号 → 隧道转发）。MITM/TLS 模式依赖证书与 TLS 栈，改动这些路径时以 `BenchmarkTunnelThroughput` 的 direct 结果作对照，并在真实环境手动抽查。

## 统计方法

单次基准受机器负载、温度、电源策略影响很大。对比流程：

```bash
go install golang.org/x/perf/cmd/benchstat@latest

# 基线（改动前）
go test ./proxy/ -run '^$' -bench 'Benchmark' -benchmem -count 10 > old.txt
# 改动后
go test ./proxy/ -run '^$' -bench 'Benchmark' -benchmem -count 10 > new.txt

benchstat old.txt new.txt
```

判定标准：

- benchstat 报告的 p 值 ≥ 0.05 视为**无显著差异**，不当作退化或优化。
- 显著变化（p < 0.05）且幅度 > 5% 时，检查分配数（allocs/op）是否同向变化再下结论。
- 性能相关 PR 附 benchstat 输出；无法复现的结果不作为合并依据。

## 环境记录

基准输出自带 `goos / goarch / cpu` 字段，随结果一并保存。对比双方必须满足：

- 同一物理机（或同型号 CI runner）、同一电源策略。
- 同一 Go 版本（`go version`）。
- 后台无其它高负载任务。

CI 不强制跑基准（受共享 runner 噪声影响，结果不可比）；基准对比由开发者本机或专用机器完成。

## 已知边界

- 吞吐/延迟基准走 loopback，反映的是**数据面相对开销**（缓冲、跟踪、锁），不代表公网绝对带宽。
- `BenchmarkFindProcessName` 在 macOS 上首次迭代含 lsof 冷启动，benchstat 对比时忽略首样本或用 `-benchtime` 固定次数。
- Windows 上进程识别结果按 PID 缓存，长驻进程中 PID 复用可能导致陈旧名称——基准不覆盖此场景，属已知限制（见 docs/PER-APP-ROUTING.md）。
