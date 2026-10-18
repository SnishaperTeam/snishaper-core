// Package evolution 提供规则进化（rule evolution）能力：对目标域名使用多种
// 代理模式探测可达性，并依据探测结果生成临时站点分组规则。
//
// 探测主体是 Tester：先直连，失败后做 TCPing（必要时回退到 NAT64 映射地址），
// 再按域名类型分流——Cloudflare 域名依次尝试 ECH、QUIC、TLS 分片，常规域名
// 依次尝试域前置、TLS 分片、QUIC。命中的方法经 GenerateRule 生成 TempRule，
// 由 ToSiteGroup 转换为应用侧站点分组配置。
package evolution

import (
	"time"
)

// TestStatus 表示单个进化测试任务的状态。
type TestStatus string

const (
	// StatusPending 表示测试任务尚未开始。
	StatusPending TestStatus = "pending"
	// StatusRunning 表示测试任务正在执行。
	StatusRunning TestStatus = "running"
	// StatusCompleted 表示测试任务已全部执行完毕。
	StatusCompleted TestStatus = "completed"
	// StatusFailed 表示测试任务失败或被手动停止。
	StatusFailed TestStatus = "failed"
)

// TestMethod 表示探测域名时使用的代理/传输方法。
type TestMethod string

const (
	// MethodDirect 表示直连（TLS 直连并发送 HTTP/1.1 请求）。
	MethodDirect TestMethod = "direct"
	// MethodDomainFronting 表示 MITM 域前置，通过伪造 SNI 建立连接。
	MethodDomainFronting TestMethod = "domain_fronting"
	// MethodTLSFragment 表示 TLS 记录分片（tls-rf 模式）。
	MethodTLSFragment TestMethod = "tls_fragment"
	// MethodECH 表示 Cloudflare ECH（Encrypted Client Hello）。
	MethodECH TestMethod = "ech"
	// MethodQUIC 表示 QUIC/HTTP3 传输。
	MethodQUIC TestMethod = "quic"
)

// StepResult 记录测试流程中单个步骤的执行结果。
type StepResult struct {
	StepName  string        `json:"step_name"`
	Success   bool          `json:"success"`
	Delay     time.Duration `json:"delay"`
	Error     string        `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// DomainTestResult 是单个域名的完整测试结果，包含各步骤明细与生成的规则。
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

// TempRule 是探测过程中生成的临时站点分组规则，应用后转为正式规则。
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

// TestConfig 控制一次测试任务的行为（IPv6、域前置 SNI 列表、超时与并发）。
type TestConfig struct {
	EnableIPv6         bool          `json:"enable_ipv6"`
	DomainFrontingSNIs []string      `json:"domain_fronting_snis"`
	Timeout            time.Duration `json:"timeout"`
	Concurrency        int           `json:"concurrency"`
}

// DefaultTestConfig 返回默认测试配置：不启用 IPv6，域前置 SNI 为
// apple.com/app-com，单步超时 3 秒，并发数 10。
func DefaultTestConfig() TestConfig {
	return TestConfig{
		EnableIPv6:         false,
		DomainFrontingSNIs: []string{"apple.com", "app-com"},
		Timeout:            3 * time.Second,
		Concurrency:        10,
	}
}

// TestTask 表示一次测试任务及其进度与结果。
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

// TCPingResult 是单个 IP 的 TCP 连通性探测结果。
type TCPingResult struct {
	IP      string        `json:"ip"`
	Success bool          `json:"success"`
	Delay   time.Duration `json:"delay"`
	Error   string        `json:"error,omitempty"`
}
