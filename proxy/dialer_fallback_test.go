package proxy

import (
	"net"
	"strings"
	"testing"
)

// startEchoListener 起一个只接受连接的本地 TCP 监听，返回其 host:port。
func startEchoListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

// TestDialUpstreamDoHFallbackAfterDeadUpstream 复现 IDM 下载 GitHub Release 报
// 502 的根因：规则 upstream 指向一个不可达的硬编码地址。修复后主候选拨号失败
// 必须按 DoH 回退到目标域名本身的解析结果，而不是把失败直接抛成 502。
func TestDialUpstreamDoHFallbackAfterDeadUpstream(t *testing.T) {
	upstream := startEchoListener(t)
	host, port, err := net.SplitHostPort(upstream)
	if err != nil {
		t.Fatalf("split listener addr: %v", err)
	}

	p := NewProxyServer("127.0.0.1:8080")
	cr := &connectResult{
		effectiveMode: "direct",
		targetHost:    "localhost",
		targetAddr:    net.JoinHostPort("localhost", port),
		rule: Rule{
			Mode:     "direct",
			Enabled:  true,
			Upstream: net.JoinHostPort(host, "1"), // 死端口：主候选必然拨号失败
			DNSMode:  "system",                    // 测试环境无 DoH 节点，回退走系统解析
		},
	}

	if err := p.dialUpstream(cr); err != nil {
		t.Fatalf("dialUpstream should succeed via DoH fallback, got: %v", err)
	}
	if cr.conn == nil {
		t.Fatal("dialUpstream left cr.conn nil")
	}
	_ = cr.conn.Close()
}

// TestDialUpstreamFallbackExcludesTriedCandidates 保证回退候选不会重复尝试
// 主阶段已经失败过的地址。
func TestBuildDoHFallbackCandidatesExcludesTried(t *testing.T) {
	upstream := startEchoListener(t)
	_, port, _ := net.SplitHostPort(upstream)

	p := NewProxyServer("127.0.0.1:8080")
	cr := &connectResult{
		effectiveMode: "direct",
		targetHost:    "localhost",
		targetAddr:    net.JoinHostPort("localhost", port),
		rule:          Rule{Mode: "direct", Enabled: true, DNSMode: "system"},
	}
	tried := []string{net.JoinHostPort("127.0.0.1", port)}
	fallback := p.buildDoHFallbackCandidates(cr, tried)
	for _, addr := range fallback {
		if addr == tried[0] {
			t.Fatalf("fallback re-tries already-failed candidate %s: %v", addr, fallback)
		}
	}
}

// TestDialUpstreamNoFallbackForLiteralTarget 目标本身是字面 IP 时没有可回退的
// 解析，dialUpstream 必须把拨号错误原样返回（含失败候选与原因），供上层回
// 502 并写入日志。
func TestDialUpstreamNoFallbackForLiteralTarget(t *testing.T) {
	p := NewProxyServer("127.0.0.1:8080")
	cr := &connectResult{
		effectiveMode: "direct",
		targetHost:    "127.0.0.1",
		targetAddr:    net.JoinHostPort("127.0.0.1", "1"),
		rule:          Rule{Mode: "direct", Enabled: true},
	}
	err := p.dialUpstream(cr)
	if err == nil {
		t.Fatal("expected dial error for dead literal target")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("error should name the failed candidate, got: %v", err)
	}
	if cr.conn != nil {
		t.Fatal("cr.conn must stay nil on failure")
	}
}

// TestBuiltinRulesCoverDownloadDomains 与 TestBuiltinGitHubAssetsUseTencentReverseProxy
// 是 rules/config.json 的数据守卫测试，随数据文件留在使用本库的应用仓库
// （通过导出的 MatchDomainScore 复用同一匹配语义），库内不内置数据文件，故不在此保留。
