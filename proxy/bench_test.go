// 可重复性能基准：规则匹配、连接跟踪与 direct 模式隧道数据面的
// 吞吐/延迟/并发。运行方法与环境记录见 docs/benchmarks.md。
package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// benchRuleManager builds an in-memory RuleManager loaded with n suffix rules.
// Matching cost scales with rule count, so sizes bracket a light and a heavy
// user configuration.
func benchRuleManager(b *testing.B, n int, processRules int) *RuleManager {
	b.Helper()
	dir := b.TempDir()
	rm := NewRuleManager(filepath.Join(dir, "settings.json"), filepath.Join(dir, "rules.json"))
	if err := rm.LoadConfig(); err != nil {
		b.Fatalf("LoadConfig: %v", err)
	}
	rules := make([]Rule, 0, n+processRules)
	for i := 0; i < n; i++ {
		rules = append(rules, Rule{
			Domain: fmt.Sprintf("site-%d.example.com", i),
			Mode:   "direct",
			Enabled: true,
		})
	}
	for i := 0; i < processRules; i++ {
		rules = append(rules, Rule{
			Domain:  "app.example.com",
			Mode:    "direct",
			Enabled: true,
			Process: "chrome.exe,firefox.exe",
		})
	}
	rm.SetRules(rules)
	return rm
}

// BenchmarkRuleMatch measures the per-request rule decision cost — the hot
// path every CONNECT and SOCKS5 request pays before dialing.
func BenchmarkRuleMatch(b *testing.B) {
	for _, n := range []int{100, 1000} {
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			rm := benchRuleManager(b, n, 0)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rm.matchRuleFor("www.example.com", "mitm", "")
			}
		})
	}
}

// BenchmarkRuleMatchProcess measures the decision cost with per-application
// rules in the set (matching, not the OS process lookup itself — that is
// BenchmarkFindProcessName's job).
func BenchmarkRuleMatchProcess(b *testing.B) {
	rm := benchRuleManager(b, 100, 10)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rm.matchRuleFor("app.example.com", "mitm", "chrome.exe")
	}
}

// BenchmarkFindProcessName measures the OS-level client process resolution
// cost. On macOS this includes the lsof exec (first call only; the cache
// serves repeats), so its number reflects the cache, matching production.
func BenchmarkFindProcessName(b *testing.B) {
	if !ProcessRoutingSupported() {
		b.Skip("process lookup unsupported on this platform")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Skipf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, c)
			_ = c.Close()
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = findProcessName(conn.LocalAddr().String())
	}
}

// BenchmarkNormalizeHost measures host normalization, called once per request.
func BenchmarkNormalizeHost(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = normalizeHost("WWW.Example.COM.")
	}
}

// BenchmarkProcessNameInList measures the per-rule process list comparison.
func BenchmarkProcessNameInList(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = processNameInList("msedge.exe", "chrome.exe,firefox.exe,msedge.exe,opera.exe")
	}
}

// BenchmarkConnRegistryRegisterRemove measures tracked-connection bookkeeping
// (register + remove per tunnel) at full registry capacity so eviction runs on
// the hot path, mirroring a busy long-running process.
func BenchmarkConnRegistryRegisterRemove(b *testing.B) {
	reg := newConnRegistry()
	// Pre-fill to capacity: every new register then evicts the oldest entry.
	for i := 0; i < maxTrackedConns; i++ {
		reg.register(ConnInfo{Protocol: "https", StartedAt: time.Now()})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id, _ := reg.register(ConnInfo{Protocol: "https", StartedAt: time.Now()})
		reg.remove(id)
	}
}

// BenchmarkConnRegistrySnapshot measures the connection-viewer refresh cost at
// full capacity — the price the UI polling interval pays.
func BenchmarkConnRegistrySnapshot(b *testing.B) {
	reg := newConnRegistry()
	for i := 0; i < maxTrackedConns; i++ {
		reg.register(ConnInfo{Protocol: "https", StartedAt: time.Now()})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reg.snapshot()
	}
}

// benchProxyServer starts a ProxyServer on an ephemeral port in direct mode
// and returns it with its address.
func benchProxyServer(b *testing.B) (*ProxyServer, string) {
	b.Helper()
	dir := b.TempDir()
	rm := NewRuleManager(filepath.Join(dir, "settings.json"), filepath.Join(dir, "rules.json"))
	if err := rm.LoadConfig(); err != nil {
		b.Fatalf("LoadConfig: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	p := NewProxyServer(addr, WithRuleManager(rm))
	if err := p.Start(); err != nil {
		b.Fatalf("proxy start: %v", err)
	}
	b.Cleanup(func() { _ = p.Stop() })
	return p, addr
}

// echoListener starts a TCP echo server and returns its address.
func echoListener(b *testing.B) string {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("echo listen: %v", err)
	}
	b.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}(c)
		}
	}()
	return ln.Addr().String()
}

// dialTunnel opens a CONNECT tunnel through the proxy to dst.
func dialTunnel(b *testing.B, proxyAddr, dst string) (net.Conn, *bufio.Reader) {
	b.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		b.Fatalf("dial proxy: %v", err)
	}
	br := bufio.NewReader(c)
	req := "CONNECT " + dst + " HTTP/1.1\r\nHost: " + dst + "\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		b.Fatalf("write CONNECT: %v", err)
	}
	status, err := br.ReadString('\n')
	if err != nil {
		b.Fatalf("read CONNECT status: %v", err)
	}
	if len(status) < 12 || status[:12] != "HTTP/1.1 200" {
		b.Fatalf("unexpected CONNECT status: %q", status)
	}
	for { // drain remaining response headers
		line, err := br.ReadString('\n')
		if err != nil {
			b.Fatalf("drain headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return c, br
}

// BenchmarkTunnelThroughput measures sustained bidirectional transfer through a
// direct-mode CONNECT tunnel (64 KiB round trips over loopback). Shortcuts in
// the tunnel data path (buffer sizing, tracking overhead) show up here.
func BenchmarkTunnelThroughput(b *testing.B) {
	echo := echoListener(b)
	_, proxyAddr := benchProxyServer(b)
	tunnel, br := dialTunnel(b, proxyAddr, echo)
	b.Cleanup(func() { _ = tunnel.Close() })

	chunk := make([]byte, 64*1024)
	sink := make([]byte, len(chunk))
	b.SetBytes(int64(len(chunk) * 2)) // up + down
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := tunnel.Write(chunk); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(br, sink); err != nil {
			b.Fatalf("read: %v", err)
		}
	}
}

// BenchmarkTunnelShortConnections measures tunnel setup + small transfer +
// teardown per iteration — the churn pattern of API-heavy workloads.
func BenchmarkTunnelShortConnections(b *testing.B) {
	echo := echoListener(b)
	_, proxyAddr := benchProxyServer(b)
	payload := []byte("snishaper-benchmark")
	sink := make([]byte, len(payload))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tunnel, br := dialTunnel(b, proxyAddr, echo)
		if _, err := tunnel.Write(payload); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(br, sink); err != nil {
			b.Fatalf("read: %v", err)
		}
		_ = tunnel.Close()
	}
}

// BenchmarkTunnelConcurrent measures many simultaneous tunnels each doing
// small round trips — per-connection goroutine and lock contention.
func BenchmarkTunnelConcurrent(b *testing.B) {
	echo := echoListener(b)
	_, proxyAddr := benchProxyServer(b)
	payload := []byte("snishaper-benchmark")
	sink := make([]byte, len(payload))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		tunnel, br := dialTunnel(b, proxyAddr, echo)
		defer tunnel.Close()
		for pb.Next() {
			if _, err := tunnel.Write(payload); err != nil {
				b.Fatalf("write: %v", err)
			}
			if _, err := io.ReadFull(br, sink); err != nil {
				b.Fatalf("read: %v", err)
			}
		}
	})
}

// BenchmarkSOCKS5ShortConnections mirrors the SOCKS5 entry point of the short
// connection churn workload above (same listener; SOCKS5 is multiplexed on the
// proxy port).
func BenchmarkSOCKS5ShortConnections(b *testing.B) {
	echo := echoListener(b)
	_, proxyAddr := benchProxyServer(b)

	host, portStr, err := net.SplitHostPort(echo)
	if err != nil {
		b.Fatalf("split echo addr: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	// SOCKS5 CONNECT handshake: greeting (no auth) then connect request.
	handshake := func(c net.Conn) {
		if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			b.Fatalf("greeting: %v", err)
		}
		resp := make([]byte, 2)
		if _, err := io.ReadFull(c, resp); err != nil {
			b.Fatalf("greeting response: %v", err)
		}
		if resp[0] != 0x05 || resp[1] != 0x00 {
			b.Fatalf("unexpected greeting response: %v", resp)
		}
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, host...)
		req = append(req, byte(port>>8), byte(port&0xff))
		if _, err := c.Write(req); err != nil {
			b.Fatalf("connect request: %v", err)
		}
		resp2 := make([]byte, 3) // ver, rep, rsv
		if _, err := io.ReadFull(c, resp2); err != nil {
			b.Fatalf("connect response: %v", err)
		}
		if resp2[1] != 0x00 {
			b.Fatalf("connect refused: %v", resp2)
		}
		if err := drainSocksAddr(c); err != nil {
			b.Fatalf("drain bound addr: %v", err)
		}
	}

	payload := []byte("snishaper-benchmark")
	sink := make([]byte, len(payload))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			b.Fatalf("dial socks: %v", err)
		}
		handshake(c)
		if _, err := c.Write(payload); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(c, sink); err != nil {
			b.Fatalf("read: %v", err)
		}
		_ = c.Close()
	}
}
