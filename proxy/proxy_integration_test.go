// Package proxy_test 集成冒烟测试：仅通过导出 API 装配 ProxyServer，
// 走一条真实的 HTTP 代理请求（路由 → 拨号 → 隧道转发），
// 证明库交付的公开接口足以独立驱动数据面。
package proxy_test

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SnishaperTeam/snishaper-core/log"
	"github.com/SnishaperTeam/snishaper-core/proxy"
)

// freePort 预占一个端口再立即释放，降低 NewProxyServer 绑定时的碰撞概率。
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestProxyServerHTTPEndToEnd 起一个本地源站，通过 ProxyServer 发送
// 绝对 URI 的 HTTP 请求，断言响应体完整送达（direct 模式全链路）。
func TestProxyServerHTTPEndToEnd(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello-from-origin")
	}))
	defer origin.Close()

	dir := t.TempDir()
	rm := proxy.NewRuleManager(
		filepath.Join(dir, "settings.json"),
		filepath.Join(dir, "rules.json"),
	)
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig with fresh temp paths: %v", err)
	}

	port := freePort(t)
	p := proxy.NewProxyServer(
		"127.0.0.1:"+strconv.Itoa(port),
		proxy.WithRuleManager(rm),
		proxy.WithLogger(log.Func(func(format string, args ...any) {
			t.Logf(format, args...)
		})),
	)
	if err := p.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer func() { _ = p.Stop() }()

	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "hello-from-origin") {
		t.Fatalf("body = %q, want it to contain origin payload", body)
	}
}

// TestProxyServerStartStopIdempotent Start/Stop 必须可安全重复调用
// （嵌入方在重载配置时常这样用）。
func TestProxyServerStartStopIdempotent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	rm := proxy.NewRuleManager(filepath.Join(dir, "settings.json"), filepath.Join(dir, "rules.json"))
	_ = rm.LoadConfig()

	p := proxy.NewProxyServer("127.0.0.1:"+strconv.Itoa(freePort(t)), proxy.WithRuleManager(rm))
	if err := p.Start(); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("second start must be no-op: %v", err)
	}
	if err := p.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if err := p.Stop(); err != nil {
		t.Fatalf("second stop must be no-op: %v", err)
	}
}
