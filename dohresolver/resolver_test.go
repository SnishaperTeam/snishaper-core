package dohresolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	utls "github.com/refraction-networking/utls"

	"github.com/SnishaperTeam/snishaper-core/netiface"
)

// countingFakeProxy 统计 DoH 节点拨号次数：所有 DoH 查询最终都要经过
// ProxyServer.DialWithRule 建连，这个计数就是"真实扇出了几次查询"的代理指标。
type countingFakeProxy struct {
	dials atomic.Int64
}

func (f *countingFakeProxy) DialWithRule(ctx context.Context, network, addr string, rule Rule) (net.Conn, error) {
	f.dials.Add(1)
	return nil, fmt.Errorf("dial refused: %s", addr)
}

func (f *countingFakeProxy) GetUConn(conn net.Conn, sni, verifyName string, rule Rule, allowUnknownAuthority bool, alpn string, ech []byte) *utls.UConn {
	return nil
}

func (f *countingFakeProxy) ResolveRuleECHConfig(host string, rule Rule) []byte { return nil }

func (f *countingFakeProxy) UpdateECHProfileConfig(profileID string, configBytes []byte) {}

func (f *countingFakeProxy) GetPhysicalBinding(targetAddr string) (netiface.Binding, bool) {
	return netiface.Binding{}, false
}

// deadNodeResolver 返回一个节点指向必然拨号失败的本地端口的解析器。
func deadNodeResolver(t *testing.T) (*FailoverResolver, *countingFakeProxy) {
	t.Helper()
	// 找一个肯定没人监听的端口：绑定后立刻关闭，端口大概率仍未被复用，
	// 拨号会立刻收到 connection refused 而不是超时，测试无需等待。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	proxy := &countingFakeProxy{}
	getNodes := func() []DNSNode {
		return []DNSNode{{
			Name:    "dead",
			URL:     fmt.Sprintf("https://127.0.0.1:%d/dns-query", deadPort),
			Enabled: true,
		}}
	}
	return NewFailoverResolver(proxy, getNodes), proxy
}

// TestResolveIPsNegativeCacheAfterFailure 验证解析失败进入负缓存：
// 第二次调用必须立即失败且不再发起任何节点拨号（issue #181 重试风暴的闸门）。
func TestResolveIPsNegativeCacheAfterFailure(t *testing.T) {
	r, proxy := deadNodeResolver(t)

	if _, err := r.ResolveIPs(context.Background(), "example.com"); err == nil {
		t.Fatal("expected first resolution to fail against dead node")
	}
	first := proxy.dials.Load()
	if first == 0 {
		t.Fatal("first resolution should have attempted node dials")
	}

	_, err := r.ResolveIPs(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "negative cache") {
		t.Fatalf("second resolution should fail fast from negative cache, got: %v", err)
	}
	if got := proxy.dials.Load(); got != first {
		t.Fatalf("negative cache hit must not dial nodes again: before=%d after=%d", first, got)
	}
}

// TestResolveIPsConcurrentCallsShareOneExchange 验证同域名并发解析 singleflight：
// N 个并发调用只触发一次真实 DoH 扇出（leader 的 2 次拨号），
// 而不是 N × 2 次 —— 这是 goroutine 堆积 OOM 的直接放大器。
func TestResolveIPsConcurrentCallsShareOneExchange(t *testing.T) {
	r, proxy := deadNodeResolver(t)

	const callers = 10
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = r.ResolveIPs(context.Background(), "storm.example.com")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err == nil {
			t.Fatalf("caller %d should have failed against dead node", i)
		}
	}
	// leader 为 A/AAAA 两次查询各拨号一次；允许小幅竞争余量，
	// 但必须远小于无 singleflight 时的 callers×2。
	if got := proxy.dials.Load(); got > 4 {
		t.Fatalf("singleflight should collapse %d concurrent calls to ~2 dials, got %d", callers, got)
	}
}

// TestResolveIPsCanceledCallerDoesNotPoisonCache 验证调用方取消不写入负缓存：
// 否则一个客户端断开会把该域名对所有调用方错误地封死 15s。
func TestResolveIPsCanceledCallerDoesNotPoisonCache(t *testing.T) {
	r, _ := deadNodeResolver(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.ResolveIPs(ctx, "canceled.example.com"); err == nil {
		t.Fatal("expected canceled context to fail")
	}

	// 取消错误不得进入负缓存：清空正缓存后再次解析应重新发起（仍失败，
	// 但错误必须来自真实拨号而非 negative cache）。
	_, err := r.ResolveIPs(context.Background(), "canceled.example.com")
	if err == nil || strings.Contains(err.Error(), "negative cache") {
		t.Fatalf("canceled caller must not poison negative cache, got: %v", err)
	}
}
