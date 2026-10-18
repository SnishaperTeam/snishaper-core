package singtun

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// logCapture 收集 logf 管道收到的日志行。数据面在独立 goroutine 里写日志，
// 因此必须加锁读取。
type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (c *logCapture) logf(msg string) {
	c.mu.Lock()
	c.lines = append(c.lines, msg)
	c.mu.Unlock()
}

// findLine 返回第一条包含 substr 的日志行。
func (c *logCapture) findLine(substr string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.lines {
		if strings.Contains(l, substr) {
			return l, true
		}
	}
	return "", false
}

// runSniffFlowWithLogs 跑一条"目标为 IP、首包带 SNI"的真实连接，并捕获日志。
// 与 runFlowThroughHandler 相同的编排，只是把 logf 换成可读的收集器。
func runSniffFlowWithLogs(t *testing.T, cap *logCapture) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	h := NewHandler(l.Addr().String(), nil, cap.logf)

	client, serverEnd := net.Pipe()
	defer client.Close()
	src := M.SocksaddrFrom(netip.MustParseAddr("10.0.0.1"), 50000)
	// IP 目标才会触发惰性 SNI 嗅探（见 NewConnectionEx 的 D5 注释）。
	dst := M.SocksaddrFrom(netip.MustParseAddr("93.184.216.34"), 443)
	hello := buildClientHelloRecord("example.com", nil)

	go func() {
		_, _ = client.Write(hello)
	}()
	go func() {
		h.NewConnectionEx(context.Background(), serverEnd, src, dst, nil)
	}()

	px, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer px.Close()
	_ = px.SetDeadline(time.Now().Add(5 * time.Second))

	br := bufio.NewReader(px)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT line: %v", err)
	}
	if !strings.HasPrefix(line, "CONNECT example.com:") {
		t.Fatalf("CONNECT must use the sniffed domain, got %q", line)
	}
	for {
		hl, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if hl == "\r\n" || hl == "\n" {
			break
		}
	}
	if _, err := px.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		t.Fatalf("write 200: %v", err)
	}
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(br, hdr); err != nil {
		t.Fatalf("read tunnel bytes: %v", err)
	}
	rest := 0
	if hdr[0] == 0x16 {
		rest = int(hdr[3])<<8 | int(hdr[4])
	} else {
		rest = len(hello) - len(hdr)
	}
	if _, err := io.ReadFull(br, make([]byte, rest)); err != nil {
		t.Fatalf("read tunnel payload: %v", err)
	}
}

// "SNI sniffed" 是每连接级别的日志：目标为 IP 的连接（浏览器很常见）都会触发。
// 它必须以 debug 前缀输出，否则会通过 FlowWeaver 默认开启的日志过滤器刷屏。
//
// 这个用例驱动真实数据面并要求产出确实出现过，因此把该行改回 Info（或改掉
// 前缀）都会失败——它盯的是生产路径，而不是手写的字符串字面量。
func TestSNISniffedLogsAtDebugLevel(t *testing.T) {
	cap := &logCapture{}
	runSniffFlowWithLogs(t, cap)

	line, ok := cap.findLine("SNI sniffed")
	if !ok {
		t.Fatalf("expected a %q log line from the sniff path; captured %v", "SNI sniffed", cap.lines)
	}
	if !strings.HasPrefix(line, "[sing-tun:debug] ") {
		t.Errorf("SNI sniffed must be debug-level, got %q", line)
	}
	// Info 级前缀是 "[sing-tun] "，会被默认过滤器放行 → 视为回归。
	if strings.HasPrefix(line, "[sing-tun] ") {
		t.Errorf("SNI sniffed must not be info-level (floods the log page): %q", line)
	}
}

// 反向约束：TUN 生命周期日志仍必须是 Info，不能被一并降级，
// 否则"只降这一条"的修复会误伤正常的启动/停止可见性。
func TestHandlerLifecycleLogsStayInfo(t *testing.T) {
	cap := &logCapture{}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	NewHandler(l.Addr().String(), nil, cap.logf)

	line, ok := cap.findLine("Handler created")
	if !ok {
		t.Fatalf("expected a %q log line; captured %v", "Handler created", cap.lines)
	}
	if !strings.HasPrefix(line, "[sing-tun] ") {
		t.Errorf("Handler created must stay info-level, got %q", line)
	}
}
