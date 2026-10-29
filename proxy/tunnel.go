package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SnishaperTeam/snishaper-core/config"
)

func (p *ProxyServer) handleRequest(w http.ResponseWriter, req *http.Request) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	matchHost := normalizeHost(host)
	mode := p.GetMode()
	rule := p.rules.matchRuleFor(matchHost, mode, p.clientProcess(req.RemoteAddr))

	p.tracef("[Proxy] Request: %s -> %s (match: %s, runtime-mode: %s, rule-mode: %s)", req.Method, host, matchHost, mode, rule.Mode)

	switch req.Method {
	case http.MethodConnect:
		p.handleConnect(w, req, rule)
	default:
		p.handleHTTP(w, req, rule)
	}
}

func (p *ProxyServer) handleConnect(w http.ResponseWriter, req *http.Request, rule Rule) {
	targetAuthority := req.URL.Host
	if targetAuthority == "" {
		targetAuthority = req.Host
	}
	targetHost := normalizeHost(targetAuthority)
	targetAddr := ensureAddrWithPort(targetAuthority, "443")

	if p.isSelfTarget(targetAuthority) {
		p.tracef("[Connect] Rejected loopback request targeting proxy itself: %s", targetAuthority)
		http.Error(w, "Loop detected: request targets the proxy itself", http.StatusForbidden)
		return
	}

	cr := p.prepareConnect(targetHost, targetAddr, rule)

	// direct 模式不再特殊处理，统一走 dialUpstream + handleTransparent 路径
	// 这样直连也用 DoH 解析器选 IP（而非系统 DNS，避免 TUN 模式下系统 DNS 进 TUN 死循环）
	// 且 IPv4 优先，避免 IPv6 成为唯一候选

	// QUIC 规则命中的 TCP 连接：浏览器对 QUIC 站点回退到 TCP 时，本地终结 TLS
	// 后经 H3/QUIC 上游 replay（NewQUICRoundTripper），用 QUIC 绕过 TCP 层 SNI 阻断。
	if cr.effectiveMode == "quic" {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Hijack not supported", http.StatusInternalServerError)
			return
		}
		clientConn, rw, err := hijacker.Hijack()
		if err != nil {
			p.tracef("[Connect] QUIC hijack failed: %v", err)
			return
		}
		if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			clientConn.Close()
			return
		}
		if err := rw.Flush(); err != nil {
			clientConn.Close()
			return
		}
		clientConn = wrapHijackedConn(clientConn, rw)
		_ = clientConn.SetDeadline(time.Time{})
		clientConn = p.trackConn(clientConn, "https", targetHost, "", cr.rule, cr.effectiveMode)
		p.handleQUICMITM(clientConn, cr.targetHost, cr.rule)
		return
	}

	if cr.effectiveMode == "migration" {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Hijack not supported", http.StatusInternalServerError)
			return
		}
		clientConn, rw, err := hijacker.Hijack()
		if err != nil {
			p.tracef("[Connect] Migration hijack failed: %v", err)
			return
		}
		clientConn = wrapHijackedConn(clientConn, rw)
		_ = clientConn.SetDeadline(time.Time{})
		clientConn = p.trackConn(clientConn, "https", targetHost, "", cr.rule, cr.effectiveMode)
		_, targetPort, _ := net.SplitHostPort(cr.targetAddr)
		if targetPort == "" {
			targetPort = "443"
		}
		p.handleMigration(clientConn, cr.targetHost, targetPort, cr.rule)
		return
	}

	// mitm 不用 cr.conn：上游 ALPN 要按客户端宣告的协议来定，连接只能在 TLS 握手
	// 回调里由 establishUpstreamConn 建立，这里仅解析候选地址（订阅节点隧道除外）。
	if cr.effectiveMode == "mitm" {
		if ok, err := p.dialSubscriptionTunnel(cr); ok && err != nil {
			http.Error(w, "Failed to connect to upstream", http.StatusBadGateway)
			p.tracef("[Connect] Subscription tunnel failed for %s: %v", cr.targetHost, err)
			return
		}
		if !cr.tunnelled {
			if err := p.resolveDialCandidates(cr); err != nil {
				p.tracef("[Connect] 502 (local): CONNECT %s mode=mitm rule-mode=%s upstream=%s error=%v",
					targetAuthority, rule.Mode, rule.Upstream, err)
				http.Error(w, "Failed to connect to upstream", http.StatusBadGateway)
				p.tracef("[Connect] Failed to resolve upstream candidates for %s: %v", cr.targetHost, err)
				return
			}
		}
	} else if err := p.dialUpstream(cr); err != nil {
		p.tracef("[Connect] 502 (local): CONNECT %s mode=%s rule-mode=%s upstream=%s candidates=%v error=%v",
			targetAuthority, cr.effectiveMode, rule.Mode, rule.Upstream, cr.dialCandidates, err)
		http.Error(w, "Failed to connect to upstream", http.StatusBadGateway)
		p.tracef("[Connect] All upstream connect attempts failed: %v, error: %v", cr.dialCandidates, err)
		return
	}

	// cr.conn 仅 tls-rf / transparent / 订阅隧道 MITM 使用，纯候选路径下为 nil
	closeUpstream := func() {
		if cr.conn != nil {
			cr.conn.Close()
		}
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack not supported", http.StatusInternalServerError)
		closeUpstream()
		return
	}

	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		p.tracef("[Connect] Hijack failed: %v", err)
		closeUpstream()
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		p.tracef("[Connect] Write 200 failed: %v", err)
		clientConn.Close()
		closeUpstream()
		return
	}
	if err := rw.Flush(); err != nil {
		p.tracef("[Connect] Flush 200 failed: %v", err)
		clientConn.Close()
		closeUpstream()
		return
	}
	clientConn = wrapHijackedConn(clientConn, rw)
	_ = clientConn.SetDeadline(time.Time{})
	clientConn = p.trackConn(clientConn, "https", targetHost, cr.dialAddr, cr.rule, cr.effectiveMode)
	if cr.conn != nil {
		_ = cr.conn.SetDeadline(time.Time{})
	}

	switch cr.effectiveMode {
	case "mitm":
		if cr.tunnelled {
			p.handleMITMWithConn(clientConn, cr.targetHost, cr.rule, cr.dialCandidates, cr.dialAddr, cr.conn)
		} else {
			p.handleMITM(clientConn, cr.targetHost, cr.rule, cr.dialCandidates, cr.dialAddr)
		}
	case "tls-rf":
		p.handleTLSFragment(clientConn, cr.conn, cr.targetHost, cr.rule)
	default:
		p.handleTransparent(clientConn, cr.conn, cr.targetHost, cr.rule)
	}
}


// isSelfTarget 判断请求目标地址是否为代理自身监听端口，用于阻止自连死循环。
// 例如代理监听 127.0.0.1:8080 时，任何发往 127.0.0.1:8080 / localhost:8080 的请求都应被拒绝。
func (p *ProxyServer) isSelfTarget(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if idx := strings.Index(host, "://"); idx >= 0 {
		host = host[idx+3:]
	}
	if idx := strings.IndexAny(host, "/?#"); idx >= 0 {
		host = host[:idx]
	}

	hostOnly, port := host, ""
	if h, p_, err := net.SplitHostPort(host); err == nil {
		hostOnly, port = h, p_
	} else if strings.HasPrefix(host, "[") {
		hostOnly = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	} else if i := strings.LastIndex(host, ":"); i >= 0 {
		hostOnly, port = host[:i], host[i+1:]
	}

	selfHost, selfPort := "", ""
	if h, p_, err := net.SplitHostPort(p.listenAddr); err == nil {
		selfHost, selfPort = h, p_
	}

	if port == "" {
		if selfPort != "" && selfPort != "80" && selfPort != "443" {
			return false
		}
	} else if selfPort != "" && port != selfPort {
		return false
	}

	hostOnly = strings.ToLower(strings.Trim(strings.TrimSuffix(strings.TrimSpace(hostOnly), "."), "[]"))
	selfHost = strings.ToLower(strings.Trim(strings.TrimSuffix(strings.TrimSpace(selfHost), "."), "[]"))
	if hostOnly == "localhost" {
		hostOnly = "127.0.0.1"
	}
	if selfHost == "" || selfHost == "localhost" {
		selfHost = "127.0.0.1"
	}

	if ip := net.ParseIP(hostOnly); ip != nil {
		hostOnly = ip.String()
	}
	if ip := net.ParseIP(selfHost); ip != nil {
		selfHost = ip.String()
	}

	if selfHost == "0.0.0.0" || selfHost == "::" {
		switch hostOnly {
		case "127.0.0.1", "::1", "0.0.0.0", "::":
			return true
		}
		return false
	}

	if hostOnly == "0.0.0.0" || hostOnly == "::" {
		return true
	}

	return hostOnly == selfHost
}

// candidateDial 携带单个明文 HTTP 请求的拨号候选与规则，经请求 context
// 传给共享的 candidateTransport.DialContext。
type candidateDial struct {
	candidates []string
	rule       Rule
}

type candidateDialCtxKeyType int

const candidateDialCtxKey candidateDialCtxKeyType = 0

// candidateDialTransport 返回唯一的 transport 克隆：DialContext 从请求
// context 取出候选与规则逐个拨号。单实例共享让连接池可复用，替代旧的
// 每请求克隆（每请求克隆导致连接永不复用）。
func (p *ProxyServer) candidateDialTransport() *http.Transport {
	p.mu.RLock()
	t := p.candidateTransport
	p.mu.RUnlock()
	if t != nil {
		return t
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.candidateTransport == nil {
		t = p.transport.Clone()
		t.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			cd, ok := ctx.Value(candidateDialCtxKey).(*candidateDial)
			if !ok {
				return nil, fmt.Errorf("no candidate dial info in request context")
			}
			var lastErr error
			for _, candidate := range cd.candidates {
				conn, err := p.dialWithRule(ctx, network, candidate, cd.rule)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		}
		p.candidateTransport = t
	}
	return p.candidateTransport
}

func (p *ProxyServer) handleHTTP(w http.ResponseWriter, req *http.Request, rule Rule) {
	newReq := req.Clone(req.Context())
	newReq.RequestURI = ""
	newReq.Header.Del("Proxy-Connection")

	if newReq.URL.Scheme == "" {
		if req.TLS != nil {
			newReq.URL.Scheme = "https"
		} else {
			newReq.URL.Scheme = "http"
		}
	}
	if newReq.URL.Host == "" {
		newReq.URL.Host = req.Host
	}
	if newReq.Host == "" {
		newReq.Host = req.Host
	}
	if newReq.Host == "" {
		newReq.Host = newReq.URL.Host
	}

	if p.isSelfTarget(newReq.URL.Host) {
		p.tracef("[HTTP] Rejected loopback request targeting proxy itself: %s", newReq.URL.Host)
		http.Error(w, "Loop detected: request targets the proxy itself", http.StatusForbidden)
		return
	}

	if (rule.Mode == "mitm" || rule.Mode == "quic") && newReq.URL.Scheme == "http" {
		httpsURL := *newReq.URL
		httpsURL.Scheme = "https"
		if httpsURL.Host == "" {
			httpsURL.Host = req.Host
		}
		http.Redirect(w, req, httpsURL.String(), http.StatusMovedPermanently)
		return
	}

	if strings.EqualFold(strings.TrimSpace(rule.Mode), "block") {
		p.tracef("[HTTP] Refused request to %s: blocked by rule", newReq.URL.Host)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if rule.Mode == "direct" {
		resp, err := p.transport.RoundTrip(newReq)
		if err != nil {
			p.tracef("[HTTP] Direct proxy failed: %v", err)
			http.Error(w, "Failed to proxy", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	transport := http.RoundTripper(p.transport)
	if rule.Upstream != "" {
		defaultPort := "80"
		if strings.EqualFold(newReq.URL.Scheme, "https") {
			defaultPort = "443"
		}
		candidates := p.buildDialCandidates(req.Context(), normalizeHost(newReq.Host), ensureAddrWithPort(newReq.URL.Host, defaultPort), rule, rule.Mode)
		if len(candidates) > 0 {
			newReq.URL.Host = candidates[0]
		}
		if p.isSelfTarget(newReq.URL.Host) {
			p.tracef("[HTTP] Rejected upstream candidate targeting proxy itself: %s", newReq.URL.Host)
			http.Error(w, "Loop detected: upstream targets the proxy itself", http.StatusForbidden)
			return
		}
	} else {
		defaultPort := "80"
		if strings.EqualFold(newReq.URL.Scheme, "https") {
			defaultPort = "443"
		}
		targetAddr := ensureAddrWithPort(newReq.URL.Host, defaultPort)
		dialCandidates := p.buildDialCandidates(req.Context(), normalizeHost(newReq.Host), targetAddr, rule, rule.Mode)
		if len(dialCandidates) > 0 && dialCandidates[0] != targetAddr {
			transport = p.candidateDialTransport()
			ctx := context.WithValue(newReq.Context(), candidateDialCtxKey, &candidateDial{
				candidates: dedupeDialCandidates(dialCandidates),
				rule:       rule,
			})
			newReq = newReq.WithContext(ctx)
		}
	}

	resp, err := transport.RoundTrip(newReq)
	if err != nil {
		p.tracef("[HTTP] Proxy failed: %v", err)
		http.Error(w, "Failed to connect to upstream", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *ProxyServer) directTunnel(clientConn, upstreamConn net.Conn) {
	p.tracef("[Tunnel] Starting direct tunnel")
	var wg sync.WaitGroup
	wg.Add(2)

	buf1 := tunnelBufPool.Get().(*[]byte)
	buf2 := tunnelBufPool.Get().(*[]byte)

	go func() {
		defer wg.Done()
		defer tunnelBufPool.Put(buf1)
		n, err := io.CopyBuffer(upstreamConn, clientConn, *buf1)
		p.tracef("[Tunnel] Client -> Upstream: %d bytes, err: %v", n, err)
		config.HalfClose(upstreamConn)
	}()
	go func() {
		defer wg.Done()
		defer tunnelBufPool.Put(buf2)
		n, err := io.CopyBuffer(clientConn, upstreamConn, *buf2)
		p.tracef("[Tunnel] Upstream -> Client: %d bytes, err: %v", n, err)
		config.HalfClose(clientConn)
	}()
	wg.Wait()
	clientConn.Close()
	upstreamConn.Close()
	p.tracef("[Tunnel] Tunnel closed")
}

// GetStats 返回下行与上行字节计数（第三个返回值保留，恒为 0）。
func (p *ProxyServer) GetStats() (int64, int64, int64) {
	return atomic.LoadInt64(&p.bytesDown), atomic.LoadInt64(&p.bytesUp), 0
}
