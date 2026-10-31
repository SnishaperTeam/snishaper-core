package dohresolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SnishaperTeam/snishaper-core/config"
	corelog "github.com/SnishaperTeam/snishaper-core/log"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"

	"github.com/SnishaperTeam/snishaper-core/netiface"
)

// CertVerifyConfig 重新导出 config 包的证书校验配置类型。
type CertVerifyConfig = config.CertVerifyConfig

// DNSNode 表示一个 DoH 上游节点。
type DNSNode struct {
	Name          string           `json:"name"`
	URL           string           `json:"url"`
	SNI           string           `json:"sni"`
	ECHEnabled    bool             `json:"ech_enabled"`
	ECHProfileID  string           `json:"ech_profile_id"`
	QUIC          bool             `json:"quic"`
	IPs           []string         `json:"ips"`
	CertVerify    CertVerifyConfig `json:"cert_verify"`
	ECHAutoUpdate bool             `json:"ech_auto_update"`
	Enabled       bool             `json:"enabled"`
}

// Rule 描述 DoH 解析时按域名应用的策略。
type Rule struct {
	SniFake       string
	ECHEnabled    bool
	ECHProfileID  string
	CertVerify    CertVerifyConfig
	ECHAutoUpdate bool
}

// ProxyServer 抽象接口，表达 DoH 模块对代理底层网络传输和安全状态的依赖
type ProxyServer interface {
	DialWithRule(ctx context.Context, network, addr string, rule Rule) (net.Conn, error)
	GetUConn(conn net.Conn, sni, verifyName string, rule Rule, allowUnknownAuthority bool, alpn string, ech []byte) *utls.UConn
	ResolveRuleECHConfig(host string, rule Rule) []byte
	UpdateECHProfileConfig(profileID string, configBytes []byte)
	// GetPhysicalBinding 返回与目标地址 IP 族匹配的出站网卡绑定信息。
	// TUN 模式下用于把 QUIC/UDP socket 绑到物理网卡，绕过 TUN 避免流量回环。
	GetPhysicalBinding(targetAddr string) (netiface.Binding, bool)
}

type dnsCacheEntry struct {
	ips       []string
	expiresAt time.Time
	staleAt   time.Time
}

// nodeClientIdleTimeout 是复用的 DoH 传输层保留空闲连接的时间。
const nodeClientIdleTimeout = 90 * time.Second

// negativeCacheTTL 是解析失败结果的负缓存时长：足够吸收客户端的密集重试，
// 又能在网络恢复/节点恢复后很快重试真实解析。
const negativeCacheTTL = 15 * time.Second

// resolveCall 是 singleflight 一次域名解析的共享结果载体。
type resolveCall struct {
	done chan struct{}
	ips  []string
	err  error
}

// maxCachedNodeClients 限制缓存的 DoH 客户端数量：节点配置变化（URL/SNI/IP/证书校验策略）
// 或 QUIC 节点 ECH 配置热更新时会产生新条目，超限时按最久未使用淘汰并关闭。
const maxCachedNodeClients = 16

// nodeClient 是一个按节点配置复用的 DoH 客户端及其释放逻辑。
type nodeClient struct {
	client   *http.Client
	closeFn  func()
	echSig   string // QUIC 客户端构建时固化的 ECH config 指纹
	lastUsed time.Time
}

// FailoverResolver 是带节点故障转移的 DoH 解析器。
type FailoverResolver struct {
	proxy    ProxyServer
	getNodes func() []DNSNode
	logger   corelog.Logger
	// brand 决定 DoH 请求携带的产品 User-Agent。
	brand    config.Brand
	dnsCache sync.Map // domain -> *dnsCacheEntry

	// refreshInflight 实现同域名后台刷新 singleflight：
	// 过期-but-fresh 缓存的并发请求只触发一次后台 DoH 解析。
	refreshMu       sync.Mutex
	refreshInflight map[string]struct{}

	// negCache 记录最近解析失败的域名（domain -> 失败失效时间）。
	// 死域名（广告/遥测）的重试风暴曾把每次失败都重新放大成 2 查询 × N 节点
	// 的并发 DoH 扇出，goroutine 无限堆积直至 OOM（SniShaper issue #181）。
	// 失败短时负缓存让后续重试立即失败，扇出只发生一次。
	negCache sync.Map

	// resolveInflight 实现并发解析 singleflight（domain -> *resolveCall）：
	// 同一域名的并发 ResolveIPs 只有一个真正发起 DoH 查询，其余等待其结果。
	resolveInflight sync.Map

	clientMu    sync.Mutex             // 保护 clients
	clients     map[string]*nodeClient // node 配置指纹 -> 复用中的 DoH 客户端
	clientLocks [keyLockShards]sync.Mutex
}

// Option is a functional option for NewFailoverResolver.
type Option func(*FailoverResolver)

// WithLogger injects the logger used for DoH handshake recovery traces
// (log.Nop default: an unconfigured resolver stays silent).
func WithLogger(l corelog.Logger) Option {
	return func(r *FailoverResolver) { r.logger = l }
}

// WithBrand declares the embedding application, which supplies the product
// token in the DoH User-Agent.
func WithBrand(b config.Brand) Option {
	return func(r *FailoverResolver) { r.brand = b.Resolve() }
}

// dohUserAgentPrefix is the browser-shaped part of the DoH User-Agent. Some
// resolvers reject non-browser clients outright, so every embedder sends the
// same browser prefix and appends its own product token.
const dohUserAgentPrefix = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 "

// userAgent returns the DoH User-Agent for this application: the shared
// browser prefix plus the product name, so operators can attribute queries to
// a product instead of seeing the reference product's name.
func (r *FailoverResolver) userAgent() string {
	return dohUserAgentPrefix + r.brand.Display() + "/1.0"
}

// keyLockShards 是节点客户端键的分片锁数量。ResolveIPAddrs 会并发发起 A/AAAA 两个查询，
// 同一节点的两个 goroutine 必须串行完成"查缓存 → 建连 → 入缓存"，否则会各自建一个客户端，
// 后写入的那个会把前一个正在使用的客户端关闭，导致请求失败。
const keyLockShards = 32

// nodeClientLock 返回缓存键对应的分片锁（FNV-1a 散列）。
func (r *FailoverResolver) nodeClientLock(key string) *sync.Mutex {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &r.clientLocks[h%keyLockShards]
}

// logf routes resolver logging to the injected logger.
func (r *FailoverResolver) logf(format string, args ...any) {
	if r.logger != nil {
		r.logger.Printf(format, args...)
	}
}

// NewFailoverResolver creates a failover DoH resolver backed by the proxy
// adapter and the DNS nodes returned by getNodes.
func NewFailoverResolver(proxy ProxyServer, getNodes func() []DNSNode, opts ...Option) *FailoverResolver {
	r := &FailoverResolver{
		proxy:           proxy,
		getNodes:        getNodes,
		clients:         make(map[string]*nodeClient),
		refreshInflight: make(map[string]struct{}),
		logger:          corelog.Nop,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(r)
		}
	}
	return r
}

// nodeClientKey 生成客户端缓存键。任何影响底层 transport 行为（拨号地址、SNI、
// 证书校验策略、传输协议）的字段变化都必须映射到不同的键，否则会复用错误的连接。
func nodeClientKey(node DNSNode) string {
	var b strings.Builder
	b.WriteString(node.URL)
	b.WriteByte(0)
	b.WriteString(node.SNI)
	b.WriteByte(0)
	b.WriteString(strconv.FormatBool(node.QUIC))
	b.WriteByte(0)
	b.WriteString(strconv.FormatBool(node.ECHEnabled))
	b.WriteByte(0)
	b.WriteString(node.ECHProfileID)
	b.WriteByte(0)
	b.WriteString(node.CertVerify.Mode)
	b.WriteByte(0)
	b.WriteString(strconv.FormatBool(node.CertVerify.AllowUnknownAuthority))
	b.WriteByte(0)
	b.WriteString(strings.Join(node.CertVerify.Names, ","))
	b.WriteByte(0)
	b.WriteString(strings.Join(node.CertVerify.Suffixes, ","))
	b.WriteByte(0)
	b.WriteString(strings.Join(node.CertVerify.SPKISHA256, ","))
	b.WriteByte(0)
	b.WriteString(strings.Join(node.IPs, ","))
	return b.String()
}

// reuseNodeClient 返回可复用的客户端。ECH 指纹不匹配（配置被热补丁更新）时返回 nil，
// 由调用方重建，避免继续使用固化在 TLS 配置里的旧 ECH。
func (r *FailoverResolver) reuseNodeClient(key, echSig string) *http.Client {
	r.clientMu.Lock()
	defer r.clientMu.Unlock()

	cl, ok := r.clients[key]
	if !ok || cl.echSig != echSig {
		return nil
	}
	cl.lastUsed = time.Now()
	return cl.client
}

// storeNodeClient 记录新建的客户端，并关闭被替换或淘汰的旧客户端。
// 关闭动作放在锁外执行，QUIC transport 的 Close 会等待连接收尾，不应阻塞其他查询。
func (r *FailoverResolver) storeNodeClient(key, echSig string, client *http.Client, closeFn func()) {
	var stale []*nodeClient

	r.clientMu.Lock()
	if old, ok := r.clients[key]; ok {
		stale = append(stale, old)
	}
	r.clients[key] = &nodeClient{
		client:   client,
		closeFn:  closeFn,
		echSig:   echSig,
		lastUsed: time.Now(),
	}

	for len(r.clients) > maxCachedNodeClients {
		oldestKey := ""
		var oldest time.Time
		for k, v := range r.clients {
			if oldestKey == "" || v.lastUsed.Before(oldest) {
				oldestKey, oldest = k, v.lastUsed
			}
		}
		if oldestKey == "" {
			break
		}
		stale = append(stale, r.clients[oldestKey])
		delete(r.clients, oldestKey)
	}
	r.clientMu.Unlock()

	for _, s := range stale {
		s.closeFn()
	}
}

// Close 释放所有缓存的 DoH 客户端：关闭 QUIC 连接、其底层 UDP socket 以及 TCP 空闲连接。
// 停止代理或切换 TUN 模式（出站绑定网卡变化）后必须调用，否则连接与 goroutine 会泄漏。
func (r *FailoverResolver) Close() {
	var stale []*nodeClient

	// 逐分片加锁，避免与正在建连接的 getNodeClient 交错（否则 Close 之后又塞入新客户端）。
	for i := range r.clientLocks {
		r.clientLocks[i].Lock()
	}
	r.clientMu.Lock()
	for k, v := range r.clients {
		stale = append(stale, v)
		delete(r.clients, k)
	}
	r.clientMu.Unlock()
	for i := len(r.clientLocks) - 1; i >= 0; i-- {
		r.clientLocks[i].Unlock()
	}

	for _, s := range stale {
		s.closeFn()
	}
}

func (r *FailoverResolver) getNodeClient(ctx context.Context, node DNSNode) (*http.Client, error) {
	parsedURL, err := url.Parse(node.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid node URL: %w", err)
	}
	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	rule := Rule{
		SniFake:       node.SNI,
		ECHEnabled:    node.ECHEnabled,
		ECHProfileID:  node.ECHProfileID,
		CertVerify:    node.CertVerify,
		ECHAutoUpdate: node.ECHAutoUpdate,
	}

	// QUIC 客户端的 TLS 配置在构建时固化 ECH config，配置被热补丁更新后必须重建客户端，
	// 因此把 ECH 指纹并入缓存判定。TCP 路径每次握手都会重新解析 ECH，无需参与判定。
	var quicECH []byte
	if node.QUIC && node.ECHEnabled {
		quicECH = r.proxy.ResolveRuleECHConfig(host, rule)
	}
	echSig := string(quicECH)

	clientKey := nodeClientKey(node)

	// 同一节点的并发查询（A/AAAA 双查询、故障转移并发）串行化：
	// 先查缓存，未命中才建连并入缓存，避免重复建连与互相关闭。
	keyLock := r.nodeClientLock(clientKey)
	keyLock.Lock()
	defer keyLock.Unlock()

	if c := r.reuseNodeClient(clientKey, echSig); c != nil {
		return c, nil
	}

	// QUIC/HTTP3 path
	if node.QUIC {
		// 与 echSig 同一次解析结果，避免重复查询 ECH 配置。
		echBytes := quicECH
		tlsConfig := &tls.Config{
			ServerName:         host,
			NextProtos:         []string{"h3", "h3-29", "h3-32"},
			InsecureSkipVerify: true,
		}
		if len(echBytes) > 0 {
			tlsConfig.EncryptedClientHelloConfigList = echBytes
			tlsConfig.InsecureSkipVerify = false
		} else if !node.CertVerify.AllowUnknownAuthority {
			// 与主代理路径一致：默认仅校验证书链（不匹配主机名），
			// 不再无验证放行；用户显式允许未知 CA 时保持原行为
			tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
				return config.VerifyChainOnly(cs.PeerCertificates)
			}
		}
		if rule.SniFake != "" {
			tlsConfig.ServerName = rule.SniFake
		}

		var dialAddrs []string
		if len(node.IPs) > 0 {
			for _, ip := range node.IPs {
				dialAddrs = append(dialAddrs, net.JoinHostPort(ip, port))
			}
		} else {
			dialAddrs = []string{net.JoinHostPort(host, port)}
		}

		tr := &http3.Transport{
			TLSClientConfig: tlsConfig,
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				for _, addr := range dialAddrs {
					// TUN 模式下把 QUIC socket 绑到物理网卡，避免 UDP 流量被 TUN 捕获回环。
					// 注意：QUIC 的 ListenPacket 必须绑本地通配地址（0.0.0.0:0 / [::]:0），
					// 绑具体目标地址会收不到回包；网卡归属由 Control 里的
					// IP_UNICAST_IF / SO_BINDTODEVICE 指定。
					remote, err := net.ResolveUDPAddr("udp", addr)
					if err != nil {
						continue
					}
					listenAddr := "[::]:0"
					if remote.IP.To4() != nil {
						listenAddr = "0.0.0.0:0"
					}
					listener := &net.ListenConfig{}
					if binding, ok := r.proxy.GetPhysicalBinding(addr); ok {
						listener.Control = binding.Control(netiface.FamilyOf(addr))
					}
					pc, err := listener.ListenPacket(ctx, "udp", listenAddr)
					if err != nil {
						continue
					}
					udpConn, ok := pc.(*net.UDPConn)
					if !ok {
						pc.Close()
						continue
					}
					conn, err := quic.Dial(ctx, udpConn, remote, tlsCfg, cfg)
					if err == nil {
						// quic.Dial 不会关闭调用方传入的 PacketConn（createdPacketConn=false），
						// 该 socket 只服务于这一个 QUIC 连接，因此连接结束时必须显式关闭，
						// 否则每个成功的 QUIC 拨号都会泄漏一个 UDP socket。
						go func(c *net.UDPConn, qc *quic.Conn) {
							<-qc.Context().Done()
							_ = c.Close()
						}(udpConn, conn)
						return conn, nil
					}
					_ = udpConn.Close()
				}
				return nil, fmt.Errorf("all QUIC dial failed for %s", host)
			},
		}

		client := &http.Client{
			Transport: tr,
			Timeout:   10 * time.Second,
		}
		// tr.Close 关闭池中所有 QUIC 连接，连接关闭后上面的协程会一并关掉各自的 UDP socket。
		// 客户端被替换或淘汰时由 storeNodeClient 调用，避免 transport 与 socket 泄漏。
		r.storeNodeClient(clientKey, echSig, client, func() { _ = tr.Close() })
		return client, nil
	}

	// TCP/TLS path (default)
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// 收集拨号候选 IP
			var dialCandidates []string
			if len(node.IPs) > 0 {
				for _, ip := range node.IPs {
					dialCandidates = append(dialCandidates, net.JoinHostPort(ip, port))
				}
			} else {
				dialCandidates = []string{net.JoinHostPort(host, port)}
			}

			var dialConn net.Conn
			var dialErr error
			for _, cand := range dialCandidates {
				dialConn, dialErr = r.proxy.DialWithRule(ctx, network, cand, rule)
				if dialErr == nil && dialConn != nil {
					break
				}
			}
			if dialErr != nil || dialConn == nil {
				return nil, dialErr
			}

			echBytes := r.proxy.ResolveRuleECHConfig(host, rule)
			verifyName := host
			if rule.SniFake != "" {
				verifyName = rule.SniFake
			}

			// 通过代理系统的 GetUConn 进行 uTLS 混淆客户端指纹和 ECH 注入
			uconn := r.proxy.GetUConn(
				dialConn,
				rule.SniFake,
				verifyName,
				rule,
				node.CertVerify.AllowUnknownAuthority,
				"http/1.1",
				echBytes,
			)

			if err := uconn.HandshakeContext(ctx); err != nil {
				dialConn.Close()
				return nil, err
			}
			return uconn, nil
		},
		ResponseHeaderTimeout: 5 * time.Second,
		// 复用同一节点时保留空闲连接，避免每次查询都重建 TCP+TLS（含 uTLS 握手）。
		IdleConnTimeout: nodeClientIdleTimeout,
	}

	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	r.storeNodeClient(clientKey, echSig, client, func() { tr.CloseIdleConnections() })
	return client, nil
}

func (r *FailoverResolver) exchangeNode(ctx context.Context, node *DNSNode, msg *dns.Msg) (*dns.Msg, error) {
	return r.exchangeNodeWithRetry(ctx, node, msg, true)
}

func (r *FailoverResolver) exchangeNodeWithRetry(ctx context.Context, node *DNSNode, msg *dns.Msg, allowRetry bool) (*dns.Msg, error) {
	client, err := r.getNodeClient(ctx, *node)
	if err != nil {
		return nil, err
	}

	msg = msg.Copy()
	msg.Id = 0

	buf, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", node.URL, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}

	if node.SNI != "" {
		u, _ := url.Parse(node.URL)
		if u != nil && isLiteralIP(u.Hostname()) {
			req.Host = node.SNI
		}
	}

	req.ContentLength = int64(len(buf))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", r.userAgent())

	resp, err := client.Do(req)
	if err != nil {
		// 阻断自愈：ECH 被拒时优先使用服务端 RetryConfigList，其次安全 DNS 刷新后重试。
		// 无 profile ID 时刷新无处落地，重试只会复用同样的旧 ECH，因此跳过自愈。
		if allowRetry && node.ECHEnabled && node.ECHAutoUpdate && node.ECHProfileID != "" {
			parsedURL, _ := url.Parse(node.URL)
			if parsedURL != nil {
				host := parsedURL.Hostname()
				var echErr *utls.ECHRejectionError
				if errors.As(err, &echErr) {
					r.logf("[DOH] ECH rejected for %s (retryConfigs=%d), recovering...", host, len(echErr.RetryConfigList))
					if recovered := r.recoverNodeECH(ctx, node, host, echErr); recovered {
						return r.exchangeNodeWithRetry(ctx, node, msg, false)
					}
					r.logf("[DOH] ECH recovery failed for %s", host)
				} else {
					// 非明确 ECH 拒绝时仍尝试 DNS 刷新（兼容被包装的错误）
					r.logf("[DOH] Handshake failed for %s (%v), attempting ECH DNS refresh...", host, err)
					if newECH, refreshErr := r.ResolveECHSafe(ctx, host); refreshErr == nil && len(newECH) > 0 {
						r.logf("[DOH] Successfully refreshed ECH for %s (%d bytes). Syncing and retrying...", host, len(newECH))
						r.proxy.UpdateECHProfileConfig(node.ECHProfileID, newECH)
						return r.exchangeNodeWithRetry(ctx, node, msg, false)
					}
				}
			}
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	respBuf, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	resMsg := new(dns.Msg)
	if err := resMsg.Unpack(respBuf); err != nil {
		return nil, err
	}

	return resMsg, nil
}

// Exchange 按启用节点顺序执行 DNS 报文交换，失败时自动转移到下一节点。
func (r *FailoverResolver) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if r.getNodes == nil {
		return nil, fmt.Errorf("getNodes callback not configured")
	}
	nodes := r.getNodes()

	var activeNodes []DNSNode
	for _, n := range nodes {
		if !n.Enabled {
			continue
		}
		activeNodes = append(activeNodes, n)
	}

	var lastErr error
	if len(activeNodes) > 0 {
		primary := &activeNodes[0]
		resp, primaryErr := r.exchangeNode(ctx, primary, msg)
		if primaryErr == nil && resp != nil {
			return resp, nil
		}
		lastErr = primaryErr

		if len(activeNodes) > 1 {
			type result struct {
				msg *dns.Msg
				err error
			}
			resChan := make(chan result, len(activeNodes)-1)
			ctxCancel, cancel := context.WithCancel(ctx)
			defer cancel()

			for i, node := range activeNodes[1:] {
				go func(idx int, n DNSNode) {
					m, e := r.exchangeNode(ctxCancel, &activeNodes[idx+1], msg)
					if e == nil && m != nil {
						resChan <- result{m, nil}
						cancel()
					} else {
						resChan <- result{nil, e}
					}
				}(i, node)
			}

			for i := 0; i < len(activeNodes)-1; i++ {
				select {
				case res := <-resChan:
					if res.err == nil {
						return res.msg, nil
					}
					lastErr = res.err
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("all DNS nodes failed to exchange: %w", lastErr)
	}
	return nil, fmt.Errorf("all DNS nodes failed to exchange (no active nodes)")
}

// TestNode 用解析 cloudflare.com 的方式探测节点，返回解析到的 A 记录。
func (r *FailoverResolver) TestNode(ctx context.Context, node DNSNode) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("cloudflare.com"), dns.TypeA)

	resp, err := r.exchangeNode(ctx, &node, msg)
	if err != nil {
		return nil, err
	}

	var ips []string
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A records returned")
	}
	return ips, nil
}

// ResolveIPs 解析域名并返回 IP 字符串列表。
func (r *FailoverResolver) ResolveIPs(ctx context.Context, domain string) ([]string, error) {
	// 负缓存命中：该域名最近解析失败，立即返回错误。这是重试风暴下的
	// 第一道闸门 —— 不查缓存的话，每个并发调用都会重新扇出完整 DoH 查询。
	if v, ok := r.negCache.Load(domain); ok {
		if expiry, valid := v.(time.Time); valid && time.Now().Before(expiry) {
			return nil, fmt.Errorf("DNS resolution for %s failed recently (negative cache)", domain)
		}
		r.negCache.Delete(domain)
	}

	now := time.Now()

	if val, ok := r.dnsCache.Load(domain); ok {
		entry := val.(*dnsCacheEntry)
		if now.Before(entry.expiresAt) {
			return entry.ips, nil
		}
		if now.Before(entry.staleAt) {
			// 同一域名同时只允许一个后台刷新，避免过期风暴放大成并发 DoH 解析
			r.refreshMu.Lock()
			if _, busy := r.refreshInflight[domain]; !busy {
				r.refreshInflight[domain] = struct{}{}
				r.refreshMu.Unlock()
				go func(dom string) {
					defer func() {
						r.refreshMu.Lock()
						delete(r.refreshInflight, dom)
						r.refreshMu.Unlock()
					}()
					bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					_, _ = r.resolveAndCache(bgCtx, dom)
				}(domain)
			} else {
				r.refreshMu.Unlock()
			}
			return entry.ips, nil
		}
	}

	ips, err := r.resolveSingleflight(ctx, domain)
	if err != nil {
		// 只缓存真实失败。调用方被取消（客户端已断开）或结果本身是取消错误时
		// 不进负缓存 —— 否则一次断开会把该域名对所有调用方错误地封死 15s。
		if ctx.Err() == nil && !errors.Is(err, context.Canceled) {
			r.negCache.Store(domain, time.Now().Add(negativeCacheTTL))
		}
		return nil, err
	}
	return ips, nil
}

// resolveSingleflight 保证同一域名同一时刻只有一个真实解析在执行，
// 后到的并发调用等待并复用其结果，而不是各自扇出一份 DoH 查询。
func (r *FailoverResolver) resolveSingleflight(ctx context.Context, domain string) ([]string, error) {
	call := &resolveCall{done: make(chan struct{})}
	if actual, loaded := r.resolveInflight.LoadOrStore(domain, call); loaded {
		existing := actual.(*resolveCall)
		select {
		case <-existing.done:
			return existing.ips, existing.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	defer func() {
		r.resolveInflight.Delete(domain)
		close(call.done)
	}()
	call.ips, call.err = r.resolveAndCache(ctx, domain)
	return call.ips, call.err
}

func (r *FailoverResolver) resolveAndCache(ctx context.Context, domain string) ([]string, error) {
	ipAddrs, err := r.ResolveIPAddrs(ctx, domain)
	if err != nil {
		return nil, err
	}

	ips := make([]string, 0, len(ipAddrs))
	for _, ip := range ipAddrs {
		if ip == nil {
			continue
		}
		ips = append(ips, ip.String())
	}

	if len(ips) > 0 {
		now := time.Now()
		entry := &dnsCacheEntry{
			ips:       ips,
			expiresAt: now.Add(2 * time.Minute),
			staleAt:   now.Add(24 * time.Hour),
		}
		r.dnsCache.Store(domain, entry)
	}

	return ips, nil
}

// ResolveIPAddrs 解析域名并返回 net.IP 列表。
func (r *FailoverResolver) ResolveIPAddrs(ctx context.Context, domain string) ([]net.IP, error) {
	type result struct {
		ips []net.IP
		err error
	}

	query := func(qtype uint16) ([]net.IP, error) {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(domain), qtype)
		resp, err := r.Exchange(ctx, msg)
		if err != nil {
			return nil, err
		}
		var ips []net.IP
		for _, ans := range resp.Answer {
			switch a := ans.(type) {
			case *dns.A:
				ips = append(ips, a.A)
			case *dns.AAAA:
				ips = append(ips, a.AAAA)
			}
		}
		return ips, nil
	}

	// 同时查询 A（IPv4）与 AAAA（IPv6）：
	// 之前只查 A，导致 dns_mode 为 prefer_ipv6 / ipv6_only 时永远没有 IPv6 候选。
	// 并发查询避免双重延迟；返回顺序 IPv4 在前，调用方按 dns_mode 自行排序/过滤。
	chA := make(chan result, 1)
	chAAAA := make(chan result, 1)
	go func() {
		ips, err := query(dns.TypeA)
		chA <- result{ips, err}
	}()
	go func() {
		ips, err := query(dns.TypeAAAA)
		chAAAA <- result{ips, err}
	}()

	rA := <-chA
	rAAAA := <-chAAAA

	var ips []net.IP
	ips = append(ips, rA.ips...)
	ips = append(ips, rAAAA.ips...)
	if len(ips) == 0 {
		if rA.err != nil {
			return nil, rA.err
		}
		if rAAAA.err != nil {
			return nil, rAAAA.err
		}
		return nil, fmt.Errorf("no A/AAAA records for %s", domain)
	}
	return ips, nil
}

func isLiteralIP(host string) bool {
	return net.ParseIP(host) != nil
}

// ResolveECH fetches the ECH config for a domain via TypeHTTPS (65)
func (r *FailoverResolver) ResolveECH(ctx context.Context, domain string) ([]byte, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)

	resp, err := r.Exchange(ctx, msg)
	if err != nil {
		return nil, err
	}

	for _, ans := range resp.Answer {
		if https, ok := ans.(*dns.HTTPS); ok {
			for _, opt := range https.Value {
				if ech, ok := opt.(*dns.SVCBECHConfig); ok {
					return ech.ECH, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no ECH config found for %s", domain)
}

// ExchangeSafe issues the DNS query ONLY using nodes that don't have ECH enabled.
func (r *FailoverResolver) ExchangeSafe(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if r.getNodes == nil {
		return nil, fmt.Errorf("getNodes callback not configured")
	}
	nodes := r.getNodes()

	var safeNodes []DNSNode
	for _, n := range nodes {
		if n.Enabled && !n.ECHEnabled {
			safeNodes = append(safeNodes, n)
		}
	}

	if len(safeNodes) == 0 {
		return nil, fmt.Errorf("no safe (non-ECH) DNS nodes available for fallback")
	}

	for _, node := range safeNodes {
		resp, err := r.exchangeNodeWithRetry(ctx, &node, msg, false)
		if err == nil {
			return resp, nil
		}
	}

	return nil, fmt.Errorf("all safe DNS resolution attempts failed")
}

// recoverNodeECH attempts to recover from an ECH rejection by applying retry configs
// provided by the server. Returns true if a usable ECH config was found and cached.
func (r *FailoverResolver) recoverNodeECH(ctx context.Context, node *DNSNode, host string, echErr *utls.ECHRejectionError) bool {
	rawCfg := echErr.RetryConfigList
	if len(rawCfg) == 0 {
		return false
	}
	r.proxy.UpdateECHProfileConfig(node.ECHProfileID, rawCfg)
	r.logf("[DOH] Applied server retry ECH config for %s (%d bytes)", host, len(rawCfg))
	return true
}

// ResolveECHSafe fetches the ECH config for a domain via standard nodes (no ECH).
func (r *FailoverResolver) ResolveECHSafe(ctx context.Context, domain string) ([]byte, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)

	resp, err := r.ExchangeSafe(ctx, msg)
	if err != nil {
		return nil, err
	}

	for _, ans := range resp.Answer {
		if https, ok := ans.(*dns.HTTPS); ok {
			for _, opt := range https.Value {
				if ech, ok := opt.(*dns.SVCBECHConfig); ok {
					return ech.ECH, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no ECH config found via safe source for %s", domain)
}
