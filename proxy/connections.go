package proxy

import (
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ConnInfo is one entry of the active-connection snapshot returned by
// ProxyServer.ActiveConnections. Fields the proxy cannot know are left empty:
// the UI must present an empty field as "unavailable", never as confirmed data.
type ConnInfo struct {
	ID          uint64    `json:"id"`
	Protocol    string    `json:"protocol"`             // "https" (CONNECT tunnel), "socks5"
	Host        string    `json:"host,omitempty"`       // requested host (domain or literal IP)
	DstAddr     string    `json:"dst_addr,omitempty"`   // dialed destination ip:port, when known
	Rule        string    `json:"rule,omitempty"`       // site-group ID of the matched rule
	RuleDomain  string    `json:"rule_domain,omitempty"` // domain pattern that matched
	Mode        string    `json:"mode"`                 // effective proxy mode
	Source      string    `json:"source,omitempty"`     // "manual", "auto" or "default"
	State       string    `json:"state"`                // "active" while the tunnel is open
	StartedAt   time.Time `json:"started_at"`
	BytesUp     int64     `json:"bytes_up"`             // client → remote
	BytesDown   int64     `json:"bytes_down"`           // remote → client
}

// maxTrackedConns bounds the registry so connection inspection can never grow
// memory without limit. Eviction drops the oldest entry first.
const maxTrackedConns = 4096

type connRegistry struct {
	mu      sync.RWMutex
	nextID  uint64
	entries map[uint64]*trackedEntry
	order   []uint64 // registration order, oldest first, for bounded eviction
}

type trackedEntry struct {
	info ConnInfo // immutable after registration; counters live below
	up   atomic.Int64
	down atomic.Int64
}

func newConnRegistry() *connRegistry {
	return &connRegistry{entries: make(map[uint64]*trackedEntry)}
}

func (r *connRegistry) register(info ConnInfo) (uint64, *trackedEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextID++
	id := r.nextID
	if r.entries == nil {
		r.entries = make(map[uint64]*trackedEntry)
	}
	if len(r.entries) >= maxTrackedConns && len(r.order) > 0 {
		oldest := r.order[0]
		r.order = r.order[1:]
		delete(r.entries, oldest)
	}
	entry := &trackedEntry{info: info}
	r.entries[id] = entry
	r.order = append(r.order, id)
	return id, entry
}

func (r *connRegistry) remove(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, id)
	for i, v := range r.order {
		if v == id {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
}

func (r *connRegistry) snapshot() []ConnInfo {
	r.mu.RLock()
	entries := make([]*trackedEntry, 0, len(r.entries))
	for _, e := range r.entries {
		entries = append(entries, e)
	}
	r.mu.RUnlock()

	out := make([]ConnInfo, 0, len(entries))
	for _, e := range entries {
		info := e.info
		info.BytesUp = e.up.Load()
		info.BytesDown = e.down.Load()
		out = append(out, info)
	}
	// Newest first: the viewer refreshes on an interval and the most recent
	// connections are the ones the user is looking for.
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return out
}

// trackingConn wraps the client side of a tunnel so byte counters and the
// entry lifetime follow the connection without any extra bookkeeping at the
// call sites beyond the initial wrap.
type trackingConn struct {
	net.Conn
	reg   *connRegistry
	id    uint64
	entry *trackedEntry
	once  sync.Once
}

func (c *trackingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.entry.up.Add(int64(n))
	return n, err
}

func (c *trackingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.entry.down.Add(int64(n))
	return n, err
}

func (c *trackingConn) Close() error {
	c.once.Do(func() { c.reg.remove(c.id) })
	return c.Conn.Close()
}

// ruleSource classifies where a matched rule came from, mirroring the
// precedence in matchRule: an AutoRouted rule came from the auto-routing
// layer, a rule without a domain pattern is the built-in direct default,
// everything else is a manual rule.
func ruleSource(rule Rule) string {
	switch {
	case rule.AutoRouted:
		return "auto"
	case rule.Domain == "":
		return "default"
	default:
		return "manual"
	}
}

// clientProcess resolves the base name of the process behind a client
// connection, but only when a per-application rule needs it: the TCP-table
// scan costs real work per request, so without process rules it stays free.
// Returns "" when unsupported, unknown or unnecessary — per-application rules
// fail closed on "".
func (p *ProxyServer) clientProcess(remoteAddr string) string {
	if p.rules == nil || !p.rules.HasProcessRules() {
		return ""
	}
	return findProcessName(remoteAddr)
}

// ActiveConnections returns a snapshot of the connections currently tracked by
// the server, newest first. It is safe to call from any goroutine.
func (p *ProxyServer) ActiveConnections() []ConnInfo {
	if p.conns == nil {
		return nil
	}
	return p.conns.snapshot()
}

// trackConn registers a client tunnel connection for the connection viewer and
// returns a counting wrapper. The entry disappears when the wrapper is closed.
// protocol is "https" for CONNECT tunnels, "socks5" for SOCKS5 tunnels.
func (p *ProxyServer) trackConn(clientConn net.Conn, protocol, host, dstAddr string, rule Rule, effectiveMode string) net.Conn {
	if p.conns == nil || clientConn == nil {
		return clientConn
	}
	info := ConnInfo{
		Protocol:   protocol,
		Host:       host,
		DstAddr:    dstAddr,
		Rule:       rule.SiteID,
		RuleDomain: rule.Domain,
		Mode:       effectiveMode,
		Source:     ruleSource(rule),
		State:      "active",
		StartedAt:  time.Now(),
	}
	id, entry := p.conns.register(info)
	return &trackingConn{Conn: clientConn, reg: p.conns, id: id, entry: entry}
}
