package proxy

import (
	"net"
	"testing"
	"time"
)

func TestConnRegistryRegisterSnapshotRemove(t *testing.T) {
	r := newConnRegistry()
	id, entry := r.register(ConnInfo{Protocol: "https", Host: "a.com", Mode: "direct", State: "active", StartedAt: time.Now()})
	entry.up.Add(100)
	entry.down.Add(50)

	snap := r.snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(snap))
	}
	if snap[0].Host != "a.com" || snap[0].BytesUp != 100 || snap[0].BytesDown != 50 {
		t.Fatalf("unexpected snapshot entry: %+v", snap[0])
	}

	r.remove(id)
	if got := len(r.snapshot()); got != 0 {
		t.Fatalf("expected empty snapshot after remove, got %d", got)
	}
}

func TestConnRegistryNewestFirst(t *testing.T) {
	r := newConnRegistry()
	base := time.Now()
	for i, host := range []string{"old.com", "new.com"} {
		id, _ := r.register(ConnInfo{Host: host, StartedAt: base.Add(time.Duration(i) * time.Second)})
		_ = id
	}
	snap := r.snapshot()
	if len(snap) != 2 || snap[0].Host != "new.com" {
		t.Fatalf("expected newest first, got %+v", snap)
	}
}

func TestConnRegistryBounded(t *testing.T) {
	r := newConnRegistry()
	for i := 0; i < maxTrackedConns+10; i++ {
		r.register(ConnInfo{Host: "h", StartedAt: time.Now()})
	}
	if got := len(r.snapshot()); got != maxTrackedConns {
		t.Fatalf("registry must stay bounded at %d entries, got %d", maxTrackedConns, got)
	}
}

type fakeConn struct{ net.Conn }

func (fakeConn) Read(b []byte) (int, error) { return len(b), nil }
func (fakeConn) Write(b []byte) (int, error) { return len(b), nil }
func (fakeConn) Close() error             { return nil }

func TestTrackConnCounters(t *testing.T) {
	p := NewProxyServer("127.0.0.1:0")
	wrapped := p.trackConn(fakeConn{}, "https", "a.com", "1.2.3.4:443", Rule{SiteID: "g1", Domain: "a.com", Mode: "mitm"}, "mitm")
	if _, err := wrapped.Write([]byte("hello-down")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 3)
	if _, err := wrapped.Read(buf); err != nil {
		t.Fatal(err)
	}

	snap := p.ActiveConnections()
	if len(snap) != 1 {
		t.Fatalf("expected 1 tracked conn, got %d", len(snap))
	}
	c := snap[0]
	if c.Protocol != "https" || c.Host != "a.com" || c.DstAddr != "1.2.3.4:443" || c.Rule != "g1" || c.Mode != "mitm" || c.Source != "manual" {
		t.Fatalf("unexpected ConnInfo: %+v", c)
	}
	if c.BytesUp != 3 || c.BytesDown != 10 {
		t.Fatalf("expected up=3 down=10, got up=%d down=%d", c.BytesUp, c.BytesDown)
	}

	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	if got := len(p.ActiveConnections()); got != 0 {
		t.Fatalf("entry must be removed on close, got %d", got)
	}
}

func TestRuleSource(t *testing.T) {
	cases := []struct {
		rule   Rule
		source string
	}{
		{Rule{AutoRouted: true}, "auto"},
		{Rule{}, "default"},
		{Rule{Domain: "a.com"}, "manual"},
	}
	for _, c := range cases {
		if got := ruleSource(c.rule); got != c.source {
			t.Fatalf("ruleSource(%+v) = %q, want %q", c.rule, got, c.source)
		}
	}
}
