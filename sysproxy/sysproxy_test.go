//go:build windows || darwin || linux

package sysproxy

import "testing"

// TestNewReturnsDistinctManagers Manager 必须每个实例各自持有快照与缓存，
// 这是本包从「进程级全局状态」改为实例化的核心约定。
func TestNewReturnsDistinctManagers(t *testing.T) {
	a := New()
	b := New()
	if a == nil || b == nil {
		t.Fatal("New returned nil manager")
	}
	if a == b {
		t.Fatal("New must return distinct instances")
	}
	a.runAsUser = "alice"
	if b.runAsUser != "" {
		t.Errorf("instances share state: b.runAsUser = %q, want empty", b.runAsUser)
	}
}

// TestWithRunAsUser 注入的原始用户落在实例上；库自身不读环境变量，
// 由调用方（sudo 启动的应用）显式传入。
func TestWithRunAsUser(t *testing.T) {
	m := New(WithRunAsUser("alice"))
	if m.runAsUser != "alice" {
		t.Errorf("runAsUser = %q, want alice", m.runAsUser)
	}

	// nil Option 必须被忽略，不能 panic。
	m2 := New(nil, WithRunAsUser("bob"))
	if m2.runAsUser != "bob" {
		t.Errorf("runAsUser = %q, want bob", m2.runAsUser)
	}
}
