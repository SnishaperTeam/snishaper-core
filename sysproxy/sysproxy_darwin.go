//go:build darwin

package sysproxy

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const proxyHostDarwin = "127.0.0.1"

// SystemProxyStatus 描述当前系统代理的状态。
type SystemProxyStatus struct {
	// Enabled 表示系统代理是否已启用。
	Enabled bool
	// Server 是代理服务器地址，格式为 host:port。
	Server string
	// Override 是代理绕过列表；macOS 下 networksetup 不提供该信息，保持为空。
	Override string
	// kind 记录 Status 检测到的代理类型（webproxy / socksfirewallproxy）。
	// RestoreOriginal 依赖它恢复同类代理，避免把用户的 SOCKS 系统代理
	// 恢复成 HTTP 代理（浏览器会向 SOCKS 端口发 CONNECT 而全部失败）。
	kind string
}

// Manager 是系统代理管理器。
//
// 每个实例各自持有原始代理快照与状态查询缓存，不依赖包级全局状态，
// 因此同一进程内可以安全地创建多个互不影响的 Manager。
type Manager struct {
	mu        sync.Mutex
	original  *SystemProxyStatus
	cached    SystemProxyStatus
	lastCheck time.Time
	// runAsUser 是 sudo 场景下要切换到的原始用户（仅 Linux 使用）。
	runAsUser string
}

func darwinServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("[sysproxy] networksetup not available: %w", err)
	}
	var services []string
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if name == "" || strings.HasPrefix(name, "*") || strings.Contains(name, "An asterisk") {
			continue
		}
		services = append(services, name)
	}
	return services, nil
}

func darwinGetProxy(kind string) (enabled bool, host string, port int) {
	services, err := darwinServices()
	if err != nil {
		return false, "", 0
	}
	for _, svc := range services {
		out, err := exec.Command("networksetup", "-get"+kind, svc).CombinedOutput()
		if err != nil {
			continue
		}
		lines := strings.Split(string(out), "\n")
		var h, p string
		var en bool
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Enabled:") {
				en = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "Enabled:")), "yes")
			} else if strings.HasPrefix(line, "Server:") {
				h = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
			} else if strings.HasPrefix(line, "Port:") {
				p = strings.TrimSpace(strings.TrimPrefix(line, "Port:"))
			}
		}
		if en && h != "" {
			port, _ := strconv.Atoi(p)
			return true, h, port
		}
	}
	return false, "", 0
}

// Status 返回当前系统代理状态。
//
// 查询结果缓存 2 秒，避免频繁调用 networksetup；写入设置后缓存立即失效。
func (m *Manager) Status() SystemProxyStatus {
	m.mu.Lock()
	if !m.lastCheck.IsZero() && time.Since(m.lastCheck) < 2*time.Second {
		status := m.cached
		m.mu.Unlock()
		return status
	}
	m.mu.Unlock()

	status := SystemProxyStatus{}
	if en, host, port := darwinGetProxy("webproxy"); en {
		status.Enabled = true
		status.kind = "webproxy"
		status.Server = net.JoinHostPort(host, strconv.Itoa(port))
	}
	if !status.Enabled {
		if en, host, port := darwinGetProxy("socksfirewallproxy"); en {
			status.Enabled = true
			status.kind = "socksfirewallproxy"
			status.Server = net.JoinHostPort(host, strconv.Itoa(port))
		}
	}

	m.mu.Lock()
	m.cached = status
	m.lastCheck = time.Now()
	m.mu.Unlock()

	return status
}

func darwinSetProxy(kind string, enable bool, host string, port int) error {
	services, err := darwinServices()
	if err != nil {
		return err
	}
	for _, svc := range services {
		if enable {
			if err := exec.Command("networksetup", "-set"+kind, svc, host, strconv.Itoa(port)).Run(); err != nil {
				return fmt.Errorf("[sysproxy] set %s on %q: %w", kind, svc, err)
			}
		} else {
			if err := exec.Command("networksetup", "-set"+kind+"state", svc, "off").Run(); err != nil {
				return fmt.Errorf("[sysproxy] disable %s on %q: %w", kind, svc, err)
			}
		}
	}
	return nil
}

// Set 按给定状态写入系统代理设置。
//
// 启用代理时 server 必须是非空的 host:port 地址；启用会同时设置
// webproxy 与 securewebproxy 并关闭 socksfirewallproxy（两者并存时
// 系统行为未定义），关闭则把三者都置为 off。
func (m *Manager) Set(enable bool, server string) error {
	if enable {
		host, portStr, err := net.SplitHostPort(strings.TrimSpace(server))
		if err != nil {
			return fmt.Errorf("[sysproxy] invalid server %q: %w", server, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("[sysproxy] invalid port in %q", server)
		}
		if err := darwinSetProxy("webproxy", true, host, port); err != nil {
			return err
		}
		if err := darwinSetProxy("securewebproxy", true, host, port); err != nil {
			return err
		}
		if err := darwinSetProxy("socksfirewallproxy", false, "", 0); err != nil {
			return err
		}
	} else {
		if err := darwinSetProxy("webproxy", false, "", 0); err != nil {
			return err
		}
		if err := darwinSetProxy("securewebproxy", false, "", 0); err != nil {
			return err
		}
		if err := darwinSetProxy("socksfirewallproxy", false, "", 0); err != nil {
			return err
		}
	}

	m.invalidateCache()

	return nil
}

// Enable 在本机回环地址的给定端口上启用系统代理。
//
// 端口必须位于 1..65535，代理地址为 "127.0.0.1:<port>"。
func (m *Manager) Enable(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("[sysproxy] invalid port: %d", port)
	}
	return m.Set(true, fmt.Sprintf("%s:%d", proxyHostDarwin, port))
}

// Disable 关闭系统代理。
func (m *Manager) Disable() error {
	return m.Set(false, "")
}

// SaveOriginal 记录当前系统代理状态，供 RestoreOriginal 恢复。
func (m *Manager) SaveOriginal() error {
	status := m.Status()
	m.mu.Lock()
	m.original = &status
	m.mu.Unlock()
	return nil
}

// RestoreOriginal 把系统代理恢复为 SaveOriginal 记录的状态。
//
// 未调用过 SaveOriginal 时为空操作。原状态是 SOCKS 代理时按 SOCKS 恢复，
// 而不是走 Set 的 webproxy 路径。
func (m *Manager) RestoreOriginal() error {
	m.mu.Lock()
	original := m.original
	m.mu.Unlock()
	if original == nil {
		return nil
	}
	if original.Enabled {
		if original.kind == "socksfirewallproxy" {
			host, portStr, err := net.SplitHostPort(original.Server)
			if err != nil {
				return fmt.Errorf("[sysproxy] invalid original server %q: %w", original.Server, err)
			}
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("[sysproxy] invalid original port in %q", original.Server)
			}
			if err := darwinSetProxy("socksfirewallproxy", true, host, port); err != nil {
				return err
			}
			m.invalidateCache()
			return nil
		}
		return m.Set(true, original.Server)
	}
	return m.Set(false, "")
}

// Manual 打开 macOS 网络设置界面。
func (m *Manager) Manual() error {
	return exec.Command("open", "x-apple.systempreferences:com.apple.systempreferences.Network").Run()
}

// invalidateCache 使状态缓存失效，下一次 Status 会重新调用 networksetup。
func (m *Manager) invalidateCache() {
	m.mu.Lock()
	m.lastCheck = time.Time{}
	m.mu.Unlock()
}
