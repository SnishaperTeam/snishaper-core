//go:build linux

package sysproxy

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Linux system proxy is configured through GSettings (org.gnome.system.proxy),
// the standard mechanism on Ubuntu/GNOME and Debian GNOME desktops.
//
// When the app runs elevated (root, via sudo), gsettings writes land in
// root's dconf and are invisible to the user session. Commands are therefore
// re-dispatched to $SUDO_USER preserving the user's session bus so the users'
// own desktop proxy settings change.

const (
	proxySchema = "org.gnome.system.proxy"
	httpSchema  = "org.gnome.system.proxy.http"
	httpsSchema = "org.gnome.system.proxy.https"

	proxyHostLinux   = "127.0.0.1"
	proxyOverrideGDN = "['localhost', '127.0.0.0/8', '::1']"
)

// SystemProxyStatus 描述当前系统代理的状态。
type SystemProxyStatus struct {
	// Enabled 表示系统代理是否已启用（GNOME 下对应 mode=manual）。
	Enabled bool
	// Server 是代理服务器地址，格式为 host:port。
	Server string
	// Override 是 GNOME 的 ignore-hosts 值，即代理绕过列表。
	Override string
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

// runGSettings executes a gsettings command, routed through the configured
// invoking user when running as root. Returns combined stdout.
func (m *Manager) runGSettings(args ...string) ([]byte, error) {
	bin, err := exec.LookPath("gsettings")
	if err != nil {
		return nil, fmt.Errorf("gsettings not found (GNOME desktop required): %w", err)
	}
	var cmd *exec.Cmd
	if os.Geteuid() == 0 {
		user := m.runAsUser
		if user != "" {
			envs := []string{"DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "DISPLAY", "WAYLAND_DISPLAY", "XDG_CURRENT_DESKTOP"}
			full := make([]string, 0, 5+len(args))
			full = append(full, "-u", user, "--preserve-env="+strings.Join(envs, ","), bin)
			full = append(full, args...)
			cmd = exec.Command("sudo", full...)
		} else {
			cmd = exec.Command(bin, args...)
		}
	} else {
		cmd = exec.Command(bin, args...)
	}
	return cmd.Output()
}

func (m *Manager) gsettingsGet(schema, key string) (string, error) {
	out, err := m.runGSettings("get", schema, key)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(out))
	v = strings.Trim(v, "'")
	return v, nil
}

func (m *Manager) gsettingsSet(schema, key, value string) error {
	_, err := m.runGSettings("set", schema, key, value)
	return err
}

// Status 返回当前系统代理状态。
//
// 查询结果缓存 2 秒，避免频繁调用 gsettings；写入设置后缓存立即失效。
func (m *Manager) Status() SystemProxyStatus {
	m.mu.Lock()
	if !m.lastCheck.IsZero() && time.Since(m.lastCheck) < 2*time.Second {
		status := m.cached
		m.mu.Unlock()
		return status
	}
	m.mu.Unlock()

	status := SystemProxyStatus{}
	if mode, err := m.gsettingsGet(proxySchema, "mode"); err == nil && strings.EqualFold(mode, "manual") {
		status.Enabled = true
		host, _ := m.gsettingsGet(httpSchema, "host")
		port, _ := m.gsettingsGet(httpSchema, "port")
		p, _ := strconv.Atoi(strings.TrimSpace(port))
		if strings.TrimSpace(host) != "" && p > 0 {
			status.Server = net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(p))
		}
		if ignore, err := m.gsettingsGet(proxySchema, "ignore-hosts"); err == nil {
			status.Override = strings.TrimRight(strings.TrimLeft(ignore, "["), "]")
		}
	}

	m.mu.Lock()
	m.cached = status
	m.lastCheck = time.Now()
	m.mu.Unlock()

	return status
}

// Set 按给定状态写入系统代理设置。
//
// 启用代理时 server 必须是非空的 host:port 地址，并写入 HTTP/HTTPS 的
// host 与 port；关闭代理时把 GNOME 代理模式设为 none。GNOME 处于 auto
// （PAC）模式时无法与手动 host/port 共存，会返回错误。
func (m *Manager) Set(enable bool, server string) error {
	if enable {
		mode, err := m.gsettingsGet(proxySchema, "mode")
		if err != nil {
			return fmt.Errorf("[sysproxy] gsettings not available: %w", err)
		}
		if strings.EqualFold(strings.TrimSpace(mode), "auto") {
			// 'auto' mode uses a PAC URL and cannot be combined with manual
			// host/port values; switch to manual explicitly.
			return fmt.Errorf("[sysproxy] GNOME proxy is in 'auto' (PAC) mode; switch to manual or none in GNOME network settings first")
		}

		host, portStr, err := net.SplitHostPort(strings.TrimSpace(server))
		if err != nil {
			return fmt.Errorf("[sysproxy] invalid server %q: %w", server, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("[sysproxy] invalid port in %q", server)
		}

		if err := m.gsettingsSet(proxySchema, "mode", "'manual'"); err != nil {
			return fmt.Errorf("[sysproxy] set mode manual: %w", err)
		}
		for _, schema := range []string{httpSchema, httpsSchema} {
			if err := m.gsettingsSet(schema, "host", "'"+host+"'"); err != nil {
				return fmt.Errorf("[sysproxy] set %s host: %w", schema, err)
			}
			if err := m.gsettingsSet(schema, "port", strconv.Itoa(port)); err != nil {
				return fmt.Errorf("[sysproxy] set %s port: %w", schema, err)
			}
		}
		if err := m.gsettingsSet(proxySchema, "ignore-hosts", proxyOverrideGDN); err != nil {
			return fmt.Errorf("[sysproxy] set ignore-hosts: %w", err)
		}
	} else {
		if err := m.gsettingsSet(proxySchema, "mode", "'none'"); err != nil {
			return fmt.Errorf("[sysproxy] set mode none: %w", err)
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
	return m.Set(true, fmt.Sprintf("%s:%d", proxyHostLinux, port))
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
// 未调用过 SaveOriginal 时为空操作。
func (m *Manager) RestoreOriginal() error {
	m.mu.Lock()
	original := m.original
	m.mu.Unlock()
	if original == nil {
		return nil
	}
	if original.Enabled {
		return m.Set(true, original.Server)
	}
	return m.Set(false, "")
}

// Manual 打开桌面环境的网络设置界面。
func (m *Manager) Manual() error {
	for _, bin := range []string{"gnome-control-center", "nm-connection-editor"} {
		if path, err := exec.LookPath(bin); err == nil {
			cmd := exec.Command(path, "network")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Start()
		}
	}
	return fmt.Errorf("no desktop network settings tool found (gnome-control-center / nm-connection-editor)")
}

// invalidateCache 使状态缓存失效，下一次 Status 会重新调用 gsettings。
func (m *Manager) invalidateCache() {
	m.mu.Lock()
	m.lastCheck = time.Time{}
	m.mu.Unlock()
}
