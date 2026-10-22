//go:build windows

package sysproxy

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

const (
	proxySettingsKey              = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	internetOptionRefresh         = 37
	internetOptionSettingsChanged = 39
)

// wininetDLL 与 internetSetOptionProc 是只读的惰性 DLL 绑定句柄，
// 不是包级可变状态，因此保留为包级变量（与 core 其余 windows 文件一致）。
var (
	wininetDLL            = syscall.NewLazyDLL("wininet.dll")
	internetSetOptionProc = wininetDLL.NewProc("InternetSetOptionW")
)

// SystemProxyStatus 描述当前系统代理的状态。
type SystemProxyStatus struct {
	// Enabled 表示系统代理是否已启用。
	Enabled bool
	// Server 是代理服务器地址，格式为 host:port。
	Server string
	// Override 是代理绕过列表；本包启用代理时固定写入 "<local>"。
	Override string
	// AutoConfigURL 是 WinInet 的 PAC 地址（AutoConfigURL 注册表值）。
	// PAC 存在时 WinInet 优先走 PAC 而忽略 ProxyServer，因此启用代理前
	// 必须先清掉它，恢复时原样写回。
	AutoConfigURL string
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

func notifyProxyChange() error {
	if err := callInternetSetOption(internetOptionSettingsChanged); err != nil {
		return err
	}
	return callInternetSetOption(internetOptionRefresh)
}

func callInternetSetOption(option uintptr) error {
	ret, _, callErr := internetSetOptionProc.Call(0, option, 0, 0)
	if ret != 0 {
		return nil
	}
	if callErr != syscall.Errno(0) {
		return callErr
	}
	return fmt.Errorf("InternetSetOptionW failed for option %d", option)
}

// Status 返回当前系统代理状态。
//
// 查询结果缓存 2 秒，避免频繁读取注册表；写入设置后缓存立即失效。
func (m *Manager) Status() SystemProxyStatus {
	m.mu.Lock()
	if !m.lastCheck.IsZero() && time.Since(m.lastCheck) < 2*time.Second {
		status := m.cached
		m.mu.Unlock()
		return status
	}
	m.mu.Unlock()

	status := SystemProxyStatus{}
	k, err := registry.OpenKey(registry.CURRENT_USER, proxySettingsKey, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()

		enableVal, _, err := k.GetIntegerValue("ProxyEnable")
		if err == nil && enableVal == 1 {
			status.Enabled = true
		}

		server, _, err := k.GetStringValue("ProxyServer")
		if err == nil {
			status.Server = strings.TrimSpace(server)
		}

		override, _, err := k.GetStringValue("ProxyOverride")
		if err == nil {
			status.Override = strings.TrimSpace(override)
		}

		pac, _, err := k.GetStringValue("AutoConfigURL")
		if err == nil {
			status.AutoConfigURL = strings.TrimSpace(pac)
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
// 启用代理时 server 必须是非空的 host:port 地址；启用时固定把
// ProxyOverride 写为 "<local>"，与旧实现保持一致。
func (m *Manager) Set(enable bool, server string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, proxySettingsKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("[sysproxy] failed to open registry key: %w", err)
	}
	defer k.Close()

	enableVal := uint64(0)
	if enable {
		enableVal = 1
	}
	if err := k.SetDWordValue("ProxyEnable", uint32(enableVal)); err != nil {
		return fmt.Errorf("[sysproxy] failed to set ProxyEnable: %w", err)
	}

	if enable {
		if server == "" {
			return fmt.Errorf("[sysproxy] server cannot be empty when enabling proxy")
		}
		if err := k.SetStringValue("ProxyServer", server); err != nil {
			return fmt.Errorf("[sysproxy] failed to set ProxyServer: %w", err)
		}
		override := "<local>"
		if err := k.SetStringValue("ProxyOverride", override); err != nil {
			return fmt.Errorf("[sysproxy] failed to set ProxyOverride: %w", err)
		}
		// WinInet 优先使用 PAC：不清掉 AutoConfigURL 时流量会继续按 PAC
		// 分流，完全绕过刚写好的 ProxyServer。
		if err := k.DeleteValue("AutoConfigURL"); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("[sysproxy] failed to clear AutoConfigURL: %w", err)
		}
	}

	m.invalidateCache()

	return notifyProxyChange()
}

// Enable 在本机回环地址的给定端口上启用系统代理。
//
// 端口必须位于 1..65535，代理地址为 "127.0.0.1:<port>"。
func (m *Manager) Enable(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("[sysproxy] invalid port: %d", port)
	}
	server := fmt.Sprintf("127.0.0.1:%d", port)
	return m.Set(true, server)
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

	k, err := registry.OpenKey(registry.CURRENT_USER, proxySettingsKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("[sysproxy] failed to open registry key for restore: %w", err)
	}
	defer k.Close()

	enableVal := uint64(0)
	if original.Enabled {
		enableVal = 1
	}
	_ = k.SetDWordValue("ProxyEnable", uint32(enableVal))

	if original.Enabled && original.Server != "" {
		_ = k.SetStringValue("ProxyServer", original.Server)
		if original.Override != "" {
			_ = k.SetStringValue("ProxyOverride", original.Override)
		}
	}
	if original.AutoConfigURL != "" {
		_ = k.SetStringValue("AutoConfigURL", original.AutoConfigURL)
	}

	m.invalidateCache()

	return notifyProxyChange()
}

// Manual 打开 Windows 系统代理设置界面。
func (m *Manager) Manual() error {
	return startHiddenCommand("cmd", "/c", "start", "ms-settings:network-proxy")
}

// invalidateCache 使状态缓存失效，下一次 Status 会重新读取注册表。
func (m *Manager) invalidateCache() {
	m.mu.Lock()
	m.lastCheck = time.Time{}
	m.mu.Unlock()
}
