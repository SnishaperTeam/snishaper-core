//go:build windows || darwin || linux

// Package sysproxy 提供「系统代理开关」能力。
//
// 该包把各桌面系统的系统级代理设置统一为同一套实例化 API：
//
//   - Windows：读写注册表 Internet Settings（ProxyEnable/ProxyServer/
//     ProxyOverride），并通过 InternetSetOptionW 通知系统立即生效；
//   - macOS：通过 networksetup 修改各网络服务的 HTTP/HTTPS 代理；
//   - Linux：通过 gsettings 修改 GNOME 的 org.gnome.system.proxy 配置。
//
// 所有可变状态（原始代理快照、状态查询缓存）都保存在 Manager 实例中，
// 包内不存在包级可变状态，因此同一进程内可以安全地创建多个互不影响的
// Manager。典型用法：
//
//	m := sysproxy.New()
//	if err := m.SaveOriginal(); err != nil {
//		// 处理错误
//	}
//	if err := m.Enable(8080); err != nil {
//		// 处理错误
//	}
//	// ... 使用代理 ...
//	_ = m.RestoreOriginal()
//
// 修改系统代理通常需要管理员（Windows）或 root（Linux）权限；本包只负责
// 写入设置，不负责提权。
package sysproxy

// Option 调整 Manager 的可选行为。
type Option func(*Manager)

// WithRunAsUser 指定以 root 运行时把系统命令切换到哪个原始用户（仅 Linux 生效）。
//
// 库本身不读环境变量：调用方若通过 sudo 启动，应显式传入
// os.Getenv("SUDO_USER")；传空字符串表示直接在当前用户下执行。
func WithRunAsUser(user string) Option {
	return func(m *Manager) { m.runAsUser = user }
}

// New 创建一个新的系统代理管理器。
func New(opts ...Option) *Manager {
	m := &Manager{}
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}
	return m
}
