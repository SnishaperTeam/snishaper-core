package singtun

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// logfHandler 把 slog 记录桥接回 App 层注入的 logf func(string) 管道。
//
// slog 仅限 pkg/singtun 内部使用（设计决策 D9）：对外 NewManager(resolver, logf)
// 签名不变，所有日志最终仍经 logf 进入 App 日志管道，App 层零改动。
// 分级体现在消息前缀（[sing-tun] / [sing-tun:debug] / [sing-tun:warn] /
// [sing-tun:error]），logf 管道本身不过滤，保持切换前"全部输出"的行为。
type logfHandler struct {
	logf func(string)
}

// newBridgedLogger 构建输出到 logf 的 *slog.Logger。logf 为 nil 时所有日志静默丢弃。
func newBridgedLogger(logf func(string)) *slog.Logger {
	return slog.New(&logfHandler{logf: logf})
}

// Enabled 在 logf 管道存在时返回 true。
func (h *logfHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return h.logf != nil
}

// Handle 把 slog 记录格式化后写入 logf 管道。
func (h *logfHandler) Handle(_ context.Context, r slog.Record) error {
	if h.logf == nil {
		return nil
	}
	var b strings.Builder
	switch {
	case r.Level >= slog.LevelError:
		b.WriteString("[sing-tun:error] ")
	case r.Level >= slog.LevelWarn:
		b.WriteString("[sing-tun:warn] ")
	case r.Level >= slog.LevelInfo:
		b.WriteString("[sing-tun] ")
	default:
		b.WriteString("[sing-tun:debug] ")
	}
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteByte(' ')
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(a.Value.String())
		return true
	})
	h.logf(b.String())
	return nil
}

// WithAttrs 忽略属性并返回自身。
func (h *logfHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
// WithGroup 忽略分组并返回自身。
func (h *logfHandler) WithGroup(string) slog.Handler      { return h }

// singTunLogger 适配 sing-tun 的日志接口，输出经 slog 分级后桥接回 logf。
type singTunLogger struct {
	logger *slog.Logger
}

// Trace 输出 trace 日志（映射到 debug 级别）。
func (l *singTunLogger) Trace(args ...any) { l.output(slog.LevelDebug, "trace", args...) }
// Debug 输出 debug 级别日志。
func (l *singTunLogger) Debug(args ...any) { l.output(slog.LevelDebug, "debug", args...) }
// Info 输出 info 级别日志。
func (l *singTunLogger) Info(args ...any)  { l.output(slog.LevelInfo, "info", args...) }
// Warn 输出 warn 级别日志。
func (l *singTunLogger) Warn(args ...any)  { l.output(slog.LevelWarn, "warn", args...) }
// Error 输出 error 级别日志。
func (l *singTunLogger) Error(args ...any) { l.output(slog.LevelError, "error", args...) }
// Fatal 输出 fatal 日志（映射到 error 级别）。
func (l *singTunLogger) Fatal(args ...any) { l.output(slog.LevelError, "fatal", args...) }
// Panic 输出 panic 日志（映射到 error 级别）。
func (l *singTunLogger) Panic(args ...any) { l.output(slog.LevelError, "panic", args...) }

func (l *singTunLogger) output(level slog.Level, tag string, args ...any) {
	if l.logger == nil {
		return
	}
	msg := tag
	if len(args) > 0 {
		msg = tag + ": " + fmt.Sprint(args...)
	}
	l.logger.Log(context.Background(), level, msg)
}
