// Package log defines the minimal logging contract used across snishaper-core.
//
// The library never writes to the standard logger on its own: every package
// receives a Logger via functional options or a setter and falls back to Nop
// when none is injected.
package log

import stdlog "log"

// Logger is the logging interface accepted by all snishaper-core packages.
// Implementations must be safe for concurrent use.
type Logger interface {
	Printf(format string, args ...any)
}

// Nop silently discards all output. It is the default when no logger is
// injected, so an unconfigured library never writes anywhere on its own.
var Nop Logger = nopLogger{}

type nopLogger struct{}

func (nopLogger) Printf(string, ...any) {}

// Std adapts the standard library logger to Logger. It is provided for
// embedders that want snishaper-core output on the process log.
var Std Logger = stdLogger{}

type stdLogger struct{}

func (stdLogger) Printf(format string, args ...any) { stdlog.Printf(format, args...) }

// Func adapts a printf-style function to Logger.
func Func(fn func(format string, args ...any)) Logger { return funcLogger{fn: fn} }

type funcLogger struct {
	fn func(format string, args ...any)
}

// Printf delegates to the wrapped log function.
func (f funcLogger) Printf(format string, args ...any) { f.fn(format, args...) }
