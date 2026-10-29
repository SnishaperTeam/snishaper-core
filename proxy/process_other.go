//go:build !windows && !linux && !darwin

package proxy

// ProcessRoutingSupported reports whether the platform can resolve the process
// behind a local TCP connection.
func ProcessRoutingSupported() bool { return false }

// findProcessName always returns "" on unsupported platforms: an unidentified
// application must fail closed for per-application rules (they never match).
func findProcessName(remoteAddr string) string { return "" }
