//go:build darwin

package proxy

import (
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ProcessRoutingSupported reports whether the platform can resolve the process
// behind a local TCP connection.
//
// shortcut: lsof costs ~100ms per lookup, cache 10s per client endpoint to keep
// per-app rules affordable on busy connections; client ports are stable for the
// lifetime of a tunnel so a short TTL cannot mislabel long-lived sessions.
func ProcessRoutingSupported() bool { return true }

type procCacheEntry struct {
	name    string
	expires time.Time
}

var (
	procCacheMu sync.Mutex
	procCache   = map[string]procCacheEntry{}
)

const procCacheTTL = 10 * time.Second

// findProcessName returns the executable base name (lower-cased) of the
// process that owns the established TCP connection whose remote endpoint is
// remoteAddr, or "" when it cannot be identified.
//
// macOS has no public "who owns this TCP connection" API, so this shells out
// to lsof filtered to the exact endpoint. Failures (missing lsof, sandboxed
// exec) return "" and per-application rules fail closed.
func findProcessName(remoteAddr string) string {
	remote, err := net.ResolveTCPAddr("tcp", remoteAddr)
	if err != nil || remote.Port == 0 {
		return ""
	}

	procCacheMu.Lock()
	if e, ok := procCache[remoteAddr]; ok && time.Now().Before(e.expires) {
		procCacheMu.Unlock()
		return e.name
	}
	procCacheMu.Unlock()

	name := lsofProcessName(remote)
	procCacheMu.Lock()
	procCache[remoteAddr] = procCacheEntry{name: name, expires: time.Now().Add(procCacheTTL)}
	// 有界缓存：清理过期项，避免长时间运行后无限增长。
	if len(procCache) > 4096 {
		for k, v := range procCache {
			if time.Now().After(v.expires) {
				delete(procCache, k)
			}
		}
	}
	procCacheMu.Unlock()
	return name
}

func lsofProcessName(remote *net.TCPAddr) string {
	host := remote.IP.String()
	if remote.IP.To4() == nil {
		host = "[" + host + "]"
	}
	cmd := exec.Command("lsof", "-nP", "-iTCP@"+host+":"+itoa(remote.Port), "-sTCP:ESTABLISHED", "-Fpn")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	pid := ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid = line[1:]
		case 'n':
			// First NAME line follows its PID line; take that pairing.
			if pid != "" {
				return processNameByPID(pid)
			}
		}
	}
	return ""
}

func processNameByPID(pid string) string {
	out, err := exec.Command("ps", "-p", pid, "-o", "comm=").Output()
	if err != nil {
		return ""
	}
	name := strings.TrimSpace(string(out))
	if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
		name = name[idx+1:]
	}
	return strings.ToLower(name)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
