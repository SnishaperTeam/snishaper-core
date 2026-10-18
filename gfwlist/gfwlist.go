// Package gfwlist loads and serves a domain blocklist in GFWList format
// (one domain per line, '#'/'!' comments skipped) with suffix matching.
package gfwlist

import (
	"bufio"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/SnishaperTeam/snishaper-core/log"
)

// GFWList holds a loaded domain blocklist. The zero value is not usable;
// construct with NewGFWList.
type GFWList struct {
	mu       sync.RWMutex
	domains  map[string]bool
	count    int
	lastLoad time.Time
	logger   log.Logger
}

// Option is a functional option for NewGFWList.
type Option func(*GFWList)

// WithLogger injects the logger used when a list is loaded (log.Nop default).
func WithLogger(l log.Logger) Option {
	return func(g *GFWList) { g.logger = l }
}

// NewGFWList creates an empty GFWList.
func NewGFWList(opts ...Option) *GFWList {
	g := &GFWList{
		domains: make(map[string]bool),
		logger:  log.Nop,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(g)
		}
	}
	return g
}

// LoadFromReader replaces the blocklist content with the domains parsed from
// r and returns the number of loaded domains.
func (g *GFWList) LoadFromReader(r io.Reader) (int, error) {
	scanner := bufio.NewScanner(r)
	domains := make(map[string]bool, 5000)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") ||
			strings.HasPrefix(line, "Source:") || strings.HasPrefix(line, "---") {
			continue
		}
		domains[strings.ToLower(line)] = true
		count++
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}

	g.mu.Lock()
	g.domains = domains
	g.count = count
	g.lastLoad = time.Now()
	g.mu.Unlock()

	if g.logger != nil {
		g.logger.Printf("[GFWList] Loaded %d domains", count)
	}
	return count, nil
}

// LoadFromFile replaces the blocklist content with the domains parsed from
// the file at path.
func (g *GFWList) LoadFromFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return g.LoadFromReader(f)
}

// IsBlocked checks if the host (or any parent domain) is in the GFW list.
func (g *GFWList) IsBlocked(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.domains) == 0 {
		return false
	}

	// Exact match
	if g.domains[host] {
		return true
	}

	// Suffix match: walk up the domain hierarchy
	parts := strings.Split(host, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if g.domains[parent] {
			return true
		}
	}
	return false
}

// Count returns the number of domains in the loaded list.
func (g *GFWList) Count() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.count
}

// LastLoadTime returns the time of the last successful load (zero if never).
func (g *GFWList) LastLoadTime() time.Time {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.lastLoad
}
