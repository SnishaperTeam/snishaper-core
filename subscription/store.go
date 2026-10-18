package subscription

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultSubscriptionID is the built-in entry that keeps the shipped rules and
// offers no node selection.
const DefaultSubscriptionID = "builtin-default"

// MaxPayloadBytes caps a subscription download so a hostile or misconfigured
// endpoint cannot exhaust memory.
const MaxPayloadBytes = 8 << 20

// Entry is a stored subscription.
type Entry struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	URL        string            `json:"url"`
	Builtin    bool              `json:"builtin"`
	UpdatedAt  int64             `json:"updated_at"`
	UserInfo   UserInfo          `json:"user_info"`
	NodeCount  int               `json:"node_count"`
	RuleCount  int               `json:"rule_count"`
	Groups     []Group           `json:"groups"`
	Nodes      []Node            `json:"nodes"`
	SiteGroups []SiteGroup       `json:"site_groups"`
	Selection  map[string]string `json:"selection"`
	Error      string            `json:"error,omitempty"`
}

// Store persists subscriptions and tracks the active one.
type Store struct {
	mu         sync.RWMutex
	path       string
	entries    []*Entry
	activeID   string
	logf       func(string)
	fetchProxy string
}

type storeFile struct {
	ActiveID string   `json:"active_id"`
	Entries  []*Entry `json:"entries"`
}

// NewStore loads the subscription store from disk. A missing file yields a
// store containing only the built-in default entry.
func NewStore(path string, logf func(string)) *Store {
	s := &Store{path: path, logf: logf, activeID: DefaultSubscriptionID}
	s.entries = []*Entry{builtinDefaultEntry()}
	if err := s.load(); err != nil && logf != nil {
		logf(fmt.Sprintf("[Subscription] load failed: %v", err))
	}
	if s.find(DefaultSubscriptionID) == nil {
		s.entries = append([]*Entry{builtinDefaultEntry()}, s.entries...)
	}
	if s.find(s.activeID) == nil {
		s.activeID = DefaultSubscriptionID
	}
	return s
}

func builtinDefaultEntry() *Entry {
	return &Entry{
		ID:         DefaultSubscriptionID,
		Name:       "Default Rules",
		Builtin:    true,
		UpdatedAt:  0,
		Groups:     []Group{},
		Nodes:      []Node{},
		SiteGroups: []SiteGroup{},
		Selection:  map[string]string{},
	}
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var sf storeFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return err
	}

	seen := make(map[string]bool)
	for _, e := range sf.Entries {
		if e == nil || e.ID == "" || seen[e.ID] {
			continue
		}
		if e.ID == DefaultSubscriptionID {
			continue
		}
		seen[e.ID] = true
		if e.Selection == nil {
			e.Selection = map[string]string{}
		}
		s.entries = append(s.entries, e)
	}
	if sf.ActiveID != "" {
		s.activeID = sf.ActiveID
	}
	return nil
}

// Reload re-reads the store file, picking up changes written by another
// process (the GUI). A successful read replaces the entry list and the
// active id; on any read or parse failure the in-memory state survives.
func (s *Store) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var sf storeFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return err
	}

	entries := []*Entry{builtinDefaultEntry()}
	seen := make(map[string]bool)
	for _, e := range sf.Entries {
		if e == nil || e.ID == "" || seen[e.ID] || e.ID == DefaultSubscriptionID {
			continue
		}
		seen[e.ID] = true
		if e.Selection == nil {
			e.Selection = map[string]string{}
		}
		entries = append(entries, e)
	}
	s.entries = entries
	if sf.ActiveID != "" && (sf.ActiveID == DefaultSubscriptionID || seen[sf.ActiveID]) {
		s.activeID = sf.ActiveID
	}
	return nil
}

func (s *Store) saveLocked() error {
	sf := storeFile{ActiveID: s.activeID}
	for _, e := range s.entries {
		if e.Builtin {
			continue
		}
		sf.Entries = append(sf.Entries, e)
	}

	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o644)
}

func (s *Store) find(id string) *Entry {
	for _, e := range s.entries {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// List returns all subscriptions with the built-in entry first.
func (s *Store) List() []*Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Entry, 0, len(s.entries))
	out = append(out, s.entries...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Builtin != out[j].Builtin {
			return out[i].Builtin
		}
		return i < j
	})
	return out
}

// ActiveID returns the currently selected subscription.
func (s *Store) ActiveID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeID
}

// Get returns a subscription by id.
func (s *Store) Get(id string) *Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.find(id)
}

// SetActive selects the active subscription. Selecting the built-in entry
// restores the shipped rules; any other entry loads that subscription's rules.
func (s *Store) SetActive(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.find(id)
	if entry == nil {
		return fmt.Errorf("subscription %q not found", id)
	}
	// A rules-only subscription (no nodes, but site groups) is activatable;
	// an entry with neither nodes nor rules can carry nothing and is rejected.
	if !entry.Builtin && len(entry.Nodes) == 0 && len(entry.SiteGroups) == 0 {
		if entry.Error != "" {
			return fmt.Errorf("subscription %q has no usable nodes: %s", entry.Name, entry.Error)
		}
		return fmt.Errorf("subscription %q has no usable nodes", entry.Name)
	}

	s.activeID = id
	return s.saveLocked()
}

// SetFetchProxy routes subscription downloads through the given HTTP proxy
// first (the running local proxy), falling back to direct. Empty means direct
// only. Subscription provider domains are often unreachable directly; Clash
// clients update through their own running proxy, hence the same approach.
func (s *Store) SetFetchProxy(proxyURL string) {
	s.mu.Lock()
	s.fetchProxy = proxyURL
	s.mu.Unlock()
}

func (s *Store) fetchProxyValue() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fetchProxy
}

// Add registers a new subscription by downloading and parsing it.
func (s *Store) Add(name, url string) (*Entry, error) {
	name = strings.TrimSpace(name)
	url = strings.TrimSpace(url)
	if url == "" {
		return nil, errors.New("subscription url is required")
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, errors.New("subscription url must start with http:// or https://")
	}

	payload, userInfo, err := s.fetch(url)
	if err != nil {
		return nil, err
	}

	cfg, err := ParseClash(payload)
	if err != nil {
		return nil, err
	}
	if len(cfg.Nodes) == 0 {
		return nil, errors.New("subscription contains no supported proxy nodes")
	}

	entry := &Entry{
		ID:         newID(name, url),
		Name:       name,
		URL:        url,
		UpdatedAt:  time.Now().Unix(),
		UserInfo:   userInfo,
		NodeCount:  len(cfg.Nodes),
		RuleCount:  len(cfg.Groups),
		Groups:     cfg.Groups,
		Nodes:      cfg.Nodes,
		SiteGroups: ConvertRules(cfg),
		Selection:  map[string]string{},
	}
	if entry.Name == "" {
		entry.Name = deriveNameFromURL(url)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.find(entry.ID); existing != nil {
		*existing = *entry
		return existing, s.saveLocked()
	}
	s.entries = append(s.entries, entry)
	return entry, s.saveLocked()
}

// Update re-downloads an existing subscription.
func (s *Store) Update(id string) (*Entry, error) {
	s.mu.RLock()
	entry := s.find(id)
	var url string
	if entry != nil {
		url = entry.URL
	}
	s.mu.RUnlock()

	if entry == nil {
		return nil, fmt.Errorf("subscription %q not found", id)
	}
	if entry.Builtin {
		return entry, nil
	}

	payload, userInfo, err := s.fetch(url)
	if err != nil {
		s.markError(id, err)
		return nil, err
	}

	cfg, err := ParseClash(payload)
	if err != nil {
		s.markError(id, err)
		return nil, err
	}
	if len(cfg.Nodes) == 0 {
		err := errors.New("subscription contains no supported proxy nodes")
		s.markError(id, err)
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	target := s.find(id)
	if target == nil {
		return nil, fmt.Errorf("subscription %q not found", id)
	}
	// Preserve the user's node choices across updates.
	selection := target.Selection
	if selection == nil {
		selection = map[string]string{}
	}
	target.UpdatedAt = time.Now().Unix()
	// The quota is provider data and only that: like Clash, keep the previous
	// numbers when a response carries no subscription-userinfo header instead
	// of resetting them to zero.
	if userInfoHasData(userInfo) {
		target.UserInfo = userInfo
	}
	target.NodeCount = len(cfg.Nodes)
	target.RuleCount = len(cfg.Groups)
	target.Groups = cfg.Groups
	target.Nodes = cfg.Nodes
	target.SiteGroups = ConvertRules(cfg)
	target.Selection = pruneSelection(selection, cfg.Groups)
	target.Error = ""
	return target, s.saveLocked()
}

func (s *Store) markError(id string, cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry := s.find(id); entry != nil {
		entry.Error = cause.Error()
		_ = s.saveLocked()
	}
}

// Delete removes a subscription. The built-in entry cannot be removed.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if id == DefaultSubscriptionID {
		return errors.New("the default rules subscription cannot be deleted")
	}

	idx := -1
	for i, e := range s.entries {
		if e.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("subscription %q not found", id)
	}

	s.entries = append(s.entries[:idx], s.entries[idx+1:]...)
	if s.activeID == id {
		s.activeID = DefaultSubscriptionID
	}
	return s.saveLocked()
}

// SelectNode records the chosen node for a group.
func (s *Store) SelectNode(subscriptionID, group, node string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.find(subscriptionID)
	if entry == nil {
		return fmt.Errorf("subscription %q not found", subscriptionID)
	}
	if entry.Builtin {
		return errors.New("the default rules subscription has no nodes to select")
	}
	if entry.Selection == nil {
		entry.Selection = map[string]string{}
	}
	entry.Selection[group] = node
	return s.saveLocked()
}

// ActiveSiteGroups returns the rule set of the active subscription, or nil when
// the built-in rules should be used.
func (s *Store) ActiveSiteGroups() []SiteGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry := s.find(s.activeID)
	if entry == nil || entry.Builtin {
		return nil
	}
	return entry.SiteGroups
}

// ActiveEntry returns a snapshot of the active subscription. The copy is made
// under the store lock, so callers may read the fields without holding it —
// Update and Add mutate the live entry concurrently.
func (s *Store) ActiveEntry() *Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry := s.find(s.activeID)
	if entry == nil {
		return nil
	}

	cloned := *entry
	cloned.Selection = make(map[string]string, len(entry.Selection))
	for k, v := range entry.Selection {
		cloned.Selection[k] = v
	}
	cloned.Nodes = append([]Node(nil), entry.Nodes...)
	cloned.Groups = append([]Group(nil), entry.Groups...)
	cloned.SiteGroups = append([]SiteGroup(nil), entry.SiteGroups...)
	return &cloned
}

// ActiveNode returns the node selected for the first group that carries a
// usable selection — Clash treats the active subscription as one proxy group,
// so this is "the" current exit. ok=false when the built-in rules are active
// or no usable node is selected.
func (s *Store) ActiveNode() (Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry := s.find(s.activeID)
	if entry == nil || entry.Builtin || len(entry.Nodes) == 0 {
		return Node{}, false
	}
	for _, group := range entry.Groups {
		selected := entry.Selection[group.Name]
		if selected == "" {
			continue
		}
		for _, n := range entry.Nodes {
			if n.Name == selected && n.Supported() {
				return n, true
			}
		}
	}
	return Node{}, false
}

// NodeByID resolves one node of a subscription by name.
func (s *Store) NodeByID(subscriptionID, nodeName string) (Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry := s.find(subscriptionID)
	if entry == nil {
		return Node{}, false
	}
	for _, n := range entry.Nodes {
		if n.Name == nodeName && n.Supported() {
			return n, true
		}
	}
	return Node{}, false
}

// NodeHTTPClient builds an HTTP client whose TLS connections are tunnelled
// through the given proxy node — the Clash Verge URL-test semantics: the
// request leaves through the node and the node's server resolves the target
// domain, so polluted local DNS cannot skew the measurement. The timeout
// bounds dial, handshake and response headers as a whole.
func NodeHTTPClient(node Node, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				host, portStr = addr, "443"
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				port = 443
			}

			// node.DialTimeout does not take a context (some protocol dials
			// ignore one anyway), so bound the dial against ctx explicitly
			// and discard a late connection instead of leaking it.
			type dialResult struct {
				conn net.Conn
				err  error
			}
			ch := make(chan dialResult, 1)
			go func() {
				tunnel, dialErr := node.DialTimeout(host, port, timeout)
				ch <- dialResult{tunnel, dialErr}
			}()
			var tunnel net.Conn
			select {
			case r := <-ch:
				if r.err != nil {
					return nil, r.err
				}
				tunnel = r.conn
			case <-ctx.Done():
				go func() {
					if r := <-ch; r.conn != nil {
						r.conn.Close()
					}
				}()
				return nil, ctx.Err()
			}

			tconn := tls.Client(tunnel, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
			if err := tconn.HandshakeContext(ctx); err != nil {
				tunnel.Close()
				return nil, err
			}
			return tconn, nil
		},
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

// fetch downloads the subscription payload the way Clash Verge does: through
// the currently selected node first (subscription providers are routinely
// unreachable directly, and the local proxy would still route their domains
// direct), then through the configured local proxy, then direct.
func (s *Store) fetch(rawURL string) ([]byte, UserInfo, error) {
	clients := make([]*http.Client, 0, 3)
	if node, ok := s.ActiveNode(); ok {
		clients = append(clients, NodeHTTPClient(node, 30*time.Second))
	}
	if proxyURL := s.fetchProxyValue(); proxyURL != "" {
		if pu, err := neturl.Parse(proxyURL); err == nil {
			clients = append(clients, &http.Client{
				Timeout: 30 * time.Second,
				Transport: &http.Transport{
					Proxy:           http.ProxyURL(pu),
					TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
				},
			})
		}
	}
	clients = append(clients, &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	})

	var errs []error
	for _, client := range clients {
		payload, userInfo, err := fetchWith(client, rawURL)
		if err == nil {
			return payload, userInfo, nil
		}
		errs = append(errs, err)
	}
	return nil, UserInfo{}, errors.Join(errs...)
}

// userInfoHasData reports whether the provider advertised any quota field in
// this response. Subscription quota is never self-counted or extrapolated —
// only the values from the subscription-userinfo header are shown.
func userInfoHasData(u UserInfo) bool {
	return u.Upload > 0 || u.Download > 0 || u.Total > 0 || u.ExpireTime > 0
}

// pruneSelection drops selections for groups the refreshed subscription no
// longer declares.
func pruneSelection(selection map[string]string, groups []Group) map[string]string {
	if len(selection) == 0 {
		return map[string]string{}
	}
	valid := make(map[string]bool, len(groups))
	for _, g := range groups {
		valid[g.Name] = true
	}
	out := make(map[string]string, len(selection))
	for k, v := range selection {
		if valid[k] {
			out[k] = v
		}
	}
	return out
}

func newID(name, url string) string {
	seed := name
	if seed == "" {
		seed = url
	}
	sum := fnv1a(seed)
	return fmt.Sprintf("sub-%d-%x", time.Now().UnixNano(), sum&0xffffff)
}

func fnv1a(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

func deriveNameFromURL(url string) string {
	trimmed := strings.TrimSuffix(url, "/")
	// Drop the query string first: subscription URLs routinely carry tokens
	// (…/moscow?token=…), and the name should be the path segment only.
	if idx := strings.IndexByte(trimmed, '?'); idx >= 0 {
		trimmed = strings.TrimSuffix(trimmed[:idx], "/")
	}
	if idx := strings.LastIndex(trimmed, "/"); idx >= 0 && idx < len(trimmed)-1 {
		return trimmed[idx+1:]
	}
	return url
}

// AddEntryForTest registers a subscription without network access. It exists so
// packages that embed Store (such as proxy) can exercise activation paths in
// tests without standing up an HTTP server.
func (s *Store) AddEntryForTest(name, url string) *Entry {
	entry := &Entry{
		ID:         newID(name, url),
		Name:       name,
		URL:        url,
		UpdatedAt:  time.Now().Unix(),
		Groups:     []Group{},
		Nodes:      []Node{},
		SiteGroups: []SiteGroup{},
		Selection:  map[string]string{},
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.find(entry.ID); existing != nil {
		*existing = *entry
		return existing
	}
	s.entries = append(s.entries, entry)
	return entry
}

// SetSiteGroupsForTest replaces the rule set of an entry created by
// AddEntryForTest. Domains and mode are all the proxy layer needs, so callers
// in other packages can supply their own SiteGroup type via the callback.
func (s *Store) SetSiteGroupsForTest(id string, groups []SiteGroup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry := s.find(id); entry != nil {
		entry.SiteGroups = groups
		entry.RuleCount = len(groups)
	}
}

// SetNodesForTest replaces the node list of an entry created by AddEntryForTest.
func (s *Store) SetNodesForTest(id string, nodes []Node) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry := s.find(id); entry != nil {
		entry.Nodes = nodes
		entry.NodeCount = len(nodes)
	}
}

// SetGroupsForTest replaces the proxy-group list of an entry created by
// AddEntryForTest.
func (s *Store) SetGroupsForTest(id string, groups []Group) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry := s.find(id); entry != nil {
		entry.Groups = groups
	}
}

// Fetch downloads a subscription payload and reads the quota header if present.
// When proxyURL is non-empty the request is attempted through that HTTP proxy
// first, with a direct connection as fallback.
func Fetch(rawURL string, proxyURL string) ([]byte, UserInfo, error) {
	clients := make([]*http.Client, 0, 2)
	if proxyURL != "" {
		if pu, err := neturl.Parse(proxyURL); err == nil {
			clients = append(clients, &http.Client{
				Timeout: 30 * time.Second,
				Transport: &http.Transport{
					Proxy:           http.ProxyURL(pu),
					TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
				},
			})
		}
	}
	clients = append(clients, &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	})

	var errs []error
	for _, client := range clients {
		payload, userInfo, err := fetchWith(client, rawURL)
		if err == nil {
			return payload, userInfo, nil
		}
		errs = append(errs, err)
	}
	return nil, UserInfo{}, errors.Join(errs...)
}

func fetchWith(client *http.Client, rawURL string) ([]byte, UserInfo, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, UserInfo{}, err
	}
	req.Header.Set("User-Agent", "clash-verge/v2.0 FlowWeaver")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, UserInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, UserInfo{}, fmt.Errorf("http status %d", resp.StatusCode)
	}

	payload, err := io.ReadAll(io.LimitReader(resp.Body, MaxPayloadBytes))
	if err != nil {
		return nil, UserInfo{}, err
	}
	if len(payload) == 0 {
		return nil, UserInfo{}, errors.New("subscription response was empty")
	}

	userInfo := ParseSubscriptionUserInfo(resp.Header.Get("Subscription-Userinfo"))
	return payload, userInfo, nil
}
