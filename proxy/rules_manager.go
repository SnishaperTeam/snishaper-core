package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/SnishaperTeam/snishaper-core/config"
	"github.com/SnishaperTeam/snishaper-core/dohresolver"
	"github.com/SnishaperTeam/snishaper-core/log"
	"github.com/SnishaperTeam/snishaper-core/subscription"
)

// RuleManager 负责站点规则与各项配置的加载、保存和热更新。
type RuleManager struct {
	rules                         []Rule
	siteGroups                    []SiteGroup
	upstreams                     []Upstream
	dnsNodes                      []DNSNode
	settingsPath                  string
	rulesPath                     string
	cloudflareConfig              CloudflareConfig
	ipPoolConfigs                 []IPPoolConfig
	tunConfig                     TUNConfig
	fragConfig                    FragmentConfig
	closeToTray                   bool
	hibernateOnClose              bool
	autoStart                     bool
	showMainOnAutoStart           bool
	autoEnableProxyOnAutoStart    bool
	autoEnableSysProxyOnAutoStart bool
	autoUpdateRules               bool

	listenPort           string
	echProfiles          []ECHProfile
	nat64Profiles        []NAT64Profile
	autoRouter           *AutoRouter
	autoRoutingConfig    AutoRoutingConfig
	mu                   sync.RWMutex
	routeEventCallback   func(domain, mode string)
	onConfigSaved        func()
	language             string
	theme                string
	appearanceMode       string
	migrationEnabled     bool
	migrationServer      string
	updateChannel        string
	downloadSource       string
	customDownloadSource string
	rulesHashMu          sync.Mutex
	rulesHash            string
	logger               log.Logger
	routerDebug          bool
	// brand 标识嵌入方产品名，决定 TUN 网卡默认名等用户可见标识。
	brand            config.Brand
	domainRegexCache sync.Map

	subscriptions     *subscription.Store
	builtinSiteGroups []SiteGroup

	// 分层规则（issue #172，v0.7）：upstreamRules 是随规则更新整体替换的
	// 上游备份（config.upstream.json），内存中的 siteGroups 等字段始终是
	// 有效状态（config.json，可直接手编）。用户差量不落盘，按需由
	// computeUserLayer 对有效状态与备份求差得出。
	upstreamRules RulesConfig
}

// SetRouteEventCallback 设置路由模式变化时的回调。
func (r *RuleManager) SetRouteEventCallback(cb func(domain, mode string)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routeEventCallback = cb
}

func (r *RuleManager) emitRouteEvent(domain, mode string) {
	r.mu.RLock()
	cb := r.routeEventCallback
	r.mu.RUnlock()
	if cb != nil {
		cb(domain, mode)
	}
}

// SetOnConfigSaved 设置配置保存成功后的回调。
func (r *RuleManager) SetOnConfigSaved(cb func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onConfigSaved = cb
}

// logf routes RuleManager logging to the injected logger. The default is
// log.Nop, so an unconfigured manager stays silent.
func (r *RuleManager) logf(format string, args ...any) {
	if r.logger != nil {
		r.logger.Printf(format, args...)
	}
}

// triggerConfigSaved fires the config-saved callback asynchronously.
// It is always called from methods that already hold rm.mu, so no extra locking is needed.
func (r *RuleManager) triggerConfigSaved() {
	cb := r.onConfigSaved
	if cb != nil {
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					r.logf("[Config] panic in onConfigSaved callback: %v", rec)
				}
			}()
			cb()
		}()
	}
}

// RulesConfig 是配置文件的完整 JSON 结构。
type RulesConfig struct {
	// ConfigVersion 显式配置模式版本（缺失 = 0，legacy）。由本构建在
	// 保存时写为 CurrentConfigVersion；更高版本拒绝加载。
	ConfigVersion int            `json:"config_version,omitempty"`
	SiteGroups    []SiteGroup    `json:"site_groups"`
	Upstreams     []Upstream     `json:"upstreams"`
	DNSNodes      []DNSNode      `json:"dns_nodes,omitempty"`
	ECHProfiles   []ECHProfile   `json:"ech_profiles,omitempty"`
	NAT64Profiles []NAT64Profile `json:"nat64_profiles,omitempty"`
}

// DNSNode defines a DoH upstream with optional SNI obfuscation.
// It reuses the same dial-level concepts as proxy rules (SNI spoofing, ECH, QUIC, static IPs).
func (r *RuleManager) SetRules(rules []Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = rules
}

// processNameInList reports whether the process base name appears in the
// comma-separated rule process list. Comparison is case-insensitive.
func processNameInList(process, list string) bool {
	process = strings.ToLower(strings.TrimSpace(process))
	if process == "" {
		return false
	}
	for _, item := range strings.Split(list, ",") {
		if strings.ToLower(strings.TrimSpace(item)) == process {
			return true
		}
	}
	return false
}

// HasProcessRules reports whether any enabled rule carries a process filter.
// Callers use it to skip the process lookup cost when no rule needs it.
func (r *RuleManager) HasProcessRules() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, rule := range r.rules {
		if rule.Enabled && rule.Process != "" {
			return true
		}
	}
	return false
}

// matchRule selects the best rule for host. routerDebug (WithRouterDebug)
// enables per-request routing logs; it defaults to off to avoid log spam.
func (r *RuleManager) matchRule(host, mode string) Rule {
	rule, _, _ := r.matchRuleDetailed(host, mode, "", false, true)
	return rule
}

// matchRuleFor is matchRule with a known client process for per-application
// rules ("" when unknown — such rules then never match).
func (r *RuleManager) matchRuleFor(host, mode, process string) Rule {
	rule, _, _ := r.matchRuleDetailed(host, mode, process, false, true)
	return rule
}

// processRuleBonus outranks every domain score class so per-application rules
// always win over domain rules for their processes.
const processRuleBonus = 1 << 20

// matchRuleDetailed is the real matching pipeline. matchRule (real traffic)
// and ExplainMatch (simulated queries) both land here so the explanation can
// never drift from the engine. process is the client process base name for
// per-application rules ("" when unknown or unsupported — such rules then
// never match). collect gathers every matching candidate with its priority
// score; emit controls whether route events fire (simulated queries must not
// pollute the live route feed).
func (r *RuleManager) matchRuleDetailed(host, mode, process string, collect, emit bool) (Rule, []MatchCandidate, bool) {
	host = normalizeHost(host)
	mode = strings.ToLower(strings.TrimSpace(mode))
	process = strings.ToLower(strings.TrimSpace(process))

	// 手动规则匹配在锁内完成；命中所需的一切都先取本地副本再放锁：
	// AutoRouter.Decide 可能触发 5s 的 DoH 查询，持锁等它会让规则写入方全部停摆。
	r.mu.RLock()
	best := Rule{}
	bestScore := -1
	var candidates []MatchCandidate
	for _, rule := range r.rules {
		if !rule.Enabled {
			continue
		}

		score := domainMatchScore(host, rule.Domain, &r.domainRegexCache)
		if rule.Process != "" {
			// 进程规则：进程未知/不支持/不匹配时一律不参与（fail closed）。
			// 进程规则的域名可为空（"*" 同义），表示该进程的所有目标。
			if process == "" || !processNameInList(process, rule.Process) {
				continue
			}
			if score < 0 && (rule.Domain == "" || rule.Domain == "*") {
				score = 0
			}
			if score < 0 {
				continue
			}
			score += processRuleBonus
		}
		if score >= 0 {
			if collect {
				candidates = append(candidates, MatchCandidate{
					Domain:  rule.Domain,
					SiteID:  rule.SiteID,
					Mode:    rule.Mode,
					Score:   score,
					Process: rule.Process,
				})
			}
			if score > bestScore {
				best = rule
				bestScore = score
			}
		}
	}
	autoRouter := r.autoRouter
	autoMode := r.autoRoutingConfig.Mode
	routerDebug := r.routerDebug
	r.mu.RUnlock()

	// 如果命中了特定规则
	if bestScore >= 0 {
		downgraded := false
		if mode == "transparent" && best.Mode == "mitm" {
			if routerDebug {
				r.logf("[RuleMatch] Global Transparent detected: Downgrading MITM rule (%s) to DIRECT to avoid cert errors.", host)
			}
			best.Mode = "direct"
			downgraded = true
		}
		if routerDebug {
			r.logf("[Router] %s -> %s", host, best.Mode)
		}
		if emit {
			r.emitRouteEvent(host, best.Mode)
		}
		return best, candidates, downgraded
	}

	// 自动分流层：手动规则未命中时，查询 AutoRouter
	if autoRouter != nil && autoMode != "" {
		autoRule := autoRouter.Decide(host)
		if autoRule.Mode != "direct" {
			if routerDebug {
				r.logf("[Router] %s -> %s (AutoRoute)", host, autoRule.Mode)
			}
			if emit {
				r.emitRouteEvent(host, autoRule.Mode)
			}
			return autoRule, candidates, false
		}
	}

	// 未命中任何规则，走直连
	if r.routerDebug {
		r.logf("[Router] %s -> direct (Default)", host)
	}
	if emit {
		r.emitRouteEvent(host, "direct")
	}
	return Rule{
		Mode:    "direct",
		Enabled: true,
	}, candidates, false
}

// NewRuleManager creates a RuleManager persisting settings to settingsPath and
// rules to rulesPath. Optional settings (WithLogger, WithRouterDebug) are
// applied via functional options.
func NewRuleManager(settingsPath, rulesPath string, opts ...Option) *RuleManager {
	rm := &RuleManager{
		settingsPath:        settingsPath,
		rulesPath:           rulesPath,
		rules:               []Rule{},
		closeToTray:         true,
		showMainOnAutoStart: true,
		language:            "zh",
		theme:               "dark",
		logger:              log.Nop,
	}
	applyRuleManagerOptions(rm, opts)
	return rm
}

func findECHProfileByID(profiles []ECHProfile, id string) *ECHProfile {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	for i := range profiles {
		if profiles[i].ID == id {
			return &profiles[i]
		}
	}
	return nil
}

func ensureLegacyCloudflareProfile(profiles *[]ECHProfile) string {
	const profileID = "legacy-cloudflare"
	if existing := findECHProfileByID(*profiles, profileID); existing != nil {
		normalizeECHProfile(existing)
		if existing.Name == "" {
			existing.Name = "Legacy Cloudflare"
		}
		if existing.DiscoveryDomain == "" {
			existing.DiscoveryDomain = "crypto.cloudflare.com"
		}
		return existing.ID
	}

	*profiles = append(*profiles, ECHProfile{
		ID:              profileID,
		Name:            "Legacy Cloudflare",
		DiscoveryDomain: "crypto.cloudflare.com",
		AutoUpdate:      true,
	})
	return profileID
}

func migrateLegacyECHRules(siteGroups []SiteGroup, profiles *[]ECHProfile) bool {
	migrated := false
	for i := range siteGroups {
		siteGroups[i].ECHProfileID = strings.TrimSpace(siteGroups[i].ECHProfileID)
		siteGroups[i].ECHDomain = strings.TrimSpace(siteGroups[i].ECHDomain)
		if siteGroups[i].ECHEnabled && siteGroups[i].ECHProfileID == "" &&
			strings.EqualFold(siteGroups[i].ECHDomain, "crypto.cloudflare.com") {
			siteGroups[i].ECHProfileID = ensureLegacyCloudflareProfile(profiles)
			siteGroups[i].ECHDomain = ""
			migrated = true
		}
	}
	return migrated
}

// LoadConfig 从磁盘加载配置，文件缺失时使用默认值。
func (rm *RuleManager) LoadConfig() error {
	report, err := rm.LoadConfigWithMigration()
	if err != nil {
		return err
	}
	for _, c := range report.Changes {
		rm.logf("[Config] migrated: %s", c)
	}
	for _, w := range report.Warnings {
		rm.logf("[Config] warning: %s", w)
	}
	for _, e := range report.Errors {
		rm.logf("[Config] error: %s", e)
	}
	return nil
}

// finishLoadConfig 运行加载后的归一化、修复与规则构建；迁移发现记入
// report（可为 nil，仅内部旧路径使用）。
func (rm *RuleManager) finishLoadConfig(report *MigrationReport) error {
	if report == nil {
		report = &MigrationReport{}
	}

	// 校验旧配置：移除的字段、非法值、冲突规则、不支持选项。必须先于
	// 下面的归一化循环：校验器要把"原值 → 归一值"记入迁移报告。
	rm.validateSiteGroups(report)

	for i := range rm.siteGroups {
		rm.siteGroups[i].DNSMode = normalizeDNSMode(rm.siteGroups[i].DNSMode)
	}
	if rm.upstreams == nil {
		rm.upstreams = []Upstream{}
	}
	if rm.echProfiles == nil {
		rm.echProfiles = []ECHProfile{}
	}
	if rm.nat64Profiles == nil {
		rm.nat64Profiles = []NAT64Profile{}
	}
	for i := range rm.echProfiles {
		normalizeECHProfile(&rm.echProfiles[i])
	}
	rm.applySettingsDefaults()

	migrated := false
	for i := range rm.siteGroups {
		rm.siteGroups[i].Website = strings.TrimSpace(rm.siteGroups[i].Website)
		if rm.siteGroups[i].Website == "" {
			rm.siteGroups[i].Website = inferWebsiteFromSiteGroup(rm.siteGroups[i])
			migrated = true
		}
	}
	if migrateLegacyECHRules(rm.siteGroups, &rm.echProfiles) {
		migrated = true
	}

	rm.buildRules()
	// buildRules 之后立刻快照内置规则：ActivateSubscription 回退默认订阅时
	// 要从这里恢复出厂 siteGroups。
	rm.snapshotBuiltinSiteGroups()
	if migrated {
		if err := rm.saveRulesConfig(); err != nil {
			rm.logf("[Config] migrate website field failed: %v", err)
		} else {
			rm.logf("[Config] migrated website field for existing site groups")
		}
	}
	return nil
}

func (rm *RuleManager) applySettingsDefaults() {
	if rm.listenPort == "" {
		rm.listenPort = "8080"
	}
	rm.tunConfig = normalizeTUNConfig(rm.tunConfig, rm.brand)
}

func (rm *RuleManager) loadSettingsConfig() error {
	data, err := os.ReadFile(rm.settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return rm.saveDefaultSettingsConfig()
		}
		return err
	}

	var config SettingsConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	// 1. Set internal defaults first
	rm.closeToTray = true
	rm.hibernateOnClose = false
	rm.autoStart = false
	rm.showMainOnAutoStart = true
	rm.autoEnableProxyOnAutoStart = false
	rm.autoEnableSysProxyOnAutoStart = true
	rm.autoUpdateRules = true

	// 2. Override with JSON values if they exist
	rm.cloudflareConfig = config.CloudflareConfig
	rm.ipPoolConfigs = normalizeIPPoolConfigs(config.IPPools)
	rm.tunConfig = config.TUN
	rm.fragConfig = config.Fragment

	if config.ListenPort != "" {
		rm.listenPort = config.ListenPort
	}

	rm.autoRoutingConfig = config.AutoRouting
	if config.Language != "" {
		rm.language = config.Language
	}
	if config.Theme != "" {
		rm.theme = config.Theme
	}
	rm.appearanceMode = config.AppearanceMode

	if config.CloseToTray != nil {
		rm.closeToTray = *config.CloseToTray
	}
	if config.HibernateOnClose != nil {
		rm.hibernateOnClose = *config.HibernateOnClose
	}
	if config.AutoStart != nil {
		rm.autoStart = *config.AutoStart
	}
	if config.ShowMainWindowOnAutoStart != nil {
		rm.showMainOnAutoStart = *config.ShowMainWindowOnAutoStart
	}
	if config.AutoEnableProxyOnAutoStart != nil {
		rm.autoEnableProxyOnAutoStart = *config.AutoEnableProxyOnAutoStart
	}
	if config.AutoEnableSysProxyOnAutoStart != nil {
		rm.autoEnableSysProxyOnAutoStart = *config.AutoEnableSysProxyOnAutoStart
	}
	if config.AutoUpdateRules != nil {
		rm.autoUpdateRules = *config.AutoUpdateRules
	}
	if config.MigrationEnabled != nil {
		rm.migrationEnabled = *config.MigrationEnabled
	}
	rm.migrationServer = config.MigrationServer
	rm.updateChannel = config.UpdateChannel
	if rm.updateChannel == "" {
		rm.updateChannel = "stable"
	}
	rm.downloadSource = config.DownloadSource
	if rm.downloadSource == "" {
		rm.downloadSource = "down.mxw.qzz.io"
	}
	rm.customDownloadSource = config.CustomDownloadSource
	rm.applySettingsDefaults()
	return nil
}

func (rm *RuleManager) loadRulesConfig() error {
	data, err := os.ReadFile(rm.rulesPath)
	if err != nil {
		if os.IsNotExist(err) {
			return rm.saveDefaultRulesConfig()
		}
		return err
	}

	var config RulesConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	// 分层加载（issue #172，v0.7）：config.json 是可直接手编的有效状态，
	// config.upstream.json 是原样上游备份，用户差量按需由两者求差得出。
	// 备份缺失时按旧布局一次性迁移：v0.6 双文件（config.json=上游 +
	// config.user.json=用户差量）折叠为新布局；更早的单文件按三方合并
	// 基线推导上游层。两个文件保持原样（不归一化），归一化只在求差时
	// 对副本进行，保证与远端原始内容比较不产生虚假差异。
	backup, backupExists, err := loadUpstreamRulesConfigFile(rm.upstreamRulesPath())
	if err != nil {
		return err
	}
	var user UserRulesConfig
	userFileExists := false
	if !backupExists {
		user, userFileExists, err = loadUserRulesConfigFile(rm.userRulesPath())
		if err != nil {
			return err
		}
		if userFileExists {
			// v0.6 → v0.7 迁移：有效状态 = 旧上游层 + 用户差量；旧上游层
			// 原样落为备份，随后删除差量文件。
			rm.upstreamRules = config
			config = applyUserLayer(config, user)
		} else {
			rm.upstreamRules = rm.migrateLegacyRules(config)
		}
	} else {
		rm.upstreamRules = backup
	}

	rm.siteGroups = config.SiteGroups
	rm.upstreams = config.Upstreams
	rm.dnsNodes = config.DNSNodes
	rm.echProfiles = config.ECHProfiles
	rm.nat64Profiles = config.NAT64Profiles

	if !backupExists {
		if err := rm.saveEffectiveRulesConfig(); err != nil {
			rm.logf("[Config] persisting migrated effective rules failed: %v", err)
		}
		if err := rm.saveUpstreamRulesConfig(); err != nil {
			rm.logf("[Config] persisting migrated upstream backup failed: %v", err)
		}
		if userFileExists {
			if err := os.Remove(rm.userRulesPath()); err != nil && !os.IsNotExist(err) {
				rm.logf("[Config] removing migrated user rules file failed: %v", err)
			}
			rm.logf("[Config] migrated v0.6 layered rules into effective+backup layout")
		}
	}
	rm.updateRulesFileHash()
	// Ensure at least the default Ali DoH bootstrap node exists
	if len(rm.dnsNodes) == 0 {
		rm.dnsNodes = defaultDNSNodes()
	}
	return nil
}

func (rm *RuleManager) saveDefaultSettingsConfig() error {
	rm.closeToTray = true
	rm.autoStart = false
	rm.showMainOnAutoStart = true
	rm.autoEnableProxyOnAutoStart = false
	rm.autoEnableSysProxyOnAutoStart = true
	rm.autoUpdateRules = true
	rm.applySettingsDefaults()
	return rm.saveSettingsConfig()
}

func (rm *RuleManager) saveDefaultRulesConfig() error {
	rm.siteGroups = []SiteGroup{}
	rm.upstreams = []Upstream{}
	rm.dnsNodes = defaultDNSNodes()
	rm.echProfiles = []ECHProfile{}
	rm.nat64Profiles = []NAT64Profile{}
	// 全新安装：空有效状态 + 等值备份，保证求差结果为空。
	rm.upstreamRules = RulesConfig{DNSNodes: defaultDNSNodes()}
	rm.buildRules()
	if err := rm.saveUpstreamRulesConfig(); err != nil {
		return err
	}
	return rm.saveRulesConfig()
}

func (rm *RuleManager) buildRules() {
	rm.rules = []Rule{}
	upstreamMap := make(map[string]string)
	for _, up := range rm.upstreams {
		if up.Enabled && up.Address != "" {
			upstreamMap[up.ID] = up.Address
		}
	}

	echProfileMap := make(map[string]ECHProfile)
	for _, profile := range rm.echProfiles {
		echProfileMap[profile.ID] = profile
	}

	for _, sg := range rm.siteGroups {
		if !sg.Enabled {
			continue
		}

		// Resolve upstream ID to actual address
		resolvedUpstream := sg.Upstream
		if addr, ok := upstreamMap[sg.Upstream]; ok {
			resolvedUpstream = addr
		}

		resolvedUpstreams := make([]string, 0, len(sg.Upstreams))
		for _, upId := range sg.Upstreams {
			if addr, ok := upstreamMap[upId]; ok {
				resolvedUpstreams = append(resolvedUpstreams, addr)
			} else {
				resolvedUpstreams = append(resolvedUpstreams, upId)
			}
		}

		var echConfigBytes []byte
		var echProfile ECHProfile
		if sg.ECHProfileID != "" {
			if profile, ok := echProfileMap[sg.ECHProfileID]; ok {
				echProfile = profile
				if configStr := strings.TrimSpace(profile.Config); configStr != "" {
					if decoded, err := base64.StdEncoding.DecodeString(configStr); err == nil {
						echConfigBytes = decoded
						rm.logf("[BuildRules] Successfully loaded ECH Config for SiteGroup %s (%d bytes)", sg.ID, len(echConfigBytes))
					} else {
						rm.logf("[BuildRules] ERROR: Failed to decode ECH Config for SiteGroup %s: %v", sg.ID, err)
					}
				}
			} else {
				rm.logf("[BuildRules] WARNING: ECHProfileID %s linked to SiteGroup %s but profile not found", sg.ECHProfileID, sg.ID)
			}
		}

		// 进程规则可以不带域名（任何目标）；空域名列表时合成一条
		// Domain="*" 的规则，进程匹配即生效。
		domains := sg.Domains
		if len(domains) == 0 && strings.TrimSpace(sg.Process) != "" {
			domains = []string{"*"}
		}
		for _, domain := range domains {
			rule := Rule{
				Domain:             domain,
				Mode:               sg.Mode,
				Upstream:           resolvedUpstream,
				Upstreams:          resolvedUpstreams,
				DNSMode:            normalizeDNSMode(sg.DNSMode),
				SniFake:            sg.SniFake,
				ConnectPolicy:      strings.TrimSpace(sg.ConnectPolicy),
				SniPolicy:          strings.TrimSpace(sg.SniPolicy),
				Enabled:            true,
				SiteID:             sg.ID,
				ECHEnabled:         sg.ECHEnabled,
				ECHProfileID:       sg.ECHProfileID,
				UseCFPool:          sg.UseCFPool,
			IPPool:             sg.IPPool,
				Process:            strings.ToLower(strings.TrimSpace(sg.Process)),
				ECHDiscoveryDomain: echProfile.DiscoveryDomain,
				ECHDoHUpstream:     echProfile.DoHUpstream,
				ECHAutoUpdate:      echProfile.AutoUpdate,
				CertVerify:         sg.CertVerify,
				NAT64Enabled:       sg.NAT64Enabled,
				NAT64ProfileID:     sg.NAT64ProfileID,
				Frag:               sg.Frag,
			}
			rm.rules = append(rm.rules, rule)
		}
	}
}

// GetSiteGroups 返回全部站点分组。
func (rm *RuleManager) GetSiteGroups() []SiteGroup {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.siteGroups
}

// GetListenPort 返回本地监听端口。
func (rm *RuleManager) GetListenPort() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.listenPort
}

// SetListenPort 设置本地监听端口。
func (rm *RuleManager) SetListenPort(port string) {
	rm.mu.Lock()
	rm.listenPort = port
	rm.mu.Unlock()
}

// SaveConfig 将当前配置写回磁盘。
func (rm *RuleManager) SaveConfig() error {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if err := rm.saveSettingsConfig(); err != nil {
		return err
	}
	return rm.saveRulesConfig()
}

// GetCloudflareConfig 返回 Cloudflare IP 池配置。
func (rm *RuleManager) GetCloudflareConfig() CloudflareConfig {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.cloudflareConfig
}

// GetIPPoolsConfig 返回全部命名 IP 池配置（cloudfront、自定义 CDN 等）。
func (rm *RuleManager) GetIPPoolsConfig() []IPPoolConfig {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return append([]IPPoolConfig(nil), rm.ipPoolConfigs...)
}

// UpdateIPPoolsConfig 覆盖保存全部命名 IP 池配置。
func (rm *RuleManager) UpdateIPPoolsConfig(pools []IPPoolConfig) error {
	rm.mu.Lock()
	rm.ipPoolConfigs = normalizeIPPoolConfigs(pools)
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// normalizeIPPoolConfigs trims pool names, drops entries without a usable
// name, and enforces lowercase unique names (cloudflare is reserved for the
// legacy Cloudflare pool).
func normalizeIPPoolConfigs(pools []IPPoolConfig) []IPPoolConfig {
	seen := make(map[string]struct{}, len(pools))
	out := make([]IPPoolConfig, 0, len(pools))
	for _, pool := range pools {
		name := strings.ToLower(strings.TrimSpace(pool.Name))
		if name == "" || name == "cloudflare" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		pool.Name = name
		pool.PreferredIPs = trimNonEmpty(pool.PreferredIPs)
		pool.APIKey = strings.TrimSpace(pool.APIKey)
		seen[name] = struct{}{}
		out = append(out, pool)
	}
	return out
}

func trimNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// GetTUNConfig 返回 TUN 配置。
func (rm *RuleManager) GetTUNConfig() TUNConfig {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return normalizeTUNConfig(rm.tunConfig, rm.brand)
}

// GetCloseToTray 返回关闭窗口时是否最小化到托盘。
func (rm *RuleManager) GetCloseToTray() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.closeToTray
}

// GetFragmentConfig 返回 TLS 分片配置。
func (rm *RuleManager) GetFragmentConfig() FragmentConfig {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return normalizeFragmentConfig(rm.fragConfig)
}

// SetFragmentConfig 更新 TLS 分片配置。
func (rm *RuleManager) SetFragmentConfig(cfg FragmentConfig) error {
	rm.mu.Lock()
	rm.fragConfig = normalizeFragmentConfig(cfg)
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// SetCloseToTray 设置关闭窗口时是否最小化到托盘。
func (rm *RuleManager) SetCloseToTray(enabled bool) error {
	rm.mu.Lock()
	rm.closeToTray = enabled
	if !enabled {
		rm.hibernateOnClose = false
	}
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// GetHibernateOnClose 返回关闭时是否休眠。
func (rm *RuleManager) GetHibernateOnClose() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.hibernateOnClose && rm.closeToTray
}

// SetHibernateOnClose 设置关闭时是否休眠。
func (rm *RuleManager) SetHibernateOnClose(enabled bool) error {
	rm.mu.Lock()
	if enabled {
		rm.closeToTray = true
	}
	rm.hibernateOnClose = enabled
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// GetAutoStart 返回是否开机自启。
func (rm *RuleManager) GetAutoStart() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.autoStart
}

// SetAutoStart 设置是否开机自启。
func (rm *RuleManager) SetAutoStart(enabled bool) error {
	rm.mu.Lock()
	rm.autoStart = enabled
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// GetShowMainWindowOnAutoStart 返回自启时是否显示主窗口。
func (rm *RuleManager) GetShowMainWindowOnAutoStart() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.showMainOnAutoStart
}

// SetShowMainWindowOnAutoStart 设置自启时是否显示主窗口。
func (rm *RuleManager) SetShowMainWindowOnAutoStart(enabled bool) error {
	rm.mu.Lock()
	rm.showMainOnAutoStart = enabled
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// GetAutoEnableProxyOnAutoStart 返回自启时是否自动启动代理内核。
func (rm *RuleManager) GetAutoEnableProxyOnAutoStart() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.autoEnableProxyOnAutoStart
}

// SetAutoEnableProxyOnAutoStart 设置自启时是否自动启动代理内核。
func (rm *RuleManager) SetAutoEnableProxyOnAutoStart(enabled bool) error {
	rm.mu.Lock()
	rm.autoEnableProxyOnAutoStart = enabled
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// GetAutoEnableSysProxyOnAutoStart 返回自启时是否自动设置系统代理。
func (rm *RuleManager) GetAutoEnableSysProxyOnAutoStart() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.autoEnableSysProxyOnAutoStart
}

// SetAutoEnableSysProxyOnAutoStart 设置自启时是否自动设置系统代理。
func (rm *RuleManager) SetAutoEnableSysProxyOnAutoStart(enabled bool) error {
	rm.mu.Lock()
	rm.autoEnableSysProxyOnAutoStart = enabled
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// GetAutoUpdateRules 返回是否自动更新规则。
func (rm *RuleManager) GetAutoUpdateRules() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.autoUpdateRules
}

// SetAutoUpdateRules 设置是否自动更新规则。
func (rm *RuleManager) SetAutoUpdateRules(enabled bool) error {
	rm.mu.Lock()
	rm.autoUpdateRules = enabled
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// GetLanguage 返回界面语言。
func (r *RuleManager) GetLanguage() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.language
}

// SetLanguage 设置界面语言。
func (r *RuleManager) SetLanguage(lang string) error {
	r.mu.Lock()
	r.language = lang
	r.mu.Unlock()
	return r.saveSettingsConfig()
}

// GetTheme 返回界面主题。
func (r *RuleManager) GetTheme() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.theme == "" {
		return "dark" // Default to dark
	}
	return r.theme
}

// SetTheme 设置界面主题。
func (r *RuleManager) SetTheme(theme string) error {
	r.mu.Lock()
	r.theme = theme
	r.mu.Unlock()
	return r.saveSettingsConfig()
}

// GetAppearanceMode 返回浅色/深色模式（"light"/"dark"/"system"），
// 从未设置过时返回空串，让前端保留本地缓存的上一选择。
func (r *RuleManager) GetAppearanceMode() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.appearanceMode
}

// SetAppearanceMode 设置外观模式。
func (r *RuleManager) SetAppearanceMode(mode string) error {
	switch mode {
	case "light", "dark", "system":
	default:
		return fmt.Errorf("invalid appearance mode: %s", mode)
	}
	r.mu.Lock()
	r.appearanceMode = mode
	r.mu.Unlock()
	return r.saveSettingsConfig()
}

// UpdateCloudflareConfig 更新 Cloudflare IP 池配置。
func (rm *RuleManager) UpdateCloudflareConfig(cfg CloudflareConfig) error {
	rm.mu.Lock()
	rm.cloudflareConfig = cfg
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// UpdateTUNConfig 更新 TUN 配置。
func (rm *RuleManager) UpdateTUNConfig(cfg TUNConfig) error {
	rm.mu.Lock()
	rm.tunConfig = normalizeTUNConfig(cfg, rm.brand)
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// AddSiteGroup 新增一个站点分组。
func (rm *RuleManager) AddSiteGroup(sg SiteGroup) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	sg.ID = generateID()
	sg.Website = strings.TrimSpace(sg.Website)
	rm.siteGroups = append(rm.siteGroups, sg)
	rm.buildRules()
	return rm.saveRulesConfig()
}

// UpdateSiteGroup 按 ID 更新站点分组。
func (rm *RuleManager) UpdateSiteGroup(sg SiteGroup) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	sg.Website = strings.TrimSpace(sg.Website)
	for i, s := range rm.siteGroups {
		if s.ID == sg.ID {
			rm.siteGroups[i] = sg
			break
		}
	}
	rm.buildRules()
	return rm.saveRulesConfig()
}

// DeleteSiteGroup 按 ID 删除站点分组。
func (rm *RuleManager) DeleteSiteGroup(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, s := range rm.siteGroups {
		if s.ID == id {
			rm.siteGroups = append(rm.siteGroups[:i], rm.siteGroups[i+1:]...)
			break
		}
	}
	rm.buildRules()
	return rm.saveRulesConfig()
}

// GetUpstreams 返回全部上游配置。
func (rm *RuleManager) GetUpstreams() []Upstream {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.upstreams
}

// AddUpstream 新增一个上游。
func (rm *RuleManager) AddUpstream(u Upstream) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	u.ID = generateID()
	rm.upstreams = append(rm.upstreams, u)
	return rm.saveRulesConfig()
}

// UpdateUpstream 按 ID 更新上游。
func (rm *RuleManager) UpdateUpstream(u Upstream) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, up := range rm.upstreams {
		if up.ID == u.ID {
			rm.upstreams[i] = u
			break
		}
	}
	return rm.saveRulesConfig()
}

// DeleteUpstream 按 ID 删除上游。
func (rm *RuleManager) DeleteUpstream(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, up := range rm.upstreams {
		if up.ID == id {
			rm.upstreams = append(rm.upstreams[:i], rm.upstreams[i+1:]...)
			break
		}
	}
	return rm.saveRulesConfig()
}

// --- DNS Node CRUD ---

func (rm *RuleManager) GetDNSNodes() []DNSNode {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if rm.dnsNodes == nil {
		return []DNSNode{}
	}
	out := make([]DNSNode, len(rm.dnsNodes))
	copy(out, rm.dnsNodes)
	return out
}

// AddDNSNode 新增一个 DNS 节点。
func (rm *RuleManager) AddDNSNode(n DNSNode) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	n.ID = generateID()
	rm.dnsNodes = append(rm.dnsNodes, n)
	return rm.saveRulesConfig()
}

// UpdateDNSNode 按 ID 更新 DNS 节点。
func (rm *RuleManager) UpdateDNSNode(n DNSNode) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, node := range rm.dnsNodes {
		if node.ID == n.ID {
			rm.dnsNodes[i] = n
			break
		}
	}
	return rm.saveRulesConfig()
}

// DeleteDNSNode 按 ID 删除 DNS 节点。
func (rm *RuleManager) DeleteDNSNode(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, node := range rm.dnsNodes {
		if node.ID == id {
			rm.dnsNodes = append(rm.dnsNodes[:i], rm.dnsNodes[i+1:]...)
			break
		}
	}
	return rm.saveRulesConfig()
}

// SetDNSNodePriority reorders DNS nodes by moving the node with the given ID
// to the specified target index (0-based). Nodes are queried in list order.
func (rm *RuleManager) SetDNSNodePriority(id string, targetIndex int) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	srcIdx := -1
	for i, node := range rm.dnsNodes {
		if node.ID == id {
			srcIdx = i
			break
		}
	}
	if srcIdx < 0 {
		return fmt.Errorf("dns node %s not found", id)
	}
	if targetIndex < 0 {
		targetIndex = 0
	}
	if targetIndex >= len(rm.dnsNodes) {
		targetIndex = len(rm.dnsNodes) - 1
	}
	if srcIdx == targetIndex {
		return nil
	}

	node := rm.dnsNodes[srcIdx]
	rm.dnsNodes = append(rm.dnsNodes[:srcIdx], rm.dnsNodes[srcIdx+1:]...)
	tail := append([]DNSNode{}, rm.dnsNodes[targetIndex:]...)
	rm.dnsNodes = append(rm.dnsNodes[:targetIndex], node)
	rm.dnsNodes = append(rm.dnsNodes, tail...)
	return rm.saveRulesConfig()
}

func (rm *RuleManager) saveSettingsConfig() error {
	listenPort := rm.listenPort
	if listenPort == "" {
		listenPort = "8080"
	}
	closeToTray := rm.closeToTray
	hibernateOnClose := rm.hibernateOnClose
	autoStart := rm.autoStart
	showMainOnAutoStart := rm.showMainOnAutoStart
	autoEnableProxyOnAutoStart := rm.autoEnableProxyOnAutoStart
	autoEnableSysProxyOnAutoStart := rm.autoEnableSysProxyOnAutoStart
	autoUpdateRules := rm.autoUpdateRules
	migrationEnabled := rm.migrationEnabled
	cloudflareConfig := rm.cloudflareConfig
	ipPoolConfigs := rm.ipPoolConfigs
	tunConfig := normalizeTUNConfig(rm.tunConfig, rm.brand)
	fragConfig := normalizeFragmentConfig(rm.fragConfig)

	settings := SettingsConfig{
		ConfigVersion: CurrentConfigVersion,
		ListenPort:    listenPort,

		CloseToTray:                   &closeToTray,
		HibernateOnClose:              &hibernateOnClose,
		AutoStart:                     &autoStart,
		ShowMainWindowOnAutoStart:     &showMainOnAutoStart,
		AutoEnableProxyOnAutoStart:    &autoEnableProxyOnAutoStart,
		AutoEnableSysProxyOnAutoStart: &autoEnableSysProxyOnAutoStart,
		AutoUpdateRules:               &autoUpdateRules,
		CloudflareConfig:              cloudflareConfig,
		IPPools:                       ipPoolConfigs,
		AutoRouting:                   rm.autoRoutingConfig,
		TUN:                           tunConfig,
		Fragment:                      fragConfig,
		Language:                      rm.language,
		Theme:                         rm.theme,
		AppearanceMode:                rm.appearanceMode,

		MigrationEnabled:     &migrationEnabled,
		MigrationServer:      rm.migrationServer,
		UpdateChannel:        rm.updateChannel,
		DownloadSource:       rm.downloadSource,
		CustomDownloadSource: rm.customDownloadSource,
	}

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(rm.settingsPath), 0755); err != nil {
		return err
	}
	if err := writeFileAtomic(rm.settingsPath, data, 0644); err != nil {
		return err
	}
	rm.triggerConfigSaved()
	return nil
}

// writeFileAtomic writes data via a temp file + rename so a concurrent reader
// (or a crash mid-write) can never observe a truncated config file.
func writeFileAtomic(path string, data []byte, perm fs.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (rm *RuleManager) saveRulesConfig() error {
	// A non-default subscription replaces siteGroups with subscription-derived
	// rules. Persisting them would overwrite the layered rules and lose the
	// user's built-in configuration, so writes are blocked until the default
	// subscription is active again.
	if active := rm.activeSubscriptionID(); active != "" && active != subscription.DefaultSubscriptionID {
		rm.logf("[Subscription] skipping rules persist while subscription %q is active", active)
		return nil
	}

	// v0.7 分层保存（issue #172）：config.json 只写有效状态；上游备份
	// （config.upstream.json）仅由规则更新和迁移改写。用户差量不落盘，
	// 下次加载时由有效状态与备份求差自动恢复。
	if err := rm.saveEffectiveRulesConfig(); err != nil {
		return err
	}
	rm.updateRulesFileHash()
	rm.triggerConfigSaved()
	return nil
}

// GetECHProfiles 返回全部 ECH 配置档案。
func (rm *RuleManager) GetECHProfiles() []ECHProfile {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if rm.echProfiles == nil {
		return []ECHProfile{}
	}
	return rm.echProfiles
}

// UpsertECHProfile 新增或更新一个 ECH 配置档案。
func (rm *RuleManager) UpsertECHProfile(p ECHProfile) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	normalizeECHProfile(&p)
	if p.ID == "" {
		p.ID = generateID()
		rm.echProfiles = append(rm.echProfiles, p)
	} else {
		found := false
		for i, x := range rm.echProfiles {
			if x.ID == p.ID {
				rm.echProfiles[i] = p
				found = true
				break
			}
		}
		if !found {
			rm.echProfiles = append(rm.echProfiles, p)
		}
	}
	return rm.saveRulesConfig()
}

// DeleteECHProfile 按 ID 删除 ECH 配置档案。
func (rm *RuleManager) DeleteECHProfile(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, x := range rm.echProfiles {
		if x.ID == id {
			rm.echProfiles = append(rm.echProfiles[:i], rm.echProfiles[i+1:]...)
			break
		}
	}
	return rm.saveRulesConfig()
}

// GetBinaryECHConfig 按 ID 返回 ECH 配置的二进制数据。
func (r *RuleManager) GetBinaryECHConfig(id string) []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, p := range r.echProfiles {
		if p.ID == id {
			data, err := base64.StdEncoding.DecodeString(p.Config)
			if err == nil && len(data) > 0 {
				return data
			}
			break
		}
	}
	return nil
}

// UpdateECHProfileConfig 更新档案对应的 ECH 二进制配置。
func (r *RuleManager) UpdateECHProfileConfig(profileID string, configBytes []byte) error {
	if profileID == "" || len(configBytes) == 0 {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	found := false
	configBase64 := base64.StdEncoding.EncodeToString(configBytes)
	for i := range r.echProfiles {
		if r.echProfiles[i].ID == profileID {
			if r.echProfiles[i].Config == configBase64 {
				return nil // No change
			}
			r.echProfiles[i].Config = configBase64
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("profile %s not found", profileID)
	}

	r.logf("[RuleManager] ECH Profile %s updated via sync", profileID)
	return r.saveRulesConfig()
}

// GetAutoRoutingConfig 返回自动路由配置。
func (rm *RuleManager) GetAutoRoutingConfig() AutoRoutingConfig {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.autoRoutingConfig
}

// UpdateAutoRoutingConfig 更新自动路由配置。
func (rm *RuleManager) UpdateAutoRoutingConfig(cfg AutoRoutingConfig) error {
	rm.mu.Lock()
	rm.autoRoutingConfig = cfg
	if rm.autoRouter != nil {
		rm.autoRouter.UpdateConfig(cfg)
	}
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// GetAutoRouter 返回自动路由器实例。
func (rm *RuleManager) GetAutoRouter() *AutoRouter {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.autoRouter
}

// InitAutoRouter 用给定解析器初始化自动路由器。
func (rm *RuleManager) InitAutoRouter(resolver *dohresolver.FailoverResolver) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	// 停掉旧实例的 30 分钟缓存清理协程，重复初始化才不会泄漏。
	if rm.autoRouter != nil {
		rm.autoRouter.Stop()
	}
	rm.autoRouter = NewAutoRouter(rm.autoRoutingConfig, resolver, WithLogger(rm.logger))

	// Try loading cached GFW list
	cachePath := gfwListCachePath(rm.rulesPath)
	if count, err := rm.autoRouter.GetGFWList().LoadFromFile(cachePath); err == nil {
		rm.logf("[AutoRoute] Loaded %d domains from cache: %s", count, cachePath)
	} else {
		rm.logf("[AutoRoute] No cached GFW list at %s: %v", cachePath, err)
	}
}

// GetAutoRoutingStatus 返回 GFW 列表的加载状态。
func (rm *RuleManager) GetAutoRoutingStatus() GFWListStatus {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if rm.autoRouter != nil {
		return rm.autoRouter.GetStatus()
	}
	return GFWListStatus{
		Enabled: false,
		Mode:    string(rm.autoRoutingConfig.Mode),
	}
}

// GetNAT64Profiles 返回全部 NAT64 配置档案。
func (rm *RuleManager) GetNAT64Profiles() []NAT64Profile {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if rm.nat64Profiles == nil {
		return []NAT64Profile{}
	}
	out := make([]NAT64Profile, len(rm.nat64Profiles))
	copy(out, rm.nat64Profiles)
	return out
}

// AddNAT64Profile 新增一个 NAT64 配置档案。
func (rm *RuleManager) AddNAT64Profile(p NAT64Profile) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	p.ID = generateID()
	rm.nat64Profiles = append(rm.nat64Profiles, p)
	return rm.saveRulesConfig()
}

// UpdateNAT64Profile 按 ID 更新 NAT64 配置档案。
func (rm *RuleManager) UpdateNAT64Profile(p NAT64Profile) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, profile := range rm.nat64Profiles {
		if profile.ID == p.ID {
			rm.nat64Profiles[i] = p
			break
		}
	}
	return rm.saveRulesConfig()
}

// DeleteNAT64Profile 按 ID 删除 NAT64 配置档案。
func (rm *RuleManager) DeleteNAT64Profile(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, profile := range rm.nat64Profiles {
		if profile.ID == id {
			rm.nat64Profiles = append(rm.nat64Profiles[:i], rm.nat64Profiles[i+1:]...)
			break
		}
	}
	return rm.saveRulesConfig()
}

// GetNAT64PrefixByID 按 ID 返回 NAT64 前缀。
func (rm *RuleManager) GetNAT64PrefixByID(id string) string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	for _, p := range rm.nat64Profiles {
		if p.ID == id {
			return p.Prefix
		}
	}
	return ""
}

// GetMigrationEnabled 返回是否启用会话迁移。
func (rm *RuleManager) GetMigrationEnabled() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.migrationEnabled
}

// SetMigrationEnabled 设置是否启用会话迁移。
func (rm *RuleManager) SetMigrationEnabled(enabled bool) error {
	rm.mu.Lock()
	rm.migrationEnabled = enabled
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// GetMigrationServer 返回会话迁移服务器地址。
func (rm *RuleManager) GetMigrationServer() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.migrationServer
}

// SetMigrationServer 设置会话迁移服务器地址。
func (rm *RuleManager) SetMigrationServer(server string) error {
	rm.mu.Lock()
	rm.migrationServer = strings.TrimSpace(server)
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// GetUpdateChannel 返回当前更新通道。
func (rm *RuleManager) GetUpdateChannel() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if rm.updateChannel == "" {
		return "stable"
	}
	return rm.updateChannel
}

// SetUpdateChannel 设置更新通道。
func (rm *RuleManager) SetUpdateChannel(channel string) error {
	rm.mu.Lock()
	rm.updateChannel = channel
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// GetDownloadSource 返回下载源设置。
func (rm *RuleManager) GetDownloadSource() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if rm.downloadSource == "" {
		return "down.mxw.qzz.io"
	}
	return rm.downloadSource
}

// SetDownloadSource 设置下载源。
func (rm *RuleManager) SetDownloadSource(src string) error {
	rm.mu.Lock()
	rm.downloadSource = src
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

// GetCustomDownloadSource 返回自定义下载源前缀。
func (rm *RuleManager) GetCustomDownloadSource() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.customDownloadSource
}

// SetCustomDownloadSource 设置自定义下载源前缀。
func (rm *RuleManager) SetCustomDownloadSource(prefix string) error {
	rm.mu.Lock()
	rm.customDownloadSource = prefix
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}
