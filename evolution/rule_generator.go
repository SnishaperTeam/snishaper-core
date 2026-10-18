package evolution

import (
	"fmt"
	"strings"
	"time"
)

// GenerateRule 根据域名与命中的测试方法生成临时规则。method 决定规则的代理
// 模式（mitm/tls-rf/quic）；sniFake 与 echEnabled 仅在对应方法下生效。
func GenerateRule(domain string, method TestMethod, sniFake string, echEnabled bool) *TempRule {
	rule := &TempRule{
		ID:         fmt.Sprintf("evolution-%s-%s", domain, method),
		Name:       extractDomainPrefix(domain),
		Domain:     domain,
		Method:     method,
		CreatedAt:  time.Now(),
		IsApplied:  false,
		ECHEnabled: echEnabled,
	}

	switch method {
	case MethodDomainFronting:
		rule.Mode = "mitm"
		rule.SniFake = sniFake
	case MethodTLSFragment:
		rule.Mode = "tls-rf"
	case MethodECH:
		rule.Mode = "mitm"
		rule.ECHEnabled = true
	case MethodQUIC:
		rule.Mode = "quic"
	}

	return rule
}

func extractDomainPrefix(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return domain
}

// ToSiteGroup 把临时规则转换为站点分组配置（map 结构与 rules/config.json 的
// site_groups 条目一致），供应用侧直接写入规则文件。
func (r *TempRule) ToSiteGroup() map[string]interface{} {
	siteGroup := map[string]interface{}{
		"id":      r.ID,
		"name":    r.Name,
		"website": inferWebsite(r.Domain),
		"domains": []string{r.Domain},
		"mode":    r.Mode,
		"enabled": true,
	}

	if r.SniFake != "" {
		siteGroup["sni_fake"] = r.SniFake
	}

	if r.ECHEnabled {
		siteGroup["ech_enabled"] = true
		siteGroup["ech_profile_id"] = "legacy-cloudflare"
	}

	if r.UseCFPool {
		siteGroup["use_cf_pool"] = true
	}

	// NAT64 绑定：tcping 直连失败后经 NAT64 映射回退成功的域名，
	// 应用规则时必须携带 nat64 配置，实际拨号才会走 NAT64 通道。
	if r.NAT64Enabled && r.NAT64ProfileID != "" {
		siteGroup["nat64_enabled"] = true
		siteGroup["nat64_profile_id"] = r.NAT64ProfileID
	}

	return siteGroup
}

func inferWebsite(domain string) string {
	if strings.Contains(domain, "google") {
		return "Google"
	}
	if strings.Contains(domain, "github") {
		return "GitHub"
	}
	if strings.Contains(domain, "telegram") {
		return "Telegram"
	}
	if strings.Contains(domain, "twitter") || strings.Contains(domain, "x.com") {
		return "Twitter"
	}
	if strings.Contains(domain, "youtube") {
		return "YouTube"
	}
	if strings.Contains(domain, "facebook") || strings.Contains(domain, "fb.com") {
		return "Facebook"
	}
	if strings.Contains(domain, "instagram") {
		return "Instagram"
	}
	if strings.Contains(domain, "cloudflare") {
		return "Cloudflare"
	}
	if strings.Contains(domain, "amazon") || strings.Contains(domain, "aws") {
		return "Amazon"
	}
	if strings.Contains(domain, "microsoft") {
		return "Microsoft"
	}

	return "Others"
}
