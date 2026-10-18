package proxy

import (
	"github.com/SnishaperTeam/snishaper-core/config"
	"github.com/SnishaperTeam/snishaper-core/log"
)

// options carries the construction-time settings shared by NewProxyServer and
// NewRuleManager. Options irrelevant to a specific constructor are ignored.
type options struct {
	listenAddr    string
	ruleManager   *RuleManager
	certGenerator CertGenerator
	logger        log.Logger
	onStop        func(error)
	routerDebug   bool
	brand         config.Brand
}

// Option is a functional option accepted by NewProxyServer and NewRuleManager.
type Option func(*options)

// WithListenAddr overrides the initial listen address (host:port) of a
// ProxyServer.
func WithListenAddr(addr string) Option {
	return func(o *options) { o.listenAddr = addr }
}

// WithRuleManager attaches a RuleManager to the ProxyServer at construction
// time instead of calling SetRuleManager afterwards.
func WithRuleManager(rm *RuleManager) Option {
	return func(o *options) { o.ruleManager = rm }
}

// WithCertGenerator sets the CA certificate generator used by MITM mode.
func WithCertGenerator(cg CertGenerator) Option {
	return func(o *options) { o.certGenerator = cg }
}

// WithLogger injects the logger used by a ProxyServer or RuleManager. The
// default is log.Nop: an unconfigured library stays silent.
func WithLogger(l log.Logger) Option {
	return func(o *options) { o.logger = l }
}

// WithOnStop registers a callback fired when the ProxyServer stops
// unexpectedly (the same hook as the OnStop field).
func WithOnStop(cb func(error)) Option {
	return func(o *options) { o.onStop = cb }
}

// WithRouterDebug enables per-request routing decision logs on a RuleManager.
// It replaces the SNISHAPER_ROUTER_DEBUG=1 environment variable of the
// monolithic build.
func WithRouterDebug(enabled bool) Option {
	return func(o *options) { o.routerDebug = enabled }
}

// WithBrand declares which application embeds this library. The brand decides
// the user-visible product name: the default TUN adapter name, which interfaces
// count as our own tunnel during outbound selection, and the CA subject used by
// the certificate manager. The zero value keeps the reference product's name.
func WithBrand(b config.Brand) Option {
	return func(o *options) { o.brand = b }
}

// WithProductName is WithBrand for the common case of only naming the product.
func WithProductName(name string) Option {
	return WithBrand(config.Brand{Name: name})
}

// applyProxyOptions applies the constructor options to a freshly created
// ProxyServer. Nil options are ignored.
func applyProxyOptions(p *ProxyServer, opts []Option) {
	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	if o.listenAddr != "" {
		p.listenAddr = o.listenAddr
	}
	if o.ruleManager != nil {
		p.rules = o.ruleManager
	}
	if o.certGenerator != nil {
		p.certGenerator = o.certGenerator
	}
	if o.logger != nil {
		p.logger = o.logger
	}
	if o.onStop != nil {
		p.OnStop = o.onStop
	}
	if o.brand.Name != "" {
		p.brand = o.brand.Resolve()
	}
}

// applyRuleManagerOptions applies the constructor options to a freshly
// created RuleManager. Nil options are ignored.
func applyRuleManagerOptions(rm *RuleManager, opts []Option) {
	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	if o.logger != nil {
		rm.logger = o.logger
	}
	rm.routerDebug = o.routerDebug
	if o.brand.Name != "" {
		rm.brand = o.brand.Resolve()
	}
}
