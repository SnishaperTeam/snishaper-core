package config

import "strings"

// DefaultProductName is the product name snishaper-core assumes when an
// embedder does not declare its own.
//
// SniShaper, the reference application, uses the default. Other embedders (for
// example FlowWeaver) pass their own name so that user-visible artefacts — the
// TUN adapter, the installed CA, stale-adapter cleanup — carry their brand
// instead of the library's reference product.
const DefaultProductName = "SniShaper"

// brandTunnelNames are the device names every embedder of this library shares,
// because they come from the sing-tun driver rather than from the product.
var brandTunnelNames = []string{"singtun", "sing-tun"}

// Brand identifies the application embedding snishaper-core. The zero value is
// valid and means DefaultProductName.
type Brand struct {
	// Name is the product name as it should appear to users, for example
	// "SniShaper" or "FlowWeaver". Empty means DefaultProductName.
	Name string
}

// Resolve returns b with the product name defaulted and trimmed. Use it before
// reading Name; the other methods call it for you.
func (b Brand) Resolve() Brand {
	if trimmed := strings.TrimSpace(b.Name); trimmed != "" {
		b.Name = trimmed
	} else {
		b.Name = DefaultProductName
	}
	return b
}

// Display returns the resolved product name.
func (b Brand) Display() string { return b.Resolve().Name }

// OwnNames returns the interface names that identify this product specifically,
// lower-cased: the product name and its dashed form. Unlike Tunnels it excludes
// the names every sing-tun based application shares.
//
// Use OwnNames when the match decides whether something may be *deleted* or
// treated as this product's own. A description containing "sing-tun" proves
// nothing: sing-box and mihomo use the same Wintun driver, so acting on that
// name would tear down another application's adapter.
func (b Brand) OwnNames() []string {
	display := b.Display()
	name := strings.ToLower(display)
	names := []string{name}
	// Dashed must see the original casing: "snishaper" has no word boundary to
	// split on, "SniShaper" does.
	if dashed := Dashed(display); dashed != name {
		names = append(names, dashed)
	}
	return names
}

// Tunnels returns the interface names this product may give its own TUN
// devices, lower-cased: OwnNames plus the shared sing-tun driver names (an
// adapter left behind by an older build may carry only those).
//
// Matching must be exact (plus a trailing numeric suffix), never a substring:
// a name that merely contains one of these, such as "Tundra", must stay
// unrelated.
func (b Brand) Tunnels() []string {
	names := b.OwnNames()
	return append(names, brandTunnelNames...)
}

// Dashed converts a CamelCase product name to its dashed lower-case form:
// "SniShaper" becomes "sni-shaper", "FlowWeaver" becomes "flow-weaver".
// Names without an upper-case letter are returned unchanged.
func Dashed(name string) string {
	var b strings.Builder
	b.Grow(len(name) + 4)
	runes := []rune(name)
	for i, r := range runes {
		if r >= 'A' && r <= 'Z' {
			// Split only at a word boundary: an upper-case run is one word
			// ("HTTPProxy" stays "httpproxy"+"proxy" at the last letter).
			prevLower := i > 0 && runes[i-1] >= 'a' && runes[i-1] <= 'z'
			nextLower := i+1 < len(runes) && runes[i+1] >= 'a' && runes[i+1] <= 'z'
			if i > 0 && (prevLower || nextLower) {
				b.WriteByte('-')
			}
		}
		b.WriteRune(r)
	}
	return strings.ToLower(b.String())
}
