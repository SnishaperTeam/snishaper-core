package config

import (
	"strings"
	"testing"
)

// TestBrandResolveDefaultsToReferenceProduct pins the backwards-compatibility
// rule: an embedder that says nothing keeps the reference product's name, so
// existing users see no change.
func TestBrandResolveDefaultsToReferenceProduct(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"zero value", "", DefaultProductName},
		{"whitespace only", "   ", DefaultProductName},
		{"explicit", "SniShaper", "SniShaper"},
		{"embedder", "FlowWeaver", "FlowWeaver"},
		{"padded", "  FlowWeaver  ", "FlowWeaver"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Brand{Name: tc.in}).Display(); got != tc.want {
				t.Errorf("Brand{Name: %q}.Display() = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDashed(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"SniShaper", "sni-shaper"},
		{"FlowWeaver", "flow-weaver"},
		{"snishaper", "snishaper"},
		{"flowweaver", "flowweaver"},
		{"", ""},
		{"A", "a"},
		{"HTTPProxy", "http-proxy"},
	} {
		if got := Dashed(tc.in); got != tc.want {
			t.Errorf("Dashed(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestOwnNamesExcludeSharedDriverNames is the safety contract for every
// destructive decision (stale adapter cleanup, certificate trust matching): a
// name shared with other sing-tun applications must never appear here, or one
// product would delete another's adapter.
func TestOwnNamesExcludeSharedDriverNames(t *testing.T) {
	for _, name := range []string{"", "SniShaper", "FlowWeaver", "MyApp"} {
		brand := Brand{Name: name}
		for _, own := range brand.OwnNames() {
			if own == "" {
				t.Errorf("Brand{Name: %q}.OwnNames() contains an empty token", name)
			}
			for _, shared := range brandTunnelNames {
				if own == shared {
					t.Errorf("Brand{Name: %q}.OwnNames() = %v must not contain the shared driver name %q",
						name, brand.OwnNames(), shared)
				}
			}
			if own != strings.ToLower(own) {
				t.Errorf("Brand{Name: %q}.OwnNames() token %q must be lower-cased", name, own)
			}
		}
	}
}

// TestOwnNamesIncludeProductForms checks the concrete tokens each product
// needs: the plain name and, when the name is CamelCase, its dashed form.
func TestOwnNamesIncludeProductForms(t *testing.T) {
	for _, tc := range []struct {
		name     string
		contains []string
		missing  []string
	}{
		{"SniShaper", []string{"snishaper", "sni-shaper"}, nil},
		{"FlowWeaver", []string{"flowweaver", "flow-weaver"}, nil},
		{"", []string{"snishaper", "sni-shaper"}, nil},
		{"snishaper", []string{"snishaper"}, []string{"sni-shaper"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Brand{Name: tc.name}.OwnNames()
			joined := strings.Join(got, ",")
			for _, want := range tc.contains {
				if !strings.Contains(joined, want) {
					t.Errorf("OwnNames() = %v, want to contain %q", got, want)
				}
			}
			for _, bad := range tc.missing {
				for _, token := range got {
					if token == bad {
						t.Errorf("OwnNames() = %v, must not contain %q", got, bad)
					}
				}
			}
		})
	}
}

// TestTunnelsExtendOwnNames documents the recognition-only superset used for
// matching existing devices, never for deleting them.
func TestTunnelsExtendOwnNames(t *testing.T) {
	brand := Brand{Name: "FlowWeaver"}
	tunnels := brand.Tunnels()

	for _, own := range brand.OwnNames() {
		found := false
		for _, tunnel := range tunnels {
			if tunnel == own {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Tunnels() = %v must contain OwnNames() token %q", tunnels, own)
		}
	}
	for _, shared := range brandTunnelNames {
		found := false
		for _, tunnel := range tunnels {
			if tunnel == shared {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Tunnels() = %v must contain the shared driver name %q", tunnels, shared)
		}
	}
}
