package certmanager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SnishaperTeam/snishaper-core/config"
)

func TestLoadCACorruptedCertPEMReturnsError(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(caPath, []byte("not a pem file"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("not a pem file"), 0644); err != nil {
		t.Fatal(err)
	}
	cm := NewCertManager(caPath, keyPath)
	if err := cm.LoadCA(); err == nil {
		t.Fatal("expected error for corrupted CA pem, got nil")
	}
}

func TestLoadCACorruptedKeyPEMReturnsError(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	cm := NewCertManager(caPath, keyPath)
	if err := cm.GenerateCA(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("garbage"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := cm.LoadCA(); err == nil {
		t.Fatal("expected error for corrupted key pem, got nil")
	}
}

// TestGeneratedCASubjectCarriesProductName pins the user-visible identity of the
// generated CA. Users see this subject in the Windows trust store and in
// browser certificate dialogs, so an embedder must never ship a root labelled
// with another product's name.
func TestGeneratedCASubjectCarriesProductName(t *testing.T) {
	for _, tc := range []struct {
		name      string
		manager   *CertManager
		wantOrg   string
		wantCN    string
		notInName string
	}{
		{
			name:      "reference product keeps legacy identity",
			manager:   NewCertManager(filepath.Join(t.TempDir(), "ca.crt"), filepath.Join(t.TempDir(), "ca.key")),
			wantOrg:   "SniShaper",
			wantCN:    "SniShaper CA",
			notInName: "FlowWeaver",
		},
		{
			name:      "embedder is branded",
			manager:   NewCertManagerFor(config.Brand{Name: "FlowWeaver"}, filepath.Join(t.TempDir(), "ca.crt"), filepath.Join(t.TempDir(), "ca.key")),
			wantOrg:   "FlowWeaver",
			wantCN:    "FlowWeaver CA",
			notInName: "SniShaper",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.manager.GenerateCA(); err != nil {
				t.Fatalf("GenerateCA: %v", err)
			}
			ca := tc.manager.GetCACert()
			if ca == nil {
				t.Fatal("GetCACert returned nil after GenerateCA")
			}
			if org := strings.Join(ca.Subject.Organization, ","); org != tc.wantOrg {
				t.Errorf("Organization = %q, want %q", org, tc.wantOrg)
			}
			if ca.Subject.CommonName != tc.wantCN {
				t.Errorf("CommonName = %q, want %q", ca.Subject.CommonName, tc.wantCN)
			}
			if subject := ca.Subject.String(); strings.Contains(subject, tc.notInName) {
				t.Errorf("subject %q leaks foreign product name %q", subject, tc.notInName)
			}
			if brand := tc.manager.Brand().Display(); !strings.Contains(ca.Subject.String(), brand) {
				t.Errorf("subject %q does not carry brand %q", ca.Subject.String(), brand)
			}
		})
	}
}

// TestInitCertManagerForBrand checks the on-disk entry point used by embedders:
// it must create the CA when missing and load the existing one otherwise.
func TestInitCertManagerForBrand(t *testing.T) {
	dir := t.TempDir()

	cm, err := InitCertManagerFor(config.Brand{Name: "FlowWeaver"}, dir)
	if err != nil {
		t.Fatalf("InitCertManagerFor (create): %v", err)
	}
	if cm.GetCACert() == nil {
		t.Fatal("no CA generated on first init")
	}
	if org := strings.Join(cm.GetCACert().Subject.Organization, ","); org != "FlowWeaver" {
		t.Fatalf("Organization = %q, want FlowWeaver", org)
	}

	// A second init must reuse the CA rather than regenerate it, otherwise every
	// startup would invalidate already-trusted certificates.
	again, err := InitCertManagerFor(config.Brand{Name: "FlowWeaver"}, dir)
	if err != nil {
		t.Fatalf("InitCertManagerFor (reload): %v", err)
	}
	if got, want := again.GetCACert().SerialNumber, cm.GetCACert().SerialNumber; got.Cmp(want) != 0 {
		t.Errorf("serial changed on reload: got %s, want %s", got, want)
	}
}

// TestBrandTextMatchingIsProductScoped guards the trust-store scan: it decides
// which installed roots this application may list and uninstall, so matching a
// foreign product would let one app remove another app's root CA.
func TestBrandTextMatchingIsProductScoped(t *testing.T) {
	snishaper := config.Brand{}
	flowweaver := config.Brand{Name: "FlowWeaver"}

	if !matchesBrandText(snishaper, "CN=SniShaper CA, O=SniShaper") {
		t.Error("SniShaper did not recognise its own CA")
	}
	if !matchesBrandText(flowweaver, "CN=FlowWeaver CA, O=FlowWeaver") {
		t.Error("FlowWeaver did not recognise its own CA")
	}
	if matchesBrandText(flowweaver, "CN=SniShaper CA, O=SniShaper") {
		t.Error("FlowWeaver claimed the SniShaper CA")
	}
	if matchesBrandText(snishaper, "CN=FlowWeaver CA, O=FlowWeaver") {
		t.Error("SniShaper claimed the FlowWeaver CA")
	}
	if matchesBrandText(flowweaver, "CN=DigiCert Global Root CA, O=DigiCert Inc") {
		t.Error("FlowWeaver claimed a public root CA")
	}
}

// TestLinuxAnchorFileNameIsProductScoped covers the Linux trust-store anchor
// name, which must differ per product so two embedders do not overwrite or
// uninstall one another's anchor file.
func TestLinuxAnchorFileNameIsProductScoped(t *testing.T) {
	if got := caAnchorFileNameFor(config.Brand{}); got != "snishaper-ca.crt" {
		t.Errorf("default anchor = %q, want snishaper-ca.crt", got)
	}
	if got := caAnchorFileNameFor(config.Brand{Name: "FlowWeaver"}); got != "flowweaver-ca.crt" {
		t.Errorf("FlowWeaver anchor = %q, want flowweaver-ca.crt", got)
	}
	// A name that is not filename-safe must still produce a usable anchor name.
	for _, name := range []string{"My App!", "  ", "中文"} {
		got := caAnchorFileNameFor(config.Brand{Name: name})
		if got == "" || !strings.HasSuffix(got, "-ca.crt") {
			t.Errorf("caAnchorFileNameFor(%q) = %q, want a *-ca.crt name", name, got)
		}
		if strings.ContainsAny(got, ` /\:*?"<>|`) {
			t.Errorf("caAnchorFileNameFor(%q) = %q contains filename-unsafe characters", name, got)
		}
	}
}
