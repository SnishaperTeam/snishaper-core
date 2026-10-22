package certmanager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/SnishaperTeam/snishaper-core/config"
	"github.com/SnishaperTeam/snishaper-core/internal/openutil"
)

// CertManager manages the embedding application's CA certificate and key used
// to sign MITM certificates.
type CertManager struct {
	caCert  *x509.Certificate
	caKey   *rsa.PrivateKey
	certMu  sync.RWMutex
	caPath  string
	keyPath string

	// Cache for CA install status to avoid expensive PowerShell calls
	lastStatus CAInstallStatus
	lastCheck  time.Time

	// brand 决定 CA 主题与信任库中"哪些证书属于本应用"的判定。
	brand config.Brand
}

// NewCertManager creates a CertManager reading and writing the CA at the given
// paths, using the reference product's name in the CA subject.
func NewCertManager(caPath, keyPath string) *CertManager {
	return NewCertManagerFor(config.Brand{}, caPath, keyPath)
}

// NewCertManagerFor creates a CertManager whose CA carries the given brand.
// The brand appears in the certificate subject ("<Product>" organization,
// "<Product> CA" common name) and in the trust-store search that recognises the
// CA as ours.
func NewCertManagerFor(brand config.Brand, caPath, keyPath string) *CertManager {
	return &CertManager{
		caPath:  caPath,
		keyPath: keyPath,
		brand:   brand.Resolve(),
	}
}

// Brand returns the product identity this manager signs certificates for.
func (cm *CertManager) Brand() config.Brand { return cm.brand }

// caAnchorFileNameFor returns the anchor file name for a product, e.g.
// "snishaper-ca.crt" / "flowweaver-ca.crt". Keeping it brand-specific stops two
// embedders from overwriting (and later uninstalling) one another's anchor.
func caAnchorFileNameFor(brand config.Brand) string {
	var b strings.Builder
	for _, r := range strings.ToLower(brand.Display()) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			// Spaces, punctuation and non-ASCII characters cannot appear in a
			// trust-store file name.
			b.WriteByte('-')
		}
	}
	safe := strings.Trim(b.String(), "-")
	if safe == "" {
		safe = "root"
	}
	return safe + "-ca.crt"
}

// matchesBrandText reports whether text carries this application's product
// name. Matching uses only the product name (never a shared driver string), so
// certificates belonging to other tools are never claimed as ours.
func matchesBrandText(brand config.Brand, text string) bool {
	lowered := strings.ToLower(text)
	for _, token := range brand.OwnNames() {
		if token != "" && strings.Contains(lowered, token) {
			return true
		}
	}
	return false
}

func (cm *CertManager) generateCAUnlocked() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %w", err)
	}

	name := cm.brand.Display()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{name},
			CommonName:   name + " CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}

	cm.caCert = cert
	cm.caKey = privateKey

	return cm.saveCA()
}

// GenerateCA creates a new CA certificate and key and saves them to disk.
func (cm *CertManager) GenerateCA() error {
	cm.certMu.Lock()
	defer cm.certMu.Unlock()
	return cm.generateCAUnlocked()
}

// writeFileAtomic writes data through a temp file + rename so a crash or power
// loss mid-write never leaves a truncated file behind.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (cm *CertManager) saveCA() error {
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cm.caKey)})
	if err := writeFileAtomic(cm.caPath, caPEM, 0644); err != nil {
		return err
	}
	return writeFileAtomic(cm.keyPath, keyPEM, 0600)
}

// LoadCA loads the existing CA certificate and key from disk, generating a new CA if missing.
func (cm *CertManager) LoadCA() error {
	cm.certMu.Lock()
	defer cm.certMu.Unlock()

	caData, err := os.ReadFile(cm.caPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cm.generateCAUnlocked()
		}
		return err
	}

	block, _ := pem.Decode(caData)
	if block == nil {
		return errors.New("invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	keyData, err := os.ReadFile(cm.keyPath)
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return errors.New("invalid CA key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}

	cm.caCert = cert
	cm.caKey = key

	return nil
}

// GetCACertPath returns the file path of the CA certificate.
func (cm *CertManager) GetCACertPath() string {
	return cm.caPath
}

// GetCertPool returns a new x509 pool containing the loaded CA certificate.
func (cm *CertManager) GetCertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	if cm.caCert != nil {
		pool.AddCert(cm.caCert)
	}
	return pool
}

// GetCACert returns the loaded CA certificate, or nil if not loaded.
func (cm *CertManager) GetCACert() *x509.Certificate {
	cm.certMu.RLock()
	defer cm.certMu.RUnlock()
	return cm.caCert
}

// GetCAKey returns the CA private key, or nil if not loaded.
func (cm *CertManager) GetCAKey() interface{} {
	cm.certMu.RLock()
	defer cm.certMu.RUnlock()
	return cm.caKey
}

// IsCAInstalled reports whether the CA is installed in the platform trust store.
func (cm *CertManager) IsCAInstalled() bool {
	status := cm.GetCAInstallStatus()
	return status.Installed
}

// CAInstallStatus describes whether the CA is installed and how to install it.
type CAInstallStatus struct {
	Installed   bool
	Platform    string
	CertPath    string
	InstallHelp string
}

// GetCAInstallStatus returns the cached-or-fresh CA install status for the platform.
func (cm *CertManager) GetCAInstallStatus() CAInstallStatus {
	cm.certMu.Lock()
	if !cm.lastCheck.IsZero() && time.Since(cm.lastCheck) < 5*time.Minute {
		status := cm.lastStatus
		cm.certMu.Unlock()
		return status
	}
	cm.certMu.Unlock()

	status := CAInstallStatus{
		CertPath:    cm.caPath,
		Platform:    runtime.GOOS,
		InstallHelp: platformInstallHelp(cm.brand),
	}

	if cm.caCert == nil {
		if err := cm.LoadCA(); err != nil {
			return status
		}
	}
	if cm.caCert == nil {
		return status
	}

	status.Installed = platformCACertInstalled(cm.brand, certThumbprint(cm.caCert))

	// Update cache
	cm.certMu.Lock()
	cm.lastStatus = status
	cm.lastCheck = time.Now()
	cm.certMu.Unlock()

	return status
}

// certThumbprint returns the uppercase hex SHA-1 of the certificate DER. Every
// platform trust store addresses certificates by it.
func certThumbprint(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// InstallCA installs the CA into the platform trust store after removing older generations.
func (cm *CertManager) InstallCA() error {
	if cm.caCert == nil || cm.caKey == nil {
		if err := cm.LoadCA(); err != nil {
			return err
		}
	}
	if cm.caPath == "" {
		return fmt.Errorf("CA certificate path is empty")
	}

	// Drop earlier generations of the CA before installing the current one.
	if certs, err := cm.GetInstalledCertificates(); err == nil {
		for _, c := range certs {
			_ = cm.UninstallCertificate(c.Token)
		}
	}

	if err := platformInstallCA(cm.brand, cm.caPath); err != nil {
		return err
	}

	cm.invalidateInstallStatusCache()
	return nil
}

// InstalledCert describes a certificate this app installed in the platform trust store.
type InstalledCert struct {
	Subject       string `json:"subject"`
	Thumbprint    string `json:"thumbprint"`
	NotAfter      string `json:"notAfter"`
	StoreName     string `json:"storeName"`
	StoreLocation string `json:"storeLocation"`
	Token         string `json:"token"`
}

// GetInstalledCertificates lists the certificates this app owns in the platform
// trust store.
func (cm *CertManager) GetInstalledCertificates() ([]InstalledCert, error) {
	return platformListCerts(cm.brand)
}

// UninstallCertificate removes a previously installed certificate by thumbprint or store token.
func (cm *CertManager) UninstallCertificate(thumbprint string) error {
	if thumbprint == "" {
		return fmt.Errorf("thumbprint is empty")
	}

	storeLocation := ""
	storeName := ""
	certThumbprint := thumbprint
	if parts := strings.SplitN(thumbprint, "|", 3); len(parts) == 3 {
		storeLocation = parts[0]
		storeName = parts[1]
		certThumbprint = parts[2]
	}

	if err := platformUninstallCert(cm.brand, storeLocation, storeName, certThumbprint); err != nil {
		return err
	}

	cm.invalidateInstallStatusCache()
	return nil
}

func (cm *CertManager) invalidateInstallStatusCache() {
	cm.certMu.Lock()
	cm.lastCheck = time.Time{}
	cm.certMu.Unlock()
}

// OpenCertDir opens the directory holding the CA files in the system file manager.
func (cm *CertManager) OpenCertDir() error {
	return openutil.OpenTarget(filepath.Dir(cm.caPath))
}

// OpenCAFile reveals the CA certificate file in the system file manager.
func (cm *CertManager) OpenCAFile() error {
	return openutil.RevealPath(cm.caPath)
}

// GetCACertPEM returns the CA certificate in PEM form, or an empty string if not loaded.
func (cm *CertManager) GetCACertPEM() string {
	cm.certMu.RLock()
	defer cm.certMu.RUnlock()
	if cm.caCert == nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw}))
}

// RegenerateCA uninstalls old CA certificates, generates a fresh CA and installs it.
func (cm *CertManager) RegenerateCA() error {
	// 1. Try to clean up existing certificates from system store
	certs, err := cm.GetInstalledCertificates()
	if err == nil {
		for _, c := range certs {
			_ = cm.UninstallCertificate(c.Token)
		}
	}

	// 2. Generate new CA
	cm.certMu.Lock()
	if err := cm.generateCAUnlocked(); err != nil {
		cm.certMu.Unlock()
		return err
	}
	cm.certMu.Unlock()

	// 3. Install the new one
	return cm.InstallCA()
}

// ExportCert returns the CA certificate in PEM encoding.
func (cm *CertManager) ExportCert() ([]byte, error) {
	cm.certMu.RLock()
	defer cm.certMu.RUnlock()
	if cm.caCert == nil {
		return nil, fmt.Errorf("no CA certificate available")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw}), nil
}

// InitCertManager loads or creates the CA in certDir and returns a ready
// CertManager for the reference product.
func InitCertManager(certDir string) (*CertManager, error) {
	return InitCertManagerFor(config.Brand{}, certDir)
}

// InitCertManagerFor loads or creates the CA in certDir for the given brand.
// The brand decides the CA subject, so each application installs a
// recognisably-named root instead of sharing (and uninstalling) one another's.
func InitCertManagerFor(brand config.Brand, certDir string) (*CertManager, error) {
	os.MkdirAll(certDir, 0755)

	cm := NewCertManagerFor(
		brand,
		filepath.Join(certDir, "ca.crt"),
		filepath.Join(certDir, "ca.key"),
	)

	if err := cm.LoadCA(); err != nil {
		// Keep the unreadable files for forensics instead of deleting the old
		// trust anchor: renaming preserves the auto-recovery without data loss.
		_ = os.Rename(cm.caPath, cm.caPath+".corrupt.bak")
		_ = os.Rename(cm.keyPath, cm.keyPath+".corrupt.bak")
		if genErr := cm.GenerateCA(); genErr != nil {
			return nil, fmt.Errorf("load existing CA failed: %v; regenerate failed: %w", err, genErr)
		}
	}

	return cm, nil
}
