package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SPIFFEConfig holds SPIFFE configuration
type SPIFFEConfig struct {
	SocketPath    string        `json:"socket_path"`
	TrustDomain   string        `json:"trust_domain"`
	ServiceName   string        `json:"service_name"`
	Timeout       time.Duration `json:"timeout"`
	RetryInterval time.Duration `json:"retry_interval"`
	MaxRetries    int           `json:"max_retries"`
}

// SPIFFEIdentity represents a SPIFFE identity
type SPIFFEIdentity struct {
	ID           spiffeid.ID         `json:"id"`
	Certificates []*x509.Certificate `json:"certificates"`
	PrivateKey   interface{}         `json:"private_key"`
	TrustBundle  []*x509.Certificate `json:"trust_bundle"`
	ExpiresAt    time.Time           `json:"expires_at"`
}

// SPIFFEManager manages SPIFFE identities and certificates
type SPIFFEManager struct {
	config   *SPIFFEConfig
	logger   *logrus.Logger
	source   *workloadapi.X509Source
	identity *SPIFFEIdentity
	stopCh   chan struct{}
}

// NewSPIFFEManager creates a new SPIFFE manager
func NewSPIFFEManager(config *SPIFFEConfig, logger *logrus.Logger) *SPIFFEManager {
	return &SPIFFEManager{
		config: config,
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

// Start starts the SPIFFE manager
func (sm *SPIFFEManager) Start(ctx context.Context) error {
	sm.logger.WithFields(logrus.Fields{
		"socket_path":  sm.config.SocketPath,
		"trust_domain": sm.config.TrustDomain,
		"service_name": sm.config.ServiceName,
	}).Info("Starting SPIFFE manager")

	// Create X509Source
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(sm.config.SocketPath)))
	if err != nil {
		return fmt.Errorf("failed to create X509Source: %w", err)
	}
	sm.source = source

	// Fetch initial identity
	if err := sm.fetchIdentity(ctx); err != nil {
		return fmt.Errorf("failed to fetch initial identity: %w", err)
	}

	// Start identity watcher
	go sm.watchIdentity(ctx)

	return nil
}

// Stop stops the SPIFFE manager
func (sm *SPIFFEManager) Stop() {
	sm.logger.Info("Stopping SPIFFE manager")
	close(sm.stopCh)
	if sm.source != nil {
		sm.source.Close()
	}
}

// GetIdentity returns the current SPIFFE identity
func (sm *SPIFFEManager) GetIdentity() *SPIFFEIdentity {
	return sm.identity
}

// GetTLSConfig returns a TLS config for the current identity
func (sm *SPIFFEManager) GetTLSConfig(ctx context.Context) (*tls.Config, error) {
	if sm.identity == nil {
		return nil, fmt.Errorf("no identity available")
	}

	// Create TLS config with SPIFFE certificates
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: sm.certificatesToDER(sm.identity.Certificates),
				PrivateKey:  sm.identity.PrivateKey,
			},
		},
		RootCAs: sm.createCertPool(sm.identity.TrustBundle),
	}

	return tlsConfig, nil
}

// GetClientTLSConfig returns a TLS config for client connections
func (sm *SPIFFEManager) GetClientTLSConfig(ctx context.Context, serverID spiffeid.ID) (*tls.Config, error) {
	if sm.source == nil {
		return nil, fmt.Errorf("SPIFFE source not initialized")
	}

	// Use SPIFFE TLS config helper
	tlsConfig := tlsconfig.MTLSClientConfig(sm.source, sm.source, tlsconfig.AuthorizeID(serverID))
	return tlsConfig, nil
}

// GetServerTLSConfig returns a TLS config for server connections
func (sm *SPIFFEManager) GetServerTLSConfig(ctx context.Context, authorizedIDs ...spiffeid.ID) (*tls.Config, error) {
	if sm.source == nil {
		return nil, fmt.Errorf("SPIFFE source not initialized")
	}

	var authorizer tlsconfig.Authorizer
	if len(authorizedIDs) > 0 {
		authorizer = tlsconfig.AuthorizeOneOf(authorizedIDs...)
	} else {
		// Allow any ID from the same trust domain
		trustDomain, err := spiffeid.TrustDomainFromString(sm.config.TrustDomain)
		if err != nil {
			return nil, fmt.Errorf("invalid trust domain: %w", err)
		}
		authorizer = tlsconfig.AuthorizeMemberOf(trustDomain)
	}

	tlsConfig := tlsconfig.MTLSServerConfig(sm.source, sm.source, authorizer)
	return tlsConfig, nil
}

// ValidateIdentity validates a SPIFFE identity
func (sm *SPIFFEManager) ValidateIdentity(identity *SPIFFEIdentity) error {
	if identity == nil {
		return fmt.Errorf("identity is nil")
	}

	if len(identity.Certificates) == 0 {
		return fmt.Errorf("no certificates in identity")
	}

	// Check certificate expiration
	now := time.Now()
	for i, cert := range identity.Certificates {
		if cert.NotAfter.Before(now) {
			return fmt.Errorf("certificate %d is expired", i)
		}
		if cert.NotBefore.After(now) {
			return fmt.Errorf("certificate %d is not yet valid", i)
		}
	}

	// Validate SPIFFE ID
	if identity.ID.IsZero() {
		return fmt.Errorf("invalid SPIFFE ID")
	}

	// Check trust domain
	expectedTrustDomain, err := spiffeid.TrustDomainFromString(sm.config.TrustDomain)
	if err != nil {
		return fmt.Errorf("invalid configured trust domain: %w", err)
	}

	if identity.ID.TrustDomain().String() != expectedTrustDomain.String() {
		return fmt.Errorf("identity trust domain %s does not match expected %s",
			identity.ID.TrustDomain(), expectedTrustDomain)
	}

	return nil
}

// GetServiceID returns the SPIFFE ID for this service
func (sm *SPIFFEManager) GetServiceID() (spiffeid.ID, error) {
	trustDomain, err := spiffeid.TrustDomainFromString(sm.config.TrustDomain)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("invalid trust domain: %w", err)
	}

	serviceID, err := spiffeid.FromPath(trustDomain, fmt.Sprintf("/gpushield/%s", sm.config.ServiceName))
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("failed to create service ID: %w", err)
	}

	return serviceID, nil
}

// CreateNodeID creates a SPIFFE ID for a node
func (sm *SPIFFEManager) CreateNodeID(nodeID string) (spiffeid.ID, error) {
	trustDomain, err := spiffeid.TrustDomainFromString(sm.config.TrustDomain)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("invalid trust domain: %w", err)
	}

	nodeSpiffeID, err := spiffeid.FromPath(trustDomain, fmt.Sprintf("/gpushield/node/%s", nodeID))
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("failed to create node ID: %w", err)
	}

	return nodeSpiffeID, nil
}

// CreateSensorID creates a SPIFFE ID for a sensor
func (sm *SPIFFEManager) CreateSensorID(nodeID string) (spiffeid.ID, error) {
	trustDomain, err := spiffeid.TrustDomainFromString(sm.config.TrustDomain)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("invalid trust domain: %w", err)
	}

	sensorID, err := spiffeid.FromPath(trustDomain, fmt.Sprintf("/gpushield/sensor/%s", nodeID))
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("failed to create sensor ID: %w", err)
	}

	return sensorID, nil
}

// fetchIdentity fetches the current identity from SPIRE
func (sm *SPIFFEManager) fetchIdentity(ctx context.Context) error {
	sm.logger.Debug("Fetching SPIFFE identity")

	// Get SVID from source
	svid, err := sm.source.GetX509SVID()
	if err != nil {
		return fmt.Errorf("failed to get X509SVID: %w", err)
	}

	// Get trust bundle
	bundle, err := sm.source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		return fmt.Errorf("failed to get trust bundle: %w", err)
	}

	identity := &SPIFFEIdentity{
		ID:           svid.ID,
		Certificates: svid.Certificates,
		PrivateKey:   svid.PrivateKey,
		TrustBundle:  bundle.X509Authorities(),
		ExpiresAt:    svid.Certificates[0].NotAfter,
	}

	// Validate the identity
	if err := sm.ValidateIdentity(identity); err != nil {
		return fmt.Errorf("identity validation failed: %w", err)
	}

	sm.identity = identity
	sm.logger.WithFields(logrus.Fields{
		"spiffe_id":  identity.ID.String(),
		"expires_at": identity.ExpiresAt,
	}).Info("Successfully fetched SPIFFE identity")

	return nil
}

// watchIdentity watches for identity updates
func (sm *SPIFFEManager) watchIdentity(ctx context.Context) {
	sm.logger.Info("Starting SPIFFE identity watcher")

	// Create a context that can be cancelled
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Watch for updates using a ticker (simplified approach)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.stopCh:
			sm.logger.Info("Stopping SPIFFE identity watcher")
			return
		case <-ctx.Done():
			sm.logger.Info("Context cancelled, stopping SPIFFE identity watcher")
			return
		case <-ticker.C:
			if err := sm.fetchIdentity(watchCtx); err != nil {
				sm.logger.WithError(err).Error("Failed to refresh identity")
			}
		}
	}
}

// certificatesToDER converts certificates to DER format
func (sm *SPIFFEManager) certificatesToDER(certs []*x509.Certificate) [][]byte {
	var derCerts [][]byte
	for _, cert := range certs {
		derCerts = append(derCerts, cert.Raw)
	}
	return derCerts
}

// createCertPool creates a certificate pool from certificates
func (sm *SPIFFEManager) createCertPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

// IdentityInfo provides information about the current identity
type IdentityInfo struct {
	ID          string    `json:"id"`
	TrustDomain string    `json:"trust_domain"`
	Path        string    `json:"path"`
	ExpiresAt   time.Time `json:"expires_at"`
	IsValid     bool      `json:"is_valid"`
}

// GetIdentityInfo returns information about the current identity
func (sm *SPIFFEManager) GetIdentityInfo() *IdentityInfo {
	if sm.identity == nil {
		return &IdentityInfo{
			IsValid: false,
		}
	}

	return &IdentityInfo{
		ID:          sm.identity.ID.String(),
		TrustDomain: sm.identity.ID.TrustDomain().String(),
		Path:        sm.identity.ID.Path(),
		ExpiresAt:   sm.identity.ExpiresAt,
		IsValid:     sm.ValidateIdentity(sm.identity) == nil,
	}
}

// SPIFFEHTTPClient creates an HTTP client with SPIFFE authentication
func (sm *SPIFFEManager) SPIFFEHTTPClient(ctx context.Context, serverID spiffeid.ID) (*http.Client, error) {
	tlsConfig, err := sm.GetClientTLSConfig(ctx, serverID)
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS config: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

// VerifyPeerIdentity verifies the identity of a peer
func (sm *SPIFFEManager) VerifyPeerIdentity(peerCerts []*x509.Certificate, expectedID spiffeid.ID) error {
	if len(peerCerts) == 0 {
		return fmt.Errorf("no peer certificates provided")
	}

	// Extract SPIFFE ID from the first certificate
	peerID, err := x509svid.IDFromCert(peerCerts[0])
	if err != nil {
		return fmt.Errorf("failed to extract SPIFFE ID from peer certificate: %w", err)
	}

	if peerID.IsZero() {
		return fmt.Errorf("no SPIFFE ID found in peer certificate")
	}

	// Verify the peer ID matches expected
	if peerID.String() != expectedID.String() {
		return fmt.Errorf("peer ID %s does not match expected %s", peerID, expectedID)
	}

	// Verify the certificate chain against our trust bundle
	if sm.identity == nil {
		return fmt.Errorf("no local identity available for verification")
	}

	roots := sm.createCertPool(sm.identity.TrustBundle)
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err = peerCerts[0].Verify(opts)
	if err != nil {
		return fmt.Errorf("failed to verify peer certificate chain: %w", err)
	}

	return nil
}

// DefaultSPIFFEConfig returns a default SPIFFE configuration
func DefaultSPIFFEConfig(serviceName string) *SPIFFEConfig {
	return &SPIFFEConfig{
		SocketPath:    "unix:///tmp/spire-agent/public/api.sock",
		TrustDomain:   "gpushield.local",
		ServiceName:   serviceName,
		Timeout:       30 * time.Second,
		RetryInterval: 5 * time.Second,
		MaxRetries:    3,
	}
}

// ParseSocketPath parses and validates a SPIFFE socket path
func ParseSocketPath(socketPath string) (string, error) {
	if socketPath == "" {
		return "", fmt.Errorf("socket path cannot be empty")
	}

	// Parse as URL to validate format
	u, err := url.Parse(socketPath)
	if err != nil {
		return "", fmt.Errorf("invalid socket path format: %w", err)
	}

	// Support both unix:// and file:// schemes
	if u.Scheme != "unix" && u.Scheme != "file" {
		return "", fmt.Errorf("unsupported socket scheme: %s", u.Scheme)
	}

	return socketPath, nil
}
