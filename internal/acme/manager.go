// ACME configuration adapted from DNSACME; modified for independent profiles.
// Apache-2.0, copyright DNSACME contributors and SynoHarbor contributors.
package acme

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/caddyserver/certmagic"
	"github.com/lefterry/synoharbor/internal/model"
	"github.com/libdns/cloudflare"
	"go.uber.org/zap"
)

type runtime struct {
	config *certmagic.Config
	cache  *certmagic.Cache
	issuer *certmagic.ACMEIssuer
	key    string
	ctx    context.Context
	cancel context.CancelFunc
}
type Manager struct {
	Dir     string
	Issued  func(string)
	Allowed func(string) bool
	mu      sync.Mutex
	active  map[string]*runtime
}

func New(dir string, issued func(string)) *Manager {
	return &Manager{Dir: dir, Issued: issued, active: map[string]*runtime{}}
}
func (m *Manager) get(p model.CertificateProfile, token string) (*runtime, error) {
	if !model.ValidID(p.ID) {
		return nil, errors.New("invalid profile ID")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Allowed != nil && !m.Allowed(p.ID) {
		return nil, errors.New("certificate management was stopped")
	}
	key := model.Hash([]any{p.Domain, p.Email, p.KeyType, p.Staging, token})
	if r := m.active[p.ID]; r != nil {
		if r.key == key {
			return r, nil
		}
		r.cancel()
		r.cache.Stop()
		delete(m.active, p.ID)
	}
	dir := filepath.Join(m.Dir, p.ID)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	// Discard raw provider/ACME logs: responses may contain tokens. Operation
	// stages and sanitized failures are recorded by the worker instead.
	log := zap.NewNop()
	var cfg *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
		if m.Allowed != nil && !m.Allowed(p.ID) {
			return nil, errors.New("profile no longer managed")
		}
		return cfg, nil
	}, Logger: log})
	cfg = certmagic.New(cache, certmagic.Config{Storage: &certmagic.FileStorage{Path: dir}, KeySource: certmagic.StandardKeyGenerator{KeyType: certmagic.KeyType(p.KeyType)}, Logger: log, OnEvent: func(ctx context.Context, event string, data map[string]any) error {
		if event == "cert_obtained" && m.Issued != nil {
			m.Issued(p.ID)
		}
		return nil
	}})
	issuer := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{Email: p.Email, Agreed: true, DisableHTTPChallenge: true, DisableTLSALPNChallenge: true, DNS01Solver: &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{DNSProvider: &cloudflare.Provider{APIToken: token}}}, Logger: log})
	issuer.CA = certmagic.LetsEncryptProductionCA
	if p.Staging {
		issuer.CA = certmagic.LetsEncryptStagingCA
	}
	cfg.Issuers = []certmagic.Issuer{issuer}
	runtimeCtx, cancel := context.WithCancel(context.Background())
	r := &runtime{config: cfg, cache: cache, issuer: issuer, key: key, ctx: runtimeCtx, cancel: cancel}
	m.active[p.ID] = r
	return r, nil
}
func (m *Manager) Obtain(ctx context.Context, p model.CertificateProfile, token string, force bool) error {
	r, e := m.get(p, token)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	if force {
		e = r.config.RenewCertSync(ctx, p.Domain, true)
	} else {
		e = r.config.ManageSync(ctx, []string{p.Domain})
	}
	if e != nil {
		return errors.New("ACME issuance failed; check DNS-01 token permissions, domain and outbound DNS connectivity")
	}
	return nil
}
func (m *Manager) Manage(ctx context.Context, p model.CertificateProfile, token string) error {
	r, e := m.get(p, token)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	if e = r.config.ManageSync(ctx, []string{p.Domain}); e != nil {
		return errors.New("automatic certificate management failed")
	}
	return nil
}
func (m *Manager) Material(ctx context.Context, p model.CertificateProfile, token string) ([]byte, []byte, error) {
	r, e := m.get(p, token)
	if e != nil {
		return nil, nil, e
	}
	cert, e := r.config.Storage.Load(ctx, certmagic.StorageKeys.SiteCert(r.issuer.IssuerKey(), p.Domain))
	if e != nil {
		return nil, nil, e
	}
	key, e := r.config.Storage.Load(ctx, certmagic.StorageKeys.SitePrivateKey(r.issuer.IssuerKey(), p.Domain))
	return cert, key, e
}
func (m *Manager) Adopt(ctx context.Context, p model.CertificateProfile, token string, cert, key []byte) error {
	r, e := m.get(p, token)
	if e != nil {
		return e
	}
	meta, _ := json.Marshal(certmagic.CertificateResource{SANs: []string{p.Domain}})
	for storageKey, b := range map[string][]byte{certmagic.StorageKeys.SiteCert(r.issuer.IssuerKey(), p.Domain): cert, certmagic.StorageKeys.SitePrivateKey(r.issuer.IssuerKey(), p.Domain): key, certmagic.StorageKeys.SiteMeta(r.issuer.IssuerKey(), p.Domain): meta} {
		if e = r.config.Storage.Store(ctx, storageKey, b); e != nil {
			return e
		}
	}
	return nil
}
func (m *Manager) Stop(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.active[id]; r != nil {
		r.cancel()
		r.cache.Stop()
		delete(m.active, id)
	}
}
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.active {
		r.cancel()
		r.cache.Stop()
	}
	m.active = map[string]*runtime{}
}
