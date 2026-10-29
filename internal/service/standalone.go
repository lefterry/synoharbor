package service

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/lefterry/synoharbor/internal/dsm"
	"github.com/lefterry/synoharbor/internal/model"
)

type StandaloneRequest struct {
	Hostname     string `json:"hostname"`
	Email        string `json:"email"`
	CredentialID string `json:"credentialId"`
	KeyType      string `json:"keyType"`
}
type StandaloneAccess struct {
	model.Meta
	Hostname      string `json:"hostname"`
	CertificateID string `json:"certificateId"`
	ProxyID       string `json:"proxyId"`
}

func (a *App) Standalone() StandaloneAccess {
	var v StandaloneAccess
	_ = a.Store.Get("standalone", "main", &v)
	return v
}

// Existing routes stay available when adding a replacement hostname. Retries
// reuse the durable profile/route; deployed certificates are never reissued.
func (a *App) SetupStandalone(ctx context.Context, req StandaloneRequest) (any, error) {
	if a.RecoveryPaused() {
		return nil, errors.New("finish recovery before configuring standalone access")
	}
	req.Hostname = strings.ToLower(strings.TrimSpace(req.Hostname))
	if !model.ValidDomain(req.Hostname, false) {
		return nil, errors.New("enter a fully qualified standalone hostname")
	}
	profile := model.CertificateProfile{Meta: model.Meta{ID: uuid.NewString()}, Domain: req.Hostname, Email: strings.TrimSpace(req.Email), CredentialID: req.CredentialID, KeyType: req.KeyType, Managed: true, AutoRenew: true, Status: "queued"}
	if e := profile.Validate(); e != nil {
		return nil, e
	}
	var credential model.Credential
	if a.Store.Get("credentials", req.CredentialID, &credential) != nil || !credential.Configured {
		return nil, errors.New("select a configured Cloudflare credential")
	}
	cfg := a.Settings()
	if !cfg.Connected {
		return nil, errors.New("connect the DSM deployment account first")
	}
	var certs []model.CertificateProfile
	var proxies []model.ProxyHost
	if e := a.Store.List("certificates", &certs); e != nil {
		return nil, e
	}
	if e := a.Store.List("proxies", &proxies); e != nil {
		return nil, e
	}
	host := model.ProxyHost{Meta: model.Meta{ID: uuid.NewString()}, AppUI: true, Hostname: req.Hostname, Target: model.Target{Scheme: "https", Host: "127.0.0.1", Port: cfg.Port}, Enabled: true, Managed: true, Status: "queued", Advanced: model.Advanced{ForceSSL: true, BodySizeMB: 2}}
	for _, p := range proxies {
		if p.Hostname == req.Hostname && !p.ExternalDeleted {
			if !p.AppUI || p.AdvancedBypassed {
				return nil, errors.New("this hostname already has a proxy; choose another hostname or review it in DSM")
			}
			host = p
			host.Enabled = true
			host.Target.Port = cfg.Port
		}
	}
	for _, p := range certs {
		if p.Domain == req.Hostname && !p.Staging && p.Managed && !p.ExternalDeleted {
			if p.KeyType != req.KeyType {
				return nil, errors.New("an existing certificate is reused with its current key type; edit it in Certificates to change key settings")
			}
			profile = p
		}
	}
	// A failed native read must never authorize creation or overwrite.
	if e := a.withDSM(ctx, false, "", func(c *dsm.Client) error {
		snap, e := c.Snapshot(ctx)
		if e != nil {
			return e
		}
		for _, p := range snap.Proxies {
			if dsm.String(dsm.Object(p, "frontend"), "fqdn") == req.Hostname && dsm.Number(dsm.Object(p, "frontend"), "port") == 443 && dsm.ID(p) != host.NativeID {
				return errors.New("a native DSM proxy already uses this hostname")
			}
		}
		return nil
	}); e != nil {
		return nil, e
	}
	profile.Email = strings.TrimSpace(req.Email)
	profile.CredentialID = req.CredentialID
	profile.AutoRenew = true
	host.CertificateID = profile.ID
	if host.LoopbackPort == 0 {
		port, e := a.AllocatePort(host.ID)
		if e != nil {
			return nil, e
		}
		host.LoopbackPort = port
	}
	if _, e := a.Preview(&host); e != nil {
		return nil, e
	}
	if e := a.Store.Put("certificates", &profile.Meta, &profile); e != nil {
		return nil, e
	}
	host.Status = "queued"
	if e := a.Store.Put("proxies", &host.Meta, &host); e != nil {
		return nil, e
	}
	state := a.Standalone()
	state.ID = "main"
	state.Hostname = host.Hostname
	state.CertificateID = profile.ID
	state.ProxyID = host.ID
	if e := a.Store.Put("standalone", &state.Meta, &state); e != nil {
		return nil, e
	}
	kind, id := "certificate.issue", profile.ID
	if profile.NativeID != "" && profile.PendingFingerprint == "" {
		kind, id = "proxy.apply", host.ID
	} else if profile.PendingFingerprint != "" {
		kind = "certificate.deploy"
	}
	op, e := a.Store.Enqueue(kind, id, nil)
	return map[string]any{"standalone": state, "operation": op}, e
}
