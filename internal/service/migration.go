package service

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/lefterry/synoharbor/internal/dsm"
	"github.com/lefterry/synoharbor/internal/model"
)

type MigrationService struct {
	Domain          string       `json:"domain"`
	Target          model.Target `json:"target"`
	AdoptExisting   bool         `json:"adoptExisting"`
	TrustSelfSigned bool         `json:"trustSelfSigned"`
}
type Migration struct {
	Email        string             `json:"email"`
	KeyType      string             `json:"keyType"`
	CredentialID string             `json:"credentialId"`
	Services     []MigrationService `json:"services"`
}
type MigrationResult struct {
	Domain        string `json:"domain"`
	CertificateID string `json:"certificateId"`
	ProxyID       string `json:"proxyId"`
	OperationID   string `json:"operationId"`
	Action        string `json:"action"`
}

func (a *App) Migrate(ctx context.Context, manifest Migration) ([]MigrationResult, error) {
	if !a.Settings().Connected {
		return nil, errors.New("complete the SynoHarbor DSM trusted-device sign-in before migrating services")
	}
	for _, s := range manifest.Services {
		if !model.ValidDomain(s.Domain, false) {
			return nil, errors.New("invalid migration domain")
		}
		if e := s.Target.Validate(); e != nil {
			return nil, e
		}
	}
	var credential model.Credential
	if e := a.Store.Get("credentials", manifest.CredentialID, &credential); e != nil {
		return nil, errors.New("select an existing Cloudflare credential")
	}
	var e error
	if e = a.Sync(ctx); e != nil {
		return nil, e
	}
	var snap model.DSMSnapshot
	if e = a.Store.Get("snapshot", "main", &snap); e != nil {
		return nil, e
	}
	out := []MigrationResult{}
	for _, service := range manifest.Services {
		var profiles []model.CertificateProfile
		_ = a.Store.List("certificates", &profiles)
		var profile model.CertificateProfile
		for _, p := range profiles {
			if p.Domain == service.Domain && !p.ExternalDeleted {
				profile = p
			}
		}
		var hosts []model.ProxyHost
		_ = a.Store.List("proxies", &hosts)
		var host model.ProxyHost
		for _, p := range hosts {
			if p.Hostname == service.Domain && !p.ExternalDeleted {
				host = p
			}
		}
		if profile.ID != "" && host.ID != "" {
			out = append(out, MigrationResult{Domain: service.Domain, CertificateID: profile.ID, ProxyID: host.ID, Action: "already configured"})
			continue
		}
		nativeID, nativeHash, nativeCertID := "", "", ""
		nativeHSTS := false
		for _, p := range snap.Proxies {
			front := dsm.Object(p, "frontend")
			if dsm.String(front, "fqdn") == service.Domain && dsm.Number(front, "port") == 443 {
				nativeID = dsm.ID(p)
				nativeHash = model.Hash(p)
				h := dsm.Object(front, "https")
				nativeHSTS, _ = h["hsts"].(bool)
			}
		}
		if service.AdoptExisting {
			if nativeID == "" {
				return out, errors.New("the requested native DSM proxy was not found for adoption")
			}
			for _, c := range snap.Certificates {
				services, _ := c["services"].([]any)
				for _, s := range services {
					v, _ := s.(map[string]any)
					if dsm.String(v, "subscriber") == "ReverseProxy" && dsm.String(v, "service") == nativeID {
						nativeCertID = dsm.ID(c)
					}
				}
			}
			if nativeCertID == "" {
				return out, errors.New("native SSL assignment unavailable")
			}
		} else if nativeID != "" {
			return out, errors.New("a native proxy already uses this hostname; explicitly adopt it")
		}
		if profile.ID == "" {
			profile = model.CertificateProfile{Meta: model.Meta{ID: uuid.NewString()}, Domain: service.Domain, Email: manifest.Email, KeyType: manifest.KeyType, CredentialID: manifest.CredentialID, Managed: true, AutoRenew: true, Status: "queued", NativeID: nativeCertID}
			if profile.KeyType == "" {
				profile.KeyType = "rsa4096"
			}
			if service.AdoptExisting {
				if e = a.AdoptCertificate(ctx, profile); e != nil {
					return out, e
				}
				if e = a.Store.Get("certificates", profile.ID, &profile); e != nil {
					return out, e
				}
			} else {
				if e = profile.Validate(); e != nil {
					return out, e
				}
				if e = a.Store.Put("certificates", &profile.Meta, &profile); e != nil {
					return out, e
				}
			}
		}
		if host.ID == "" {
			target := service.Target
			if service.TrustSelfSigned {
				if target.Scheme != "https" || target.Host != "127.0.0.1" {
					return out, errors.New("automatic migration pinning is restricted to an explicit HTTPS loopback upstream")
				}
				cert, e := CaptureCertificate(ctx, target)
				if e != nil {
					return out, e
				}
				target.TLS.TrustedPEM = cert
				target.TLS.Verify = true
			}
			host = model.ProxyHost{Meta: model.Meta{ID: uuid.NewString()}, Hostname: service.Domain, Target: target, CertificateID: profile.ID, NativeID: nativeID, NativeHash: nativeHash, Enabled: true, Managed: true, Status: "queued", Advanced: model.Advanced{WebSockets: true, ForceSSL: true, HSTS: nativeHSTS, IncludeSubdomains: nativeHSTS, ConnectTimeout: 60, ReadTimeout: 60, SendTimeout: 60, BodySizeMB: 128}}
			host.LoopbackPort, e = a.AllocatePort(host.ID)
			if e != nil {
				return out, e
			}
			if e = host.Validate(); e != nil {
				return out, e
			}
			if _, e = a.Preview(&host); e != nil {
				return out, e
			}
			if e = a.Store.Put("proxies", &host.Meta, &host); e != nil {
				return out, e
			}
		}
		kind := "certificate.issue"
		action := "issue independent SSL and create native proxy"
		objectID := profile.ID
		if service.AdoptExisting {
			token, e := a.credential(profile.CredentialID)
			if e != nil {
				return out, e
			}
			if e = a.ACME.Manage(ctx, profile, token); e != nil {
				return out, e
			}
			kind = "proxy.apply"
			objectID = host.ID
			action = "adopt existing SSL without reissuance; configure native Advanced proxy"
		}
		op, e := a.Store.Enqueue(kind, objectID, nil)
		if e != nil {
			return out, e
		}
		out = append(out, MigrationResult{Domain: service.Domain, CertificateID: profile.ID, ProxyID: host.ID, OperationID: op.ID, Action: action})
	}
	return out, nil
}
func CaptureCertificate(ctx context.Context, target model.Target) (string, error) {
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{InsecureSkipVerify: true}}
	conn, e := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	if e != nil {
		return "", errors.New("cannot read upstream TLS certificate")
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("upstream certificate missing")
	}
	leaf := state.PeerCertificates[0]
	if leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil {
		return "", errors.New("upstream is not self-signed; use the public trust chain or provide an explicit CA")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})), nil
}
