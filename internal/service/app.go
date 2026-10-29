package service

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lefterry/synoharbor/internal/acme"
	"github.com/lefterry/synoharbor/internal/broker"
	"github.com/lefterry/synoharbor/internal/dsm"
	"github.com/lefterry/synoharbor/internal/model"
	"github.com/lefterry/synoharbor/internal/nginx"
	"github.com/lefterry/synoharbor/internal/store"
)

type App struct {
	Store    *store.Store
	Broker   broker.Client
	ACME     *acme.Manager
	dsmMu    sync.Mutex
	renewMu  sync.Mutex
	renewing map[string]bool
	NewDSM   func(model.Settings, model.ConnectionSecret) *dsm.Client
}

func New(s *store.Store) *App {
	a := &App{Store: s, renewing: map[string]bool{}, NewDSM: dsm.New}
	a.ACME = acme.New(filepath.Join(s.Dir, "acme"), func(id string) {
		var p model.CertificateProfile
		if s.Get("certificates", id, &p) == nil && p.Status != "issuing" && p.Status != "replacing" && p.Status != "linking" {
			_, _ = s.Enqueue("certificate.deploy", id, nil)
		}
	})
	a.ACME.Allowed = func(id string) bool {
		var p model.CertificateProfile
		return s.Get("certificates", id, &p) == nil && p.Managed && !p.ExternalDeleted
	}
	return a
}
func (a *App) Settings() model.Settings {
	var s model.Settings
	if a.Store.Get("settings", "main", &s) != nil {
		s.ID = "main"
		s.Port = 5001
		s.Theme = "system"
	}
	return s
}
func (a *App) withDSM(ctx context.Context, interactive bool, otp string, fn func(*dsm.Client) error) error {
	a.dsmMu.Lock()
	defer a.dsmMu.Unlock()
	s := a.Settings()
	if s.AuthStatus == "reauth_required" && !interactive {
		return errors.New("DSM sign-in is required; automatic logins are paused")
	}
	var secret model.ConnectionSecret
	if a.Store.Secret("dsm", &secret) != nil || secret.Password == "" {
		return errors.New("configure the DSM connection in Settings")
	}
	c := a.NewDSM(s, secret)
	err := c.Login(ctx, otp)
	s.CheckedAt = time.Now().UTC()
	if err != nil {
		s.AuthMessage = err.Error()
		s.AuthStatus = "error"
		s.Connected = false
		if dsm.TerminalAuth(err) {
			s.AuthStatus = "reauth_required"
			if prev := a.Settings(); prev.AuthStatus != "reauth_required" {
				_ = a.Broker.Call(ctx, broker.Request{Action: "notify", Message: "DSM sign-in needs attention. Open SynoHarbor Settings to restore certificate deployment."}, nil)
			}
		}
		_ = a.Store.Put("settings", &s.Meta, &s)
		return err
	}
	defer c.Logout(context.Background())
	s.Connected = true
	s.AuthStatus = "ready"
	s.AuthMessage = "Trusted device ready"
	if err = a.Store.PutSecretObject("settings", &s.Meta, &s, "dsm", c.Secret); err != nil {
		return err
	}
	return fn(c)
}
func (a *App) Connect(ctx context.Context, account, password, otp string, port int) error {
	if account == "" || port < 1 || port > 65535 {
		return errors.New("enter a DSM administrator account and HTTPS management port")
	}
	s := a.Settings()
	var secret model.ConnectionSecret
	_ = a.Store.Secret("dsm", &secret)
	if password != "" {
		if secret.Password != password {
			secret.DeviceID = ""
			secret.DeviceName = ""
		}
		secret.Password = password
	}
	if s.Account != account || s.Port != port {
		secret.DeviceID = ""
		secret.DeviceName = ""
	}
	s.Account, s.Port = account, port
	s.AuthStatus = "connecting"
	s.Connected = false
	if e := a.Store.PutSecretObject("settings", &s.Meta, &s, "dsm", secret); e != nil {
		return e
	}
	return a.withDSM(ctx, true, otp, func(*dsm.Client) error { return nil })
}
func (a *App) Sync(ctx context.Context) error {
	return a.withDSM(ctx, false, "", func(c *dsm.Client) error {
		snap, e := c.Snapshot(ctx)
		if e != nil {
			var previous model.DSMSnapshot
			if a.Store.Get("snapshot", "main", &previous) == nil {
				previous.Error = e.Error()
				_ = a.Store.Put("snapshot", &previous.Meta, &previous)
			}
			return e
		}
		var prev model.DSMSnapshot
		_ = a.Store.Get("snapshot", "main", &prev)
		snap.Meta = prev.Meta
		snap.ID = "main"
		if enabled, err := c.HTTP2(ctx); err == nil {
			snap.HTTP2 = enabled
		}

		if e = a.Store.Put("snapshot", &snap.Meta, &snap); e != nil {
			return e
		}
		err := a.reconcile(ctx, snap)
		if err != nil {
			snap.Error = err.Error()
			_ = a.Store.Put("snapshot", &snap.Meta, &snap)
		}
		return err
	})
}
func (a *App) reconcile(ctx context.Context, snap model.DSMSnapshot) error {
	certs := map[string]model.DSMObject{}
	proxies := map[string]model.DSMObject{}
	for _, o := range snap.Certificates {
		certs[dsm.ID(o)] = o
	}
	for _, o := range snap.Proxies {
		proxies[dsm.ID(o)] = o
	}
	var profiles []model.CertificateProfile
	var hosts []model.ProxyHost
	if e := a.Store.List("certificates", &profiles); e != nil {
		return e
	}
	if e := a.Store.List("proxies", &hosts); e != nil {
		return e
	}
	for _, p := range profiles {
		if p.NativeID == "" || p.ExternalDeleted {
			continue
		}
		if _, ok := certs[p.NativeID]; !ok {
			if e := a.markRemoved("certificate", p.NativeID); e != nil {
				return e
			}
			p.ExternalDeleted = true
			p.AutoRenew = false
			p.Status = "deleted_in_dsm"
			p.Message = "Removed from DSM; renewal stopped"
			if e := a.Store.Put("certificates", &p.Meta, &p); e != nil {
				return e
			}
			a.ACME.Stop(p.ID)
		} else if p.Fingerprint != "" && p.Managed {
			var material map[string]string
			if err := a.Broker.Call(ctx, broker.Request{Action: "native-certificate-info", ID: p.NativeID}, &material); err != nil {
				return err
			}
			fingerprint, leaf, err := dsm.Fingerprint([]byte(material["certificate"]))
			if err != nil {
				return err
			}
			if fingerprint != p.Fingerprint && fingerprint != p.PendingFingerprint {
				p.Fingerprint = fingerprint
				p.ExpiresAt = leaf.NotAfter
				p.Issuer = leaf.Issuer.CommonName
				p.AutoRenew = false
				p.Managed = false
				p.PendingFingerprint = ""
				p.Status = "changed_in_dsm"
				p.Message = "Native certificate replacement adopted; review this profile before resuming ACME management"
				if len(leaf.DNSNames) == 1 && model.ValidDomain(leaf.DNSNames[0], true) {
					p.Domain = leaf.DNSNames[0]
				}
				if err = a.Store.Put("certificates", &p.Meta, &p); err != nil {
					return err
				}
				a.ACME.Stop(p.ID)
			}
		}
	}
	for _, p := range hosts {
		if p.ExternalDeleted {
			message := "Removed in DSM"
			if len(dependentProxies(snap, p)) > 0 {
				message = "Native proxy removed; Advanced rules retained for dependent DSM proxies"
			}
			if p.Message != message {
				p.Message = message
				if e := a.Store.Put("proxies", &p.Meta, &p); e != nil {
					return e
				}
			}
			continue
		}
		if p.NativeID == "" || p.ExternalDeleted || !p.Enabled || p.Status == "applying" || p.Status == "queued" {
			continue
		}
		o, ok := proxies[p.NativeID]
		if !ok {
			if e := a.markRemoved("proxy", p.ID); e != nil {
				return e
			}
			p.ExternalDeleted = true
			p.Enabled = false
			p.Managed = false
			p.Status = "deleted_in_dsm"
			p.Message = "Removed in DSM"
			if len(dependentProxies(snap, p)) > 0 {
				p.Message = "Native proxy removed; Advanced rules retained for dependent DSM proxies"
			}
			if e := a.Store.Put("proxies", &p.Meta, &p); e != nil {
				return e
			}
			continue
		}
		bindingChanged := false
		actualCertificate := certificateFor(snap, p.NativeID)
		for _, profile := range profiles {
			if profile.ID == p.CertificateID && profile.NativeID != actualCertificate && actualCertificate != "" {
				p.CertificateID = ""
				for _, candidate := range profiles {
					if candidate.NativeID == actualCertificate {
						p.CertificateID = candidate.ID
					}
				}
				p.HTTPSVerified = false
				p.Status = "changed_in_dsm"
				p.Message = "Native SSL assignment changed in DSM; adopted without rebinding"
				bindingChanged = true
				break
			}
		}
		hash := model.Hash(o)
		if hash != p.NativeHash {
			f, b := dsm.Object(o, "frontend"), dsm.Object(o, "backend")
			if hostname := dsm.String(f, "fqdn"); model.ValidDomain(hostname, false) {
				p.Hostname = hostname
			}
			nativeManaged := dsm.String(b, "fqdn") == "127.0.0.1" && dsm.Number(b, "port") == p.LoopbackPort && dsm.Number(b, "protocol") == 0
			if !nativeManaged {
				p.AdvancedBypassed = true
				p.HTTPSVerified = false
				p.Target = model.Target{Scheme: "http", Host: dsm.String(b, "fqdn"), Port: dsm.Number(b, "port")}
				if dsm.Number(b, "protocol") == 1 {
					p.Target.Scheme = "https"
				}
				p.Status = "advanced_bypassed"
				p.Message = "Target changed in DSM; Advanced rules are detached"
			} else {
				p.Status = "changed_in_dsm"
				p.Message = "Native DSM changes adopted"
			}
			p.NativeHash = hash
			if e := a.Store.Put("proxies", &p.Meta, &p); e != nil {
				return e
			}
		} else if bindingChanged {
			if e := a.Store.Put("proxies", &p.Meta, &p); e != nil {
				return e
			}
		}
	}
	// Also retry a previously interrupted rules update and retire orphaned
	// listeners once their final native dependency disappears. The broker skips
	// unchanged bundles, so ordinary refreshes do not reload nginx.
	return a.ApplyRules(ctx)
}
func (a *App) RenderInput() (nginx.Input, error) {
	in := nginx.Input{Access: map[string]model.AccessList{}, Passwords: map[string]map[string]string{}}
	if e := a.Store.List("proxies", &in.Hosts); e != nil {
		return in, e
	}
	active := []model.ProxyHost{}
	var snapshot model.DSMSnapshot
	_ = a.Store.Get("snapshot", "main", &snapshot)
	for _, p := range in.Hosts {
		inactive := p.ExternalDeleted || !p.Managed || p.AdvancedBypassed || !p.Enabled
		if inactive && len(dependentProxies(snapshot, p)) == 0 {
			continue
		}
		var applied model.ProxyHost
		if a.Store.Get("applied-proxies", p.ID, &applied) == nil {
			if inactive {
				applied.Advanced.ForceSSL = false
			}
			active = append(active, applied)
		}
	}
	in.Hosts = active
	var access []model.AccessList
	if e := a.Store.List("access", &access); e != nil {
		return in, e
	}
	for _, v := range access {
		in.Access[v.ID] = v
		var hashes map[string]string
		if len(v.Users) > 0 {
			if e := a.Store.Secret("access:"+v.ID, &hashes); e != nil {
				return in, e
			}
		}
		in.Passwords[v.ID] = hashes
	}
	return in, nil
}
func dependentProxies(snap model.DSMSnapshot, p model.ProxyHost) []string {
	ids := []string{}
	if p.LoopbackPort == 0 {
		return ids
	}
	for _, o := range snap.Proxies {
		b := dsm.Object(o, "backend")
		if dsm.ID(o) != p.NativeID && dsm.String(b, "fqdn") == "127.0.0.1" && dsm.Number(b, "port") == p.LoopbackPort {
			ids = append(ids, dsm.ID(o))
		}
	}
	return ids
}
func (a *App) ApplyRules(ctx context.Context) error { return a.applyRulesFor(ctx, nil) }
func (a *App) applyRulesFor(ctx context.Context, p *model.ProxyHost) error {
	in, e := a.RenderInput()
	if e != nil {
		return e
	}
	if p != nil && !p.Enabled {
		var snapshot model.DSMSnapshot
		_ = a.Store.Get("snapshot", "main", &snapshot)
		if len(dependentProxies(snapshot, *p)) > 0 {
			var previous model.ProxyHost
			if a.Store.Get("applied-proxies", p.ID, &previous) == nil {
				previous.Advanced.ForceSSL = false
				p = &previous
			}
		}
	}
	if p != nil {
		found := false
		for i, h := range in.Hosts {
			if h.ID == p.ID {
				in.Hosts[i] = *p
				found = true
			}
		}
		if !found {
			in.Hosts = append(in.Hosts, *p)
		}
	}
	if e = a.Broker.Call(ctx, broker.Request{Action: "apply", Config: in}, nil); e != nil {
		return e
	}
	if p != nil {
		applied := *p
		var previous model.ProxyHost
		_ = a.Store.Get("applied-proxies", p.ID, &previous)
		applied.Version = previous.Version
		return a.Store.Put("applied-proxies", &applied.Meta, &applied)
	}
	return nil
}

func (a *App) Preview(p *model.ProxyHost) (any, error) {
	in, e := a.RenderInput()
	if e != nil {
		return nil, e
	}
	if p != nil {
		found := false
		for i, v := range in.Hosts {
			if v.ID == p.ID {
				in.Hosts[i] = *p
				found = true
			}
		}
		if !found {
			in.Hosts = append(in.Hosts, *p)
		}
	}
	b, e := nginx.Render(in)
	if e != nil {
		return nil, e
	}
	return map[string]any{"nginx": b.Config, "files": nginx.FileNames(b), "nativeProxy": func() any {
		if p == nil {
			return nil
		}
		return dsm.ProxyEntry(*p)
	}(), "scope": "Owned SynoHarbor nginx rules and the listed native DSM objects"}, nil
}
func (a *App) credential(id string) (string, error) {
	var token string
	if e := a.Store.Secret("cloudflare:"+id, &token); e != nil || token == "" {
		return "", errors.New("Cloudflare credential unavailable")
	}
	return token, nil
}
func (a *App) Certificate(ctx context.Context, id string, renew, deployOnly bool) error {
	var p model.CertificateProfile
	if e := a.Store.Get("certificates", id, &p); e != nil {
		return e
	}
	if p.ExternalDeleted || !p.Managed {
		return errors.New("certificate is not actively managed")
	}
	token, e := a.credential(p.CredentialID)
	if e != nil {
		return e
	}
	if !deployOnly {
		p.Status = "issuing"
		if e = a.Store.Put("certificates", &p.Meta, &p); e != nil {
			return e
		}
		if e = a.ACME.Obtain(ctx, p, token, renew); e != nil {
			p.Status = "error"
			p.Message = e.Error()
			_ = a.Store.Put("certificates", &p.Meta, &p)
			return e
		}
	}
	cert, key, e := a.ACME.Material(ctx, p, token)
	if e != nil {
		return errors.New("stored certificate unavailable; issue it first")
	}
	fingerprint, leaf, e := dsm.Fingerprint(cert)
	if e != nil {
		return e
	}
	if deployOnly && p.NativeID != "" && p.Fingerprint == fingerprint && p.PendingFingerprint == "" {
		return nil
	}
	p.PendingFingerprint = fingerprint
	p.ExpiresAt = leaf.NotAfter
	p.Issuer = leaf.Issuer.CommonName
	p.Status = "deployment_pending"
	p.Message = "Certificate stored; DSM deployment pending"
	if e = a.Store.Put("certificates", &p.Meta, &p); e != nil {
		return e
	}
	e = a.withDSM(ctx, false, "", func(c *dsm.Client) error {
		// Prove an existing native object still exists before attempting replacement.
		snap, e := c.Snapshot(ctx)
		if e != nil {
			return e
		}
		if p.NativeID != "" {
			found := false
			for _, o := range snap.Certificates {
				found = found || dsm.ID(o) == p.NativeID
			}
			if !found {
				a.ACME.Stop(p.ID)
				p.ExternalDeleted = true
				p.AutoRenew = false
				return errors.New("certificate was removed in DSM; automatic recreation stopped")
			}
			var current map[string]string
			if e = a.Broker.Call(ctx, broker.Request{Action: "native-certificate-info", ID: p.NativeID}, &current); e != nil {
				return e
			}
			fp, _, err := dsm.Fingerprint([]byte(current["certificate"]))
			if err != nil {
				return err
			}
			if p.Fingerprint != "" && fp != p.Fingerprint && fp != p.PendingFingerprint {
				p.Managed = false
				p.AutoRenew = false
				p.Status = "changed_in_dsm"
				p.PendingFingerprint = ""
				a.ACME.Stop(p.ID)
				return errors.New("certificate changed in DSM; automatic replacement stopped")
			}
			if e = a.rememberCertificate(ctx, snap, p.NativeID); e != nil {
				return e
			}
		}
		// Recover a successful native import whose ID persistence was interrupted.
		if p.NativeID == "" {
			desc := "SynoHarbor: " + p.Domain + " [" + p.ID + "]"
			for _, o := range snap.Certificates {
				if dsm.String(o, "desc") == desc {
					var material map[string]string
					if e = a.Broker.Call(ctx, broker.Request{Action: "native-certificate-info", ID: dsm.ID(o)}, &material); e != nil {
						return e
					}
					fp, _, err := dsm.Fingerprint([]byte(material["certificate"]))
					if err != nil || fp != fingerprint {
						return errors.New("a different native certificate already uses this profile identity")
					}
					p.NativeID = dsm.ID(o)
				}
			}
		}
		nativeID, e := c.ImportCertificate(ctx, p.NativeID, "SynoHarbor: "+p.Domain+" ["+p.ID+"]", key, cert)
		if e != nil {
			return e
		}
		p.NativeID = nativeID
		p.Fingerprint = fingerprint
		if e = a.recordCertificate(p); e != nil {
			return e
		}
		p.PendingFingerprint = ""
		p.LastDeployed = time.Now().UTC()
		p.Status = "ready"
		p.Message = "Certificate deployed"
		return a.Store.Put("certificates", &p.Meta, &p)
	})
	if e != nil {
		p.Message = e.Error()
		if p.ExternalDeleted {
			p.Status = "deleted_in_dsm"
		}
		_ = a.Store.Put("certificates", &p.Meta, &p)
		return e
	}
	var hosts []model.ProxyHost
	_ = a.Store.List("proxies", &hosts)
	for _, h := range hosts {
		if h.CertificateID == p.ID && h.Enabled && !h.ExternalDeleted && (h.NativeID == "" || h.Status == "queued") {
			_, _ = a.Store.Enqueue("proxy.apply", h.ID, nil)
		}
	}
	return nil
}
func (a *App) AllocatePort(id string) (int, error) { return a.Store.ReservePort(id) }

func (a *App) Proxy(ctx context.Context, id string) error {
	var p model.ProxyHost
	if e := a.Store.Get("proxies", id, &p); e != nil {
		return e
	}
	if p.ExternalDeleted {
		return errors.New("proxy was deleted in DSM; explicitly adopt or create a new host")
	}
	var cert model.CertificateProfile
	if e := a.Store.Get("certificates", p.CertificateID, &cert); e != nil {
		return errors.New("select a managed certificate")
	}
	if cert.Staging {
		return errors.New("staging certificates cannot be used by a production proxy")
	}
	if cert.NativeID == "" || cert.ExternalDeleted || cert.PendingFingerprint != "" {
		return errors.New("certificate must be deployed first")
	}
	if !model.Covers(cert.Domain, p.Hostname) {
		return errors.New("certificate does not cover this hostname")
	}
	p.Managed = true
	p.AdvancedBypassed = false
	p.Status = "applying"
	p.Message = ""
	if p.LoopbackPort == 0 {
		port, e := a.AllocatePort(p.ID)
		if e != nil {
			return e
		}
		p.LoopbackPort = port
	}
	if e := p.Validate(); e != nil {
		return e
	}
	if e := a.Store.Put("proxies", &p.Meta, &p); e != nil {
		return e
	}
	if e := a.applyRulesFor(ctx, &p); e != nil {
		p.Status = "error"
		p.Message = e.Error()
		_ = a.Store.Put("proxies", &p.Meta, &p)
		return e
	}
	e := a.withDSM(ctx, false, "", func(c *dsm.Client) error {
		snap, e := c.Snapshot(ctx)
		if e != nil {
			return e
		}
		if e = a.rememberProxy(snap, p); e != nil {
			return e
		}
		if p.NativeID == "" && p.Enabled {
			for _, o := range snap.Proxies {
				front, back := dsm.Object(o, "frontend"), dsm.Object(o, "backend")
				if dsm.String(front, "fqdn") != p.Hostname || dsm.Number(front, "port") != 443 {
					continue
				}
				if dsm.String(o, "description") != "SynoHarbor: "+p.Hostname || dsm.String(back, "fqdn") != "127.0.0.1" || dsm.Number(back, "port") != p.LoopbackPort {
					return errors.New("another native proxy already uses this hostname")
				}
				p.NativeID = dsm.ID(o)
			}
		}
		if p.NativeID != "" {
			found := false
			for _, o := range snap.Proxies {
				if dsm.ID(o) == p.NativeID {
					found = true
					if p.NativeHash != "" && model.Hash(o) != p.NativeHash {
						var own NativeChange
						_ = a.Store.Get("native-changes", "proxy-"+p.ID, &own)
						if own.ExpectedHash != model.Hash(o) {
							return errors.New("proxy changed in DSM; refresh before applying this edit")
						}
					}
				}
			}
			if !found {
				return errors.New("proxy was removed in DSM; refresh before editing")
			}
		}
		if !p.Enabled {
			if p.NativeID != "" {
				if e = c.DeleteProxy(ctx, p.NativeID); e != nil {
					return e
				}
			}
			p.NativeID = ""
			current, e := c.Snapshot(ctx)
			if e != nil {
				return e
			}
			var previous model.DSMSnapshot
			_ = a.Store.Get("snapshot", "main", &previous)
			current.Meta = previous.Meta
			current.ID = "main"
			current.HTTP2 = previous.HTTP2
			if e = a.Store.Put("snapshot", &current.Meta, &current); e != nil {
				return e
			}
			p.Status = "disabled"
			if len(dependentProxies(current, p)) > 0 {
				p.Message = "Proxy disabled; internal rules retained for dependent DSM routes"
			}
			p.HTTPSVerified = false
			return a.Store.Put("proxies", &p.Meta, &p)
		}
		nativeID, e := c.SaveProxy(ctx, p)
		if e != nil {
			return e
		}
		p.NativeID = nativeID
		// Persist the native ID before binding, so retry never creates a second host.
		if e = a.Store.Put("proxies", &p.Meta, &p); e != nil {
			return e
		}
		written, e := c.Snapshot(ctx)
		if e != nil {
			return e
		}
		for _, o := range written.Proxies {
			if dsm.ID(o) == p.NativeID {
				if e = a.recordProxy(p, o); e != nil {
					return e
				}
			}
		}
		if e = c.Bind(ctx, cert.NativeID, p.NativeID); e != nil {
			return e
		}
		current, e := c.Snapshot(ctx)
		if e != nil {
			return e
		}
		for _, o := range current.Proxies {
			if dsm.ID(o) == p.NativeID {
				p.NativeHash = model.Hash(o)
				if e = a.recordProxy(p, o); e != nil {
					return e
				}
			}
		}
		return nil
	})
	if e == nil && p.Enabled {
		// DSM may return before nginx has completed its native certificate reload.
		// Keep this operation applying while fresh connections observe the binding.
		e = WaitHTTPS(ctx, p, cert.Fingerprint, time.Minute)
		if e == nil {
			p.HTTPSVerified = true
			p.Status = "ready"
			p.Message = "HTTPS verified on this NAS"
		}
	}
	if e != nil {
		p.Status = "error"
		p.Message = e.Error()
	}
	if save := a.Store.Put("proxies", &p.Meta, &p); save != nil {
		return save
	}
	if e != nil {
		return e
	}
	return a.applyRulesFor(ctx, &p)
}
func WaitHTTPS(ctx context.Context, p model.ProxyHost, fingerprint string, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	var last error
	for {
		probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		last = VerifyHTTPS(probeCtx, p, fingerprint)
		cancel()
		if last == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return last
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
func VerifyHTTPS(ctx context.Context, p model.ProxyHost, fingerprint string) error {
	roots, e := x509.SystemCertPool()
	if e != nil {
		return e
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: p.Hostname, RootCAs: roots}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", "127.0.0.1:443")
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+p.Hostname+"/", nil)
	resp, e := client.Do(req)
	if e != nil {
		return errors.New("HTTPS verification failed; check SSL binding and upstream connectivity")
	}
	defer resp.Body.Close()
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return errors.New("TLS certificate missing")
	}
	// Native certificate identity is checked independently from hostname validity.
	actual := fmt.Sprintf("%x", sha256Sum(resp.TLS.PeerCertificates[0].Raw))
	if fingerprint != "" && actual != fingerprint {
		return errors.New("DSM serves a different certificate; check the SSL service binding")
	}
	if resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 {
		return errors.New("HTTPS is valid but the upstream service is unavailable")
	}
	return nil
}
func (a *App) AdoptCertificate(ctx context.Context, p model.CertificateProfile) error {
	if p.NativeID == "" {
		return errors.New("select a native DSM certificate")
	}
	if e := p.Validate(); e != nil {
		return e
	}
	if e := a.withDSM(ctx, false, "", func(c *dsm.Client) error {
		snap, e := c.Snapshot(ctx)
		if e != nil {
			return e
		}
		return a.rememberCertificate(ctx, snap, p.NativeID)
	}); e != nil {
		return e
	}
	var material map[string]string
	if e := a.Broker.Call(ctx, broker.Request{Action: "native-certificate", ID: p.NativeID}, &material); e != nil {
		return e
	}
	fingerprint, leaf, e := dsm.Fingerprint([]byte(material["certificate"]))
	if e != nil {
		return e
	}
	check := p.Domain
	if strings.HasPrefix(check, "*.") {
		check = "adoption-check." + strings.TrimPrefix(check, "*.")
	}
	if e = leaf.VerifyHostname(check); e != nil {
		return errors.New("native certificate does not cover this profile")
	}
	p.Managed = true
	p.AutoRenew = true
	p.Fingerprint = fingerprint
	p.ExpiresAt = leaf.NotAfter
	p.Issuer = leaf.Issuer.CommonName
	p.Status = "ready"
	p.Message = "Adopted from DSM without reissuance"
	if e = a.Store.Put("certificates", &p.Meta, &p); e != nil {
		return e
	}
	token, e := a.credential(p.CredentialID)
	if e != nil {
		return e
	}
	return a.ACME.Adopt(ctx, p, token, []byte(material["certificate"]), []byte(material["key"]))
}
func (a *App) DeletePreview(kind, id string) (any, error) {
	var snap model.DSMSnapshot
	_ = a.Store.Get("snapshot", "main", &snap)
	if kind == "proxies" {
		var p model.ProxyHost
		if e := a.Store.Get(kind, id, &p); e != nil {
			return nil, e
		}
		deps := dependentProxies(snap, p)
		preview := map[string]any{"proxyId": p.NativeID, "hostname": p.Hostname, "certificate": "Preserved; certificates are deleted separately", "advancedRules": p.Managed, "dependentNativeProxies": deps, "blocked": len(deps) > 0}
		if p.AppUI {
			preview["accessWarning"] = "This removes the standalone SynoHarbor address. Open the app from the DSM desktop to configure access again."
		}
		return preview, nil
	}
	var cert model.CertificateProfile
	if e := a.Store.Get("certificates", id, &cert); e != nil {
		return nil, e
	}
	var hosts []model.ProxyHost
	_ = a.Store.List("proxies", &hosts)
	used := []string{}
	for _, p := range hosts {
		if p.CertificateID == id && !p.ExternalDeleted {
			used = append(used, p.Hostname)
		}
	}
	native := []any{}
	for _, o := range snap.Certificates {
		if dsm.ID(o) == cert.NativeID {
			if s, ok := o["services"].([]any); ok {
				native = s
			}
		}
	}
	return map[string]any{"certificateId": cert.NativeID, "domain": cert.Domain, "proxyHosts": used, "nativeServices": native, "blocked": len(used) > 0 || len(native) > 0}, nil
}
func (a *App) Delete(ctx context.Context, kind, id string) error {
	if kind == "proxies" {
		var p model.ProxyHost
		if e := a.Store.Get(kind, id, &p); e != nil {
			return e
		}
		if e := a.withDSM(ctx, false, "", func(c *dsm.Client) error {
			snap, e := c.Snapshot(ctx)
			if e != nil {
				return e
			}
			if len(dependentProxies(snap, p)) > 0 {
				return errors.New("other DSM proxies depend on this Advanced listener; edit or adopt those routes before deleting it")
			}
			return nil
		}); e != nil {
			return e
		}
		if p.NativeID != "" && !p.ExternalDeleted {
			if e := a.withDSM(ctx, false, "", func(c *dsm.Client) error { return c.DeleteProxy(ctx, p.NativeID) }); e != nil {
				return e
			}
			if e := a.markRemoved("proxy", p.ID); e != nil {
				return e
			}
		}
		p.Enabled = false
		p.Managed = false
		if e := a.Store.Put(kind, &p.Meta, &p); e != nil {
			return e
		}
		if e := a.ApplyRules(ctx); e != nil {
			return e
		}
		return a.Store.Delete(kind, id, p.Version)
	}
	if e := a.Sync(ctx); e != nil {
		return e
	}
	preview, e := a.DeletePreview(kind, id)
	if e != nil {
		return e
	}
	if preview.(map[string]any)["blocked"] == true {
		return errors.New("certificate is used by proxy hosts or native DSM services")
	}
	var p model.CertificateProfile
	if e = a.Store.Get(kind, id, &p); e != nil {
		return e
	}
	a.ACME.Stop(id)
	if p.NativeID != "" && !p.ExternalDeleted {
		if e = a.withDSM(ctx, false, "", func(c *dsm.Client) error { return c.DeleteCertificate(ctx, p.NativeID) }); e != nil {
			return e
		}
	}
	return a.Store.Delete(kind, id, p.Version)
}
func (a *App) Run(ctx context.Context) error {
	lock, e := os.OpenFile(filepath.Join(a.Store.Dir, "worker.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("another worker is already running")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	defer a.ACME.Close()
	if e := a.Store.Recover(); e != nil {
		return e
	}
	slots := make(chan struct{}, 2)
	var jobs sync.WaitGroup
	defer jobs.Wait()
	objectLocks := map[string]*sync.Mutex{}
	nextSync, nextRenew := time.Time{}, time.Time{}
	var nextBackup time.Time
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		if time.Now().After(nextSync) {
			syncCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
			if unlock, err := a.Store.Gate(syncCtx, false); err == nil {
				if e := a.Sync(syncCtx); e == nil {
					if _, e = os.Stat(filepath.Join(a.Store.Dir, "recovered")); e == nil {
						_, _ = a.Store.Enqueue("rules.apply", "recovered", nil)
					}
				}
				unlock()
			}
			cancel()
			nextSync = time.Now().Add(30 * time.Second)
		}
		if time.Now().After(nextBackup) {
			_, _ = a.Store.Enqueue("backup.create", "automatic", nil)
			nextBackup = time.Now().Add(24 * time.Hour)
		}
		if time.Now().After(nextRenew) {
			a.startRenewals(ctx)
			nextRenew = time.Now().Add(5 * time.Minute)
		}
		select {
		case slots <- struct{}{}:
		default:
			continue
		}
		op, e := a.Store.Claim()
		if errors.Is(e, sql.ErrNoRows) {
			<-slots
			continue
		}
		if e != nil {
			<-slots
			return e
		}
		if objectLocks[op.ObjectID] == nil {
			objectLocks[op.ObjectID] = &sync.Mutex{}
		}
		objectLock := objectLocks[op.ObjectID]
		jobs.Add(1)
		go func(op model.Operation) {
			defer jobs.Done()
			defer func() { <-slots }()
			objectLock.Lock()
			defer objectLock.Unlock()
			a.execute(ctx, op)
		}(op)
	}
}

func (a *App) execute(ctx context.Context, op model.Operation) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	exclusive := op.Kind == "backup.create" || op.Kind == "recovery.prepare" || op.Kind == "proxy.delete" || op.Kind == "certificate.delete"
	unlock, lockErr := a.Store.Gate(ctx, exclusive)
	if lockErr != nil {
		_ = a.Store.Finish(op.ID, lockErr)
		return
	}
	defer unlock()
	if a.managementPaused() && op.Kind != "recovery.prepare" && op.Kind != "backup.create" && op.Kind != "sync" {
		_ = a.Store.Finish(op.ID, errors.New("management is paused for uninstall recovery"))
		return
	}
	_ = a.Store.Stage(op.ID, "Processing "+op.Kind)
	var startVersion int
	if strings.HasPrefix(op.Kind, "proxy.") {
		var p model.ProxyHost
		if a.Store.Get("proxies", op.ObjectID, &p) == nil {
			startVersion = p.Version
		}
	} else if strings.HasPrefix(op.Kind, "certificate.") {
		var p model.CertificateProfile
		if a.Store.Get("certificates", op.ObjectID, &p) == nil {
			startVersion = p.Version
		}
	}
	var e error
	if op.Kind == "proxy.delete" || op.Kind == "certificate.delete" {
		if _, e = a.CreateBackup(ctx, "before-delete"); e != nil {
			_ = a.Store.Finish(op.ID, e)
			return
		}
	}
	switch op.Kind {
	case "backup.create":
		_, e = a.CreateBackup(ctx, op.ObjectID)
	case "recovery.prepare":
		var request struct {
			Token string `json:"token"`
		}
		if json.Unmarshal(op.Request, &request) != nil {
			e = errors.New("invalid restore confirmation")
		} else {
			e = a.PrepareUninstall(ctx, request.Token)
		}
	case "certificate.issue":
		e = a.Certificate(ctx, op.ObjectID, false, false)
	case "certificate.renew":
		e = a.Certificate(ctx, op.ObjectID, true, false)
	case "certificate.replace":
		e = a.ReplaceCertificate(ctx, op.ObjectID)
	case "certificate.deploy":
		e = a.Certificate(ctx, op.ObjectID, false, true)
	case "proxy.apply":
		e = a.Proxy(ctx, op.ObjectID)
	case "proxy.delete":
		e = a.Delete(ctx, "proxies", op.ObjectID)
	case "certificate.delete":
		var deleting model.CertificateProfile
		_ = a.Store.Get("certificates", op.ObjectID, &deleting)
		e = a.Delete(ctx, "certificates", op.ObjectID)
		if e == nil && deleting.NativeID != "" {
			e = a.markRemoved("certificate", deleting.NativeID)
		}
	case "sync":
		e = a.Sync(ctx)
	case "rules.apply":
		e = a.ApplyRules(ctx)
		if e == nil && op.ObjectID == "recovered" {
			_ = os.Remove(filepath.Join(a.Store.Dir, "recovered"))
		}
	default:
		e = errors.New("unsupported operation")
	}
	_ = a.Store.Finish(op.ID, e)
	// A save during a running operation must not be swallowed by active-job
	// deduplication. Only a newer user-queued revision schedules a follow-up.
	if startVersion > 0 && op.Kind == "proxy.apply" {
		var p model.ProxyHost
		if a.Store.Get("proxies", op.ObjectID, &p) == nil && p.Status == "queued" && p.Version > startVersion {
			_, _ = a.Store.Enqueue("proxy.apply", p.ID, nil)
		}
	}
	if startVersion > 0 && (op.Kind == "certificate.issue" || op.Kind == "certificate.renew" || op.Kind == "certificate.deploy") {
		var p model.CertificateProfile
		if a.Store.Get("certificates", op.ObjectID, &p) == nil && p.Status == "queued" && p.Version > startVersion {
			_, _ = a.Store.Enqueue("certificate.issue", p.ID, nil)
		}
	}
}
func (a *App) startRenewals(ctx context.Context) {
	if a.managementPaused() {
		a.ACME.Close()
		return
	}
	var profiles []model.CertificateProfile
	if a.Store.List("certificates", &profiles) != nil {
		return
	}
	for _, p := range profiles {
		if !p.Managed || !p.AutoRenew || p.NativeID == "" || p.ExternalDeleted {
			a.ACME.Stop(p.ID)
			continue
		}
		a.renewMu.Lock()
		if a.renewing[p.ID] {
			a.renewMu.Unlock()
			continue
		}
		a.renewing[p.ID] = true
		a.renewMu.Unlock()
		go func(p model.CertificateProfile) {
			defer func() { a.renewMu.Lock(); delete(a.renewing, p.ID); a.renewMu.Unlock() }()
			token, e := a.credential(p.CredentialID)
			if e == nil {
				e = a.ACME.Manage(ctx, p, token)
			}
			if e == nil {
				cert, _, err := a.ACME.Material(ctx, p, token)
				if err == nil {
					fp, _, _ := dsm.Fingerprint(cert)
					if fp != p.Fingerprint {
						_, _ = a.Store.Enqueue("certificate.deploy", p.ID, nil)
					}
				}
			}
		}(p)
	}
}
func sha256Sum(b []byte) []byte { sum := sha256.Sum256(b); return sum[:] }

func (a *App) SetHTTP2(ctx context.Context, enabled bool) error {
	return a.withDSM(ctx, false, "", func(c *dsm.Client) error {
		before, e := c.HTTP2(ctx)
		if e != nil {
			return e
		}
		state := a.recoveryState()
		if state.HTTP2Before == nil {
			state.HTTP2Before = &before
		}
		state.HTTP2After = &enabled
		if e = a.Store.Put("recovery", &state.Meta, &state); e != nil {
			return e
		}
		return c.SetHTTP2(ctx, enabled)
	})
}

func (a *App) DeleteCredential(id string) error {
	var profiles []model.CertificateProfile
	if e := a.Store.List("certificates", &profiles); e != nil {
		return e
	}
	for _, p := range profiles {
		if p.CredentialID == id && !p.ExternalDeleted {
			return errors.New("credential is used by a certificate; select a replacement first")
		}
	}
	var c model.Credential
	if e := a.Store.Get("credentials", id, &c); e != nil {
		return e
	}
	return a.Store.DeleteCredential(id, c.Version)
}
