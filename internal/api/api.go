package api

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/google/uuid"
	"github.com/lefterry/synoharbor/internal/auth"
	"github.com/lefterry/synoharbor/internal/broker"
	"github.com/lefterry/synoharbor/internal/model"
	"github.com/lefterry/synoharbor/internal/service"
	"github.com/lefterry/synoharbor/internal/store"
)

type API struct {
	App      *service.App
	Verify   func(context.Context, auth.Env) (string, string, int, error)
	Env      auth.Env
	Sessions *auth.Sessions
}

func New(a *service.App) *API {
	sessions := auth.NewSessions(a.Store)
	return &API{App: a, Env: os.Getenv, Sessions: sessions, Verify: func(ctx context.Context, env auth.Env) (string, string, int, error) {
		_, present, _ := auth.OwnCookie(env)
		if present {
			return sessions.Verify(ctx, env)
		}
		return auth.Native().Verify(ctx, env)
	}}
}
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	name, sid, status, e := a.Verify(r.Context(), a.Env)
	if e != nil {
		reply(w, status, nil, e)
		return
	}
	path := strings.Trim(r.URL.Path, "/")
	if route := r.URL.Query().Get("route"); route != "" {
		path = strings.Trim(route, "/")
	}
	if path == "" {
		path = strings.Trim(a.Env("PATH_INFO"), "/")
	}
	if i := strings.Index(path, "api.cgi/"); i >= 0 {
		path = path[i+8:]
	}
	token, e := auth.Token(filepath.Join(a.App.Store.Dir, "browser"), name, sid)
	if e != nil {
		reply(w, 503, nil, errors.New("browser security state unavailable"))
		return
	}
	if path == "session" && r.Method == "GET" {
		mode := "dsm"
		if _, present, _ := auth.OwnCookie(a.Env); present {
			mode = "standalone"
		}
		reply(w, 200, map[string]string{"user": name, "csrfToken": token, "authMode": mode}, nil)
		return
	}
	if !hmac.Equal([]byte(r.Header.Get("X-SynoHarbor-CSRF")), []byte(token)) {
		reply(w, 403, nil, errors.New("browser session verification required; reopen SynoHarbor"))
		return
	}
	if r.Method != "GET" {
		media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if e != nil || media != "application/json" {
			reply(w, 415, nil, errors.New("application/json required"))
			return
		}
		unlock, err := a.App.Store.Gate(r.Context(), path == "standalone")
		if err != nil {
			reply(w, 503, nil, errors.New("recovery is busy; retry shortly"))
			return
		}
		defer unlock()
		if path == "signout" && r.Method == "POST" {
			e := a.Sessions.Logout(r.Context(), a.Env)
			http.SetCookie(w, auth.ClearSessionCookie())
			reply(w, 200, nil, e)
			return
		}
		if a.App.RecoveryPaused() && path != "connection" && path != "backup" && path != "recovery/prepare" && path != "restore-backup" {
			reply(w, 409, nil, errors.New("management is paused for recovery; finish rollback before uninstalling"))
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	data, e := a.route(r, path)
	code := 200
	if e != nil {
		code = 400
		if errors.Is(e, store.ErrConflict) {
			code = 409
		}
		if store.NotFound(e) {
			code = 404
			e = errors.New("object not found")
		}
	}
	reply(w, code, data, e)
}
func reply(w http.ResponseWriter, status int, data any, e error) {
	w.WriteHeader(status)
	env := map[string]any{"success": e == nil, "data": data}
	if e != nil {
		env["error"] = e.Error()
	}
	_ = json.NewEncoder(w).Encode(env)
}
func decode(r *http.Request, out any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return errors.New("invalid request fields")
	}
	return nil
}
func (a *API) route(r *http.Request, path string) (any, error) {
	s := a.App.Store
	parts := strings.Split(path, "/")
	kind := parts[0]
	id := ""
	action := ""
	if len(parts) > 1 {
		id = parts[1]
	}
	if len(parts) > 2 {
		action = parts[2]
	}
	ctx := r.Context()
	if r.Method == "GET" {
		switch kind {
		case "overview":
			var certs []model.CertificateProfile
			var proxies []model.ProxyHost
			var lists []model.AccessList
			var credentials []model.Credential
			var snapshot model.DSMSnapshot
			for _, job := range []func() error{func() error { return s.List("certificates", &certs) }, func() error { return s.List("proxies", &proxies) }, func() error { return s.List("access", &lists) }, func() error { return s.List("credentials", &credentials) }} {
				if e := job(); e != nil {
					return nil, e
				}
			}
			_ = s.Get("snapshot", "main", &snapshot)
			ops, e := s.Operations()
			brokerReady := a.App.Broker.Call(ctx, broker.Request{Action: "status"}, nil) == nil
			return map[string]any{"build": broker.Build, "brokerReady": brokerReady, "certificates": certs, "proxies": proxies, "accessLists": lists, "credentials": credentials, "snapshot": snapshot, "operations": ops, "settings": a.App.Settings()}, e
		case "operations":
			if id != "" {
				return s.Operation(id)
			}
			return s.Operations()
		case "settings":
			return a.App.Settings(), nil
		case "standalone":
			return a.App.Standalone(), nil
		case "backups":
			return a.App.Backups(ctx)
		case "recovery":
			return a.App.RecoveryPreview(ctx)
		case "recovery-status":
			var status any
			e := a.App.Broker.Call(ctx, broker.Request{Action: "recovery-status"}, &status)
			return status, e
		case "proxies", "certificates":
			if action == "delete-preview" {
				return a.App.DeletePreview(kind, id)
			}
		}
		return nil, errors.New("unknown read endpoint")
	}
	if r.Method == "POST" {
		switch kind {
		case "sync":
			return s.Enqueue("sync", "main", nil)
		case "standalone":
			var req service.StandaloneRequest
			if e := decode(r, &req); e != nil {
				return nil, e
			}
			return a.App.SetupStandalone(ctx, req)
		case "preview":
			var p model.ProxyHost
			if e := decode(r, &p); e != nil {
				return nil, e
			}
			if p.ID == "" {
				p.ID = uuid.NewString()
			}
			if p.LoopbackPort == 0 {
				port, e := a.App.AllocatePort(p.ID)
				if e != nil {
					return nil, e
				}
				p.LoopbackPort = port
			}
			p.Managed = true
			p.Enabled = true
			return a.App.Preview(&p)
		case "connection":
			var req struct {
				Account  string `json:"account"`
				Password string `json:"password"`
				OTP      string `json:"otp"`
				Port     int    `json:"port"`
			}
			if e := decode(r, &req); e != nil {
				return nil, e
			}
			if len(req.OTP) != 0 && (len(req.OTP) != 6 || strings.Trim(req.OTP, "0123456789") != "") {
				return nil, errors.New("enter the current six-digit OTP")
			}
			e := a.App.Connect(ctx, req.Account, req.Password, req.OTP, req.Port)
			return a.App.Settings(), e
		case "http2":
			var req struct {
				Enabled bool `json:"enabled"`
			}
			if e := decode(r, &req); e != nil {
				return nil, e
			}
			return nil, a.App.SetHTTP2(ctx, req.Enabled)
		case "backup":
			return s.Enqueue("backup.create", "manual", nil)
		case "restore-backup":
			var req struct {
				ID           string `json:"id"`
				Confirmation string `json:"confirmation"`
			}
			if e := decode(r, &req); e != nil {
				return nil, e
			}
			if req.Confirmation != "RESTORE SETTINGS" {
				return nil, errors.New("confirm the selected private settings backup first")
			}
			var status any
			e := a.App.Broker.Call(ctx, broker.Request{Action: "backup-restore", ID: req.ID}, &status)
			return status, e
		case "recovery":
			var req struct {
				Token string `json:"token"`
			}
			if id != "prepare" {
				return nil, errors.New("unknown recovery action")
			}
			if e := decode(r, &req); e != nil {
				return nil, e
			}
			if len(req.Token) != 64 {
				return nil, errors.New("preview and confirm the exact DSM restore first")
			}
			return s.Enqueue("recovery.prepare", "main", req)
		case "credentials":
			var req struct {
				model.Credential
				Token string `json:"token"`
			}
			if e := decode(r, &req); e != nil {
				return nil, e
			}
			if strings.TrimSpace(req.Name) == "" {
				return nil, errors.New("credential name required")
			}
			if req.ID == "" {
				req.ID = uuid.NewString()
			}
			if req.Token != "" {
				req.Configured = true
			} else {
				var old string
				if e := s.Secret("cloudflare:"+req.ID, &old); e != nil {
					return nil, errors.New("Cloudflare API token required")
				}
				req.Configured = true
				req.Token = old
			}
			e := s.PutSecretObject("credentials", &req.Meta, &req.Credential, "cloudflare:"+req.ID, req.Token)
			return req.Credential, e
		case "certificates":
			if action == "replace" {
				return s.Enqueue("certificate.replace", id, nil)
			}
			if action == "renew" || action == "deploy" {
				return s.Enqueue("certificate."+action, id, nil)
			}
			var req struct {
				Profile json.RawMessage  `json:"profile"`
				Proxy   *model.ProxyHost `json:"proxy,omitempty"`
				Adopt   bool             `json:"adopt"`
			}
			if e := decode(r, &req); e != nil {
				return nil, e
			}
			var editable certificateInput
			if json.Unmarshal(req.Profile, &editable) != nil {
				return nil, errors.New("invalid certificate fields")
			}
			p := editable.profile()
			if !req.Adopt {
				p.NativeID = ""
			}
			var credential model.Credential
			if s.Get("credentials", p.CredentialID, &credential) != nil {
				return nil, errors.New("select an available Cloudflare credential")
			}
			if e := p.Validate(); e != nil {
				return nil, e
			}
			var existing []model.CertificateProfile
			if e := s.List("certificates", &existing); e != nil {
				return nil, e
			}
			for _, v := range existing {
				if v.ID != p.ID && v.Domain == p.Domain && v.Staging == p.Staging && !v.ExternalDeleted && v.Managed {
					return nil, errors.New("a certificate profile already exists for this domain; edit that profile")
				}
			}
			if p.Staging && req.Proxy != nil {
				return nil, errors.New("staging certificates are for issuance tests; use a production profile for a proxy")
			}
			var old model.CertificateProfile
			if p.ID != "" && s.Get("certificates", p.ID, &old) == nil {
				if old.NativeID != "" && p.Staging != old.Staging {
					return nil, errors.New("create a separate staging profile; an existing deployed certificate cannot change CA mode")
				}
				if p.Domain != old.Domain {
					return nil, errors.New("create a separate profile for another domain")
				}
				p.NativeID = old.NativeID
				p.Fingerprint = old.Fingerprint
				p.PendingFingerprint = old.PendingFingerprint
				p.LastDeployed = old.LastDeployed
				p.ExpiresAt = old.ExpiresAt
				p.Status = "queued"
				p.Issuer = old.Issuer
				p.ExternalDeleted = old.ExternalDeleted
				if p.ExternalDeleted {
					return nil, errors.New("certificate was removed from DSM")
				}
			}
			p.Managed = true
			if req.Adopt {
				if e := a.App.AdoptCertificate(ctx, p); e != nil {
					return nil, e
				}
				if req.Proxy != nil {
					h := *req.Proxy
					h.CertificateID = p.ID
					return a.saveProxy(h, true)
				}
				return map[string]string{"status": "adopted"}, nil
			}
			if p.Status == "" {
				p.Status = "queued"
			}
			if e := s.Put("certificates", &p.Meta, &p); e != nil {
				return nil, e
			}
			if req.Proxy != nil {
				h := *req.Proxy
				h.CertificateID = p.ID
				if _, e := a.saveProxy(h, false); e != nil {
					return nil, e
				}
			}
			op, e := s.Enqueue("certificate.issue", p.ID, nil)
			return map[string]any{"profile": p, "operation": op}, e
		case "proxies":
			if action == "apply" {
				return s.Enqueue("proxy.apply", id, nil)
			}
			var p model.ProxyHost
			if e := decode(r, &p); e != nil {
				return nil, e
			}
			return a.saveProxy(p, true)
		case "access":
			var req struct {
				model.AccessList
				Passwords map[string]string `json:"passwords"`
			}
			if e := decode(r, &req); e != nil {
				return nil, e
			}
			if e := req.AccessList.Validate(); e != nil {
				return nil, e
			}
			if req.ID == "" {
				req.ID = uuid.NewString()
			}
			var hashes map[string]string
			_ = s.Secret("access:"+req.ID, &hashes)
			if hashes == nil {
				hashes = map[string]string{}
			}
			next := map[string]string{}
			for i, u := range req.Users {
				password := req.Passwords[u.Username]
				if password != "" {
					if len(password) < 12 || len(password) > 256 {
						return nil, errors.New("Basic Auth passwords must have 12–256 characters")
					}
					h, e := sha512_crypt.New().Generate([]byte(password), nil)
					if e != nil {
						return nil, e
					}
					next[u.Username] = h
				} else {
					next[u.Username] = hashes[u.Username]
				}
				if next[u.Username] == "" {
					return nil, errors.New("a password is required for each new user")
				}
				req.Users[i].Configured = true
			}
			if e := s.PutSecretObject("access", &req.Meta, &req.AccessList, "access:"+req.ID, next); e != nil {
				return nil, e
			}
			return s.Enqueue("rules.apply", req.ID, nil)
		case "settings":
			var req struct {
				Theme string `json:"theme"`
			}
			if e := decode(r, &req); e != nil {
				return nil, e
			}
			if req.Theme != "system" && req.Theme != "light" && req.Theme != "dark" {
				return nil, errors.New("invalid theme")
			}
			settings := a.App.Settings()
			settings.Theme = req.Theme
			e := s.Put("settings", &settings.Meta, &settings)
			return settings, e
		}
	}
	if r.Method == "DELETE" {
		switch kind {
		case "proxies":
			return s.Enqueue("proxy.delete", id, nil)
		case "certificates":
			return s.Enqueue("certificate.delete", id, nil)
		case "access":
			var p []model.ProxyHost
			_ = s.List("proxies", &p)
			for _, h := range p {
				if h.AccessListID == id {
					return nil, errors.New("access list is used by proxy hosts")
				}
			}
			var list model.AccessList
			if e := s.Get("access", id, &list); e != nil {
				return nil, e
			}
			return nil, s.Delete("access", id, list.Version)
		case "credentials":
			return nil, a.App.DeleteCredential(id)
		}
	}
	return nil, errors.New("unsupported endpoint or method")
}
func (a *API) saveProxy(p model.ProxyHost, enqueue bool) (any, error) {
	s := a.App.Store
	var old model.ProxyHost
	if p.ID != "" && s.Get("proxies", p.ID, &old) == nil {
		if old.AppUI {
			if p.Hostname != old.Hostname {
				return nil, errors.New("configure standalone access in Settings")
			}
			version, enabled := p.Version, p.Enabled
			p = old
			p.Version = version
			p.Enabled = enabled
		}
		p.NativeID = old.NativeID
		p.NativeHash = old.NativeHash
		p.LoopbackPort = old.LoopbackPort
		p.HTTPSVerified = old.HTTPSVerified
		p.ExternalDeleted = old.ExternalDeleted
		if p.ExternalDeleted {
			return nil, errors.New("proxy was removed in DSM; create a new proxy")
		}
		if p.Hostname != old.Hostname {
			p.HTTPSVerified = false
		}
	}
	if p.AppUI && !old.AppUI {
		return nil, errors.New("create standalone access in Settings")
	}
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	p.Managed = true
	p.AdvancedBypassed = false
	if p.LoopbackPort == 0 {
		port, e := a.App.AllocatePort(p.ID)
		if e != nil {
			return nil, e
		}
		p.LoopbackPort = port
	}
	if e := p.Validate(); e != nil {
		return nil, e
	}
	if _, e := a.App.Preview(&p); e != nil {
		return nil, e
	}
	var hosts []model.ProxyHost
	_ = s.List("proxies", &hosts)
	for _, h := range hosts {
		if h.ID != p.ID && !h.ExternalDeleted && h.Hostname == p.Hostname {
			return nil, errors.New("a proxy already exists for this hostname")
		}
	}
	p.Status = "queued"
	if e := s.Put("proxies", &p.Meta, &p); e != nil {
		return nil, e
	}
	if enqueue {
		op, e := s.Enqueue("proxy.apply", p.ID, nil)
		return map[string]any{"proxy": p, "operation": op}, e
	}
	return p, nil
}

// Server-owned timestamps and operation state are intentionally excluded. Old
// clients may send those fields; json.Unmarshal ignores them, so empty date
// strings cannot break a new-certificate request or overwrite runtime state.
type certificateInput struct {
	ID           string `json:"id"`
	Version      int    `json:"version"`
	Domain       string `json:"domain"`
	Email        string `json:"email"`
	CredentialID string `json:"credentialId"`
	KeyType      string `json:"keyType"`
	Staging      bool   `json:"staging"`
	AutoRenew    bool   `json:"autoRenew"`
	NativeID     string `json:"nativeId"`
}

func (p certificateInput) profile() model.CertificateProfile {
	return model.CertificateProfile{Meta: model.Meta{ID: p.ID, Version: p.Version}, Domain: p.Domain, Email: p.Email, CredentialID: p.CredentialID, KeyType: p.KeyType, Staging: p.Staging, AutoRenew: p.AutoRenew, NativeID: p.NativeID}
}
