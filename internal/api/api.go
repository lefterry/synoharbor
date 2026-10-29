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
	"time"

	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/google/uuid"
	"github.com/lefterry/synoharbor/internal/auth"
	"github.com/lefterry/synoharbor/internal/broker"
	"github.com/lefterry/synoharbor/internal/model"
	"github.com/lefterry/synoharbor/internal/service"
	"github.com/lefterry/synoharbor/internal/store"
)

type API struct {
	App    *service.App
	Verify func(context.Context, auth.Env) (string, string, int, error)
	Env    auth.Env
}

func New(a *service.App) *API { return &API{App: a, Verify: auth.Native().Verify, Env: os.Getenv} }
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
		reply(w, 200, map[string]string{"user": name, "csrfToken": token}, nil)
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
			return map[string]any{"certificates": certs, "proxies": proxies, "accessLists": lists, "credentials": credentials, "snapshot": snapshot, "operations": ops, "settings": a.App.Settings()}, e
		case "operations":
			if id != "" {
				return s.Operation(id)
			}
			return s.Operations()
		case "settings":
			return a.App.Settings(), nil
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
			return a.App.Settings(), a.App.Connect(ctx, req.Account, req.Password, req.OTP, req.Port)
		case "legacy-import":
			return a.legacyImport(ctx)
		case "http2":
			var req struct {
				Enabled bool `json:"enabled"`
			}
			if e := decode(r, &req); e != nil {
				return nil, e
			}
			return nil, a.App.SetHTTP2(ctx, req.Enabled)
		case "backup":
			name := "backup-" + time.Now().UTC().Format("20060102T150405") + ".sqlite"
			return map[string]string{"file": name, "note": "Encrypted database backup retained in private package storage; include master.key and acme/ in a full filesystem backup"}, s.Backup(ctx, filepath.Join(s.Dir, name))
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
				if e := s.PutSecret("cloudflare:"+req.ID, req.Token); e != nil {
					return nil, e
				}
				req.Configured = true
			} else {
				var old string
				if e := s.Secret("cloudflare:"+req.ID, &old); e != nil {
					return nil, errors.New("Cloudflare API token required")
				}
				req.Configured = true
			}
			return req.Credential, s.Put("credentials", &req.Meta, &req.Credential)
		case "certificates":
			if action == "renew" || action == "deploy" {
				return s.Enqueue("certificate."+action, id, nil)
			}
			var req struct {
				Profile model.CertificateProfile `json:"profile"`
				Proxy   *model.ProxyHost         `json:"proxy,omitempty"`
				Adopt   bool                     `json:"adopt"`
			}
			if e := decode(r, &req); e != nil {
				return nil, e
			}
			p := req.Profile
			if e := p.Validate(); e != nil {
				return nil, e
			}
			var old model.CertificateProfile
			if p.ID != "" && s.Get("certificates", p.ID, &old) == nil {
				if p.Domain != old.Domain {
					return nil, errors.New("create a separate profile for another domain")
				}
				p.NativeID = old.NativeID
				p.Fingerprint = old.Fingerprint
				p.PendingFingerprint = old.PendingFingerprint
				p.LastDeployed = old.LastDeployed
				p.ExpiresAt = old.ExpiresAt
				p.Status = old.Status
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
				return map[string]string{"status": "adopted"}, nil
			}
			p.AutoRenew = true
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
			if e := s.PutSecret("access:"+req.ID, next); e != nil {
				return nil, e
			}
			if e := s.Put("access", &req.Meta, &req.AccessList); e != nil {
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
			return settings, s.Put("settings", &settings.Meta, &settings)
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
			var profiles []model.CertificateProfile
			_ = s.List("certificates", &profiles)
			for _, p := range profiles {
				if p.CredentialID == id {
					return nil, errors.New("credential is used by a certificate")
				}
			}
			var c model.Credential
			if e := s.Get("credentials", id, &c); e != nil {
				return nil, e
			}
			if e := s.Delete("credentials", id, c.Version); e != nil {
				return nil, e
			}
			return nil, s.DeleteSecret("cloudflare:" + id)
		}
	}
	return nil, errors.New("unsupported endpoint or method")
}
func (a *API) saveProxy(p model.ProxyHost, enqueue bool) (any, error) {
	s := a.App.Store
	var old model.ProxyHost
	if p.ID != "" && s.Get("proxies", p.ID, &old) == nil {
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
func (a *API) legacyImport(ctx context.Context) (any, error) {
	var legacy struct {
		Domains  []string `json:"domains"`
		Email    string   `json:"email"`
		KeyType  string   `json:"keyType"`
		Token    string   `json:"token"`
		Account  string   `json:"account"`
		Password string   `json:"password"`
		Port     int      `json:"port"`
	}
	if e := a.App.Broker.Call(ctx, broker.Request{Action: "legacy-export"}, &legacy); e != nil {
		return nil, e
	}
	s := a.App.Store
	var credentials []model.Credential
	_ = s.List("credentials", &credentials)
	var credential model.Credential
	for _, c := range credentials {
		if c.Name == "Imported from DNSACME" {
			credential = c
		}
	}
	credential.Name = "Imported from DNSACME"
	credential.Configured = true
	if credential.ID == "" {
		credential.ID = uuid.NewString()
	}
	if e := s.PutSecret("cloudflare:"+credential.ID, legacy.Token); e != nil {
		return nil, e
	}
	if e := s.Put("credentials", &credential.Meta, &credential); e != nil {
		return nil, e
	}
	settings := a.App.Settings()
	if !settings.Connected {
		settings.Account = legacy.Account
		settings.Port = legacy.Port
		settings.AuthStatus = "reauth_required"
		settings.AuthMessage = "Sign in once to create a separate SynoHarbor trusted device"
		if e := s.PutSecret("dsm", model.ConnectionSecret{Password: legacy.Password}); e != nil {
			return nil, e
		}
		if e := s.Put("settings", &settings.Meta, &settings); e != nil {
			return nil, e
		}
	}
	return map[string]any{"credential": credential, "domains": legacy.Domains, "email": legacy.Email, "keyType": legacy.KeyType, "connection": "Credentials imported privately; complete DSM sign-in with a fresh OTP"}, nil
}
