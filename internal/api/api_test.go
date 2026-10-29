package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lefterry/synoharbor/internal/auth"
	"github.com/lefterry/synoharbor/internal/model"
	"github.com/lefterry/synoharbor/internal/service"
	"github.com/lefterry/synoharbor/internal/store"
)

func TestAllManagementRoutesRequireSessionAdminAndCSRF(t *testing.T) {
	s, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	app := service.New(s)
	defer app.ACME.Close()
	a := New(app)
	for _, route := range []string{"overview", "session", "connection", "certificates", "proxies", "access", "credentials", "http2", "sync", "backup", "backups", "recovery", "recovery/prepare", "restore-backup", "recovery-status", "standalone", "signout"} {
		for _, method := range []string{"GET", "POST", "DELETE"} {
			for _, status := range []int{401, 403} {
				a.Verify = func(context.Context, auth.Env) (string, string, int, error) {
					return "", "", status, errors.New("denied")
				}
				r := httptest.NewRequest(method, "/api.cgi?route="+route, strings.NewReader(`{}`))
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				if w.Code != status {
					t.Fatalf("%s %s bypassed auth", method, route)
				}
			}
		}
	}
	a.Verify = func(context.Context, auth.Env) (string, string, int, error) { return "admin", "session-one", 200, nil }
	for _, route := range []string{"overview", "connection", "certificates", "proxies", "access", "credentials", "http2", "sync", "backup", "backups", "recovery", "recovery/prepare", "restore-backup", "recovery-status", "standalone", "signout"} {
		r := httptest.NewRequest("POST", "/api.cgi?route="+route, strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("%s accepted missing CSRF", route)
		}
	}
	r := httptest.NewRequest("GET", "/api.cgi?route=session", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "csrfToken") {
		t.Fatal("legitimate bootstrap failed")
	}
}

func TestCertificateWizardEmptyDatesAndCredentialCRUD(t *testing.T) {
	s, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	app := service.New(s)
	defer app.ACME.Close()
	a := New(app)
	a.Verify = func(context.Context, auth.Env) (string, string, int, error) { return "admin", "session", 200, nil }
	request := func(route, method string, body any) (int, map[string]any) {
		token, err := auth.Token(filepath.Join(s.Dir, "browser"), "admin", "session")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "/api.cgi?route="+route, strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-SynoHarbor-CSRF", token)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		var result map[string]any
		if json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatal("invalid envelope")
		}
		return w.Code, result
	}
	code, resp := request("credentials", "POST", map[string]any{"id": "credential-one", "version": 0, "name": "SynoHarbor", "token": "private-token", "configured": true})
	if code != 200 {
		t.Fatal(resp["error"])
	}
	if strings.Contains(fmt.Sprint(resp), "private-token") {
		t.Fatal("token exposed")
	}
	code, resp = request("credentials", "POST", map[string]any{"id": "credential-one", "version": 1, "name": "Renamed", "token": "", "configured": true})
	if code != 200 {
		t.Fatal(resp["error"])
	}
	var token string
	if s.Secret("cloudflare:credential-one", &token) != nil || token != "private-token" {
		t.Fatal("edit erased saved token")
	}
	profile := map[string]any{"id": "certificate-one", "version": 0, "domain": "one.example.net", "email": "admin@example.net", "credentialId": "credential-one", "keyType": "rsa4096", "autoRenew": true, "expiresAt": "", "lastDeployed": "", "updatedAt": "", "fingerprint": "forged", "status": "ready", "nativeId": "unrelated-native-object"}
	code, resp = request("certificates", "POST", map[string]any{"profile": profile, "adopt": false})
	if code != 200 {
		t.Fatalf("wizard request rejected: %v", resp["error"])
	}
	var saved model.CertificateProfile
	if s.Get("certificates", "certificate-one", &saved) != nil || saved.NativeID != "" || saved.Fingerprint != "" || saved.Status != "queued" {
		t.Fatal("client overwrote server-owned state")
	}
	code, _ = request("credentials/credential-one", "DELETE", map[string]any{})
	if code != 400 {
		t.Fatal("in-use credential was deleted")
	}
	if e = s.Delete("certificates", saved.ID, saved.Version); e != nil {
		t.Fatal(e)
	}
	code, resp = request("credentials/credential-one", "DELETE", map[string]any{})
	if code != 200 {
		t.Fatal(resp["error"])
	}
	if s.Secret("cloudflare:credential-one", &token) == nil {
		t.Fatal("deleted credential secret survived")
	}
}

func TestPublicSignInChecksOriginAndSharesPersistentBudget(t *testing.T) {
	s, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	app := service.New(s)
	defer app.ACME.Close()
	a := New(app)
	a.Env = func(k string) string {
		switch k {
		case "HTTPS":
			return "on"
		case "HTTP_HOST":
			return "127.0.0.1"
		case "HTTP_X_REAL_IP":
			return "192.168.1.7"
		}
		return ""
	}
	p := model.ProxyHost{Meta: model.Meta{ID: "standalone-test"}, Hostname: "harbor.example.net", AppUI: true, Enabled: true, Managed: true}
	if e = s.Put("proxies", &p.Meta, &p); e != nil {
		t.Fatal(e)
	}
	// Invalid credentials are rejected before any native network call.
	invoke := func(origin string) int {
		r := httptest.NewRequest("POST", "https://harbor.example.net/signin.cgi", strings.NewReader(`{"account":"admin","password":"","otp":""}`))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.SignIn(w, r)
		if strings.Contains(w.Body.String(), "csrfToken") || strings.Contains(w.Body.String(), "credentialId") {
			t.Fatal("public login exposed management data")
		}
		return w.Code
	}
	for _, origin := range []string{"", "http://harbor.example.net", "https://evil.example.net", "https://harbor.example.net.evil.net", "https://harbor.example.net/path"} {
		if code := invoke(origin); code != 403 {
			t.Fatal("untrusted origin accepted", origin, code)
		}
	}
	for i := 0; i < 10; i++ {
		if code := invoke("https://harbor.example.net"); code != 401 {
			t.Fatal("unexpected login response", code)
		}
	}
	if code := invoke("https://harbor.example.net"); code != 429 {
		t.Fatal("CGI attempts were not rate limited", code)
	}
	// A fresh CGI process/API object sees the same budget.
	fresh := New(app)
	fresh.Env = a.Env
	a = fresh
	if code := invoke("https://harbor.example.net"); code != 429 {
		t.Fatal("budget reset between requests")
	}
}
