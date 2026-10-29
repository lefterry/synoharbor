package auth

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"github.com/lefterry/synoharbor/internal/dsm"
	"github.com/lefterry/synoharbor/internal/model"
	"github.com/lefterry/synoharbor/internal/store"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Explicit NAS integration test. A temporary native proof exercises the deployed
// browser-session boundary without collecting a human password or OTP. The
// interactive Login contract is tested separately and never consumes this DID.
func TestStandaloneSessionLive(t *testing.T) {
	if os.Getenv("SYNOHARBOR_LIVE_STANDALONE") != "1" {
		t.Skip("explicit deployed NAS test")
	}
	if os.Geteuid() == 0 {
		t.Fatal("run as package user")
	}
	s, e := store.Open("/var/packages/synoharbor/var")
	if e != nil {
		t.Fatal("store unavailable")
	}
	defer s.Close()
	var cfg model.Settings
	var secret model.ConnectionSecret
	if s.Get("settings", "main", &cfg) != nil || s.Secret("dsm", &secret) != nil {
		t.Fatal("connection unavailable")
	}
	native := dsm.New(cfg, secret)
	ctx := context.Background()
	if native.Login(ctx, "") != nil {
		t.Fatal("native test session failed")
	}
	defer native.Logout(ctx)
	sessions := NewSessions(s)
	proof := native.SessionProof()
	user, _, _, e := sessions.VerifyNative(ctx, sessions.nativeEnv(proof))
	if e != nil {
		t.Fatal("native proof rejected")
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	cookie := hex.EncodeToString(raw)
	id, _ := sessionID(cookie)
	expires := time.Now().Add(5 * time.Minute).Unix()
	record := sessionRecord{Meta: model.Meta{ID: id}, User: user, Expires: expires}
	if e = s.PutSecretObject("browser-sessions", &record.Meta, &record, "browser-session:"+id, sessionSecret{User: user, Native: proof, Expires: expires}); e != nil {
		t.Fatal("session seed failed")
	}
	env := func(k string) string {
		if k == "HTTP_COOKIE" {
			return SessionCookie + "=" + cookie
		}
		return ""
	}
	defer sessions.Logout(ctx, env)
	host := os.Getenv("SYNOHARBOR_STANDALONE_HOST")
	if !model.ValidDomain(host, false) {
		t.Fatal("explicit standalone hostname required")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, "127.0.0.1:443")
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(path, method, token string, authenticated bool) (int, []byte) {
		req, _ := http.NewRequest(method, "https://"+host+path, strings.NewReader(`{}`))
		if authenticated {
			req.Header.Set("Cookie", SessionCookie+"="+cookie)
		}
		req.Header.Set("X-SynoHarbor-CSRF", token)
		req.Header.Set("Content-Type", "application/json")
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal("standalone HTTPS request failed")
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if strings.Contains(string(body), proof.SID) || strings.Contains(string(body), proof.Token) {
			t.Fatal("native proof leaked")
		}
		return resp.StatusCode, body
	}
	if code, _ := call("/", "GET", "", false); code != 200 {
		t.Fatal("app page unavailable", code)
	}
	if code, _ := call("/webapi/auth.cgi", "GET", "", false); code != 404 {
		t.Fatal("raw native API exposed", code)
	}
	if code, _ := call("/api.cgi?route=overview", "GET", "", false); code != 401 {
		t.Fatal("anonymous overview accepted", code)
	}
	code, body := call("/api.cgi?route=session", "GET", "", true)
	var result struct {
		Success bool `json:"success"`
		Data    struct {
			Token string `json:"csrfToken"`
			Mode  string `json:"authMode"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &result) != nil || code != 200 || !result.Success || result.Data.Token == "" || result.Data.Mode != "standalone" {
		t.Fatal("opaque session bootstrap failed", code)
	}
	token := result.Data.Token
	if code, _ = call("/api.cgi?route=overview", "GET", token, true); code != 200 {
		t.Fatal("authorized overview rejected", code)
	}
	if code, _ = call("/api.cgi?route=sync", "POST", "", true); code != 403 {
		t.Fatal("missing CSRF accepted", code)
	}
	if code, _ = call("/api.cgi?route=signout", "POST", token, true); code != 200 {
		t.Fatal("signout failed", code)
	}
	if code, _ = call("/api.cgi?route=session", "GET", "", true); code != 401 {
		t.Fatal("revoked session accepted", code)
	}
	if desktop := os.Getenv("SYNOHARBOR_DSM_HOST"); desktop != "" {
		if !model.ValidDomain(desktop, false) {
			t.Fatal("invalid desktop test hostname")
		}
		// Alternate two SNI/trust policies sharing the same literal NAS HTTPS
		// upstream. nginx implicit session caches are keyed by address, not SNI.
		for i := 0; i < 25; i++ {
			for _, name := range []string{host, desktop} {
				req, _ := http.NewRequest("GET", "https://"+name+"/", nil)
				resp, e := client.Do(req)
				if e != nil {
					t.Fatal("mixed-route TLS request failed")
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 {
					t.Fatal("mixed-route upstream TLS regression", name, resp.StatusCode)
				}
			}
		}
		t.Log("50 alternating standalone/DSM HTTPS requests: zero upstream or certificate failures")
	}
	t.Log("Deployed HTTPS: fixed package routing, anonymous denial, opaque session/native admin verification, CSRF and signout passed")
}
