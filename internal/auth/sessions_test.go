package auth

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lefterry/synoharbor/internal/dsm"
	"github.com/lefterry/synoharbor/internal/model"
	"github.com/lefterry/synoharbor/internal/store"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestBrowserLoginIsIndependentAndFailsClosed(t *testing.T) {
	s, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	_ = s.PutSecret("dsm", model.ConnectionSecret{Password: "worker-password", DeviceID: "worker-device"})
	sessions := NewSessions(s)
	now := time.Now()
	sessions.Now = func() time.Time { return now }
	sessions.NewDSM = func(settings model.Settings, secret model.ConnectionSecret) *dsm.Client {
		if secret.Password != "interactive-password" || secret.DeviceID != "" {
			t.Fatal("worker credentials crossed browser boundary")
		}
		c := dsm.New(settings, secret)
		c.HTTP = &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
			raw, _ := io.ReadAll(r.Body)
			v, _ := url.ParseQuery(string(raw))
			if v.Get("method") == "login" {
				if v.Get("otp_code") != "123456" || v.Get("enable_device_token") != "" || v.Get("device_id") != "" || v.Get("passwd") != "interactive-password" {
					t.Fatal("unexpected browser login contract")
				}
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":true,"data":{"sid":"native-session","synotoken":"private-native-token"}}`)), Header: http.Header{}}, nil
		})}
		return c
	}
	sessions.VerifyNative = func(_ context.Context, env Env) (string, string, int, error) {
		if env("HTTP_COOKIE") != "id=native-session" || env("HTTP_X_SYNO_TOKEN") != "private-native-token" || env("REMOTE_ADDR") != "127.0.0.1" {
			t.Fatal("untrusted session context")
		}
		return "admin", "native-session", 200, nil
	}
	cookie, user, e := sessions.Login(context.Background(), "admin", "interactive-password", "123456")
	if e != nil || user != "admin" {
		t.Fatal(e)
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Domain != "" || strings.Contains(cookie.String(), "native-session") {
		t.Fatal("unsafe browser cookie")
	}
	env := func(k string) string {
		if k == "HTTP_COOKIE" {
			return cookie.Name + "=" + cookie.Value
		}
		return "forged-caller-value"
	}
	if _, _, _, e = sessions.Verify(context.Background(), env); e != nil {
		t.Fatal(e)
	}
	for _, value := range []string{"", SessionCookie + "=forged", SessionCookie + "=" + cookie.Value + "; " + SessionCookie + "=" + cookie.Value} {
		if _, _, _, e = sessions.Verify(context.Background(), func(k string) string {
			if k == "HTTP_COOKIE" {
				return value
			}
			return ""
		}); e == nil {
			t.Fatal("forged/duplicate cookie accepted")
		}
	}
	sessions.VerifyNative = func(context.Context, Env) (string, string, int, error) {
		return "", "", 403, errors.New("role revoked")
	}
	if _, _, status, e := sessions.Verify(context.Background(), env); e == nil || status != 403 {
		t.Fatal("revoked admin accepted")
	}
	now = now.Add(9 * time.Hour)
	if _, _, _, e = sessions.Verify(context.Background(), env); e == nil {
		t.Fatal("expired session accepted")
	}
	backup := filepath.Join(s.Dir, "copy.db")
	if e = s.Backup(context.Background(), backup); e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", backup)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var n int
	if e = db.QueryRow("SELECT count(*) FROM secrets WHERE id LIKE 'browser-session:%'").Scan(&n); e != nil || n != 0 {
		t.Fatal("browser sessions restored from backup", e)
	}
	if e = db.QueryRow("SELECT count(*) FROM objects WHERE kind='browser-sessions'").Scan(&n); e != nil || n != 0 {
		t.Fatal("browser metadata restored from backup", e)
	}
}
