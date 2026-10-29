package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lefterry/synoharbor/internal/auth"
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
	for _, route := range []string{"overview", "session", "connection", "legacy-import", "certificates", "proxies", "access", "credentials", "http2", "sync", "backup"} {
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
	for _, route := range []string{"overview", "connection", "certificates", "proxies", "access", "credentials", "http2", "sync", "backup"} {
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
