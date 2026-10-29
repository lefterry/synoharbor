package dsm

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/lefterry/synoharbor/internal/model"
	"github.com/lefterry/synoharbor/internal/store"
)

// Explicit on-device test using SynoHarbor's own trusted-device connection.
// Run as sc-synoharbor; credentials never leave the NAS or enter test output.
func TestNativeCGISessionLive(t *testing.T) {
	if os.Getenv("SYNOHARBOR_LIVE_NAS") != "1" {
		t.Skip("requires explicit on-device package-user execution")
	}
	if os.Geteuid() == 0 {
		t.Fatal("run this test as the package user")
	}
	s, e := store.Open("/var/packages/synoharbor/var")
	if e != nil {
		t.Fatal("private storage unavailable")
	}
	defer s.Close()
	var settings model.Settings
	var secret model.ConnectionSecret
	if s.Get("settings", "main", &settings) != nil || s.Secret("dsm", &secret) != nil {
		t.Fatal("own connection unavailable")
	}
	c := New(settings, secret)
	if c.Login(context.Background(), "") != nil {
		t.Fatal("trusted login failed")
	}
	defer c.Logout(context.Background())
	snap, e := c.Snapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if len(snap.Certificates) == 0 {
		t.Fatal("native inventory empty")
	}
	command := exec.Command("/var/packages/synoharbor/target/bin/synoharbor", "cgi")
	command.Env = []string{"PATH=/usr/bin:/bin", "REQUEST_METHOD=GET", "QUERY_STRING=route=session", "SERVER_PROTOCOL=HTTP/1.1", "HTTP_COOKIE=id=" + c.sid, "REMOTE_ADDR=127.0.0.1", "SERVER_ADDR=127.0.0.1", "SERVER_PORT=" + strconv.Itoa(settings.Port), "HTTPS=on", "HTTP_HOST=127.0.0.1", "HTTP_X_SYNO_TOKEN=" + c.token}
	// The React client first obtains the native session token from the official
	// SYNO.API.Auth token endpoint, then sends it alongside the cookie.

	out, e := command.Output()
	if e != nil {
		t.Fatal("installed CGI execution failed")
	}
	_, body, ok := strings.Cut(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n\n")
	if !ok {
		t.Fatal("CGI envelope missing")
	}
	var result struct {
		Success bool `json:"success"`
		Data    struct {
			Token string `json:"csrfToken"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(body), &result) != nil || !result.Success || result.Data.Token == "" {
		t.Fatal("native session bootstrap rejected")
	}
	t.Log("Native inventory and native-token CGI administrator bootstrap passed; no credentials emitted")
}
