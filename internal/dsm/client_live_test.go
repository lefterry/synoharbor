package dsm

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lefterry/synoharbor/internal/broker"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

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
	baseEnv := append([]string{}, command.Env...)
	invoke := func(route, method string, payload any, csrf string, anonymous bool) (string, bool) {
		raw, _ := json.Marshal(payload)
		cmd := exec.Command("/var/packages/synoharbor/target/bin/synoharbor", "cgi")
		for _, env := range baseEnv {
			if strings.HasPrefix(env, "QUERY_STRING=") || strings.HasPrefix(env, "REQUEST_METHOD=") || (anonymous && (strings.HasPrefix(env, "HTTP_COOKIE=") || strings.HasPrefix(env, "HTTP_X_SYNO_TOKEN="))) {
				continue
			}
			cmd.Env = append(cmd.Env, env)
		}
		cmd.Env = append(cmd.Env, "QUERY_STRING=route="+route, "REQUEST_METHOD="+method, "HTTP_X_SYNOHARBOR_CSRF="+csrf)
		if method != "GET" {
			cmd.Env = append(cmd.Env, "CONTENT_TYPE=application/json", "CONTENT_LENGTH="+strconv.Itoa(len(raw)))
			cmd.Stdin = bytes.NewReader(raw)
		}
		out, e := cmd.Output()
		if e != nil {
			t.Fatal("installed CGI execution failed")
		}
		_, body, ok := strings.Cut(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n\n")
		if !ok {
			t.Fatal("CGI envelope missing")
		}
		var result struct {
			Success bool `json:"success"`
		}
		if json.Unmarshal([]byte(body), &result) != nil {
			t.Fatal("invalid CGI JSON response")
		}
		if strings.Contains(body, secret.Password) {
			t.Fatal("credential disclosure")
		}
		return body, result.Success
	}
	if _, ok := invoke("overview", "GET", nil, result.Data.Token, false); !ok {
		t.Fatal("authenticated overview failed")
	}
	for _, route := range []string{"overview", "backups", "recovery"} {
		if _, ok := invoke(route, "GET", nil, "invalid-csrf", false); ok {
			t.Fatal("invalid CSRF accepted")
		}
		if _, ok := invoke(route, "GET", nil, result.Data.Token, true); ok {
			t.Fatal("anonymous access accepted")
		}
	}
	if backupID := os.Getenv("SYNOHARBOR_RESTORE_BACKUP"); backupID != "" {
		if _, ok := invoke("restore-backup", "POST", map[string]string{"id": backupID, "confirmation": "RESTORE SETTINGS"}, result.Data.Token, false); !ok {
			t.Fatal("authenticated settings recovery did not start")
		}
		deadline := time.Now().Add(2 * time.Minute)
		var status struct{ ID, State string }
		for time.Now().Before(deadline) {
			if (broker.Client{}).Call(context.Background(), broker.Request{Action: "recovery-status"}, &status) == nil && status.ID == backupID {
				if status.State == "failed" {
					t.Fatal("settings recovery failed")
				}
				if status.State == "succeeded" {
					break
				}
			}
			time.Sleep(time.Second)
		}
		if status.State != "succeeded" {
			t.Fatal("settings recovery did not finish")
		}
		after, e := c.Snapshot(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		if len(after.Proxies) != len(snap.Proxies) || len(after.Certificates) != len(snap.Certificates) {
			t.Fatal("settings recovery altered native object inventory")
		}
		for _, p := range snap.Proxies {
			found := false
			for _, q := range after.Proxies {
				found = found || ID(p) == ID(q)
			}
			if !found {
				t.Fatal("settings recovery lost native proxy identity")
			}
		}
		t.Log("Authenticated in-app full settings restore and native ID preservation passed")
	}
	t.Log("Native inventory and native-token CGI administrator bootstrap passed; no credentials emitted")
}
