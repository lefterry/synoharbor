//go:build integration

package service

import (
	"bufio"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/lefterry/synoharbor/internal/broker"
	"github.com/lefterry/synoharbor/internal/model"
	"github.com/lefterry/synoharbor/internal/store"
)

// Adds one temporary loopback-only listener to the complete current production
// input. Native DSM objects and Cloudflare are never touched. Cleanup restores
// the original input even if a check fails.
func TestLiveNativeNginxAdvancedAndRollback(t *testing.T) {
	if os.Getenv("SYNOHARBOR_LIVE") != "1" {
		t.Skip("explicit live NAS validation only")
	}
	s, e := store.Open("/var/packages/synoharbor/var")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	a := New(s)
	defer a.ACME.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	unlock, e := s.Gate(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	original, e := a.RenderInput()
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := a.Broker.Call(context.Background(), broker.Request{Action: "apply", Config: original}, nil); e != nil {
			t.Error("restore original rules:", e)
		}
	}()
	listener, e := net.Listen("tcp", "127.0.0.1:18998")
	if e != nil {
		t.Fatal("test port already occupied")
	}
	listener.Close()
	var assets atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			conn, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				_, _ = fmt.Fprint(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				conn.Close()
			}
			return
		}
		if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Cache-Control", "public,max-age=120")
			fmt.Fprintf(w, "asset-%d", assets.Add(1))
			return
		}
		fmt.Fprintf(w, "target:%s;auth:%s;custom:%s", r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("X-Live-Request"))
	}))
	defer upstream.Close()
	alt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "alternate-location") }))
	defer alt.Close()
	tlsUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "trusted-upstream") }))
	defer tlsUpstream.Close()
	target := func(address string) model.Target {
		u, _ := url.Parse(address)
		port, _ := strconv.Atoi(u.Port())
		return model.Target{Scheme: u.Scheme, Host: u.Hostname(), Port: port, TLS: model.TLS{Verify: true}}
	}
	p := model.ProxyHost{Meta: model.Meta{ID: "live-nginx-validation"}, Hostname: "synoharbor-validation.invalid", LoopbackPort: 18998, Enabled: true, Managed: true, Target: target(upstream.URL), Advanced: model.Advanced{WebSockets: true, ConnectTimeout: 3, ReadTimeout: 4, SendTimeout: 5, BodySizeMB: 1, HSTS: true, IncludeSubdomains: true, BlockExploits: true, Locations: []model.Location{{Path: "/alternate", Target: target(alt.URL)}}}}
	acl := model.AccessList{Meta: model.Meta{ID: "live-validation-access"}, Name: "Temporary validation", Satisfy: "all", Users: []model.BasicUser{{Username: "validation", Configured: true}}, Rules: []model.IPRule{{Action: "allow", Address: "192.168.1.0/24"}}}
	hash, e := sha512_crypt.New().Generate([]byte("temporary-test-password-only"), nil)
	if e != nil {
		t.Fatal(e)
	}
	input := original
	input.Hosts = append(append([]model.ProxyHost{}, original.Hosts...), p)
	input.Access[acl.ID] = acl
	input.Passwords[acl.ID] = map[string]string{"validation": hash}
	p.AccessListID = acl.ID
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(path, ip string, auth bool, headers map[string]string) (int, string, http.Header) {
		r, _ := http.NewRequest("GET", "http://127.0.0.1:18998"+path, nil)
		r.Host = p.Hostname
		r.Header.Set("X-Real-IP", ip)
		if auth {
			r.SetBasicAuth("validation", "temporary-test-password-only")
		}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		resp, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body), resp.Header
	}
	apply := func(stage string) {
		p.Advanced.Headers = []model.Header{{Name: "X-Live-Stage", Value: stage, Response: true}, {Name: "X-Live-Request", Value: "present"}}
		input.Hosts[len(input.Hosts)-1] = p
		if e = a.Broker.Call(ctx, broker.Request{Action: "apply", Config: input}, nil); e != nil {
			t.Fatal(e)
		}
		deadline := time.Now().Add(15 * time.Second)
		stable := 0
		for {
			conn, err := net.DialTimeout("tcp", "127.0.0.1:18998", time.Second)
			if err != nil {
				if time.Now().After(deadline) {
					t.Fatal("nginx listener did not become ready")
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			conn.Close()
			_, _, h := request("/", "192.168.1.7", true, nil)
			if h.Get("X-Live-Stage") == stage {
				stable++
				if stable >= 5 {
					return
				}
			} else {
				stable = 0
			}
			if time.Now().After(deadline) {
				t.Fatal("nginx reload did not settle")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	apply("access")
	if status, _, _ := request("/", "192.168.1.7", false, nil); status != 401 {
		t.Fatal("Basic Auth missing challenge", status)
	}
	if status, body, h := request("/", "192.168.1.7", true, nil); status != 200 || !strings.Contains(body, "auth:;custom:present") || (!strings.Contains(h.Get("Strict-Transport-Security"), "includeSubDomains") || len(h.Values("Strict-Transport-Security")) != 1) {
		t.Fatal("Basic Auth, Authorization stripping, request headers or HSTS with response headers failed", status, body, h.Get("Strict-Transport-Security"))
	}
	if status, _, _ := request("/", "203.0.113.2", true, nil); status != 403 {
		t.Fatal("IP deny failed", status)
	}
	if status, body, _ := request("/alternate", "192.168.1.7", true, nil); status != 200 || body != "alternate-location" {
		t.Fatal("custom location failed", status)
	}
	if status, _, _ := request("/.git/config", "192.168.1.7", true, nil); status != 403 {
		t.Fatal("exploit filter failed", status)
	}
	invalid := p
	invalid.Advanced.Snippet = "proxy_buffer_size definitely-invalid;"
	input.Hosts[len(input.Hosts)-1] = invalid
	if e = a.Broker.Call(ctx, broker.Request{Action: "apply", Config: input}, nil); e == nil {
		t.Fatal("nginx accepted invalid size")
	}
	if status, _, _ := request("/", "192.168.1.7", true, nil); status != 200 {
		t.Fatal("rollback lost working auth-file permissions", status)
	}
	acl.Satisfy = "any"
	acl.PassAuthorization = true
	input.Access[acl.ID] = acl
	apply("either")
	if status, _, _ := request("/", "192.168.1.7", false, nil); status != 200 {
		t.Fatal("satisfy any IP failed", status)
	}
	if status, body, _ := request("/", "203.0.113.2", true, nil); status != 200 || !strings.Contains(body, "auth:Basic ") {
		t.Fatal("satisfy any password or Authorization forwarding failed", status)
	}
	p.AccessListID = ""
	p.Advanced.CacheAssets = true
	p.Advanced.ForceSSL = true
	p.HTTPSVerified = true
	apply("cache")
	_, body1, _ := request("/unique-asset.css", "192.168.1.7", false, nil)
	_, body2, _ := request("/unique-asset.css", "192.168.1.7", false, nil)
	if body1 != body2 {
		t.Fatal("static asset cache did not serve a hit", body1, body2)
	}
	_, body3, _ := request("/unique-asset.css", "192.168.1.7", false, map[string]string{"Cookie": "session=fixture"})
	if body3 == body2 {
		t.Fatal("authenticated cookie did not bypass static cache")
	}
	r, _ := http.NewRequest("GET", "http://127.0.0.1/redirect", nil)
	r.Host = p.Hostname
	resp, e := client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 308 || resp.Header.Get("Location") != "https://"+p.Hostname+"/redirect" {
		t.Fatal("Force SSL redirect failed")
	}
	conn, e := net.Dial("tcp", "127.0.0.1:18998")
	if e != nil {
		t.Fatal(e)
	}
	_, _ = fmt.Fprintf(conn, "GET /socket HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", p.Hostname)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, e := bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	if e != nil || !strings.Contains(line, "101") {
		t.Fatal("WebSocket upgrade failed", line, e)
	}
	body := strings.NewReader(strings.Repeat("x", 2<<20))
	post, _ := http.NewRequest("POST", "http://127.0.0.1:18998/upload", body)
	post.Host = p.Hostname
	resp, e = client.Do(post)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatal("body limit failed", resp.StatusCode)
	}
	p.Target = target(tlsUpstream.URL)
	p.Target.TLS.ServerName = "example.com"
	p.Target.TLS.TrustedPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsUpstream.Certificate().Raw}))
	p.Advanced.CacheAssets = false
	apply("pinned-tls")
	if status, body, _ := request("/", "192.168.1.7", false, nil); status != 200 || body != "trusted-upstream" {
		t.Fatal("explicit upstream certificate trust failed", status)
	}
	t.Log("Live nginx: Basic Auth/IP all and any, Authorization forwarding, HSTS/custom headers, custom locations, exploit filtering, invalid-config rollback, static cache/cookie bypass, Force SSL, WebSockets, body limit and pinned upstream TLS passed")
}
