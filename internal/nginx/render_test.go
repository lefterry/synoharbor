package nginx

import (
	"strings"
	"testing"

	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/lefterry/synoharbor/internal/model"
)

func host() model.ProxyHost {
	return model.ProxyHost{Meta: model.Meta{ID: "proxy-one"}, Hostname: "one.syno.example.net", Target: model.Target{Scheme: "http", Host: "127.0.0.1", Port: 8095}, LoopbackPort: 18080, Managed: true, Enabled: true}
}
func TestAdvancedRulesAndSSLReadiness(t *testing.T) {
	p := host()
	p.Advanced = model.Advanced{WebSockets: true, ForceSSL: true, HSTS: true, IncludeSubdomains: true, CacheAssets: true, BlockExploits: true, ReadTimeout: 600, BodySizeMB: 512, Headers: []model.Header{{Name: "X-Frame-Options", Value: "DENY", Response: true}}, Locations: []model.Location{{Path: "/api", Target: model.Target{Scheme: "http", Host: "127.0.0.1", Port: 8096}, Snippet: "proxy_buffering off;"}}}
	b, e := Render(Input{Hosts: []model.ProxyHost{p}})
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(b.Config, "return 308") {
		t.Fatal("redirect enabled before HTTPS verification")
	}
	for _, want := range []string{"listen 127.0.0.1:18080", "real_ip_header X-Real-IP", "includeSubDomains", "proxy_set_header Upgrade", "proxy_cache synoharbor_assets", "$synoharbor_skip_asset", "$http_cookie", "location /api", "proxy_read_timeout 600s", "client_max_body_size 512m", "X-Frame-Options", "return 403"} {
		if !strings.Contains(b.Config, want) {
			t.Errorf("missing %s", want)
		}
	}
	p.HTTPSVerified = true
	b, e = Render(Input{Hosts: []model.ProxyHost{p}})
	if e != nil || !strings.Contains(b.Config, "return 308 https://one.syno.example.net$request_uri") {
		t.Fatal("SSL redirect missing")
	}
	p.Enabled = false
	b, e = Render(Input{Hosts: []model.ProxyHost{p}})
	if e != nil || strings.Contains(b.Config, "server {") {
		t.Fatal("disabled host still served")
	}
}
func TestSnippetIsolationAndAccess(t *testing.T) {
	for _, bad := range []string{"include /etc/passwd;", "listen 443;", "root /;", "proxy_pass http://attacker;", "proxy_buffering off; } server {", "proxy_buffering off;\ninclude /etc/nginx/nginx.conf;", "access_log /tmp/owned;", "proxy_redirect $http_cookie https://attacker;"} {
		if _, e := Snippet(bad); e == nil {
			t.Errorf("unsafe snippet accepted: %s", bad)
		}
	}
	p := host()
	p.AccessListID = "access-one"
	hash, e := sha512_crypt.New().Generate([]byte("long-test-password"), nil)
	if e != nil {
		t.Fatal(e)
	}
	a := model.AccessList{Meta: model.Meta{ID: "access-one"}, Name: "LAN", Satisfy: "all", Rules: []model.IPRule{{Action: "allow", Address: "192.168.1.0/24"}}, Users: []model.BasicUser{{Username: "terry", Configured: true}}}
	b, e := Render(Input{Hosts: []model.ProxyHost{p}, Access: map[string]model.AccessList{a.ID: a}, Passwords: map[string]map[string]string{a.ID: {"terry": hash}}})
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"allow 192.168.1.0/24;", "deny all;", "satisfy all;", "auth_basic_user_file", "proxy_set_header Authorization \"\";"} {
		if !strings.Contains(b.Config, want) {
			t.Errorf("missing %s", want)
		}
	}
	if !strings.Contains(string(b.Files["access-one.htpasswd"]), "terry:$6$") {
		t.Fatal("DSM-compatible password hash missing")
	}
}
