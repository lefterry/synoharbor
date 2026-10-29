package nginx

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/lefterry/synoharbor/internal/model"
)

const Root = "/usr/local/etc/synoharbor"

type Input struct {
	Hosts     []model.ProxyHost            `json:"hosts"`
	Access    map[string]model.AccessList  `json:"access"`
	Passwords map[string]map[string]string `json:"passwords"`
}
type Bundle struct {
	Config string
	Files  map[string][]byte
}

var headerName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var hashRE = regexp.MustCompile(`^\$6\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$`)

func quoted(s string) (string, error) {
	if strings.ContainsAny(s, "\x00\r\n\\\"{};") {
		return "", errors.New("unsafe nginx value")
	}
	return `"` + s + `"`, nil
}

// Deliberately limited to location-scoped non-file directives. Quotes cannot
// smuggle a new directive, variable expansion is limited to harmless variables.
// Full global/server configuration, includes, Lua, SSI, filesystem handlers and
// listeners are never accepted from a host snippet.
func Snippet(s string) (string, error) {
	allowed := map[string]bool{"proxy_buffering": true, "proxy_request_buffering": true, "proxy_buffer_size": true, "proxy_buffers": true, "proxy_busy_buffers_size": true, "proxy_max_temp_file_size": true, "proxy_redirect": true, "proxy_cookie_path": true, "proxy_cookie_domain": true, "proxy_next_upstream": true, "proxy_next_upstream_tries": true, "proxy_next_upstream_timeout": true, "proxy_cache_valid": true, "proxy_cache_bypass": true, "proxy_no_cache": true, "send_timeout": true, "keepalive_timeout": true, "gzip": true, "gzip_types": true, "gzip_min_length": true, "tcp_nodelay": true}
	if len(s) > 16384 {
		return "", errors.New("nginx snippet is too long")
	}
	var out strings.Builder
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsAny(line, "{}\r\x00\\") || !strings.HasSuffix(line, ";") || strings.Count(line, ";") != 1 {
			return "", errors.New("use one allowed directive per line, ending with a semicolon")
		}
		f := strings.Fields(strings.TrimSuffix(line, ";"))
		if len(f) < 2 || !allowed[f[0]] {
			return "", fmt.Errorf("snippet directive %q is not permitted", strings.Split(line, " ")[0])
		}
		if strings.Contains(line, "$") {
			for _, v := range regexp.MustCompile(`\$[A-Za-z0-9_]+`).FindAllString(line, -1) {
				if v != "$http_upgrade" && v != "$http_authorization" && v != "$scheme" && v != "$host" {
					return "", errors.New("snippet variable is not permitted")
				}
			}
		}
		out.WriteString("    " + line + "\n")
	}
	return out.String(), nil
}
func Render(in Input) (Bundle, error) {
	b := Bundle{Files: map[string][]byte{}}
	var c strings.Builder
	c.WriteString("# Managed by SynoHarbor. Edit through SynoHarbor or remove the native DSM proxy.\n")
	cache := false
	seenHost := map[string]bool{}
	seenPort := map[int]bool{}
	for _, p := range in.Hosts {
		if p.Enabled && p.Managed && !p.ExternalDeleted && !p.AdvancedBypassed && p.Advanced.CacheAssets {
			cache = true
		}
	}
	if cache {
		c.WriteString("map $uri $synoharbor_skip_asset { default 1; ~*\\.(?:css|js|png|jpg|jpeg|gif|webp|ico|svg|woff|woff2|ttf)$ 0; }\nproxy_cache_path /usr/local/var/cache/synoharbor levels=1:2 keys_zone=synoharbor_assets:10m max_size=512m inactive=24h use_temp_path=off;\n")
	}
	for _, p := range in.Hosts {
		if !p.Enabled || !p.Managed || p.ExternalDeleted || p.AdvancedBypassed {
			continue
		}
		if !model.ValidID(p.ID) {
			return b, errors.New("invalid proxy ID")
		}
		if e := p.Validate(); e != nil {
			return b, e
		}
		if p.LoopbackPort < 18080 || p.LoopbackPort > 18999 {
			return b, errors.New("managed port not allocated")
		}
		if seenHost[p.Hostname] || seenPort[p.LoopbackPort] {
			return b, errors.New("duplicate managed listener")
		}
		seenHost[p.Hostname] = true
		seenPort[p.LoopbackPort] = true
		fmt.Fprintf(&c, "\n# %s (%s)\nserver {\n listen 127.0.0.1:%d;\n server_name %s;\n set_real_ip_from 127.0.0.1;\n real_ip_header X-Real-IP;\n real_ip_recursive off;\n client_max_body_size %dm;\n", p.Hostname, p.ID, p.LoopbackPort, p.Hostname, p.Advanced.BodySizeMB)
		if p.Advanced.HSTS {
			suffix := ""
			if p.Advanced.IncludeSubdomains {
				suffix = "; includeSubDomains"
			}
			fmt.Fprintf(&c, " add_header Strict-Transport-Security \"max-age=15552000%s\" always;\n", suffix)
		}
		if p.Advanced.BlockExploits {
			c.WriteString(" if ($request_uri ~* \"(?:\\\\.git/|\\\\.env(?:$|[/?])|/wp-admin/|/wp-login\\\\.php|\\\\.\\\\./|%2e%2e|%00|<script|%3cscript)\") { return 403; }\n")
		}
		if p.AccessListID != "" {
			a, ok := in.Access[p.AccessListID]
			if !ok {
				return b, errors.New("access list is missing")
			}
			if e := a.Validate(); e != nil {
				return b, e
			}
			fmt.Fprintf(&c, " satisfy %s;\n", a.Satisfy)
			hasAllow := false
			for _, r := range a.Rules {
				fmt.Fprintf(&c, " %s %s;\n", r.Action, r.Address)
				hasAllow = hasAllow || r.Action == "allow"
			}
			if hasAllow {
				c.WriteString(" deny all;\n")
			}
			if len(a.Users) > 0 {
				if !model.ValidID(a.ID) {
					return b, errors.New("invalid access list ID")
				}
				var f strings.Builder
				for _, u := range a.Users {
					h := in.Passwords[a.ID][u.Username]
					if !hashRE.MatchString(h) {
						return b, errors.New("Basic Auth password missing or unsupported")
					}
					fmt.Fprintf(&f, "%s:%s\n", u.Username, h)
				}
				b.Files[a.ID+".htpasswd"] = []byte(f.String())
				fmt.Fprintf(&c, " auth_basic \"SynoHarbor\";\n auth_basic_user_file %s/%s.htpasswd;\n", Root, a.ID)
			}
		}
		locs := []model.Location{{Path: "/", Target: p.Target, Snippet: p.Advanced.Snippet}}
		locs = append(locs, p.Advanced.Locations...)
		seen := map[string]bool{}
		for i, l := range locs {
			if seen[l.Path] {
				return b, errors.New("duplicate custom location")
			}
			seen[l.Path] = true
			fmt.Fprintf(&c, " location %s {\n", l.Path)
			a := p.Advanced
			fmt.Fprintf(&c, "  proxy_connect_timeout %ds;\n  proxy_read_timeout %ds;\n  proxy_send_timeout %ds;\n  proxy_http_version 1.1;\n  proxy_set_header Host $host;\n  proxy_set_header X-Real-IP $remote_addr;\n  proxy_set_header X-Forwarded-For $remote_addr;\n  proxy_set_header X-Forwarded-Proto https;\n", or(a.ConnectTimeout, 60), or(a.ReadTimeout, 60), or(a.SendTimeout, 60))
			if a.WebSockets {
				c.WriteString("  proxy_set_header Upgrade $http_upgrade;\n  proxy_set_header Connection $connection_upgrade;\n")
			} else {
				c.WriteString("  proxy_set_header Connection \"\";\n")
			}
			if acl, ok := in.Access[p.AccessListID]; ok && len(acl.Users) > 0 && !acl.PassAuthorization {
				c.WriteString("  proxy_set_header Authorization \"\";\n")
			}
			if a.CacheAssets {
				c.WriteString("  proxy_cache synoharbor_assets;\n  proxy_cache_methods GET HEAD;\n  proxy_cache_key \"$scheme$host$request_uri\";\n  proxy_cache_bypass $synoharbor_skip_asset $http_authorization $http_cookie $http_upgrade;\n  proxy_no_cache $synoharbor_skip_asset $http_authorization $http_cookie $http_upgrade;\n  proxy_cache_valid 200 10m;\n")
			}
			for _, h := range a.Headers {
				if !headerName.MatchString(h.Name) {
					return b, errors.New("invalid custom header name")
				}
				lower := strings.ToLower(h.Name)
				if lower == "x-real-ip" || lower == "x-forwarded-for" || lower == "x-forwarded-proto" || lower == "authorization" || lower == "connection" || lower == "upgrade" || lower == "strict-transport-security" || lower == "host" {
					return b, errors.New("use the dedicated option for this reserved header")
				}
				v, e := quoted(h.Value)
				if e != nil {
					return b, e
				}
				if strings.Contains(h.Value, "$") {
					return b, errors.New("custom headers must contain literal values")
				}
				directive := "proxy_set_header"
				tail := ""
				if h.Response {
					directive = "add_header"
					tail = " always"
				}
				fmt.Fprintf(&c, "  %s %s %s%s;\n", directive, h.Name, v, tail)
			}
			if l.Target.Scheme == "https" {
				c.WriteString("  proxy_ssl_server_name on;\n")
				name := l.Target.TLS.ServerName
				if name == "" {
					name = l.Target.Host
				}
				fmt.Fprintf(&c, "  proxy_ssl_name %s;\n", name)
				if l.Target.TLS.Verify {
					trust := "/etc/ssl/certs/ca-certificates.crt"
					if l.Target.TLS.TrustedPEM != "" {
						raw, rest := pem.Decode([]byte(l.Target.TLS.TrustedPEM))
						if raw == nil || raw.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
							return b, errors.New("provide one trusted PEM certificate")
						}
						if _, e := x509.ParseCertificate(raw.Bytes); e != nil {
							return b, errors.New("invalid trusted certificate")
						}
						file := fmt.Sprintf("%s-%d.trust.pem", p.ID, i)
						b.Files[file] = []byte(l.Target.TLS.TrustedPEM)
						trust = Root + "/" + file
					}
					fmt.Fprintf(&c, "  proxy_ssl_verify on;\n  proxy_ssl_verify_depth 5;\n  proxy_ssl_trusted_certificate %s;\n", trust)
				} else {
					c.WriteString("  proxy_ssl_verify off;\n")
				}
			}
			snippet, e := Snippet(l.Snippet)
			if e != nil {
				return b, e
			}
			c.WriteString(snippet)
			if p.Advanced.HSTS {
				suffix := ""
				if p.Advanced.IncludeSubdomains {
					suffix = "; includeSubDomains"
				}
				fmt.Fprintf(&c, "  add_header Strict-Transport-Security \"max-age=15552000%s\" always;\n", suffix)
			}
			fmt.Fprintf(&c, "  proxy_pass %s://%s;\n }\n", l.Target.Scheme, net.JoinHostPort(l.Target.Host, strconv.Itoa(l.Target.Port)))
		}
		c.WriteString("}\n")
		if p.Advanced.ForceSSL && p.HTTPSVerified {
			fmt.Fprintf(&c, "server {\n listen 80;\n listen [::]:80;\n server_name %s;\n return 308 https://%s$request_uri;\n}\n", p.Hostname, p.Hostname)
		}
	}
	b.Config = c.String()
	return b, nil
}
func or(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}
func FileNames(b Bundle) []string {
	a := []string{}
	for k := range b.Files {
		a = append(a, k)
	}
	sort.Strings(a)
	return a
}
