package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

type Meta struct {
	ID        string    `json:"id"`
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updatedAt"`
}
type CertificateProfile struct {
	Meta
	Domain             string    `json:"domain"`
	Issuer             string    `json:"issuer"`
	Email              string    `json:"email"`
	CredentialID       string    `json:"credentialId"`
	KeyType            string    `json:"keyType"`
	Staging            bool      `json:"staging"`
	NativeID           string    `json:"nativeId"`
	Fingerprint        string    `json:"fingerprint"`
	PendingFingerprint string    `json:"pendingFingerprint"`
	Managed            bool      `json:"managed"`
	AutoRenew          bool      `json:"autoRenew"`
	Status             string    `json:"status"`
	Message            string    `json:"message"`
	ExpiresAt          time.Time `json:"expiresAt"`
	LastDeployed       time.Time `json:"lastDeployed"`
	ExternalDeleted    bool      `json:"externalDeleted"`
}
type Credential struct {
	Meta
	Name       string `json:"name"`
	Configured bool   `json:"configured"`
}
type Target struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	TLS    TLS    `json:"tls"`
}
type TLS struct {
	Verify     bool   `json:"verify"`
	ServerName string `json:"serverName"`
	TrustedPEM string `json:"trustedPem"`
}
type Header struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Response bool   `json:"response"`
}
type Location struct {
	Path    string `json:"path"`
	Target  Target `json:"target"`
	Snippet string `json:"snippet"`
}
type Advanced struct {
	WebSockets        bool       `json:"webSockets"`
	ForceSSL          bool       `json:"forceSsl"`
	HSTS              bool       `json:"hsts"`
	IncludeSubdomains bool       `json:"includeSubdomains"`
	CacheAssets       bool       `json:"cacheAssets"`
	BlockExploits     bool       `json:"blockExploits"`
	Headers           []Header   `json:"headers"`
	ConnectTimeout    int        `json:"connectTimeout"`
	ReadTimeout       int        `json:"readTimeout"`
	SendTimeout       int        `json:"sendTimeout"`
	BodySizeMB        int        `json:"bodySizeMb"`
	Locations         []Location `json:"locations"`
	Snippet           string     `json:"snippet"`
}
type ProxyHost struct {
	Meta
	AppUI            bool     `json:"appUi,omitempty"`
	Hostname         string   `json:"hostname"`
	Target           Target   `json:"target"`
	CertificateID    string   `json:"certificateId"`
	AccessListID     string   `json:"accessListId"`
	Advanced         Advanced `json:"advanced"`
	NativeID         string   `json:"nativeId"`
	NativeHash       string   `json:"nativeHash"`
	LoopbackPort     int      `json:"loopbackPort"`
	Enabled          bool     `json:"enabled"`
	Managed          bool     `json:"managed"`
	AdvancedBypassed bool     `json:"advancedBypassed"`
	ExternalDeleted  bool     `json:"externalDeleted"`
	Status           string   `json:"status"`
	Message          string   `json:"message"`
	HTTPSVerified    bool     `json:"httpsVerified"`
}
type IPRule struct {
	Action  string `json:"action"`
	Address string `json:"address"`
}
type BasicUser struct {
	Username   string `json:"username"`
	Configured bool   `json:"configured"`
}
type AccessList struct {
	Meta
	Name              string      `json:"name"`
	Rules             []IPRule    `json:"rules"`
	Users             []BasicUser `json:"users"`
	Satisfy           string      `json:"satisfy"`
	PassAuthorization bool        `json:"passAuthorization"`
}
type Operation struct {
	Meta
	Kind       string          `json:"kind"`
	ObjectID   string          `json:"objectId"`
	State      string          `json:"state"`
	Stage      string          `json:"stage"`
	Message    string          `json:"message"`
	Attempts   int             `json:"attempts"`
	StartedAt  time.Time       `json:"startedAt"`
	FinishedAt time.Time       `json:"finishedAt"`
	Request    json.RawMessage `json:"-"`
}
type DSMObject map[string]any
type DSMSnapshot struct {
	Meta
	Certificates []DSMObject `json:"certificates"`
	Proxies      []DSMObject `json:"proxies"`
	SuccessAt    time.Time   `json:"successAt"`
	Error        string      `json:"error"`
	HTTP2        bool        `json:"http2"`
}
type Settings struct {
	Meta
	Account     string    `json:"account"`
	Port        int       `json:"port"`
	ServerName  string    `json:"serverName"`
	Connected   bool      `json:"connected"`
	AuthStatus  string    `json:"authStatus"`
	AuthMessage string    `json:"authMessage"`
	CheckedAt   time.Time `json:"checkedAt"`
	Theme       string    `json:"theme"`
}
type ConnectionSecret struct {
	Password   string `json:"password"`
	DeviceID   string `json:"deviceId"`
	DeviceName string `json:"deviceName"`
}

var domainRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
var idRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,80}$`)

func ValidID(s string) bool { return idRE.MatchString(s) }
func ValidDomain(s string, wildcard bool) bool {
	if wildcard {
		s = strings.TrimPrefix(s, "*.")
	}
	return len(s) <= 253 && domainRE.MatchString(s)
}
func (p CertificateProfile) Validate() error {
	if !ValidDomain(p.Domain, true) {
		return errors.New("enter a lowercase fully qualified domain or wildcard")
	}
	if _, err := mail.ParseAddress(p.Email); err != nil {
		return errors.New("a valid ACME email is required")
	}
	if p.KeyType != "rsa4096" && p.KeyType != "p256" && p.KeyType != "p384" {
		return errors.New("unsupported key type")
	}
	if !ValidID(p.CredentialID) {
		return errors.New("select a Cloudflare credential")
	}
	return nil
}
func (t Target) Validate() error {
	if t.Scheme != "http" && t.Scheme != "https" {
		return errors.New("target scheme must be HTTP or HTTPS")
	}
	if net.ParseIP(t.Host) == nil && t.Host != "localhost" && !ValidDomain(t.Host, false) {
		return errors.New("target must be an IP address or hostname")
	}
	if t.Port < 1 || t.Port > 65535 {
		return errors.New("invalid target port")
	}
	if t.TLS.ServerName != "" && net.ParseIP(t.TLS.ServerName) == nil && !ValidDomain(t.TLS.ServerName, false) {
		return errors.New("invalid upstream TLS server name")
	}
	return nil
}
func (p ProxyHost) Validate() error {
	if !ValidDomain(p.Hostname, false) {
		return errors.New("enter a lowercase proxy hostname")
	}
	if err := p.Target.Validate(); err != nil {
		return err
	}
	if p.LoopbackPort != 0 && (p.LoopbackPort < 18080 || p.LoopbackPort > 18999) {
		return errors.New("invalid managed port")
	}
	a := p.Advanced
	if p.AppUI && (p.Target.Host != "127.0.0.1" || p.Target.Scheme != "https" || len(a.Locations) != 0 || len(a.Headers) != 0 || a.Snippet != "" || a.CacheAssets || a.WebSockets || p.AccessListID != "") {
		return errors.New("standalone access uses fixed local application routes; configure it in Settings")
	}
	if a.ConnectTimeout < 0 || a.ConnectTimeout > 3600 || a.ReadTimeout < 0 || a.ReadTimeout > 86400 || a.SendTimeout < 0 || a.SendTimeout > 86400 || a.BodySizeMB < 0 || a.BodySizeMB > 1048576 {
		return errors.New("advanced limits out of range")
	}
	if len(a.Locations) > 32 || len(a.Headers) > 64 {
		return errors.New("too many advanced rules")
	}
	for _, l := range a.Locations {
		if !strings.HasPrefix(l.Path, "/") || strings.ContainsAny(l.Path, "\r\n\t $;{}\"\\#") {
			return errors.New("invalid location path")
		}
		if l.Path == "/" {
			return errors.New("use the main target for the root location")
		}
		if err := l.Target.Validate(); err != nil {
			return err
		}
	}
	return nil
}
func (a AccessList) Validate() error {
	if strings.TrimSpace(a.Name) == "" {
		return errors.New("access list name required")
	}
	if a.Satisfy != "all" && a.Satisfy != "any" {
		return errors.New("access policy must be all or any")
	}
	for _, r := range a.Rules {
		if r.Action != "allow" && r.Action != "deny" {
			return errors.New("invalid IP action")
		}
		if r.Address != "all" && net.ParseIP(r.Address) == nil {
			if _, _, e := net.ParseCIDR(r.Address); e != nil {
				return errors.New("invalid IP or CIDR")
			}
		}
	}
	for _, u := range a.Users {
		if !idRE.MatchString(u.Username) {
			return errors.New("invalid Basic Auth username")
		}
	}
	return nil
}
func Covers(domain, host string) bool {
	if domain == host {
		return true
	}
	if !strings.HasPrefix(domain, "*.") {
		return false
	}
	suffix := strings.TrimPrefix(domain, "*.")
	return strings.HasSuffix(host, "."+suffix) && !strings.Contains(strings.TrimSuffix(host, "."+suffix), ".")
}
func Hash(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
