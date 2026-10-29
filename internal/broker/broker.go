package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lefterry/synoharbor/internal/model"
	"github.com/lefterry/synoharbor/internal/nginx"
	"gopkg.in/yaml.v3"
)

const Socket = "/var/run/synoharbor-broker.sock"
const Config = "/usr/local/etc/nginx/sites-enabled/synoharbor.conf"

type Request struct {
	Action  string      `json:"action"`
	Config  nginx.Input `json:"config"`
	ID      string      `json:"id"`
	Message string      `json:"message"`
}
type Response struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}
type Client struct{ Path string }

func (c Client) Call(ctx context.Context, r Request, out any) error {
	path := c.Path
	if path == "" {
		path = Socket
	}
	conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", path)
	if e != nil {
		return errors.New("privileged DSM broker is unavailable")
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(90 * time.Second))
	if e = json.NewEncoder(conn).Encode(r); e != nil {
		return e
	}
	var resp Response
	if e = json.NewDecoder(io.LimitReader(conn, 16<<20)).Decode(&resp); e != nil {
		return errors.New("invalid broker response")
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	if out != nil {
		return json.Unmarshal(resp.Data, out)
	}
	return nil
}

type System struct {
	ConfigPath string
	Root       string
	Run        func(context.Context, string, ...string) error
	mu         sync.Mutex
}

func NativeSystem() *System {
	return &System{ConfigPath: Config, Root: nginx.Root, Run: func(ctx context.Context, path string, args ...string) error {
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
		if e := cmd.Run(); e != nil {
			return errors.New("nginx validation or reload failed; previous configuration restored")
		}
		return nil
	}}
}
func (s *System) Apply(ctx context.Context, input nginx.Input) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	bundle, e := nginx.Render(input)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(s.Root, 0750); e != nil {
		return e
	}
	if httpUser, e := user.Lookup("http"); e == nil {
		gid, _ := strconv.Atoi(httpUser.Gid)
		os.Chown(s.Root, 0, gid)
		os.MkdirAll("/usr/local/var/cache/synoharbor", 0750)
		uid, _ := strconv.Atoi(httpUser.Uid)
		os.Chown("/usr/local/var/cache/synoharbor", uid, gid)
	}
	if e = os.MkdirAll(filepath.Dir(s.ConfigPath), 0755); e != nil {
		return e
	}
	previous := map[string][]byte{}
	missing := map[string]bool{}
	writes := map[string][]byte{s.ConfigPath: []byte(bundle.Config)}
	for name, b := range bundle.Files {
		writes[filepath.Join(s.Root, name)] = b
	}
	for p := range writes {
		b, e := os.ReadFile(p)
		if errors.Is(e, os.ErrNotExist) {
			missing[p] = true
		} else if e != nil {
			return e
		} else {
			previous[p] = b
		}
	}
	restore := func() {
		for p := range writes {
			if missing[p] {
				os.Remove(p)
			} else {
				_ = atomicWrite(p, previous[p], 0640)
			}
		}
	}
	for p, b := range writes {
		if e = atomicWrite(p, b, 0640); e != nil {
			restore()
			return e
		}
		if p != s.ConfigPath {
			if g, e := user.LookupGroup("http"); e == nil {
				gid, _ := strconv.Atoi(g.Gid)
				os.Chown(p, 0, gid)
			}
		}
	}
	if e = s.Run(ctx, "/usr/bin/nginx", "-t"); e != nil {
		restore()
		return e
	}
	if e = s.Run(ctx, "/usr/bin/nginx", "-s", "reload"); e != nil {
		restore()
		_ = s.Run(ctx, "/usr/bin/nginx", "-t")
		_ = s.Run(ctx, "/usr/bin/nginx", "-s", "reload")
		return e
	}
	// Remove only previously owned credential/trust files after successful reload.
	files, _ := os.ReadDir(s.Root)
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".htpasswd") || strings.HasSuffix(f.Name(), ".trust.pem") {
			p := filepath.Join(s.Root, f.Name())
			if _, ok := writes[p]; !ok {
				os.Remove(p)
			}
		}
	}
	return nil
}
func atomicWrite(path string, b []byte, mode os.FileMode) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".synoharbor-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func Serve(ctx context.Context, path string, uid, gid int, system *System) error {
	if os.Geteuid() != 0 {
		return errors.New("broker must be started by the root package lifecycle")
	}
	os.Remove(path)
	ln, e := net.Listen("unix", path)
	if e != nil {
		return e
	}
	defer ln.Close()
	defer os.Remove(path)
	os.Chown(path, 0, gid)
	os.Chmod(path, 0660)
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, e := ln.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(90 * time.Second))
			if !peerAllowed(conn, uid) {
				return
			}
			var r Request
			if json.NewDecoder(io.LimitReader(conn, 4<<20)).Decode(&r) != nil {
				return
			}
			data, e := system.handle(ctx, r)
			resp := Response{OK: e == nil}
			if e != nil {
				resp.Error = e.Error()
			} else {
				resp.Data, _ = json.Marshal(data)
			}
			_ = json.NewEncoder(conn).Encode(resp)
		}()
	}
}
func (s *System) handle(ctx context.Context, r Request) (any, error) {
	switch r.Action {
	case "apply":
		return nil, s.Apply(ctx, r.Config)
	case "http2":
		b, e := os.ReadFile("/etc/nginx/nginx.conf")
		return map[string]bool{"enabled": strings.Contains(string(b), "http2")}, e
	case "notify":
		if len(r.Message) > 400 {
			return nil, errors.New("notification too long")
		}
		return nil, exec.CommandContext(ctx, "/usr/syno/bin/synodsmnotify", "@administrators", "SynoHarbor", r.Message).Run()
	case "legacy-export":
		return legacyExport()
	case "legacy-stop":
		return nil, exec.CommandContext(ctx, "/usr/syno/bin/synopkg", "stop", "dnsacme").Run()
	case "native-certificate":
		if !model.ValidID(r.ID) {
			return nil, errors.New("invalid certificate ID")
		}
		root := "/usr/syno/etc/certificate/_archive/" + r.ID
		cert, e := os.ReadFile(root + "/fullchain.pem")
		if e != nil {
			return nil, errors.New("native certificate chain unavailable")
		}
		key, e := os.ReadFile(root + "/privkey.pem")
		if e != nil {
			return nil, errors.New("native certificate key unavailable")
		}
		return map[string]string{"certificate": string(cert), "key": string(key)}, nil
	default:
		return nil, errors.New("broker action is not allowed")
	}
}

// Fixed-source, one-way migration; no caller-controlled filesystem path. Secrets
// travel only over the UID-checked Unix socket and never through the web API.
func legacyExport() (any, error) {
	const path = "/var/packages/dnsacme/etc/config.yaml"
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, errors.New("DNSACME configuration unavailable")
	}
	var cfg struct {
		ACME struct {
			Domains []string `yaml:"domains"`
			Email   string   `yaml:"email"`
			KeyType string   `yaml:"keyType"`
		} `yaml:"acme"`
		DNS struct {
			Provider string            `yaml:"provider"`
			Config   map[string]string `yaml:"config"`
		} `yaml:"dns"`
		Synology struct {
			Account  string `yaml:"account"`
			Password string `yaml:"password"`
			Port     int    `yaml:"port"`
		} `yaml:"synology"`
	}
	if e = yaml.Unmarshal(raw, &cfg); e != nil {
		return nil, errors.New("invalid legacy configuration")
	}
	token := cfg.DNS.Config["CLOUDFLARE_APITOKEN"]
	if token == "" {
		token = cfg.DNS.Config["CLOUDFLARE_API_TOKEN"]
	}
	if cfg.DNS.Provider != "cloudflare" || token == "" {
		return nil, errors.New("legacy Cloudflare credential unavailable")
	}
	return map[string]any{"domains": cfg.ACME.Domains, "email": cfg.ACME.Email, "keyType": cfg.ACME.KeyType, "token": token, "account": cfg.Synology.Account, "password": cfg.Synology.Password, "port": cfg.Synology.Port}, nil
}
