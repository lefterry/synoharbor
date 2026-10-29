package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lefterry/synoharbor/internal/broker"
	"github.com/lefterry/synoharbor/internal/dsm"
	"github.com/lefterry/synoharbor/internal/model"
	"github.com/lefterry/synoharbor/internal/recovery"
	"github.com/lefterry/synoharbor/internal/store"
)

type recoveryFixture struct {
	mu                   sync.Mutex
	proxies, certs       []model.DSMObject
	writes               int
	failDelete, failRead bool
	original             model.DSMObject
	app                  *App
	fp                   string
}

func recoveryProxy(id, host string, port int) model.DSMObject {
	return model.DSMObject{"UUID": id, "description": host, "frontend": map[string]any{"fqdn": host, "port": 443, "protocol": 1}, "backend": map[string]any{"fqdn": "127.0.0.1", "port": port, "protocol": 0}}
}
func newRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()
	s, e := store.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	a := New(s)
	t.Cleanup(a.ACME.Close)
	f := &recoveryFixture{app: a, original: recoveryProxy("original", "one.example.net", 8095)}
	original := model.DSMObject{}
	raw, _ := json.Marshal(f.original)
	_ = json.Unmarshal(raw, &original)
	f.proxies = []model.DSMObject{recoveryProxy("original", "one.example.net", 18080), recoveryProxy("created", "two.example.net", 18081), recoveryProxy("unrelated", "untouched.example.net", 8080)}
	service := func(subscriber, id string) map[string]any {
		return map[string]any{"subscriber": subscriber, "service": id, "owner": "root", "display_name": id}
	}
	f.certs = []model.DSMObject{{"id": "old", "desc": "Existing DSM cert", "services": []any{}}, {"id": "new", "desc": "SynoHarbor cert", "services": []any{service("ReverseProxy", "original"), service("ReverseProxy", "created"), service("Other", "foreign")}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = r.ParseForm()
		api, method := r.FormValue("api"), r.FormValue("method")
		var out any = map[string]any{}
		success := true
		switch api {
		case "SYNO.API.Auth":
			out = map[string]string{"sid": "fixture-sid", "synotoken": "fixture-token"}
		case "SYNO.Core.Certificate.CRT":
			if method == "list" {
				out = map[string]any{"certificates": f.certs}
				success = !f.failRead
			} else if method == "delete" {
				f.writes++
				var ids []string
				_ = json.Unmarshal([]byte(r.FormValue("ids")), &ids)
				next := []model.DSMObject{}
				for _, c := range f.certs {
					remove := false
					for _, id := range ids {
						remove = remove || dsm.ID(c) == id
					}
					if !remove {
						next = append(next, c)
					}
				}
				f.certs = next
			}
		case "SYNO.Core.AppPortal.ReverseProxy":
			if method == "list" {
				out = map[string]any{"entries": f.proxies}
				success = !f.failRead
			} else if method == "update" {
				f.writes++
				var entry model.DSMObject
				_ = json.Unmarshal([]byte(r.FormValue("entry")), &entry)
				for i, p := range f.proxies {
					if dsm.ID(p) == dsm.ID(entry) {
						f.proxies[i] = entry
					}
				}
			} else if method == "delete" {
				f.writes++
				if f.failDelete {
					success = false
					break
				}
				var ids []string
				_ = json.Unmarshal([]byte(r.FormValue("uuids")), &ids)
				next := []model.DSMObject{}
				for _, p := range f.proxies {
					remove := false
					for _, id := range ids {
						remove = remove || dsm.ID(p) == id
					}
					if !remove {
						next = append(next, p)
					} else {
						for _, c := range f.certs {
							services, _ := c["services"].([]any)
							kept := []any{}
							for _, v := range services {
								s, _ := v.(map[string]any)
								if dsm.String(s, "subscriber") != "ReverseProxy" || dsm.String(s, "service") != dsm.ID(p) {
									kept = append(kept, v)
								}
							}
							c["services"] = kept
						}
					}
				}
				f.proxies = next
			}
		case "SYNO.Core.Certificate.Service":
			f.writes++
			var settings []map[string]any
			_ = json.Unmarshal([]byte(r.FormValue("settings")), &settings)
			for _, setting := range settings {
				service, _ := setting["service"].(map[string]any)
				for _, c := range f.certs {
					services, _ := c["services"].([]any)
					next := []any{}
					for _, v := range services {
						s, _ := v.(map[string]any)
						if dsm.ServiceKey(s) != dsm.ServiceKey(service) {
							next = append(next, v)
						}
					}
					if dsm.ID(c) == dsm.String(setting, "id") {
						next = append(next, service)
					}
					c["services"] = next
				}
			}
		case "SYNO.Core.Web.DSM":
			out = map[string]bool{"enable_spdy": true}
		default:
			t.Errorf("unexpected DSM API: %s", api)
			success = false
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": success, "data": out, "error": map[string]int{"code": 500}})
	}))
	t.Cleanup(server.Close)
	a.NewDSM = func(settings model.Settings, secret model.ConnectionSecret) *dsm.Client {
		c := dsm.New(settings, secret)
		c.BaseURL = server.URL
		c.HTTP = server.Client()
		return c
	}
	settings := model.Settings{Meta: model.Meta{ID: "main"}, Account: "fixture", Port: 697, Connected: true}
	if e = s.Put("settings", &settings.Meta, &settings); e != nil {
		t.Fatal(e)
	}
	if e = s.PutSecret("dsm", model.ConnectionSecret{Password: "fixture-only"}); e != nil {
		t.Fatal(e)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "one.example.net"}, DNSNames: []string{"one.example.net"}, NotAfter: time.Now().Add(48 * time.Hour), NotBefore: time.Now().Add(-time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.fp, _, _ = dsm.Fingerprint(cert)
	dir, e := os.MkdirTemp("/tmp", "sh-recovery-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "broker.sock")
	ln, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	a.Broker.Path = path
	archives := recovery.Archives{Data: s.Dir, Root: filepath.Join(dir, "backups")}
	go func() {
		for {
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				var request broker.Request
				_ = json.NewDecoder(conn).Decode(&request)
				var out any
				var err error
				switch request.Action {
				case "backup-create":
					out, err = archives.Create(context.Background(), request.Message)
				case "native-certificate-info":
					out = map[string]string{"certificate": string(cert), "isDefault": "false"}
				case "apply":
					out = nil
				default:
					err = os.ErrInvalid
				}
				resp := broker.Response{Protocol: broker.Protocol, OK: err == nil}
				if err != nil {
					resp.Error = err.Error()
				} else {
					resp.Data, _ = json.Marshal(out)
				}
				_ = json.NewEncoder(conn).Encode(resp)
			}()
		}
	}()
	for _, ch := range []NativeChange{{Meta: model.Meta{ID: "proxy-one"}, Kind: "proxy", NativeID: "original", LoopbackPort: 18080, Before: original, BeforeCertificate: "old", ExpectedHash: model.Hash(f.proxies[0])}, {Meta: model.Meta{ID: "proxy-two"}, Kind: "proxy", NativeID: "created", LoopbackPort: 18081, ExpectedHash: model.Hash(f.proxies[1])}, {Meta: model.Meta{ID: "certificate-old"}, Kind: "certificate", NativeID: "old", Before: f.certs[0], ExpectedHash: f.fp}, {Meta: model.Meta{ID: "certificate-new"}, Kind: "certificate", NativeID: "new", ExpectedHash: f.fp}} {
		if e = s.Put("native-changes", &ch.Meta, &ch); e != nil {
			t.Fatal(e)
		}
	}
	for i, id := range []string{"one", "two"} {
		native := []string{"original", "created"}[i]
		p := model.ProxyHost{Meta: model.Meta{ID: id}, NativeID: native, Hostname: []string{"one.example.net", "two.example.net"}[i], LoopbackPort: 18080 + i, Enabled: true, Managed: true, NativeHash: model.Hash(f.proxies[i])}
		if e = s.Put("proxies", &p.Meta, &p); e != nil {
			t.Fatal(e)
		}
	}
	return f
}
func TestScopedRollbackPreservesUnrelatedObjectsAndSharedCertificates(t *testing.T) {
	f := newRecoveryFixture(t)
	a := f.app
	plan, e := a.RecoveryPreview(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if len(plan.Conflicts) > 0 {
		t.Fatal(plan.Conflicts)
	}
	if e = a.PrepareUninstall(context.Background(), plan.Token); e != nil {
		t.Fatal(e)
	}
	if model.Hash(nativeObject(f.proxies, "original")) != model.Hash(f.original) || nativeObject(f.proxies, "created") != nil || nativeObject(f.proxies, "unrelated") == nil {
		t.Fatal("rollback did not limit changes to owned proxies")
	}
	if nativeObject(f.certs, "new") == nil {
		t.Fatal("shared certificate removed")
	}
	if e = a.ValidateUninstall(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(a.Store.Dir, "uninstall-ready.json")); e != nil {
		t.Fatal("no successful rollback receipt")
	}
	if !a.RecoveryPaused() {
		t.Fatal("management would resume after rollback")
	}
}
func TestRollbackFailureCanResumeButCannotAuthorizeErasure(t *testing.T) {
	f := newRecoveryFixture(t)
	plan, e := f.app.RecoveryPreview(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	f.failDelete = true
	if e = f.app.PrepareUninstall(context.Background(), plan.Token); e == nil {
		t.Fatal("simulated native failure accepted")
	}
	if e = f.app.ValidateUninstall(context.Background()); e == nil {
		t.Fatal("failed rollback authorized erasure")
	}
	f.failDelete = false
	if e = f.app.PrepareUninstall(context.Background(), plan.Token); e != nil {
		t.Fatal("interrupted rollback did not resume:", e)
	}
}
func TestExternalChangesAndStaleConfirmationBlockRollback(t *testing.T) {
	for _, mode := range []string{"stale", "changed", "foreign-listener"} {
		t.Run(mode, func(t *testing.T) {
			f := newRecoveryFixture(t)
			plan, e := f.app.RecoveryPreview(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "stale":
				plan.Token = "old-token"
			case "changed":
				f.proxies[0]["description"] = "Edited in DSM"
			case "foreign-listener":
				f.proxies = append(f.proxies, recoveryProxy("another", "another.example.net", 18080))
			}
			if e = f.app.PrepareUninstall(context.Background(), plan.Token); e == nil {
				t.Fatal("unreviewed rollback accepted")
			}
			if f.writes != 0 {
				t.Fatal("native state changed before conflict rejection")
			}
		})
	}
}
func TestFailedDSMReadDoesNotBecomeDeletion(t *testing.T) {
	f := newRecoveryFixture(t)
	p := model.ProxyHost{Meta: model.Meta{ID: "read-test"}, NativeID: "original", Enabled: true, Managed: true}
	if e := f.app.Store.Put("proxies", &p.Meta, &p); e != nil {
		t.Fatal(e)
	}
	f.failRead = true
	if e := f.app.Sync(context.Background()); e == nil {
		t.Fatal("failed native read accepted")
	}
	if e := f.app.Store.Get("proxies", p.ID, &p); e != nil || p.ExternalDeleted || !p.Enabled {
		t.Fatal("failed read removed a native proxy")
	}
}
func TestPreJournalBackupCannotAuthorizeDestructiveRollback(t *testing.T) {
	f := newRecoveryFixture(t)
	var changes []NativeChange
	if e := f.app.Store.List("native-changes", &changes); e != nil {
		t.Fatal(e)
	}
	for _, ch := range changes {
		if e := f.app.Store.Delete("native-changes", ch.ID, ch.Version); e != nil {
			t.Fatal(e)
		}
	}
	p := model.ProxyHost{Meta: model.Meta{ID: "legacy"}, Hostname: "one.example.net", NativeID: "original", LoopbackPort: 18080, Managed: true, Enabled: true}
	if e := f.app.Store.Put("proxies", &p.Meta, &p); e != nil {
		t.Fatal(e)
	}
	plan, e := f.app.RecoveryPreview(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if len(plan.Conflicts) == 0 {
		t.Fatal("missing ownership journal was treated as an empty rollback")
	}
	if e = f.app.PrepareUninstall(context.Background(), plan.Token); e == nil {
		t.Fatal("unsafe cleanup of old backup was accepted")
	}
	if f.writes != 0 {
		t.Fatal("old backup damaged native routes")
	}
}
func TestNativeAliasDependencySurvivesOriginalProxyDeletion(t *testing.T) {
	f := newRecoveryFixture(t)
	s := f.app.Store
	var owner model.ProxyHost
	if e := s.Get("proxies", "one", &owner); e != nil {
		t.Fatal(e)
	}
	owner.Target = model.Target{Scheme: "http", Host: "127.0.0.1", Port: 8095}
	owner.HTTPSVerified = true
	owner.Advanced.ForceSSL = true
	owner.Meta = model.Meta{ID: "one"}
	if e := s.Put("applied-proxies", &owner.Meta, &owner); e != nil {
		t.Fatal(e)
	}
	f.proxies = append(f.proxies, recoveryProxy("alias", "alias.example.net", 18080))
	if e := f.app.Sync(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := f.app.Delete(context.Background(), "proxies", "one"); e == nil {
		t.Fatal("app deletion broke a dependent native alias")
	}
	if f.writes != 0 {
		t.Fatal("dependent route was altered")
	}
	remaining := []model.DSMObject{}
	for _, p := range f.proxies {
		if dsm.ID(p) != "original" {
			remaining = append(remaining, p)
		}
	}
	f.proxies = remaining
	if e := f.app.Sync(context.Background()); e != nil {
		t.Fatal(e)
	}
	in, e := f.app.RenderInput()
	if e != nil {
		t.Fatal(e)
	}
	if len(in.Hosts) != 1 || in.Hosts[0].ID != "one" || in.Hosts[0].Advanced.ForceSSL {
		t.Fatal("orphaned internal rules were lost or public owner redirect was resurrected")
	}
	remaining = nil
	for _, p := range f.proxies {
		if dsm.ID(p) != "alias" {
			remaining = append(remaining, p)
		}
	}
	f.proxies = remaining
	if e = f.app.Sync(context.Background()); e != nil {
		t.Fatal(e)
	}
	in, e = f.app.RenderInput()
	if e != nil || len(in.Hosts) != 0 {
		t.Fatal("unused orphan rules were not retired")
	}
}
