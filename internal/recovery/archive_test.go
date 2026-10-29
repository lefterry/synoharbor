package recovery

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lefterry/synoharbor/internal/model"
	"github.com/lefterry/synoharbor/internal/store"
)

func TestCompleteBackupSurvivesDataDeletionAndRestoresSecrets(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "package")
	s, e := store.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	p := model.Credential{Meta: model.Meta{ID: "one"}, Name: "Original token", Configured: true}
	if e = s.Put("credentials", &p.Meta, &p); e != nil {
		t.Fatal(e)
	}
	if e = s.PutSecret("cloudflare:one", "private-fixture-token"); e != nil {
		t.Fatal(e)
	}
	op, e := s.Enqueue("certificate.delete", "one", nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(filepath.Join(dir, "acme", "one"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "acme", "one", "key.pem"), []byte("private-fixture-key"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = s.Backup(context.Background(), filepath.Join(dir, ExportDB)); e != nil {
		t.Fatal(e)
	}
	a := Archives{Data: dir, Root: filepath.Join(filepath.Dir(dir), "outside-package-backups")}
	b, e := a.Create(context.Background(), "manual")
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	info, _ := os.Stat(filepath.Join(a.Root, b.ID+".tgz"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("backup not private")
	}
	if e = os.RemoveAll(dir); e != nil {
		t.Fatal(e)
	}
	if e = a.RestoreOffline(b.ID, -1, -1); e != nil {
		t.Fatal(e)
	}
	restored, e := store.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	var token string
	if e = restored.Secret("cloudflare:one", &token); e != nil || token != "private-fixture-token" {
		t.Fatal("private credential did not survive recovery")
	}
	key, _ := os.ReadFile(filepath.Join(dir, "acme", "one", "key.pem"))
	if string(key) != "private-fixture-key" {
		t.Fatal("ACME key missing")
	}
	operation, e := restored.Operation(op.ID)
	if e != nil || operation.State != "failed" {
		t.Fatal("restore would replay an unconfirmed destructive operation")
	}
	list, e := a.List()
	if e != nil || len(list) != 1 || list[0].ID != b.ID {
		t.Fatal("private backup inventory lost")
	}
}
func TestUnsafeArchiveLeavesCurrentStateUntouched(t *testing.T) {
	for _, name := range []string{"../../escape", "/tmp/escape", "acme/../master.key", "acme/link", "manifest.json"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			data := filepath.Join(dir, "data")
			_ = os.Mkdir(data, 0700)
			_ = os.WriteFile(filepath.Join(data, "sentinel"), []byte("keep"), 0600)
			a := Archives{Data: data, Root: filepath.Join(dir, "backups")}
			_ = a.init()
			id := "f862f895-7dd8-42ae-b54d-d45b1df84baf"
			f, _ := os.Create(filepath.Join(a.Root, id+".tgz"))
			gz := gzip.NewWriter(f)
			tw := tar.NewWriter(gz)
			raw, _ := json.Marshal(manifest{Format: 1, Backup: Backup{ID: id}, Files: map[string]string{}})
			_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(raw))})
			_, _ = tw.Write(raw)
			h := &tar.Header{Name: name, Mode: 0600, Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}
			_ = tw.WriteHeader(h)
			_ = tw.Close()
			_ = gz.Close()
			_ = f.Close()
			if e := a.RestoreOffline(id, -1, -1); e == nil {
				t.Fatal("unsafe recovery archive accepted")
			}
			raw, _ = os.ReadFile(filepath.Join(data, "sentinel"))
			if string(raw) != "keep" {
				t.Fatal("current state changed on invalid restore")
			}
		})
	}
}
