package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lefterry/synoharbor/internal/model"
)

func TestPersistenceConflictSecretsAndRecovery(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	p := model.CertificateProfile{Domain: "one.example.net"}
	if e = s.Put("certificates", &p.Meta, &p); e != nil {
		t.Fatal(e)
	}
	stale := p
	p.Domain = "two.example.net"
	if e = s.Put("certificates", &p.Meta, &p); e != nil {
		t.Fatal(e)
	}
	if e = s.Put("certificates", &stale.Meta, &stale); e != ErrConflict {
		t.Fatalf("stale write accepted: %v", e)
	}
	if e = s.PutSecret("test", "do-not-leak-this-secret"); e != nil {
		t.Fatal(e)
	}
	op, e := s.Enqueue("certificate.issue", p.ID, nil)
	if e != nil {
		t.Fatal(e)
	}
	same, _ := s.Enqueue("certificate.issue", p.ID, nil)
	if same.ID != op.ID {
		t.Fatal("duplicate active operation")
	}
	claimed, e := s.Claim()
	if e != nil || claimed.ID != op.ID {
		t.Fatal(e)
	}
	backup := filepath.Join(dir, "backup.sqlite")
	if e = s.Backup(context.Background(), backup); e != nil {
		t.Fatal(e)
	}
	s.Close()
	b, _ := os.ReadFile(backup)
	if bytes.Contains(b, []byte("do-not-leak-this-secret")) {
		t.Fatal("secret stored as plaintext")
	}
	s, e = Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var secret string
	if e = s.Secret("test", &secret); e != nil || secret != "do-not-leak-this-secret" {
		t.Fatal("secret did not survive restart")
	}
	if e = s.Recover(); e != nil {
		t.Fatal(e)
	}
	o, e := s.Claim()
	if e != nil || o.Attempts != 2 {
		t.Fatal("interrupted operation not resumed")
	}
}
