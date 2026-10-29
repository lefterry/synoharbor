package store

import (
	"errors"
	"github.com/lefterry/synoharbor/internal/model"
	"testing"
)

func TestRejectedEditCannotOverwriteCredentialSecret(t *testing.T) {
	s, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c := model.Credential{Meta: model.Meta{ID: "test"}, Name: "First", Configured: true}
	if e = s.PutSecretObject("credentials", &c.Meta, &c, "cloudflare:test", "original"); e != nil {
		t.Fatal(e)
	}
	stale := c
	c.Name = "Current"
	if e = s.PutSecretObject("credentials", &c.Meta, &c, "cloudflare:test", "current-token"); e != nil {
		t.Fatal(e)
	}
	stale.Name = "Old browser edit"
	if e = s.PutSecretObject("credentials", &stale.Meta, &stale, "cloudflare:test", "wrong-token"); !errors.Is(e, ErrConflict) {
		t.Fatal("stale edit accepted", e)
	}
	var token string
	if e = s.Secret("cloudflare:test", &token); e != nil || token != "current-token" {
		t.Fatal("rejected edit changed the live credential")
	}
	if e = s.Get("credentials", "test", &c); e != nil || c.Name != "Current" {
		t.Fatal("metadata/secret atomicity lost")
	}
}
