package service

import (
	"context"
	"github.com/lefterry/synoharbor/internal/model"
	"testing"
)

func TestStandaloneSetupReusesProfileAndPreservesOtherRoutes(t *testing.T) {
	f := newRecoveryFixture(t)
	a := f.app
	s := a.Store
	cred := model.Credential{Meta: model.Meta{ID: "test-credential"}, Name: "Test", Configured: true}
	if e := s.Put("credentials", &cred.Meta, &cred); e != nil {
		t.Fatal(e)
	}
	req := StandaloneRequest{Hostname: "harbor.example.net", Email: "admin@example.net", CredentialID: cred.ID, KeyType: "p256"}
	if _, e := a.SetupStandalone(context.Background(), req); e != nil {
		t.Fatal(e)
	}
	first := a.Standalone()
	var cert model.CertificateProfile
	var host model.ProxyHost
	if s.Get("certificates", first.CertificateID, &cert) != nil || s.Get("proxies", first.ProxyID, &host) != nil || !host.AppUI || host.Target.Host != "127.0.0.1" || host.Target.Port != 697 || host.HTTPSVerified {
		t.Fatal("invalid standalone route")
	}
	if _, e := a.SetupStandalone(context.Background(), req); e != nil {
		t.Fatal(e)
	}
	if a.Standalone().CertificateID != first.CertificateID || a.Standalone().ProxyID != first.ProxyID {
		t.Fatal("retry duplicated resources")
	}
	req.Hostname = "second.example.net"
	if _, e := a.SetupStandalone(context.Background(), req); e != nil {
		t.Fatal(e)
	}
	if s.Get("proxies", first.ProxyID, &host) != nil || !host.Enabled {
		t.Fatal("hostname change removed the previous access route")
	}
	previous := a.Standalone()
	f.mu.Lock()
	f.failRead = true
	f.mu.Unlock()
	req.Hostname = "failed.example.net"
	if _, e := a.SetupStandalone(context.Background(), req); e == nil {
		t.Fatal("failed read permitted creation")
	}
	if a.Standalone().ProxyID != previous.ProxyID {
		t.Fatal("failed read replaced management access")
	}
}
