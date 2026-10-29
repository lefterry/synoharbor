package broker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lefterry/synoharbor/internal/model"
	"github.com/lefterry/synoharbor/internal/nginx"
)

func TestInvalidConfigKeepsPreviousWorkingVersion(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "synoharbor.conf")
	if e := os.WriteFile(conf, []byte("# previous good configuration\n"), 0600); e != nil {
		t.Fatal(e)
	}
	called := 0
	s := &System{ConfigPath: conf, Root: filepath.Join(dir, "owned"), Run: func(context.Context, string, ...string) error { called++; return errors.New("invalid nginx syntax") }}
	p := model.ProxyHost{Meta: model.Meta{ID: "one"}, Hostname: "one.example.net", Target: model.Target{Scheme: "http", Host: "127.0.0.1", Port: 8095}, LoopbackPort: 18080, Managed: true, Enabled: true}
	if e := s.Apply(context.Background(), nginx.Input{Hosts: []model.ProxyHost{p}}); e == nil {
		t.Fatal("invalid config accepted")
	}
	b, _ := os.ReadFile(conf)
	if string(b) != "# previous good configuration\n" || called != 1 {
		t.Fatal("last valid config lost or reloaded after invalid syntax")
	}
}
