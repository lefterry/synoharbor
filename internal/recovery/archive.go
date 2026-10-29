// Package recovery holds complete, NAS-local backups outside the package data
// directory. Archives contain secrets and are never returned through the UI.
package recovery

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lefterry/synoharbor/internal/store"
)

const ExportDB = "recovery-export.sqlite"

type Backup struct {
	ID           string    `json:"id"`
	CreatedAt    time.Time `json:"createdAt"`
	Reason       string    `json:"reason"`
	Bytes        int64     `json:"bytes"`
	Certificates *int      `json:"certificates,omitempty"`
	ProxyHosts   *int      `json:"proxyHosts,omitempty"`
}
type manifest struct {
	Format int               `json:"format"`
	Backup Backup            `json:"backup"`
	Files  map[string]string `json:"files"`
}
type Archives struct{ Data, Root string }

func (a Archives) init() error {
	if !filepath.IsAbs(a.Root) || !filepath.IsAbs(a.Data) {
		return errors.New("private NAS backup location unavailable")
	}
	if err := os.MkdirAll(a.Root, 0700); err != nil {
		return err
	}
	return os.Chmod(a.Root, 0700)
}
func allowed(name string) bool {
	return name == "master.key" || name == "synoharbor.sqlite" || strings.HasPrefix(name, "acme/")
}
func safeName(name string) bool {
	return name != "" && filepath.ToSlash(filepath.Clean(name)) == name && !strings.HasPrefix(name, "/") && !strings.HasPrefix(name, "../") && !strings.Contains(name, "\\") && allowed(name)
}
func (a Archives) Create(ctx context.Context, reason string) (Backup, error) {
	var b Backup
	if reason != "manual" && reason != "automatic" && reason != "before-restore" && reason != "before-delete" && reason != "before-uninstall" {
		return b, errors.New("invalid backup reason")
	}
	if err := a.init(); err != nil {
		return b, err
	}
	files := map[string]string{"synoharbor.sqlite": filepath.Join(a.Data, ExportDB), "master.key": filepath.Join(a.Data, "master.key")}
	if err := filepath.WalkDir(filepath.Join(a.Data, "acme"), func(p string, d fs.DirEntry, err error) error {
		if errors.Is(err, os.ErrNotExist) && p == filepath.Join(a.Data, "acme") {
			return nil
		}
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("backup refuses symbolic links")
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return errors.New("backup refuses special files")
		}
		rel, e := filepath.Rel(a.Data, p)
		if e != nil {
			return e
		}
		files[filepath.ToSlash(rel)] = p
		return nil
	}); err != nil {
		return b, err
	}
	if len(files) > 50000 {
		return b, errors.New("backup file limit exceeded")
	}
	b = Backup{ID: uuid.NewString(), CreatedAt: time.Now().UTC(), Reason: reason}
	m := manifest{Format: 1, Backup: b, Files: map[string]string{}}
	// Read each file once; certmagic writes by atomic rename. No live database
	// is copied: the caller produces a consistent VACUUM INTO under the gate.
	content := map[string][]byte{}
	var total int64
	for name, p := range files {
		select {
		case <-ctx.Done():
			return Backup{}, ctx.Err()
		default:
		}
		info, e := os.Lstat(p)
		if e != nil {
			return Backup{}, e
		}
		if !info.Mode().IsRegular() || info.Size() > 64<<20 {
			return Backup{}, errors.New("invalid backup source")
		}
		if !safeName(name) {
			return Backup{}, errors.New("invalid backup member")
		}
		raw, e := os.ReadFile(p)
		if e != nil {
			return Backup{}, e
		}
		total += int64(len(raw))
		if total > 512<<20 {
			return Backup{}, errors.New("backup exceeds 512 MB")
		}
		content[name] = raw
		sum := sha256.Sum256(raw)
		m.Files[name] = hex.EncodeToString(sum[:])
	}
	if err := validatePairs(content); err != nil {
		return Backup{}, err
	}
	validation, err := os.MkdirTemp(a.Root, ".validate-*")
	if err != nil {
		return Backup{}, err
	}
	defer os.RemoveAll(validation)
	for _, name := range []string{"master.key", "synoharbor.sqlite"} {
		if err = os.WriteFile(filepath.Join(validation, name), content[name], 0600); err != nil {
			return Backup{}, err
		}
	}
	if err = validateStore(validation); err != nil {
		return Backup{}, err
	}
	database, err := store.Open(validation)
	if err != nil {
		return Backup{}, err
	}
	certs, hosts := 0, 0
	err = database.DB.QueryRow("SELECT count(*) FROM objects WHERE kind='certificates'").Scan(&certs)
	if err == nil {
		err = database.DB.QueryRow("SELECT count(*) FROM objects WHERE kind='proxies'").Scan(&hosts)
	}
	database.Close()
	if err != nil {
		return Backup{}, err
	}
	b.Certificates = &certs
	b.ProxyHosts = &hosts
	m.Backup = b
	f, err := os.CreateTemp(a.Root, ".backup-*")
	if err != nil {
		return Backup{}, err
	}
	defer os.Remove(f.Name())
	_ = f.Chmod(0600)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	write := func(name string, raw []byte) error {
		if e := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(raw)), Typeflag: tar.TypeReg}); e != nil {
			return e
		}
		_, e := tw.Write(raw)
		return e
	}
	raw, _ := json.Marshal(m)
	err = write("manifest.json", raw)
	for name, raw := range content {
		if err == nil {
			err = write(name, raw)
		}
	}
	for _, close := range []func() error{tw.Close, gz.Close, f.Sync, f.Close} {
		if e := close(); err == nil {
			err = e
		}
	}
	if err != nil {
		return Backup{}, err
	}
	path := filepath.Join(a.Root, b.ID+".tgz")
	if err = os.Rename(f.Name(), path); err != nil {
		return Backup{}, err
	}
	info, _ := os.Stat(path)
	b.Bytes = info.Size()
	return b, nil
}
func (a Archives) List() ([]Backup, error) {
	if err := a.init(); err != nil {
		return nil, err
	}
	files, e := os.ReadDir(a.Root)
	if e != nil {
		return nil, e
	}
	out := []Backup{}
	for _, f := range files {
		id := strings.TrimSuffix(f.Name(), ".tgz")
		if _, e := uuid.Parse(id); e != nil || f.IsDir() {
			continue
		}
		m, e := a.inspect(id, "", false)
		if e != nil {
			continue
		}
		info, e := f.Info()
		if e != nil {
			return nil, e
		}
		m.Backup.Bytes = info.Size()
		out = append(out, m.Backup)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
func (a Archives) Validate(id string) error { _, e := a.inspect(id, "", true); return e }
func (a Archives) inspect(id, stage string, verify bool) (manifest, error) {
	var m manifest
	if _, e := uuid.Parse(id); e != nil {
		return m, errors.New("invalid backup ID")
	}
	p := filepath.Join(a.Root, id+".tgz")
	info, e := os.Lstat(p)
	if e != nil || !info.Mode().IsRegular() {
		return m, errors.New("backup unavailable")
	}
	f, e := os.Open(p)
	if e != nil {
		return m, e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return m, e
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, 513<<20))
	seen := map[string]string{}
	var total int64
	for count := 0; ; count++ {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return m, e
		}
		if count > 50000 || h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > 64<<20 {
			return m, errors.New("unsafe recovery archive")
		}
		total += h.Size
		if total > 512<<20 {
			return m, errors.New("recovery archive exceeds limit")
		}
		if h.Name != "manifest.json" && !safeName(h.Name) {
			return m, errors.New("unsafe recovery archive path")
		}
		if _, ok := seen[h.Name]; ok {
			return m, errors.New("duplicate recovery member")
		}
		raw, e := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if e != nil || int64(len(raw)) != h.Size {
			return m, errors.New("truncated recovery archive")
		}
		sum := sha256.Sum256(raw)
		seen[h.Name] = hex.EncodeToString(sum[:])
		if h.Name == "manifest.json" {
			if e = json.Unmarshal(raw, &m); e != nil {
				return m, e
			}
			if !verify {
				return m, nil
			}
			continue
		}
		if stage != "" {
			p := filepath.Join(stage, filepath.FromSlash(h.Name))
			if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
				return m, e
			}
			if e = os.WriteFile(p, raw, 0600); e != nil {
				return m, e
			}
		}
	}
	if m.Format != 1 || m.Backup.ID != id || len(m.Files) != len(seen)-1 {
		return m, errors.New("invalid recovery manifest")
	}
	for n, h := range m.Files {
		if !safeName(n) || seen[n] != h {
			return m, errors.New("recovery checksum mismatch")
		}
	}
	if seen["master.key"] == "" || seen["synoharbor.sqlite"] == "" {
		return m, errors.New("incomplete recovery backup")
	}
	return m, nil
}

// RestoreOffline is used only by the immutable root recovery command after the
// package has stopped. It validates in a new directory before an atomic swap.
// Native DSM objects are deliberately not overwritten by a filesystem restore.
func (a Archives) RestoreOffline(id string, uid, gid int) error {
	if err := a.init(); err != nil {
		return err
	}
	stage, e := os.MkdirTemp(filepath.Dir(a.Data), ".synoharbor-restore-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	if _, e = a.inspect(id, stage, true); e != nil {
		return e
	}
	if e = validateStore(stage); e != nil {
		return e
	}
	contents := map[string][]byte{}
	e = filepath.WalkDir(filepath.Join(stage, "acme"), func(path string, d fs.DirEntry, err error) error {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".crt") || strings.HasSuffix(path, ".key")) {
			rel, _ := filepath.Rel(stage, path)
			contents[filepath.ToSlash(rel)], err = os.ReadFile(path)
			return err
		}
		return nil
	})
	if e != nil {
		return e
	}
	if e = validatePairs(contents); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(stage, "recovered"), []byte(id), 0600); e != nil {
		return e
	}
	if e = filepath.WalkDir(stage, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := os.FileMode(0600)
		if d.IsDir() {
			mode = 0700
		}
		if err = os.Chmod(p, mode); err != nil {
			return err
		}
		if uid >= 0 {
			return os.Chown(p, uid, gid)
		}
		return nil
	}); e != nil {
		return e
	}
	old := a.Data + ".before-recovery-" + uuid.NewString()
	if _, e = os.Stat(a.Data); e == nil {
		if e = os.Rename(a.Data, old); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = os.Rename(stage, a.Data); e != nil {
		_ = os.Rename(old, a.Data)
		return e
	}
	return nil
}
func validatePairs(contents map[string][]byte) error {
	for name, cert := range contents {
		if !strings.HasSuffix(name, ".crt") {
			continue
		}
		key, ok := contents[strings.TrimSuffix(name, ".crt")+".key"]
		if !ok {
			return errors.New("ACME certificate key missing from backup")
		}
		if _, e := tls.X509KeyPair(cert, key); e != nil {
			return errors.New("ACME certificate and key do not match; backup aborted")
		}
	}
	return nil
}
func validateStore(dir string) error {
	s, e := store.Open(dir)
	if e != nil {
		return e
	}
	var integrity string
	e = s.DB.QueryRow("PRAGMA integrity_check").Scan(&integrity)
	if e == nil && integrity != "ok" {
		e = errors.New("recovery database failed integrity check")
	}
	if e == nil {
		var marker int
		e = s.DB.QueryRow("SELECT count(*) FROM secrets").Scan(&marker)
	}
	if e == nil {
		e = s.VerifySecrets()
	}
	s.Close()
	if e != nil {
		return e
	}
	return nil
}
