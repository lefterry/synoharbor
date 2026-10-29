package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cgi"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/lefterry/synoharbor/internal/api"
	"github.com/lefterry/synoharbor/internal/broker"
	"github.com/lefterry/synoharbor/internal/service"
	"github.com/lefterry/synoharbor/internal/store"
)

var version = "0.1.0-dev"

func main() {
	syscall.Umask(0077)
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	broker.Build = version
	if len(os.Args) < 2 {
		return errors.New("usage: synoharbor worker|cgi|broker|version")
	}
	if os.Args[1] == "version" {
		fmt.Println(version)
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if os.Args[1] == "cgi" || os.Args[1] == "signin" || os.Args[1] == "worker" {
		if _, e := os.Stat("/var/run/synoharbor-recovering"); e == nil {
			if os.Args[1] == "cgi" || os.Args[1] == "signin" {
				return cgi.Serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Cache-Control", "no-store")
					w.WriteHeader(503)
					_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Settings recovery in progress. Reconnecting…"})
				}))
			}
			return errors.New("SynoHarbor private-state recovery is in progress; reopen the app shortly")
		}
	}
	if os.Args[1] == "recover" {
		if len(os.Args) != 3 {
			return errors.New("usage: /usr/local/libexec/synoharbor/synoharbor recover <backup-id|latest>")
		}
		return trackedRecovery(ctx, os.Args[2])
	}
	if os.Args[1] == "verify-backup" {
		if len(os.Args) != 3 {
			return errors.New("backup ID required")
		}
		return verifyBackup(ctx, os.Args[2])
	}
	if os.Args[1] == "broker" {
		u, e := user.Lookup("sc-synoharbor")
		if e != nil {
			return e
		}
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		go watchInstallation(ctx, cancel)
		return broker.Serve(ctx, broker.Socket, uid, gid, broker.NativeSystem())
	}
	dir := os.Getenv("SYNOHARBOR_DATA")
	if dir == "" {
		dir = "/var/packages/synoharbor/var"
	}
	s, e := store.Open(dir)
	if e != nil {
		return e
	}
	defer s.Close()
	app := service.New(s)
	defer app.ACME.Close()
	switch os.Args[1] {
	case "recovery-preview":
		p, e := app.RecoveryPreview(ctx)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(p)
	case "backup":
		unlock, e := s.Gate(ctx, true)
		if e != nil {
			return e
		}
		defer unlock()
		b, e := app.CreateBackup(ctx, "manual")
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(b)
	case "uninstall-check":
		if len(os.Args) != 3 {
			return errors.New("uninstall mode required")
		}
		mode := os.Args[2]
		if mode != "keep" && mode != "restore" && mode != "erase" {
			return errors.New("unknown uninstall choice")
		}
		unlock, e := s.Gate(ctx, true)
		if e != nil {
			return e
		}
		defer unlock()
		if mode != "keep" {
			if e = app.ValidateUninstall(ctx); e != nil {
				return e
			}
		}
		_, e = app.CreateBackup(ctx, "before-uninstall")
		return e
	case "seed-recovery":
		var seed service.RecoverySeed
		d := json.NewDecoder(os.Stdin)
		d.DisallowUnknownFields()
		if e = d.Decode(&seed); e != nil {
			return errors.New("invalid recovery seed")
		}
		return app.SeedRecovery(ctx, seed)
	case "worker":
		return app.Run(ctx)
	case "cgi":
		return cgi.Serve(api.New(app))
	case "signin":
		return cgi.Serve(http.HandlerFunc(api.New(app).SignIn))
	case "delete-certificate":
		if len(os.Args) != 3 {
			return errors.New("certificate ID required")
		}
		return app.Delete(ctx, "certificates", os.Args[2])
	case "replace-certificate":
		if len(os.Args) != 3 {
			return errors.New("certificate ID required")
		}
		op, err := app.Store.Enqueue("certificate.replace", os.Args[2], nil)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(op)
	case "retry":
		if len(os.Args) != 4 {
			return errors.New("usage: retry proxy.apply|certificate.deploy|certificate.issue <id>")
		}
		allowed := map[string]bool{"proxy.apply": true, "certificate.deploy": true, "certificate.issue": true}
		if !allowed[os.Args[2]] {
			return errors.New("unsupported retry operation")
		}
		op, err := app.Store.Enqueue(os.Args[2], os.Args[3], nil)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(op)
	case "delete-credential":
		if len(os.Args) != 3 {
			return errors.New("credential ID required")
		}
		return app.DeleteCredential(os.Args[2])
	case "setup-standalone":
		var req service.StandaloneRequest
		decoder := json.NewDecoder(os.Stdin)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&req) != nil {
			return errors.New("invalid standalone settings")
		}
		unlock, e := s.Gate(ctx, true)
		if e != nil {
			return e
		}
		defer unlock()
		result, e := app.SetupStandalone(ctx, req)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "apply-manifest":
		var manifest service.Migration
		decoder := json.NewDecoder(os.Stdin)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&manifest); err != nil {
			return errors.New("invalid service manifest")
		}
		results, err := app.Migrate(ctx, manifest)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(results)
	default:
		return errors.New("unknown command")
	}
}
