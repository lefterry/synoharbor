package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	if len(os.Args) < 2 {
		return errors.New("usage: synoharbor worker|cgi|broker|version")
	}
	if os.Args[1] == "version" {
		fmt.Println(version)
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if os.Args[1] == "broker" {
		u, e := user.Lookup("sc-synoharbor")
		if e != nil {
			return e
		}
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
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
	case "worker":
		return app.Run(ctx)
	case "cgi":
		return cgi.Serve(api.New(app))
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
