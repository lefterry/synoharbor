package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/lefterry/synoharbor/internal/broker"
	"github.com/lefterry/synoharbor/internal/recovery"
	"github.com/lefterry/synoharbor/internal/store"
)

func recoverBackup(ctx context.Context, id string) error {
	if os.Geteuid() != 0 {
		return errors.New("run the immutable recovery command as root")
	}
	a := broker.NativeSystem().Archives
	if id == "latest" {
		list, e := a.List()
		if e != nil {
			return e
		}
		if len(list) == 0 {
			return errors.New("no private recovery backup found")
		}
		id = list[0].ID
	}
	list, e := a.List()
	if e != nil {
		return e
	}
	found := false
	for _, b := range list {
		found = found || b.ID == id
	}
	if !found {
		return errors.New("backup ID not found")
	}
	if e = a.Validate(id); e != nil {
		return e
	}
	marker := "/var/run/synoharbor-recovering"
	if e = os.WriteFile(marker, []byte(id), 0600); e != nil {
		return e
	}
	defer os.Remove(marker)
	if e = exec.CommandContext(ctx, "/usr/syno/bin/synopkg", "stop", "synoharbor").Run(); e != nil {
		return errors.New("stop SynoHarbor before restoring a backup")
	}
	defer func() {
		_ = os.Remove(marker)
		_ = exec.CommandContext(context.Background(), "/usr/syno/bin/synopkg", "start", "synoharbor").Run()
	}()
	if _, e = os.Stat(filepath.Join(a.Data, "master.key")); e == nil {
		s, e := store.Open(a.Data)
		if e == nil {
			unlock, e := s.Gate(ctx, true)
			if e != nil {
				s.Close()
				return e
			}
			path := filepath.Join(s.Dir, recovery.ExportDB)
			_ = os.Remove(path)
			if e = s.Backup(ctx, path); e == nil {
				_, e = a.Create(ctx, "before-restore")
			}
			_ = os.Remove(path)
			unlock()
			s.Close()
			if e != nil {
				fmt.Fprintln(os.Stderr, "Current state will be preserved intact in a private before-recovery folder.")
			}
		} else {
			fmt.Fprintln(os.Stderr, "Unreadable current state will be preserved intact in a private before-recovery folder.")
		}
	}
	u, e := user.Lookup("sc-synoharbor")
	if e != nil {
		return e
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if e = a.RestoreOffline(id, uid, gid); e != nil {
		return e
	}
	_ = os.Remove(marker)
	if e = exec.CommandContext(ctx, "/usr/syno/bin/synopkg", "start", "synoharbor").Run(); e != nil {
		return errors.New("backup restored; start SynoHarbor from Package Center")
	}
	fmt.Println("Private settings restored. DSM objects are reconciled by their IDs; removed native objects will not be recreated.")
	return nil
}
func trackedRecovery(ctx context.Context, id string) error {
	if os.Geteuid() != 0 {
		return errors.New("settings recovery requires root")
	}
	lock, e := os.OpenFile("/var/run/synoharbor-recovery.lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("another recovery is already running")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = recovery.WriteStatus(recovery.Status{ID: id, State: "running", Message: "Restoring private settings; reconnecting shortly"})
	e = recoverBackup(ctx, id)
	status := recovery.Status{ID: id, State: "succeeded", Message: "Private settings restored and DSM reconciliation restarted"}
	if e != nil {
		status.State = "failed"
		status.Message = "Settings recovery failed. The private backup and previous state are retained; retry from an administrator session."
	}
	_ = recovery.WriteStatus(status)
	return e
}
func verifyBackup(ctx context.Context, id string) error {
	if os.Geteuid() != 0 {
		return errors.New("backup verification requires root")
	}
	a := broker.NativeSystem().Archives
	if e := a.Validate(id); e != nil {
		return e
	}
	parent, e := os.MkdirTemp(a.Root, ".verify-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(parent)
	a.Data = filepath.Join(parent, "state")
	if e = a.RestoreOffline(id, -1, -1); e != nil {
		return e
	}
	s, e := store.Open(a.Data)
	if e != nil {
		return e
	}
	defer s.Close()
	var profiles, hosts, credentials int
	for kind, out := range map[string]*int{"certificates": &profiles, "proxies": &hosts, "credentials": &credentials} {
		if e = s.DB.QueryRow("SELECT count(*) FROM objects WHERE kind=?", kind).Scan(out); e != nil {
			return e
		}
	}
	fmt.Printf("Backup restored in an isolated directory; SQLite integrity and secret decryption passed. Certificates: %d; proxy hosts: %d; credentials: %d. Live DSM unchanged.\n", profiles, hosts, credentials)
	return ctx.Err()
}
func watchInstallation(ctx context.Context, cancel context.CancelFunc) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, e := os.Stat("/var/packages/synoharbor/INFO"); errors.Is(e, os.ErrNotExist) {
				cancel()
				return
			}
		}
	}
}
