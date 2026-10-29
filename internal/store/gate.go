package store

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Gate coordinates CGI processes and worker jobs. Recovery needs an exclusive
// gate; ordinary mutations share it. The file is outside SQLite transactions.
func (s *Store) Gate(ctx context.Context, exclusive bool) (func(), error) {
	f, err := os.OpenFile(filepath.Join(s.Dir, "maintenance.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	for {
		err = syscall.Flock(int(f.Fd()), mode|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
