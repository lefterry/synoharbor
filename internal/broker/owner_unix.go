package broker

import (
	"os"
	"syscall"
)

func restoreOwner(path string, info os.FileInfo) {
	if v, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(path, int(v.Uid), int(v.Gid))
	}
}
