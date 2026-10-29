//go:build linux

package broker

import (
	"golang.org/x/sys/unix"
	"net"
)

func peerAllowed(conn net.Conn, uid int) bool {
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, e := c.SyscallConn()
	if e != nil {
		return false
	}
	allowed := false
	_ = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		allowed = e == nil && int(cred.Uid) == uid
	})
	return allowed
}
