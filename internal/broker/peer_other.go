//go:build !linux

package broker

import "net"

func peerAllowed(net.Conn, int) bool { return false }
