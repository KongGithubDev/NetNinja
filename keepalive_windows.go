//go:build windows

package main

import (
	"net"
	"time"
)

func setSocketKeepAlive(fd int, seconds int) {
	// Windows doesn't have TCP_KEEPIDLE/TCP_KEEPINTVL/TCP_KEEPCNT syscall constants.
	// Keepalive is set via net.TCPConn.SetKeepAlive in the caller.
	_ = fd
	_ = seconds
}

func setKeepAliveFallback(tc *net.TCPConn, seconds int) {
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(time.Duration(seconds) * time.Second)
}
