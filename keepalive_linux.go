//go:build linux

package main

import (
	"net"
	"syscall"
	"time"
)

func setSocketKeepAlive(fd int, seconds int) {
	// Enable SO_KEEPALIVE FIRST — without this, kernel ignores TCP_KEEPIDLE/INTVL/CNT
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, seconds)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, seconds)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3)
	// TCP_USER_TIMEOUT: kernel declares connection dead after this many ms
	// of unacknowledged retransmits. 4× keepalive interval = fast detection
	// without false positives on flaky links.
	tcpUserTimeout := seconds * 4 * 1000 // ms
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, 0x12 /*TCP_USER_TIMEOUT*/, tcpUserTimeout)
}

func setKeepAliveFallback(tc *net.TCPConn, seconds int) {
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(time.Duration(seconds) * time.Second)
}
