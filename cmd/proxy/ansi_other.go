//go:build !windows

package main

func enableWindowsANSI() {
	// No-op: ANSI escape sequences work natively on Unix terminals.
}
