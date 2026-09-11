//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

func enableWindowsANSI() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setMode := kernel32.NewProc("SetConsoleMode")
	getMode := kernel32.NewProc("GetConsoleMode")
	handle, _ := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	var mode uint32
	getMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	setMode.Call(uintptr(handle), uintptr(mode|0x0004)) // ENABLE_VIRTUAL_TERMINAL_PROCESSING
}
