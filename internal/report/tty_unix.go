//go:build linux || darwin || freebsd || netbsd || openbsd

package report

import (
	"os"
	"syscall"
	"unsafe"
)

// ttyColumns asks the terminal for its width (0 if unknown).
func ttyColumns(f *os.File) int {
	var ws struct{ Row, Col, X, Y uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		return 0
	}
	return int(ws.Col)
}
