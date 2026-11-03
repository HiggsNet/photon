//go:build linux && (amd64 || arm64)

package healthprobe

import (
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The Go poller handles waiting. Use a raw syscall only for this nonblocking
// receive so the runtime does not treat each drain as a blocking syscall.
func recvRawICMPNonblocking(fd int, buf []byte) (int, error) {
	n, _, errno := syscall.RawSyscall6(unix.SYS_RECVFROM, uintptr(fd),
		uintptr(unsafe.Pointer(unsafe.SliceData(buf))), uintptr(len(buf)),
		unix.MSG_DONTWAIT, 0, 0)
	runtime.KeepAlive(buf)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}
