//go:build linux && !amd64 && !arm64

package healthprobe

import "golang.org/x/sys/unix"

func recvRawICMPNonblocking(fd int, buf []byte) (int, error) {
	n, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
	return n, err
}
