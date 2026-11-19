package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func bindChainDevice(device string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, socket syscall.RawConn) error {
		var bindErr error
		if err := socket.Control(func(fd uintptr) {
			bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device)
		}); err != nil {
			return err
		}
		return bindErr
	}
}
