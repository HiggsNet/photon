//go:build linux && (amd64 || arm64)

package photonlinux

import (
	"encoding/binary"
	"net"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func (io *GossipDatagramIO) ReadDatagram(buffer []byte) (int, *net.UDPAddr, error) {
	raw, err := io.conn.SyscallConn()
	if err != nil {
		return 0, nil, err
	}

	var from unix.RawSockaddrAny
	var received uintptr
	var errno syscall.Errno
	err = raw.Read(func(fd uintptr) bool {
		// Go's poller owns waiting. This call must always be nonblocking.
		for {
			addrLen := uint32(unix.SizeofSockaddrAny)
			received, _, errno = syscall.RawSyscall6(unix.SYS_RECVFROM, fd,
				uintptr(unsafe.Pointer(unsafe.SliceData(buffer))), uintptr(len(buffer)),
				unix.MSG_DONTWAIT, uintptr(unsafe.Pointer(&from)), uintptr(unsafe.Pointer(&addrLen)))
			runtime.KeepAlive(buffer)
			if errno != unix.EINTR {
				return errno != unix.EAGAIN
			}
		}
	})
	if err != nil {
		return 0, nil, err
	}
	if errno != 0 {
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Source: io.conn.LocalAddr(), Err: errno}
	}

	switch from.Addr.Family {
	case unix.AF_INET:
		addr := (*unix.RawSockaddrInet4)(unsafe.Pointer(&from))
		port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:])
		return int(received), &net.UDPAddr{IP: addr.Addr[:], Port: int(port)}, nil
	case unix.AF_INET6:
		addr := (*unix.RawSockaddrInet6)(unsafe.Pointer(&from))
		port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:])
		zone := ""
		if addr.Scope_id != 0 {
			zone = strconv.FormatUint(uint64(addr.Scope_id), 10)
			if iface, err := net.InterfaceByIndex(int(addr.Scope_id)); err == nil {
				zone = iface.Name
			}
		}
		return int(received), &net.UDPAddr{IP: addr.Addr[:], Port: int(port), Zone: zone}, nil
	default:
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Source: io.conn.LocalAddr(), Err: unix.EAFNOSUPPORT}
	}
}
