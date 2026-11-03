package photonwindows

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type udpControlWrite struct {
	generation uint64
	handle     windows.Handle
	event      windows.Handle
	overlapped windows.Overlapped
	address    windows.RawSockaddrAny
	buffer     windows.WSABuf

	// This lock does not acquire the socket lock. Rebind can cancel an
	// operation and close the socket while its RawConn.Control callback drains.
	mu   sync.Mutex
	done bool
}

func (op *udpControlWrite) cancel() {
	op.mu.Lock()
	defer op.mu.Unlock()
	if !op.done {
		_ = windows.CancelIoEx(op.handle, &op.overlapped)
	}
}

// generation zero cancels all tunnel writes, with Gossip included only when
// the underlying socket is closing or being replaced.
func (s *packetSockets) cancelUDPControlLocked(generation uint64, includingGossip bool) {
	for op := range s.controlWrites {
		if (generation == 0 && (includingGossip || op.generation != 0)) || (generation != 0 && op.generation == generation) {
			op.cancel()
		}
	}
}

func (s *packetSockets) writeUDPControl(packet []byte, addr *net.UDPAddr, generation uint64) (int, error) {
	peer := addr.AddrPort()
	if !peer.IsValid() || addr.Port < 0 || addr.Port > 65535 {
		return 0, &net.AddrError{Err: "invalid UDP destination", Addr: addr.String()}
	}
	scope, err := udpControlScope(peer.Addr())
	if err != nil {
		return 0, err
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	op := &udpControlWrite{generation: generation, event: event}
	// The event belongs to this operation. The low bit keeps the completion
	// out of the Go runtime's completion port for the shared UDP handle.
	op.overlapped.HEvent = event | 1
	op.buffer.Len = uint32(len(packet))
	if len(packet) != 0 {
		op.buffer.Buf = &packet[0]
	}
	var pin runtime.Pinner
	pin.Pin(op)
	if op.buffer.Buf != nil {
		pin.Pin(op.buffer.Buf)
	}
	defer pin.Unpin()

	s.writeMu.Lock()
	conn := s.udp
	if !s.udpControlCurrentLocked(conn, generation, peer) {
		s.writeMu.Unlock()
		return 0, net.ErrClosed
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		s.writeMu.Unlock()
		return 0, err
	}

	var sent int
	callbackStarted := false
	controlErr := raw.Control(func(handle uintptr) {
		callbackStarted = true
		op.handle = windows.Handle(handle)
		size, addrErr := op.setDestination(peer, scope)
		if addrErr != nil {
			err = addrErr
			s.writeMu.Unlock()
			return
		}
		err = windows.WSASendTo(op.handle, &op.buffer, 1, nil, 0, &op.address, size, &op.overlapped, nil)
		pending := errors.Is(err, windows.ERROR_IO_PENDING)
		if pending {
			if s.controlWrites == nil {
				s.controlWrites = make(map[*udpControlWrite]struct{})
			}
			s.controlWrites[op] = struct{}{}
		}
		s.writeMu.Unlock()

		// Keep the socket pinned by Control until the kernel has finished
		// using this operation. The shared write lock covers submission only.
		if pending {
			sent, err = op.wait()
		} else if err == nil {
			sent, err = op.result()
		}
		op.mu.Lock()
		op.done = true
		op.mu.Unlock()
	})
	if !callbackStarted {
		s.writeMu.Unlock()
		return 0, controlErr
	}
	s.writeMu.Lock()
	delete(s.controlWrites, op)
	current := s.udpControlCurrentLocked(conn, generation, peer)
	s.writeMu.Unlock()
	if !current {
		return 0, net.ErrClosed
	}
	if err == nil && sent != len(packet) {
		err = io.ErrShortWrite
	}
	return sent, err
}

func (op *udpControlWrite) wait() (int, error) {
	status, err := windows.WaitForSingleObject(op.event, 1000)
	if err == nil && status == windows.WAIT_OBJECT_0 {
		return op.result()
	}
	if err == nil {
		err = os.ErrDeadlineExceeded
	}
	op.cancel()
	// CancelIoEx requests cancellation. Completion must be drained before
	// releasing the pinned Go buffers even when cancellation loses the race.
	_, _ = windows.WaitForSingleObject(op.event, windows.INFINITE)
	sent, completion := op.result()
	if completion == nil {
		return sent, nil
	}
	return 0, err
}

func (op *udpControlWrite) result() (int, error) {
	var transferred, flags uint32
	err := windows.WSAGetOverlappedResult(op.handle, &op.overlapped, &transferred, false, &flags)
	return int(transferred), err
}

func (op *udpControlWrite) setDestination(peer netip.AddrPort, scope uint32) (int32, error) {
	local, err := windows.Getsockname(op.handle)
	if err != nil {
		return 0, err
	}
	ip := peer.Addr()
	switch local.(type) {
	case *windows.SockaddrInet4:
		if !ip.Unmap().Is4() {
			return 0, windows.WSAEAFNOSUPPORT
		}
		to := (*windows.RawSockaddrInet4)(unsafe.Pointer(&op.address))
		*to = windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: ip.Unmap().As4()}
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&to.Port))[:], peer.Port())
		return int32(unsafe.Sizeof(*to)), nil
	case *windows.SockaddrInet6:
		to := (*windows.RawSockaddrInet6)(unsafe.Pointer(&op.address))
		*to = windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: ip.As16(), Scope_id: scope}
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&to.Port))[:], peer.Port())
		return int32(unsafe.Sizeof(*to)), nil
	default:
		return 0, windows.WSAEAFNOSUPPORT
	}
}

func udpControlScope(addr netip.Addr) (uint32, error) {
	name := addr.Zone()
	if name == "" {
		return 0, nil
	}
	if scope, err := strconv.ParseUint(name, 10, 32); err == nil {
		return uint32(scope), nil
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return uint32(iface.Index), nil
}
