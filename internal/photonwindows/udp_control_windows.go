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
	"syscall"
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
	control    udpSegmentControl
	message    windows.WSAMsg
	conn       *net.UDPConn // Identifies the immutable family of this handle.
	ipv4       bool

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
	op, err := newUDPWrite()
	if err != nil {
		return 0, err
	}
	defer op.close()
	n, _, err := s.submitUDPWrite(op, packet, peer, scope, generation, 0, udpWriteTiming{})
	return n, err
}

func newUDPWrite() (*udpControlWrite, error) {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	return &udpControlWrite{event: event}, nil
}

func (op *udpControlWrite) close() {
	_ = windows.CloseHandle(op.event)
}

type udpWriteTiming struct {
	single *fixturePacketTiming
	batch  []fixturePacketTiming
}

func (t udpWriteTiming) mark(mark func(*fixturePacketTiming)) {
	if t.single != nil {
		mark(t.single)
	}
	for i := range t.batch {
		mark(&t.batch[i])
	}
}

// submitUDPWrite uses writeMu to pin the current endpoint only until the
// native submission. A pending write keeps its descriptor and buffers pinned
// without holding the lifecycle gate. Retirement cancels it by generation.
func (s *packetSockets) submitUDPWrite(op *udpControlWrite, packet []byte, peer netip.AddrPort, scope uint32, generation uint64, segmentSize int, timing udpWriteTiming) (int, bool, error) {
	op.generation = generation
	op.done = false
	// The low bit keeps completion out of the Go runtime's completion port
	// for the shared UDP handle. Winsock resets the event on pending I/O.
	op.overlapped = windows.Overlapped{HEvent: op.event | 1}
	op.buffer = windows.WSABuf{Len: uint32(len(packet))}
	if len(packet) != 0 {
		op.buffer.Buf = &packet[0]
	}
	var pin runtime.Pinner
	pin.Pin(op)
	if op.buffer.Buf != nil {
		pin.Pin(op.buffer.Buf)
	}
	defer pin.Unpin()
	defer func() { op.buffer.Buf = nil }()

	s.writeMu.Lock()
	if segmentSize != 0 && s.udpSegmentationDisabled.Load() {
		s.writeMu.Unlock()
		return 0, false, nil
	}
	timing.mark((*fixturePacketTiming).MarkUDPWriterAcquired)
	conn := s.udp
	current := s.udpControlCurrentLocked(conn, generation, peer)
	timing.mark((*fixturePacketTiming).MarkUDPValidationDone)
	if !current {
		s.writeMu.Unlock()
		return 0, true, net.ErrClosed
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		s.writeMu.Unlock()
		return 0, true, err
	}

	var sent int
	callbackStarted := false
	controlErr := raw.Control(func(handle uintptr) {
		callbackStarted = true
		op.handle = windows.Handle(handle)
		size, addrErr := op.setDestination(conn, peer, scope)
		if addrErr != nil {
			err = addrErr
			s.writeMu.Unlock()
			return
		}
		timing.mark((*fixturePacketTiming).MarkUDPDeadlineDone)
		err = op.send(size, segmentSize)
		pending := errors.Is(err, windows.ERROR_IO_PENDING)
		if pending {
			if s.controlWrites == nil {
				s.controlWrites = make(map[*udpControlWrite]struct{})
			}
			s.controlWrites[op] = struct{}{}
		}
		s.writeMu.Unlock()

		// Keep the descriptor pinned until the kernel has finished using
		// this operation. The shared gate covers only native submission.
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
		return 0, true, controlErr
	}
	timing.mark((*fixturePacketTiming).MarkUDPWriteDone)
	s.writeMu.Lock()
	delete(s.controlWrites, op)
	current = s.udpControlCurrentLocked(conn, generation, peer)
	if !current {
		s.writeMu.Unlock()
		return 0, true, net.ErrClosed
	}
	if segmentSize != 0 {
		submitted, unsupported, result := udpSegmentWriteStatus(sent, len(packet), err)
		if unsupported {
			s.udpSegmentationDisabled.Store(true)
		}
		s.writeMu.Unlock()
		return sent, submitted, result
	}
	s.writeMu.Unlock()
	if err == nil && sent != len(packet) {
		err = io.ErrShortWrite
	}
	return sent, true, err
}

func (op *udpControlWrite) send(addressSize int32, segmentSize int) error {
	if segmentSize == 0 {
		return windows.WSASendTo(op.handle, &op.buffer, 1, nil, 0, &op.address, addressSize, &op.overlapped, nil)
	}
	op.control = udpSegmentOptions(segmentSize)
	op.message = windows.WSAMsg{
		Name:        (*syscall.RawSockaddrAny)(unsafe.Pointer(&op.address)),
		Namelen:     addressSize,
		Buffers:     &op.buffer,
		BufferCount: 1,
		Control:     windows.WSABuf{Len: uint32(unsafe.Sizeof(op.control)), Buf: (*byte)(unsafe.Pointer(&op.control))},
	}
	return windows.WSASendMsg(op.handle, &op.message, 0, nil, &op.overlapped, nil)
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

func (op *udpControlWrite) setDestination(conn *net.UDPConn, peer netip.AddrPort, scope uint32) (int32, error) {
	if op.conn != conn {
		local, err := windows.Getsockname(op.handle)
		if err != nil {
			return 0, err
		}
		switch local.(type) {
		case *windows.SockaddrInet4:
			op.ipv4 = true
		case *windows.SockaddrInet6:
			op.ipv4 = false
		default:
			return 0, windows.WSAEAFNOSUPPORT
		}
		op.conn = conn
	}
	ip := peer.Addr()
	if op.ipv4 {
		if !ip.Unmap().Is4() {
			return 0, windows.WSAEAFNOSUPPORT
		}
		to := (*windows.RawSockaddrInet4)(unsafe.Pointer(&op.address))
		*to = windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: ip.Unmap().As4()}
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&to.Port))[:], peer.Port())
		return int32(unsafe.Sizeof(*to)), nil
	}
	to := (*windows.RawSockaddrInet6)(unsafe.Pointer(&op.address))
	*to = windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: ip.As16(), Scope_id: scope}
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&to.Port))[:], peer.Port())
	return int32(unsafe.Sizeof(*to)), nil
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
