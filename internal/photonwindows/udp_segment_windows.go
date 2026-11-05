package photonwindows

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

const udpSegmentation = true

// UDP_SEND_MSG_SIZE is a DWORD per-message Winsock control field. The socket
// option stays untouched so ordinary ESP and control datagrams use plain UDP.
func writeUDPSegments(conn *net.UDPConn, packet []byte, size int, peer netip.AddrPort) (submitted, unsupported bool, err error) {
	const udpSendMsgSize = 2
	control := struct {
		header windows.WSACMSGHDR
		size   uint32
	}{
		header: windows.WSACMSGHDR{
			Len:   unsafe.Sizeof(windows.WSACMSGHDR{}) + unsafe.Sizeof(uint32(0)),
			Level: windows.IPPROTO_UDP,
			Type:  udpSendMsgSize,
		},
		size: uint32(size),
	}
	oob := unsafe.Slice((*byte)(unsafe.Pointer(&control)), int(unsafe.Sizeof(control)))
	n, _, err := conn.WriteMsgUDPAddrPort(packet, oob, peer)
	if n == 0 && err != nil {
		switch {
		case errors.Is(err, windows.WSAENOPROTOOPT), errors.Is(err, windows.WSAEOPNOTSUPP), errors.Is(err, windows.WSAEPROTONOSUPPORT):
			return false, true, nil
		case errors.Is(err, windows.WSAEMSGSIZE), errors.Is(err, windows.WSAEINVAL):
			// These reject the message without sending any segment.
			return false, false, nil
		}
	}
	// On Windows, Go can return zero bytes with a successful synchronous
	// WSASendMsg. Its poller skips the completion query in that case.
	if err == nil && n != 0 && n != len(packet) {
		err = io.ErrShortWrite
	}
	// Do not retry a datagram if Winsock might have accepted it.
	return true, false, err
}
