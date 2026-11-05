//go:build !windows

package photonwindows

import (
	"net"
	"net/netip"
)

const udpSegmentation = false

func writeUDPSegments(*net.UDPConn, []byte, int, netip.AddrPort) (submitted, unsupported bool, err error) {
	return false, true, nil
}
