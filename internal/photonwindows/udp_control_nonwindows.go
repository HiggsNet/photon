//go:build !windows

package photonwindows

import (
	"net"
	"time"
)

type udpControlWrite struct{}

func (s *packetSockets) cancelUDPControlLocked(uint64, bool) {}

func (s *packetSockets) writeUDPControl(packet []byte, addr *net.UDPAddr, generation uint64) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	conn := s.udp
	if !s.udpControlCurrentLocked(conn, generation, addr.AddrPort()) {
		return 0, net.ErrClosed
	}
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return 0, err
	}
	return conn.WriteToUDP(packet, addr)
}
