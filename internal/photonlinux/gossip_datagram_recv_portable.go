//go:build !linux || (!amd64 && !arm64)

package photonlinux

import "net"

func (io *GossipDatagramIO) ReadDatagram(buffer []byte) (int, *net.UDPAddr, error) {
	return io.conn.ReadFromUDP(buffer)
}
