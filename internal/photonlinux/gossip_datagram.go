package photonlinux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// GossipDatagramIO owns the Linux UDP socket injected into the common gossip
// transport. It implements only OS I/O and carries no gossip protocol policy.
type GossipDatagramIO struct {
	conn *net.UDPConn
}

func ListenGossipDatagram(listenAddr string) (*GossipDatagramIO, error) {
	if listenAddr == "" {
		return nil, errors.New("UDP listen address is empty")
	}
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	listenConfig := net.ListenConfig{Control: setGossipUDPReuseOptions}
	packetConn, err := listenConfig.ListenPacket(context.Background(), "udp", addr.String())
	if err != nil {
		return nil, err
	}
	conn, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return nil, fmt.Errorf("listen udp returned %T, want *net.UDPConn", packetConn)
	}
	return &GossipDatagramIO{conn: conn}, nil
}

func (io *GossipDatagramIO) WriteDatagram(payload []byte, addr *net.UDPAddr) (int, error) {
	return io.conn.WriteToUDP(payload, addr)
}

func (io *GossipDatagramIO) LocalAddr() *net.UDPAddr {
	if io == nil || io.conn == nil {
		return nil
	}
	addr, _ := io.conn.LocalAddr().(*net.UDPAddr)
	return addr
}

func (io *GossipDatagramIO) SetReadDeadline(deadline time.Time) error {
	if io == nil || io.conn == nil {
		return nil
	}
	return io.conn.SetReadDeadline(deadline)
}

func (io *GossipDatagramIO) Close() error {
	if io == nil || io.conn == nil {
		return nil
	}
	return io.conn.Close()
}
