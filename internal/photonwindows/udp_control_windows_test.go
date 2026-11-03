package photonwindows

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestWindowsIKEWriteBypassesGoDescriptorWriter(t *testing.T) {
	for _, local := range []string{"127.0.0.1", "::1", "::"} {
		t.Run(local, func(t *testing.T) {
			s, err := openPacketSockets(t.Context(), net.JoinHostPort(local, "0"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			peerIP := net.ParseIP(local)
			if peerIP.IsUnspecified() {
				// Exercise an IPv4 destination on the dual-stack socket.
				peerIP = net.IPv4(127, 0, 0, 1)
			}
			peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: peerIP})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { peer.Close() })
			endpoint := peer.LocalAddr().(*net.UDPAddr).AddrPort()
			endpoint = netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
			generation := s.reserveTunnel(endpoint, netip.AddrPort{})
			unblock := holdPacketSocketWrite(t, s.udp)
			packet := []byte("same socket IKE send")
			done := make(chan error, 1)
			go func() { done <- s.WriteIKE(generation, packet, endpoint) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("IKE send waited for the ESP descriptor writer")
			}
			if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, len(packet))
			n, source, err := peer.ReadFromUDP(buffer)
			if err != nil || source.Port != s.LocalAddr().Port || !bytes.Equal(buffer[:n], packet) {
				t.Fatalf("IKE send did not preserve the UDP socket and datagram: %v, %v", source, err)
			}
			unblock()
			s.releaseTunnel(generation)
			if err := s.WriteIKE(generation, packet, endpoint); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("retired IKE generation sent a datagram: %v", err)
			}
		})
	}
}
