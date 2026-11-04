package photonwindows

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestMeshSocketWriterBypassesDescriptorWriteLock(t *testing.T) {
	for _, bind := range []string{"127.0.0.1", "::1"} {
		t.Run(bind, func(t *testing.T) {
			s, err := openPacketSockets(t.Context(), net.JoinHostPort(bind, "0"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(bind)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { peer.Close() })
			endpoint := peer.LocalAddr().(*net.UDPAddr).AddrPort()
			generation := s.reserveTunnel(netip.AddrPort{}, endpoint)
			writer := s.newMeshPacketWriter()
			defer writer.close()
			unblock := holdPacketSocketWrite(t, s.udp)
			defer unblock()

			plain := []byte("plain")
			const segmentSize = 1300
			batch := make([]byte, 2*segmentSize)
			batch[0], batch[segmentSize] = 1, 2
			sent := make(chan error, 1)
			go func() {
				var timing fixturePacketTiming
				if err := writer.writeTunnel(generation, plain, endpoint, &timing); err != nil {
					sent <- err
					return
				}
				var traces [2]fixturePacketTiming
				submitted, err := writer.writeTunnelSegments(generation, endpoint, batch, segmentSize, traces[:])
				if !submitted && err == nil {
					for _, packet := range [][]byte{batch[:segmentSize], batch[segmentSize:]} {
						if err = writer.writeTunnel(generation, packet, endpoint, &timing); err != nil {
							break
						}
					}
				}
				sent <- err
			}()
			select {
			case err := <-sent:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				unblock()
				<-sent
				t.Fatal("mesh writer waited for the Go UDP descriptor writer")
			}
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, len(batch))
			for _, want := range [][]byte{plain, batch[:segmentSize], batch[segmentSize:]} {
				n, from, err := peer.ReadFromUDPAddrPort(buffer)
				if err != nil || from.String() != s.LocalAddr().String() || !bytes.Equal(buffer[:n], want) {
					t.Fatalf("unexpected datagram of %d bytes from %s: %v", n, from, err)
				}
			}
			s.releaseTunnel(generation)
			if err := writer.writeTunnel(generation, plain, endpoint, &fixturePacketTiming{}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("retired reservation accepted a new write: %v", err)
			}
		})
	}
}
