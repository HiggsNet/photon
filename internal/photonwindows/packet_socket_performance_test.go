package photonwindows

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

func TestPacketSocketMappedSourceAndGossipAddress(t *testing.T) {
	s, err := openPacketSockets(t.Context(), "[::]:0")
	if err != nil {
		t.Skip("IPv6 wildcard socket unavailable:", err)
	}
	t.Cleanup(func() { s.Close() })
	if !s.LocalAddr().AddrPort().Addr().Is6() {
		t.Skip("host does not provide a dual-stack IPv6 socket")
	}
	peer, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	endpoint := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	generation := s.SelectTunnel(netip.AddrPort{}, endpoint)
	destination := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.LocalAddr().AddrPort().Port())
	type gossipResult struct {
		packet []byte
		addr   *net.UDPAddr
		err    error
	}
	readResult := make(chan gossipResult, 1)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buffer := make([]byte, 1201)
		n, addr, err := s.ReadDatagram(buffer)
		readResult <- gossipResult{buffer[:n], addr, err}
	}()
	t.Cleanup(func() { s.Close(); <-readDone })
	esp := []byte{0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1}
	if _, err := peer.WriteToUDPAddrPort(esp, destination); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-s.espPackets:
		if packet.generation != generation || packet.peer != endpoint || !bytes.Equal(packet.packet, esp) {
			t.Fatal("mapped source changed tunnel endpoint or generation")
		}
	case <-time.After(time.Second):
		t.Fatal("mapped source did not reach the selected ESP queue")
	}
	// Clear the reservation so the same peer now travels through Gossip's
	// original *UDPAddr interface, preserving the actual mapped source.
	s.SelectTunnel(netip.AddrPort{}, netip.AddrPort{})
	if err := s.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDPAddrPort([]byte("gossip"), destination); err != nil {
		t.Fatal(err)
	}
	result := <-readResult
	if result.err != nil || !bytes.Equal(result.packet, []byte("gossip")) || result.addr == nil {
		t.Fatal("Gossip return contract changed", result.err, result.addr)
	}
	got := result.addr.AddrPort()
	if !got.Addr().Is4In6() || got.Addr().Unmap() != endpoint.Addr() || got.Port() != endpoint.Port() || result.addr.Zone != "" {
		t.Fatal("Gossip mapped source changed", got)
	}
}

func TestPacketSocketReadErrorHasNoAddress(t *testing.T) {
	s, err := openPacketSockets(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	n, addr, err := s.ReadDatagram(make([]byte, 1201))
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() || n != 0 || addr != nil {
		t.Fatal("timeout returned a sender address or data", n, addr, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	n, addr, err = s.ReadDatagram(make([]byte, 1201))
	if !errors.Is(err, net.ErrClosed) || n != 0 || addr != nil {
		t.Fatal("closed socket returned a sender address or data", n, addr, err)
	}
}

// Measure only the real shared-socket admission path. No AES, signed policy or
// Wintun is included, and each packet is consumed before sending the next one.
func BenchmarkPacketSocketDemux(b *testing.B) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, kind := range []string{"ESP", "IKE"} {
			b.Run(network+"/"+kind, func(b *testing.B) {
				local := "127.0.0.1:0"
				if network == "udp6" {
					local = "[::1]:0"
				}
				s, err := openPacketSockets(b.Context(), local)
				if err != nil {
					b.Fatal(err)
				}
				peerAddress, err := net.ResolveUDPAddr(network, local)
				if err != nil {
					b.Fatal(err)
				}
				peer, err := net.ListenUDP(network, peerAddress)
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { peer.Close() })
				endpoint := peer.LocalAddr().(*net.UDPAddr).AddrPort()
				generation := s.SelectTunnel(netip.AddrPort{}, endpoint)
				destination := s.LocalAddr().AddrPort()
				readDone := make(chan error, 1)
				go func() {
					_, _, err := s.ReadDatagram(make([]byte, 1201))
					readDone <- err
				}()
				b.Cleanup(func() { s.Close(); <-readDone })
				packet := make([]byte, 1200)
				copy(packet, []byte{0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1})
				queue := s.espPackets
				if kind == "IKE" {
					request, err := ike.NewInitiator()
					if err != nil {
						b.Fatal(err)
					}
					packet, err = ike.EncapsulateIKE(request.Request())
					if err != nil {
						b.Fatal(err)
					}
					queue = s.ikePackets
				}
				timer := time.NewTimer(time.Second)
				timer.Stop()
				b.Cleanup(func() { timer.Stop() })
				b.ReportAllocs()
				b.SetBytes(int64(len(packet)))
				b.ResetTimer()
				for b.Loop() {
					timer.Reset(time.Second)
					if _, err := peer.WriteToUDPAddrPort(packet, destination); err != nil {
						b.Fatal(err)
					}
					select {
					case received := <-queue:
						if received.generation != generation || received.peer != endpoint {
							b.Fatal("shared socket admitted a stale packet")
						}
					case err := <-readDone:
						// Keep cleanup able to join an already returned reader.
						readDone <- err
						b.Fatal("shared socket receiver stopped", err)
					case <-timer.C:
						b.Fatal(context.DeadlineExceeded)
					}
					timer.Stop()
				}
			})
		}
	}
}

// Exercise real simultaneous sends and echo reception with at most 16 packets
// outstanding. This isolates UDP synchronization; it includes no ESP crypto,
// authorization or Wintun, so its rate is not product tunnel throughput.
func exercisePacketSocketDuplex(t testing.TB, network string, count int, begin func()) {
	t.Helper()
	local := "127.0.0.1:0"
	if network == "udp6" {
		local = "[::1]:0"
	}
	s, err := openPacketSockets(t.Context(), local)
	if err != nil {
		t.Fatal(err)
	}
	address, err := net.ResolveUDPAddr(network, local)
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	peer, err := net.ListenUDP(network, address)
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	endpoint := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	generation := s.SelectTunnel(netip.AddrPort{}, endpoint)
	destination := s.LocalAddr().AddrPort()
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	readDone, echoDone := make(chan error, 1), make(chan error, 1)
	go func() {
		_, _, err := s.ReadDatagram(make([]byte, 1201))
		readDone <- err
	}()
	go func() {
		buffer := make([]byte, 1200)
		for {
			n, from, err := peer.ReadFromUDPAddrPort(buffer)
			if err != nil {
				echoDone <- err
				return
			}
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			if n != len(buffer) || from != destination {
				echoDone <- errors.New("duplex send changed packet length or local endpoint")
				return
			}
			if _, err := peer.WriteToUDPAddrPort(buffer[:n], from); err != nil {
				echoDone <- err
				return
			}
		}
	}()
	t.Cleanup(func() {
		s.Close()
		peer.Close()
		<-readDone
		<-echoDone
	})
	packet := make([]byte, 1200)
	copy(packet, []byte{0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1})
	timer := time.NewTimer(time.Second)
	timer.Stop()
	t.Cleanup(func() { timer.Stop() })
	begin()
	for sent, received := 0, 0; received < count; received++ {
		for sent < count && sent-received < 16 {
			binary.BigEndian.PutUint64(packet[8:16], uint64(sent))
			if err := s.WriteTunnel(generation, packet, endpoint); err != nil {
				t.Fatal(err)
			}
			sent++
		}
		timer.Reset(time.Second)
		select {
		case got := <-s.espPackets:
			binary.BigEndian.PutUint64(packet[8:16], uint64(received))
			if got.generation != generation || got.peer != endpoint || !bytes.Equal(got.packet, packet) {
				t.Fatal("duplex receive lost, reordered or changed a packet")
			}
		case err := <-readDone:
			readDone <- err
			t.Fatal("duplex socket reader stopped", err)
		case err := <-echoDone:
			echoDone <- err
			t.Fatal("duplex echo reader stopped", err)
		case <-timer.C:
			t.Fatal("duplex UDP echo timed out")
		}
		timer.Stop()
	}
}

func TestPacketSocketConcurrentDuplex(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) { exercisePacketSocketDuplex(t, network, 1000, func() {}) })
	}
}

func BenchmarkPacketSocketDuplex(b *testing.B) {
	for _, network := range []string{"udp4", "udp6"} {
		b.Run(network, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(1200)
			exercisePacketSocketDuplex(b, network, b.N, b.ResetTimer)
		})
	}
}
