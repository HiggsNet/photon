package photonwindows

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

// Hold the real UDPConn's write operation, without replacing the production
// socket or adding an I/O hook. RawConn.Write holds its descriptor's write lock
// on both Windows and Unix; its callback returns true when released.
func holdPacketSocketWrite(t *testing.T, conn *net.UDPConn) func() {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var holdErr error
	go func() {
		defer close(done)
		holdErr = raw.Write(func(uintptr) bool {
			close(entered)
			<-release
			return true
		})
	}()
	var once sync.Once
	unblock := func() {
		once.Do(func() {
			close(release)
			<-done
			if holdErr != nil {
				t.Error(holdErr)
			}
		})
	}
	t.Cleanup(unblock)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("UDP descriptor write did not start")
	}
	return unblock
}

func waitPacketSocketWriter(t *testing.T, s *packetSockets) {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if !s.writeMu.TryLock() {
			return
		}
		s.writeMu.Unlock()
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatal("production writer did not start")
		}
	}
}

func TestPacketSocketReceiveDuringBlockedWrite(t *testing.T) {
	for _, kind := range []string{"ESP", "Gossip"} {
		t.Run(kind, func(t *testing.T) {
			s, err := openPacketSockets(t.Context(), "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { peer.Close() })
			gossip, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { gossip.Close() })
			local := s.LocalAddr()
			endpoint := peer.LocalAddr().(*net.UDPAddr).AddrPort()
			generation := s.SelectTunnel(netip.AddrPort{}, endpoint)
			unblock := holdPacketSocketWrite(t, s.udp)
			outbound := []byte{0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1}
			written := make(chan error, 1)
			go func() {
				if kind == "ESP" {
					written <- s.WriteTunnel(generation, outbound, endpoint)
				} else {
					_, err := s.WriteDatagram(outbound, peer.LocalAddr().(*net.UDPAddr))
					written <- err
				}
			}()
			waitPacketSocketWriter(t, s)
			request, err := ike.NewInitiator()
			if err != nil {
				t.Fatal(err)
			}
			ikeFrame, err := ike.EncapsulateIKE(request.Request())
			if err != nil {
				t.Fatal(err)
			}
			read := make(chan error, 1)
			go func() {
				buffer := make([]byte, 1200)
				n, from, err := s.ReadDatagram(buffer)
				if err == nil && (string(buffer[:n]) != "gossip" || from.String() != gossip.LocalAddr().String()) {
					err = errors.New("Gossip content or source changed")
				}
				read <- err
			}()
			for _, packet := range [][]byte{outbound, ikeFrame} {
				if _, err := peer.WriteToUDP(packet, local); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := gossip.WriteToUDP([]byte("gossip"), local); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-read:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("a blocked send prevented Gossip/ESP/IKE reception")
			}
			for _, expected := range []struct {
				queue  <-chan tunnelDatagram
				packet []byte
			}{{s.espPackets, outbound}, {s.ikePackets, request.Request()}} {
				select {
				case got := <-expected.queue:
					if got.generation != generation || got.peer != endpoint || !bytes.Equal(got.packet, expected.packet) {
						t.Fatal("concurrent ingress changed content, source or generation")
					}
				default:
					t.Fatal("tunnel packet was not admitted before send completed")
				}
			}
			unblock()
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, 1200)
			n, from, err := peer.ReadFromUDP(buffer)
			if err != nil || from.String() != local.String() || !bytes.Equal(buffer[:n], outbound) {
				t.Fatalf("outbound socket or payload changed: %v", err)
			}
		})
	}
}

func TestPacketSocketReplacementWaitsForWrite(t *testing.T) {
	for _, change := range []string{"select", "rebind", "invalidate", "close"} {
		t.Run(change, func(t *testing.T) {
			s, err := openPacketSockets(t.Context(), "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { peer.Close() })
			endpoint := peer.LocalAddr().(*net.UDPAddr).AddrPort()
			generation := s.SelectTunnel(netip.AddrPort{}, endpoint)
			old, address := s.udp, s.LocalAddr().String()
			unblock := holdPacketSocketWrite(t, old)
			packet := []byte{0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1}
			written := make(chan error, 1)
			go func() { written <- s.WriteTunnel(generation, packet, endpoint) }()
			waitPacketSocketWriter(t, s)
			changed := make(chan error, 1)
			changing := make(chan struct{})
			go func() {
				close(changing)
				var err error
				switch change {
				case "select":
					s.SelectTunnel(netip.AddrPort{}, endpoint)
				case "rebind":
					err = s.Rebind(t.Context())
				case "invalidate":
					s.invalidate(old, nil)
				case "close":
					err = s.Close()
				}
				changed <- err
			}()
			<-changing
			select {
			case err := <-changed:
				t.Fatalf("%s crossed an unfinished write: %v", change, err)
			case <-time.After(20 * time.Millisecond):
			}
			unblock()
			if err := <-written; err != nil {
				t.Fatal("write preceding replacement failed:", err)
			}
			select {
			case err := <-changed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("replacement remained blocked after send completed")
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, 1200)
			n, from, err := peer.ReadFromUDP(buffer)
			if err != nil || from.String() != address || !bytes.Equal(buffer[:n], packet) {
				t.Fatalf("write preceding replacement lost its source or payload: %v", err)
			}
			if !errors.Is(s.WriteTunnel(generation, packet, endpoint), net.ErrClosed) {
				t.Fatal("old generation wrote after replacement")
			}
			if change == "close" {
				if _, err := s.WriteDatagram(packet, peer.LocalAddr().(*net.UDPAddr)); !errors.Is(err, net.ErrClosed) {
					t.Fatal("Gossip wrote after close")
				}
				if !errors.Is(s.Rebind(context.Background()), net.ErrClosed) {
					t.Fatal("closed sockets reopened")
				}
				return
			}
			if change == "invalidate" {
				select {
				case <-s.failed:
				default:
					t.Fatal("current socket invalidation did not request recovery")
				}
				if err := s.Rebind(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if s.LocalAddr().String() != address {
				t.Fatal("replacement changed the local endpoint")
			}
			current := s.SelectTunnel(netip.AddrPort{}, endpoint)
			if change != "select" {
				s.invalidate(old, nil)
			}
			if err := s.WriteTunnel(current, packet, endpoint); err != nil {
				t.Fatal("current generation failed after replacement:", err)
			}
		})
	}
}
