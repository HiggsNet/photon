package photonwindows

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

func TestSharedUDPIngressAndGeneration(t *testing.T) {
	s, err := openPacketSockets(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	endpoint := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	generation := s.SelectTunnel(netip.AddrPort{}, endpoint)
	read := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1201)
		n, _, err := s.ReadDatagram(buffer)
		if err == nil && !bytes.Equal(buffer[:n], []byte("gossip")) {
			err = context.Canceled
		}
		read <- err
	}()
	request, _ := ike.NewInitiator()
	frame, _ := ike.EncapsulateIKE(request.Request())
	if _, err := peer.WriteToUDP(frame, s.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-s.ikePackets:
		if packet.generation != generation || packet.peer != endpoint || !bytes.Equal(packet.packet, request.Request()) {
			t.Fatal("invalid IKE demux")
		}
	case <-time.After(time.Second):
		t.Fatal("IKE ingress blocked")
	}
	// ESP exceeds Gossip's read budget and must survive intact.
	esp := make([]byte, 4096)
	binary.BigEndian.PutUint32(esp, 0x12345678)
	if _, err := peer.WriteToUDP(esp, s.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-s.espPackets:
		if !bytes.Equal(packet.packet, esp) {
			t.Fatal("ESP truncated")
		}
	case <-time.After(time.Second):
		t.Fatal("ESP ingress blocked")
	}
	if _, err := s.WriteDatagram([]byte("gossip"), s.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-read:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Gossip blocked")
	}
	if err := s.WriteTunnel(generation, frame, endpoint); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4096)
	n, from, err := peer.ReadFromUDP(buf)
	if err != nil || from.String() != s.LocalAddr().String() || !bytes.Equal(buf[:n], frame) {
		t.Fatalf("shared source endpoint: %v", err)
	}
	if err := s.Rebind(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteTunnel(generation, frame, endpoint); err == nil {
		t.Fatal("stale generation wrote after rebind")
	}
}

func TestSharedUDPDemuxBoundsAndKeepalive(t *testing.T) {
	s, err := openPacketSockets(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	peer := netip.MustParseAddrPort("127.0.0.1:4500")
	s.SelectTunnel(netip.AddrPort{}, peer)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.demuxLocked([]byte{0xff}, peer) || len(s.ikePackets) != 0 || len(s.espPackets) != 0 {
		t.Fatal("keepalive produced authenticated traffic")
	}
	for range 1000 {
		s.demuxLocked([]byte{0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1}, peer)
	}
	if len(s.espPackets) != 64 {
		t.Fatal("unbounded queue")
	}
	if s.demuxLocked([]byte{0xff}, netip.MustParseAddrPort("127.0.0.2:4500")) {
		t.Fatal("unselected endpoint accepted")
	}
}
