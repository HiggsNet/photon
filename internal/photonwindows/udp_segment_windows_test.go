package photonwindows

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestWindowsUDPSegmentationPreservesDatagrams(t *testing.T) {
	for _, tc := range []struct {
		name, bind string
	}{{"IPv4", "127.0.0.1"}, {"IPv6", "::1"}} {
		t.Run(tc.name, func(t *testing.T) {
			sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6zero})
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(tc.bind)})
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			deadline := time.Now().Add(time.Second)
			if err := receiver.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := sender.SetWriteDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			peer := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
			const size = 1300
			packet := make([]byte, 3*size)
			for i := range 3 {
				packet[i*size] = byte(i + 1)
			}
			submitted, _, err := writeUDPSegments(sender, packet, size, peer)
			if err != nil {
				t.Fatal(err)
			}
			if !submitted {
				t.Skip("Winsock does not support UDP segmentation on this path")
			}
			control := []byte{0, 0, 0, 0, 1}
			if _, err := sender.WriteToUDPAddrPort(control, peer); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, len(packet))
			for _, want := range [][]byte{packet[:size], packet[size : 2*size], packet[2*size:], control} {
				n, _, err := receiver.ReadFromUDPAddrPort(buf)
				if err != nil || !bytes.Equal(buf[:n], want) {
					t.Fatalf("got %d bytes, want %d-byte datagram in order: %v", n, len(want), err)
				}
			}
		})
	}
}
