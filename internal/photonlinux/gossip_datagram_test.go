package photonlinux

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"
)

func TestGossipDatagramIORoundTrip(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) { testGossipDatagramRoundTrip(t, "127.0.0.1:0") })
	t.Run("IPv6", func(t *testing.T) { testGossipDatagramRoundTrip(t, "[::1]:0") })
}

func testGossipDatagramRoundTrip(t *testing.T, listen string) {
	t.Helper()
	a, err := ListenGossipDatagram(listen)
	if err != nil {
		t.Skipf("UDP sockets are unavailable: %v", err)
	}
	defer a.Close()
	b, err := ListenGossipDatagram(listen)
	if err != nil {
		t.Skipf("UDP sockets are unavailable: %v", err)
	}
	defer b.Close()

	buffer := make([]byte, 64)
	if err := b.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, _, err := b.ReadDatagram(buffer); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("empty receive = %v, want deadline exceeded", err)
	}

	want := []byte("packet")
	if _, err := a.WriteDatagram(want, b.LocalAddr()); err != nil {
		t.Fatalf("WriteDatagram: %v", err)
	}
	if err := b.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, addr, err := b.ReadDatagram(buffer)
	if err != nil {
		t.Fatalf("ReadDatagram: %v", err)
	}
	if !bytes.Equal(buffer[:n], want) {
		t.Fatalf("payload = %q, want %q", buffer[:n], want)
	}
	if addr.String() != a.LocalAddr().String() {
		t.Fatalf("addr = %v, want %v", addr, a.LocalAddr())
	}
}

func TestListenGossipDatagramReusesPort(t *testing.T) {
	first, err := ListenGossipDatagram("127.0.0.1:0")
	if err != nil {
		t.Skipf("UDP sockets are unavailable: %v", err)
	}
	defer first.Close()
	second, err := ListenGossipDatagram(first.LocalAddr().String())
	if err != nil {
		t.Skipf("UDP port reuse is unavailable: %v", err)
	}
	defer second.Close()
}
