package photonwindows

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestGossipSocketsRebindPreservesBlockedIO(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			sockets, err := openGossipSockets(t.Context(), address)
			if err != nil {
				t.Fatal(err)
			}
			defer sockets.Close()
			original := sockets.LocalAddr().String()
			old := sockets.udp
			received := make(chan error, 1)
			go func() {
				b := make([]byte, 10)
				n, _, err := sockets.ReadDatagram(b)
				if err == nil && string(b[:n]) != "new" {
					err = errors.New("unexpected datagram")
				}
				received <- err
			}()
			accepted := make(chan error, 1)
			go func() {
				conn, err := (gossipListener{sockets}).Accept()
				if conn != nil {
					conn.Close()
				}
				accepted <- err
			}()
			for range 3 {
				if err := sockets.Rebind(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if sockets.udp == old || sockets.LocalAddr().String() != original {
				t.Fatal("rebind did not replace sockets at the same endpoint")
			}
			if _, err := sockets.WriteDatagram([]byte("new"), sockets.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			conn, err := net.DialTimeout("tcp", original, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			for _, done := range []chan error{received, accepted} {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("I/O did not resume after rebind")
				}
			}
			select {
			case <-sockets.failed:
				t.Fatal("old socket close incorrectly requested recovery")
			default:
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if !errors.Is(sockets.Rebind(ctx), context.Canceled) {
				t.Fatal("canceled rebind accepted")
			}
		})
	}
}

func TestGossipSocketsFailedRebindRecoversAndCloseUnblocks(t *testing.T) {
	sockets, err := openGossipSockets(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sockets.Close()
	address := sockets.LocalAddr().String()
	sockets.tcp.Close()
	occupied, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	if err := sockets.Rebind(t.Context()); err == nil {
		t.Fatal("expected TCP conflict")
	}
	// Failed paired bind must release UDP, too.
	probe, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	probe.Close()
	read := make(chan error, 1)
	accept := make(chan error, 1)
	go func() { _, _, err := sockets.ReadDatagram(make([]byte, 10)); read <- err }()
	go func() { _, err := (gossipListener{sockets}).Accept(); accept <- err }()
	occupied.Close()
	if err := sockets.Rebind(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := sockets.Close(); err != nil {
		t.Fatal(err)
	}
	for _, done := range []chan error{read, accept} {
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("close: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("close left I/O blocked")
		}
	}
	if !errors.Is(sockets.Rebind(t.Context()), net.ErrClosed) {
		t.Fatal("rebind reopened closed adapter")
	}
}

func TestGossipSocketsReadDeadline(t *testing.T) {
	sockets, err := openGossipSockets(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sockets.Close()
	if err := sockets.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := sockets.Rebind(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, _, err = sockets.ReadDatagram(make([]byte, 10))
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("deadline lost across rebind: %v", err)
	}
}

func TestGossipSocketsBrokenAcceptRequestsRecovery(t *testing.T) {
	sockets, err := openGossipSockets(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sockets.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, err := (gossipListener{sockets}).Accept()
		if conn != nil {
			conn.Close()
		}
		accepted <- err
	}()
	sockets.mu.Lock()
	err = sockets.tcp.Close()
	sockets.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-sockets.failed:
	case <-time.After(time.Second):
		t.Fatal("broken listener did not request rebind")
	}
	if err := sockets.Rebind(t.Context()); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", sockets.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("accept worker did not recover")
	}
}
