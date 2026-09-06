package host

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func TestGossipDriverGossipObjectPullServerServesAndOwnsListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("TCP sockets are unavailable: %v", err)
	}
	driver := NewGossipDriver(NewClock(nil), DefaultEventBuffer, nil, GossipDriverConfig{})
	if err := driver.StartGossipObjectPullServer(t.Context(), listener, func(request *gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
		return &gossip.ObjectPullResponse{OK: request != nil && request.Type == gossip.ObjectPullZone}
	}, 1, time.Second); err != nil {
		t.Fatalf("StartGossipObjectPullServer: %v", err)
	}

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	response, err := gossip.ExchangeObjectPull(conn, &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: "node-a."})
	_ = conn.Close()
	if err != nil {
		t.Fatalf("ExchangeObjectPull: %v", err)
	}
	if !response.OK {
		t.Fatalf("response = %#v, want OK", response)
	}

	driver.Stop()
	if conn, err := net.DialTimeout("tcp", listener.Addr().String(), 50*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("listener still accepts after GossipDriver.Stop")
	}
}

func TestGossipDriverGossipObjectPullServerValidatesSingleOwnership(t *testing.T) {
	driver := NewGossipDriver(NewClock(nil), DefaultEventBuffer, nil, GossipDriverConfig{})
	defer driver.Stop()
	lookup := func(*gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
		return &gossip.ObjectPullResponse{OK: true}
	}
	if err := driver.StartGossipObjectPullServer(t.Context(), nil, lookup, 0, 0); !errors.Is(err, ErrGossipObjectPullListenerRequired) {
		t.Fatalf("nil listener error = %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("TCP sockets are unavailable: %v", err)
	}
	if err := driver.StartGossipObjectPullServer(t.Context(), listener, nil, 0, 0); !errors.Is(err, ErrGossipObjectPullLookupRequired) {
		_ = listener.Close()
		t.Fatalf("nil lookup error = %v", err)
	}
	if err := driver.StartGossipObjectPullServer(t.Context(), listener, lookup, 0, 0); err != nil {
		_ = listener.Close()
		t.Fatalf("first start: %v", err)
	}
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("second TCP listener is unavailable: %v", err)
	}
	defer second.Close()
	if err := driver.StartGossipObjectPullServer(t.Context(), second, lookup, 0, 0); !errors.Is(err, ErrGossipObjectPullServerStarted) {
		t.Fatalf("second start error = %v", err)
	}
}

func TestGossipDriverGossipObjectPullServerRejectsConnectionsAboveLimit(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("TCP sockets are unavailable: %v", err)
	}
	driver := NewGossipDriver(NewClock(nil), DefaultEventBuffer, nil, GossipDriverConfig{})
	defer driver.Stop()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	if err := driver.StartGossipObjectPullServer(t.Context(), listener, func(*gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
		entered <- struct{}{}
		<-release
		return &gossip.ObjectPullResponse{OK: true}
	}, 1, time.Second); err != nil {
		t.Fatalf("StartGossipObjectPullServer: %v", err)
	}

	first, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("Dial(first): %v", err)
	}
	defer first.Close()
	firstDone := make(chan error, 1)
	go func() {
		_, err := gossip.ExchangeObjectPull(first, &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: "node-a."})
		firstDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first request did not enter lookup")
	}

	second, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("Dial(second): %v", err)
	}
	_ = second.SetDeadline(time.Now().Add(time.Second))
	if _, err := gossip.ExchangeObjectPull(second, &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: "node-b."}); err == nil {
		_ = second.Close()
		t.Fatal("second request succeeded above connection limit")
	}
	_ = second.Close()

	close(release)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first request failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first request did not complete")
	}
}
