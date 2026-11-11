package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/HiggsNet/photon/internal/photonlinux"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/observer"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestObserverStartObserverServerDisabled(t *testing.T) {
	d := &Daemon{Config: &appConfig{Observer: observerConfig{Enabled: false}}}
	stop, err := d.startObserverServer(context.TODO())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stop()
}

func TestObserverStartObserverServerEnabledServesHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback TCP unavailable: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	d := &Daemon{
		State: newState(nil, corestate.NewStoreWithCheckpoint(&corestate.VerifiedState{}, &corestate.GossipCheckpoint{}, nil, nil), &photonlinux.LinuxState{}), Config: &appConfig{PeerID: "test-node", ListenAddr: "127.0.0.1:33434", Observer: observerConfig{
			Enabled:  true,
			BindAddr: "127.0.0.1",
			Port:     port,
		}},
	}
	stop, err := d.startObserverServer(context.Background())
	if err != nil {
		t.Fatalf("startObserverServer error: %v", err)
	}
	defer stop()
	client := http.Client{Timeout: time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/api/v1/status", port)
	var resp *http.Response
	for range 20 {
		resp, err = client.Get(url)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET %s error: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var apiResp observer.APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		t.Fatalf("decode response error: %v", err)
	}
	if !apiResp.OK {
		t.Fatalf("response OK should be true: %#v", apiResp)
	}
	if d.observerHub == nil {
		t.Fatal("observerHub should be wired after start")
	}
}

func TestObserverShutdownClosesEventStreams(t *testing.T) {
	for _, mode := range []string{"stop", "parent_cancel"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			_ = listener.Close()
			d := &Daemon{Config: &appConfig{Observer: observerConfig{Enabled: true, BindAddr: "127.0.0.1", Port: port}}}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			stop, err := d.startObserverServer(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			client := &http.Client{Timeout: 3 * time.Second}
			response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/events", port))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("SSE status = %d", response.StatusCode)
			}
			if mode == "parent_cancel" {
				cancel()
				if _, err := io.ReadAll(response.Body); err != nil {
					t.Fatalf("SSE did not end on parent cancellation: %v", err)
				}
			}
			done := make(chan struct{})
			go func() { stop(); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("observer waited for shutdown timeout with an open event stream")
			}
			if _, err := io.ReadAll(response.Body); err != nil {
				t.Fatalf("SSE did not finish cleanly: %v", err)
			}
			if count := d.observerHub.SubscriberCount(); count != 0 {
				t.Fatalf("SSE subscribers left after shutdown = %d", count)
			}
		})
	}
}

func TestObserverNotifyObserverNoHub(t *testing.T) {
	d := &Daemon{}
	// Should not panic when observerHub is nil
	d.notifyObserver("test", nil)
}
