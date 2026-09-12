package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/HiggsNet/photon/internal/photonlinux"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/observer"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestObserverStartObserverServerDisabled(t *testing.T) {
	d := &Daemon{
		App: &AppContext{Config: &appConfig{Observer: observerConfig{Enabled: false}}},
	}
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
		State: newState(nil, corestate.NewStoreWithCheckpoint(&corestate.VerifiedState{}, &corestate.GossipCheckpoint{}, nil), &photonlinux.LinuxState{}),
		App: &AppContext{Config: &appConfig{PeerID: "test-node", ListenAddr: "127.0.0.1:33434", Observer: observerConfig{
			Enabled:  true,
			BindAddr: "127.0.0.1",
			Port:     port,
		}}},
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

func TestObserverNotifyObserverNoHub(t *testing.T) {
	d := &Daemon{}
	// Should not panic when observerHub is nil
	d.notifyObserver("test", nil)
}
