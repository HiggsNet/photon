package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func newEndpointDiscoveryDaemon(t *testing.T, reflector string, now func() time.Time) *Daemon {
	t.Helper()
	verified, checkpoint, runtime, transport := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-b.catofes."
	transport.PeerID = string(verified.ManagedZone)
	config := defaultAppConfig()
	config.ListenAddr = "127.0.0.1:33434"
	config.AdvertiseAddrs = []string{"198.51.100.20:33434"}
	config.EndpointDiscovery = "all"
	config.Reflectors = []string{reflector}
	config.ReflectorTimeout = time.Second
	config.IPsec.AnnounceGossipEndpoints = true
	config.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	service := newTestDaemonFromOwners(&testApp{Config: config, Clock: now}, verified, checkpoint, runtime, transport, time.Second)
	t.Cleanup(func() { _ = service.Close() })
	return service
}

func endpointDiscoveryOutcome(t *testing.T, service *Daemon) endpointDiscoveryResult {
	t.Helper()
	select {
	case result := <-service.endpointResults:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("endpoint discovery never completed")
		return endpointDiscoveryResult{}
	}
}

func publishedEndpoint(t *testing.T, service *Daemon, address string) *gossip.EndpointEntry {
	t.Helper()
	view := service.State.Common.ReadView()
	record := view.State.Network.Zones[view.State.ManagedZone].Records[gossip.EndpointRecordKeyUDP]
	if record == nil {
		return nil
	}
	var endpoints gossip.EndpointRecord
	if err := json.Unmarshal(record.Value, &endpoints); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range endpoints.Endpoints {
		if endpoint.Address == address {
			return &endpoint
		}
	}
	return nil
}

func TestEndpointDiscoveryDoesNotBlockStartupOrWriteFromWorker(t *testing.T) {
	started, release := make(chan struct{}, 1), make(chan struct{})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		started <- struct{}{}
		select {
		case <-release:
			fmt.Fprint(w, "198.51.100.9")
		case <-req.Context().Done():
		}
	}))
	t.Cleanup(server.Close)
	service := newEndpointDiscoveryDaemon(t, server.URL, time.Now)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, err := service.prepareLocalState(ctx); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil || service.endpointResults == nil {
		t.Fatal("startup waited for HTTP instead of leaving discovery in flight")
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("reflector request did not start")
	}
	if publishedEndpoint(t, service, "198.51.100.20") == nil || publishedEndpoint(t, service, "198.51.100.9") != nil {
		t.Fatal("startup did not publish local candidates independently of HTTP")
	}
	pending := service.endpointResults
	for range 2 {
		if changed, err := service.handleEndpointTimerEvent(ctx); err != nil || changed || service.endpointResults != pending {
			t.Fatalf("duplicate trigger replaced in-flight discovery: changed=%v error=%v", changed, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent reflector requests = %d, want one round", calls.Load())
	}
	// A normal state change during HTTP must not invalidate the collected IPs.
	if _, err := service.handleCommonRecordMutationEvent(corestate.PutRecordIntent{Zone: "node-b.catofes.", Key: "during-discovery", Type: "policy.string", Value: []byte("value")}, false); err != nil {
		t.Fatal(err)
	}
	revision := service.State.Common.VerifiedRevision()
	close(release)
	result := endpointDiscoveryOutcome(t, service)
	if service.State.Common.VerifiedRevision() != revision || publishedEndpoint(t, service, "198.51.100.9") != nil {
		t.Fatal("background worker wrote signed state before main-loop completion")
	}
	if changed, err := service.handleEndpointDiscoveryResult(ctx, result); err != nil || !changed {
		t.Fatalf("completion changed/error = %v/%v", changed, err)
	}
	if publishedEndpoint(t, service, "198.51.100.9") == nil || service.endpointResults != nil {
		t.Fatal("completion failed to publish or release its round")
	}
	view := service.State.Common.ReadView()
	zs := view.State.Network.Zones[view.State.ManagedZone]
	if zs.Records["during-discovery"] == nil {
		t.Fatal("completion overwrote newer main-loop state")
	}
	addresses, err := ipsec.ParseAddressRecord(zs.Records[ipsec.RecordKeyAddresses])
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses.Addresses {
		if address.Address == "198.51.100.9" {
			return
		}
	}
	t.Fatalf("IPsec did not consume newly committed Gossip endpoints: %+v", addresses)
}

func TestEndpointDiscoveryStopDiscardsPendingResult(t *testing.T) {
	for _, mode := range []string{"stop", "close", "parent_cancel"} {
		t.Run(mode, func(t *testing.T) {
			started, stopped := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				close(started)
				<-req.Context().Done()
				close(stopped)
			}))
			t.Cleanup(server.Close)
			service := newEndpointDiscoveryDaemon(t, server.URL, time.Now)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			revision := service.State.Common.VerifiedRevision()
			if _, err := service.handleEndpointTimerEvent(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("request never started")
			}
			if mode == "close" {
				if err := service.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if mode == "parent_cancel" {
					cancel()
					result := endpointDiscoveryOutcome(t, service)
					if changed, err := service.handleEndpointDiscoveryResult(ctx, result); changed || !errors.Is(err, context.Canceled) {
						t.Fatalf("canceled completion changed/error = %v/%v", changed, err)
					}
				} else {
					service.stopEndpointDiscovery()
				}
			}
			if service.endpointResults != nil || service.endpointCancel != nil || service.State.Common.VerifiedRevision() != revision {
				t.Fatal("stopping discovery leaked its round or published partial results")
			}
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("HTTP request survived discovery stop")
			}
		})
	}
}

func TestEndpointDiscoveryFailureDoesNotRenewOldAddress(t *testing.T) {
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, "198.51.100.9")
	}))
	t.Cleanup(server.Close)
	clock := newFakeClock(time.Unix(1000, 0))
	service := newEndpointDiscoveryDaemon(t, server.URL, clock.Now)
	for round := range 3 {
		if _, err := service.handleEndpointTimerEvent(t.Context()); err != nil {
			t.Fatal(err)
		}
		result := endpointDiscoveryOutcome(t, service)
		if (round > 0) != (result.Error != nil) {
			t.Fatalf("round %d reflector error = %v", round, result.Error)
		}
		if _, err := service.handleEndpointDiscoveryResult(t.Context(), result); err != nil {
			t.Fatal(err)
		}
		old := publishedEndpoint(t, service, "198.51.100.9")
		if round < 2 && (old == nil || old.LastObserved != 1000) {
			t.Fatalf("round %d renewed or prematurely removed the old IP: %+v", round, old)
		}
		if round == 2 && old != nil {
			t.Fatalf("old reflector IP survived its grace period: %+v", old)
		}
		fail.Store(true)
		clock.Advance(6 * time.Minute)
	}
}

func TestEndpointDiscoveryAdvertiseOnlyDoesNotStartWorker(t *testing.T) {
	service := newEndpointDiscoveryDaemon(t, "https://unused.example", time.Now)
	service.Config.EndpointDiscovery = "advertise_only"
	if _, err := service.handleEndpointTimerEvent(t.Context()); err != nil {
		t.Fatal(err)
	}
	if service.endpointResults != nil || publishedEndpoint(t, service, "198.51.100.20") == nil {
		t.Fatal("explicit addresses should publish without a background query")
	}
	if service.linuxObservation.operationSnapshot() != nil {
		t.Fatal("address discovery occupied the main-loop operation display")
	}
}

func TestDaemonRunConsumesDiscoveryResultsAndStopsQueryOnShutdown(t *testing.T) {
	started, stopped := make(chan struct{}, 2), make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		round := calls.Add(1)
		started <- struct{}{}
		if round == 1 {
			select {
			case <-release:
				fmt.Fprint(w, "198.51.100.9")
			case <-req.Context().Done():
			}
			return
		}
		<-req.Context().Done()
		close(stopped)
	}))
	t.Cleanup(server.Close)
	verified, checkpoint, runtime, _ := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-b.catofes."
	config := defaultAppConfig()
	config.ListenAddr = "127.0.0.1:0"
	config.EndpointDiscovery = "all"
	config.Reflectors = []string{server.URL}
	config.ReflectorTimeout = time.Minute
	config.ReflectorInterval = 100 * time.Millisecond
	config.IPsec.Driver = "dry-run"
	service := newDaemon(config, newState(nil, corestate.NewStoreWithCheckpoint(verified, checkpoint, nil, nil), runtime), time.Hour, time.Now)
	service.ControlSocketPath = ""
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		done <- service.Run(ctx)
	}()
	defer func() { cancel(); <-finished; _ = service.Close() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("daemon never started discovery")
	}
	requestCtx, cancelRequest := context.WithTimeout(ctx, time.Second)
	defer cancelRequest()
	if result := service.enqueueEvent(requestCtx, daemonEvent{Type: daemonEventSyncTrigger}); result.Error != nil {
		t.Fatalf("HTTP stalled the daemon event loop: %v", result.Error)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for publishedEndpoint(t, service, "198.51.100.9") == nil {
		if time.Now().After(deadline) {
			t.Fatal("daemon did not consume its discovery completion")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("second discovery never started")
	}
	if result := service.enqueueEvent(ctx, daemonEvent{Type: daemonEventShutdown}); result.Error != nil {
		t.Fatal(result.Error)
	}
	select {
	case err := <-done:
		if err != nil || service.endpointResults != nil {
			t.Fatalf("daemon exit error/results = %v/%v", err, service.endpointResults)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon exit did not reclaim background discovery")
	}
	if ctx.Err() != nil {
		t.Fatal("shutdown canceled its caller instead of the owned HTTP context")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("daemon exit left the HTTP request running")
	}
}
