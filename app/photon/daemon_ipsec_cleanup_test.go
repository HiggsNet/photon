package main

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestDaemonHungXFRMCleanupKeepsSyncAndControlAvailable(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(&testApp{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second)
	// A slash makes the native namespace lookup fail validation. All exec
	// fallback commands are intercepted below; no host device is touched.
	xfrm := ipsec.NewSystemXFRMDriver(ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "test/blocked"})
	ipsecDriver := &ipsec.DryRunDriver{}
	release := make(chan struct{})
	defer close(release)
	var deletions atomic.Int32
	xfrm.Command = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "link delete") {
			deletions.Add(1)
			<-release
		}
		return nil, nil
	}
	installTestIPsecDrivers(service, ipsecDriver, xfrm)
	spec := ipsec.TransportLinkSpec{
		LocalZone: "node-a.catofes.", PeerZone: "node-b.catofes.", OverlayID: "main",
		TransportID: "ipsec-blocked", InterfaceName: "phx-blocked", XFRMIfID: 5100,
	}
	instance := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, time.Now())
	service.linuxObservation.replaceIPsec(map[string]ipsec.LinkInstance{instance.ID: instance}, nil)
	revision := service.State.Common.VerifiedRevision()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	reply := make(chan daemonEventResult, 1)
	service.Events <- daemonEvent{Type: daemonEventIPsecCleanup, Context: ctx, Reply: reply}
	service.processEvents(t.Context(), nil)
	if result := <-reply; !errors.Is(result.Error, ipsec.ErrXFRMOperationPending) || result.CleanedLinks != 0 {
		t.Fatalf("cleanup result = %+v", result)
	}
	remaining, summary := service.linuxObservation.ipsecSnapshot()
	if len(remaining) != 1 || summary == nil || !errors.Is(summary.LastFailure, ipsec.ErrXFRMOperationPending) {
		t.Fatalf("pending resource lost: %v, %+v", remaining, summary)
	}
	start := time.Now()
	for range 5 {
		service.Events <- daemonEvent{Type: daemonEventIPsecCleanup, Reply: reply}
		service.processEvents(t.Context(), nil)
		if result := <-reply; !errors.Is(result.Error, ipsec.ErrXFRMOperationPending) {
			t.Fatalf("retry = %+v", result)
		}
	}
	service.Events <- daemonEvent{Type: daemonEventSyncTrigger, Reply: reply}
	syncNow, shutdown := service.processEvents(t.Context(), nil)
	if result := <-reply; result.Error != nil || !syncNow || shutdown {
		t.Fatalf("sync unavailable: %+v, sync=%v, shutdown=%v", result, syncNow, shutdown)
	}
	view := controlViewRequestViaPipe[inspect.LinksDebugView](t, service, controlRequest{Method: "links_view"})
	if !view.OK || view.View.Inspection.LastFailure == nil {
		t.Fatalf("control view unavailable or hides pending operation: %+v", view)
	}
	if service.State.Common.VerifiedRevision() != revision || deletions.Load() != 1 || len(ipsecDriver.Terminated) != 1 {
		t.Fatalf("retries changed state or repeated teardown: deletions=%d, terminated=%v", deletions.Load(), ipsecDriver.Terminated)
	}
	if err := service.Close(); !errors.Is(err, ipsec.ErrXFRMOperationPending) {
		t.Fatalf("close = %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("retries/control/close waited for hung worker: %s", elapsed)
	}
}

type partialCleanupIPsecDriver struct {
	ipsec.DryRunDriver
	failConnection string
	err            error
	listErr        error
}

func (d *partialCleanupIPsecDriver) TerminateSA(ctx context.Context, name string) error {
	if name == d.failConnection {
		return d.err
	}
	return d.DryRunDriver.TerminateSA(ctx, name)
}

func (d *partialCleanupIPsecDriver) ListConnections(ctx context.Context) ([]ipsec.ConnectionState, error) {
	if d.listErr != nil {
		return nil, d.listErr
	}
	return d.DryRunDriver.ListConnections(ctx)
}

func TestIPsecCleanupFailurePreservesCompletedProgress(t *testing.T) {
	for _, mode := range []string{"cleanup", "purge", "orphans"} {
		t.Run(mode, func(t *testing.T) {
			verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
			now := time.Unix(6000, 0)
			service := newTestDaemonFromOwners(&testApp{Config: defaultAppConfig(), Clock: func() time.Time { return now }}, verified, checkpoint, runtime, config, time.Second)
			defer service.Close()
			instances := make(map[string]ipsec.LinkInstance)
			for i, peer := range []zone.ZonePath{"node-b.catofes.", "node-z.catofes."} {
				spec := ipsec.TransportLinkSpec{LocalZone: "node-a.catofes.", PeerZone: peer, OverlayID: "main", TransportID: "ipsec-" + string(peer), InterfaceName: "phx-" + string(peer[:6]), XFRMIfID: 5100 + uint32(i)}
				instance := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now)
				instances[instance.ID] = instance
			}
			ids := make([]string, 0, len(instances))
			for id := range instances {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			injected := errors.New("injected cleanup failure")
			driver := &partialCleanupIPsecDriver{failConnection: instances[ids[1]].TransportID, err: injected}
			wantRemaining, wantCleaned := 1, 1
			if mode == "orphans" {
				driver.failConnection = ""
				driver.listErr = injected
				wantRemaining, wantCleaned = 0, 2
			}
			installTestIPsecDrivers(service, driver, driver)
			service.linuxObservation.replaceIPsec(instances, &ipsecObservationSummary{ActualSAs: []photonstate.LinkSAObservation{{Name: "old-sa"}}})
			revision := service.State.Common.VerifiedRevision()
			stateNotices := 0
			service.Hooks.OnStateChanged = func() { stateNotices++ }
			var err error
			if mode == "purge" {
				err = service.cleanupPurgePlanIPsecLinks(t.Context(), instances, &purgePlan{LinkInstances: ids})
			} else {
				var cleaned int
				cleaned, _, err = service.handleIPsecCleanupEvent(t.Context(), mode == "orphans")
				if cleaned != wantCleaned {
					t.Fatalf("cleaned = %d, want %d", cleaned, wantCleaned)
				}
			}
			if !errors.Is(err, injected) || len(driver.Unloaded) != wantCleaned {
				t.Fatalf("cleanup error/unloaded = %v/%v", err, driver.Unloaded)
			}
			remaining, summary := service.linuxObservation.ipsecSnapshot()
			if len(remaining) != wantRemaining {
				t.Fatalf("observed remaining links = %d, want %d", len(remaining), wantRemaining)
			}
			if _, exists := remaining[ids[0]]; exists {
				t.Fatal("successfully removed link remained in the observation")
			}
			if summary == nil || !errors.Is(summary.LastFailure, injected) || summary.LastRunUnix != now.Unix() || len(summary.ActualSAs) != 0 {
				t.Fatalf("cleanup failure or stale SA state was not recorded: %+v", summary)
			}
			if !service.ipsecDirty || !service.routingDirty || !service.firewallDirty {
				t.Fatal("partial cleanup did not request existing platform reconciliation")
			}
			if service.State.Common.VerifiedRevision() != revision {
				t.Fatal("recording cleanup progress changed signed state")
			}
			if stateNotices != 0 {
				t.Fatal("runtime cleanup emitted a signed-state notification")
			}
			response := controlViewRequestViaPipe[inspect.LinksDebugView](t, service, controlRequest{Method: "links_view"})
			if !response.OK || response.View.Inspection.LinkInstances != wantRemaining || response.View.Inspection.LastFailure == nil {
				t.Fatalf("CLI did not reflect partial cleanup: %+v", response)
			}
		})
	}
}
