package main

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

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
