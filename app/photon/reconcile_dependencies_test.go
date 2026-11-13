package main

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/service"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestLocalMutationFlushesOnlyDependentLayers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		intents []corestate.LocalIntent
		want    []string
	}{
		{"route", []corestate.LocalIntent{
			corestate.AnnounceRouteIntent{Zone: "node-a.catofes.", Prefix: "10.0.1.0/24"},
			corestate.WithdrawRouteIntent{Zone: "node-a.catofes.", Prefix: "10.0.1.0/24"},
		}, []string{"firewall", "routing"}},
		{"service", []corestate.LocalIntent{
			corestate.PublishSOCKS5Intent{Endpoints: []service.SOCKS5Endpoint{{Region: "test", Address: "10.0.0.1", Port: 1080}}},
			corestate.WithdrawSOCKS5Intent{},
		}, nil},
		{"generic_record", []corestate.LocalIntent{
			corestate.PutRecordIntent{Zone: "node-a.catofes.", Key: "custom", Type: "policy.string", Value: []byte("value")},
		}, []string{"firewall", "routing", "ipsec"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verified, checkpoint, runtime, config := buildTestRoutingOwners(t)
			verified.ManagedZone = "node-a.catofes."
			d := newTestDaemonFromOwners(&testApp{Config: config, Clock: func() time.Time { return time.Unix(8000, 0) }}, verified, checkpoint, runtime, config, time.Second)
			defer d.Close()
			notifications := 0
			d.Hooks.OnStateChanged = func() { notifications++ }
			for _, intent := range tc.intents {
				before := d.State.Common.VerifiedRevision()
				// Preview must never invalidate platform state or emit a commit notice.
				if _, err := d.handleCommonRecordMutationEvent(intent, true); err != nil {
					t.Fatal(err)
				}
				if d.ipsecDirty || d.routingDirty || d.firewallDirty {
					t.Fatal("preview invalidated platform state")
				}
				reply := make(chan daemonEventResult, 1)
				d.Events <- daemonEvent{Type: daemonEventCommonMutation, CommonIntent: intent, Reply: reply}
				var flushed []string
				d.Hooks.OnReconcileFlush = func(layer string) { flushed = append(flushed, layer) }
				d.processEvents(t.Context(), nil)
				if result := <-reply; result.Error != nil {
					t.Fatal(result.Error)
				}
				if d.State.Common.VerifiedRevision() <= before {
					t.Fatal("mutation did not commit")
				}
				if !reflect.DeepEqual(flushed, tc.want) {
					t.Fatalf("flushes = %v, want %v", flushed, tc.want)
				}
			}
			if notifications != len(tc.intents) {
				t.Fatalf("notifications = %d, want %d", notifications, len(tc.intents))
			}
		})
	}
}

func TestLocalEndpointAndProtocolPublicationOnlyInvalidatesIPsec(t *testing.T) {
	d := newEndpointDiscoveryDaemon(t, "", func() time.Time { return time.Unix(8000, 0) })
	endpoints := []gossip.LocalEndpoint{{IP: net.ParseIP("198.51.100.20"), Port: 33434}}
	if changed, err := d.publishLocalEndpoints(endpoints); err != nil || !changed {
		t.Fatalf("endpoint publication = %v, %v", changed, err)
	}
	if !d.ipsecDirty || d.routingDirty || d.firewallDirty {
		t.Fatal("endpoint publication invalidated unrelated layers")
	}
	// A second publication must preserve an independently pending routing update.
	d.routingDirty = true
	if _, err := d.publishLocalProtocols(); err != nil {
		t.Fatal(err)
	}
	if !d.ipsecDirty || !d.routingDirty || d.firewallDirty {
		t.Fatal("protocol publication lost pending work or invalidated firewall")
	}
	// Re-publishing identical records must not trigger another adjustment.
	d.ipsecDirty, d.routingDirty = false, false
	if changed, err := d.publishLocalProtocols(); err != nil || changed {
		t.Fatalf("unchanged publication = %v, %v", changed, err)
	}
	if d.ipsecDirty || d.routingDirty || d.firewallDirty {
		t.Fatal("unchanged publication invalidated platform state")
	}
}

func TestUnknownLocalIntentDependenciesRemainConservative(t *testing.T) {
	for _, intent := range []corestate.LocalIntent{nil, corestate.GrantDelegationIntent{}, corestate.RevokeDelegationIntent{}, corestate.PutProtocolRecordIntent{Kind: "future"}} {
		if got := localIntentReconcileLayers(intent); got != reconcileAll {
			t.Fatalf("%T dependencies = %v", intent, got)
		}
	}
	// Runtime link output propagation remains independent of signed records.
	d := &Daemon{}
	d.publishIPsecObservation(8000, map[string]ipsec.LinkInstance{"new": {InterfaceName: "phx-new"}}, nil, nil, nil, nil, nil)
	if !d.routingDirty || !d.firewallDirty {
		t.Fatal("new link output did not invalidate its consumers")
	}
}
