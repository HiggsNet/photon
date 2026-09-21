package main

import (
	"context"
	"errors"
	"testing"
	"time"

	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type eventBatchFirewallDriver struct {
	firewall.DryRunDriver
	err error
}

func (d *eventBatchFirewallDriver) Apply(context.Context, *firewall.FirewallDesiredState) (firewall.FirewallApplyResult, error) {
	return firewall.FirewallApplyResult{}, d.err
}

func TestDaemonEventBatchReconcileReply(t *testing.T) {
	for _, layer := range []string{"routing", "firewall"} {
		for _, received := range []bool{false, true} {
			for _, failed := range []bool{false, true} {
				name := layer
				if received {
					name += "/received"
				} else {
					name += "/queued"
				}
				if failed {
					name += "/failure"
				} else {
					name += "/success"
				}
				t.Run(name, func(t *testing.T) {
					var backendErr error
					if failed {
						backendErr = errors.New("injected backend failure")
					}
					var service *Daemon
					var event daemonEvent
					if layer == "routing" {
						fixture := newRoutingDisabledFixture(t, false, ipsec.RoutingModeManaged, true)
						fixture.enabledBird.startErr = backendErr
						service = fixture.service
						event = daemonEvent{Type: daemonEventCommonMutation, CommonIntent: corestate.WithdrawRouteIntent{Zone: "node-a.catofes.", Prefix: "10.0.0.0/24"}}
					} else {
						verified, checkpoint, runtime, config := buildTestRoutingOwners(t)
						runtime.EndpointACLs = map[string]photonstate.EndpointACL{"test": {Name: "test", Destination: "10.0.0.1", Scope: endpointACLScopeIP, Selectors: []string{"*.catofes."}}}
						appConfig := defaultAppConfig()
						appConfig.Firewall.Instances = []firewall.FirewallInstanceSpec{{ID: "host", NetNS: "host", IsHost: true, Enabled: true, Mode: firewall.ModeManaged, Backend: firewall.BackendAuto}}
						service = newTestDaemonFromOwners(&testApp{Config: appConfig, Clock: func() time.Time { return time.Unix(4000, 0) }}, verified, checkpoint, runtime, config, time.Second)
						driver := &eventBatchFirewallDriver{err: backendErr}
						driver.Backend = firewall.BackendNFT
						installTestFirewallDriver(service, driver)
						event = daemonEvent{Type: daemonEventEndpointACLRemove, Key: "test"}
					}
					flushes := 0
					service.Hooks.OnReconcileFlush = func(got string) {
						if got == layer {
							flushes++
						}
					}
					event.Reply = make(chan daemonEventResult, 1)
					var first *daemonEvent
					if received {
						first = &event
					} else {
						service.Events <- event
					}
					syncNow, shutdown, _, routingFlushed, firewallFlushed := service.processEvents(context.Background(), first)
					select {
					case result := <-event.Reply:
						if !errors.Is(result.Error, backendErr) {
							t.Fatalf("reply error = %v, want %v", result.Error, backendErr)
						}
					default:
						t.Fatal("event was not replied to")
					}
					if shutdown || syncNow != (layer == "routing") {
						t.Fatalf("sync/shutdown = %v/%v", syncNow, shutdown)
					}
					flushed := routingFlushed
					if layer == "firewall" {
						flushed = firewallFlushed
					}
					if !flushed || flushes != 1 {
						t.Fatalf("flushed/count = %v/%d, want true/1", flushed, flushes)
					}
				})
			}
		}
	}
}

func TestDaemonEventBatchFirstPrecedesQueuedShutdown(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(&testApp{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second)
	first := daemonEvent{Type: daemonEventSyncTrigger, Reply: make(chan daemonEventResult, 1)}
	stop := daemonEvent{Type: daemonEventShutdown, Reply: make(chan daemonEventResult, 1)}
	after := daemonEvent{Type: daemonEventSyncTrigger, Reply: make(chan daemonEventResult, 1)}
	service.Events <- stop
	service.Events <- after
	syncNow, shutdown, _, _, _ := service.processEvents(context.Background(), &first)
	if !syncNow || !shutdown || len(first.Reply) != 1 || len(stop.Reply) != 1 || len(after.Reply) != 0 || len(service.Events) != 1 {
		t.Fatalf("first/batch shutdown order: sync=%v shutdown=%v replies=%d/%d/%d queued=%d", syncNow, shutdown, len(first.Reply), len(stop.Reply), len(after.Reply), len(service.Events))
	}
}
