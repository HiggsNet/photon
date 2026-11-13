package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	photonstate "github.com/HiggsNet/photon/internal/state"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
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
					syncNow, shutdown := service.processEvents(context.Background(), first)
					select {
					case result := <-event.Reply:
						if !errors.Is(result.Error, backendErr) {
							t.Fatalf("reply error = %v, want %v", result.Error, backendErr)
						}
					default:
						t.Fatal("event was not replied to")
					}
					if shutdown || syncNow {
						t.Fatalf("sync/shutdown = %v/%v", syncNow, shutdown)
					}
					if flushes != 1 {
						t.Fatalf("flush count = %d, want 1", flushes)
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
	syncNow, shutdown := service.processEvents(context.Background(), &first)
	if !syncNow || !shutdown || len(first.Reply) != 1 || len(stop.Reply) != 1 || len(after.Reply) != 0 || len(service.Events) != 1 {
		t.Fatalf("first/batch shutdown order: sync=%v shutdown=%v replies=%d/%d/%d queued=%d", syncNow, shutdown, len(first.Reply), len(stop.Reply), len(after.Reply), len(service.Events))
	}
}

func TestDaemonEventBatchCoalescesReloadsAndRepliesAfterApply(t *testing.T) {
	fixture := newRoutingDisabledFixture(t, false, ipsec.RoutingModeManaged, true)
	service := fixture.service
	backendErr := errors.New("routing backend failed")
	fixture.enabledBird.startErr = backendErr
	replies := []chan daemonEventResult{make(chan daemonEventResult, 1), make(chan daemonEventResult, 1)}
	for _, reply := range replies {
		service.Events <- daemonEvent{Type: daemonEventRoutingReload, Reply: reply}
	}
	flushes := 0
	service.Hooks.OnReconcileFlush = func(layer string) {
		if layer == "routing" {
			flushes++
		}
		for _, reply := range replies {
			if len(reply) != 0 {
				t.Fatal("command replied before the batch finished applying")
			}
		}
	}
	service.processEvents(t.Context(), nil)
	if flushes != 1 {
		t.Fatalf("reload batch applied %d times, want 1", flushes)
	}
	for _, reply := range replies {
		if result := <-reply; !errors.Is(result.Error, backendErr) {
			t.Fatalf("reload lost backend error: %v", result.Error)
		}
	}
}

func TestDaemonEventBatchYieldsBeforeQueueIsEmpty(t *testing.T) {
	service := &Daemon{Events: make(chan daemonEvent, maxDaemonEventBatch+3)}
	first := daemonEvent{Type: daemonEventSyncTrigger, Reply: make(chan daemonEventResult, 1)}
	for i := 0; i < cap(service.Events); i++ {
		service.Events <- daemonEvent{Type: daemonEventSyncTrigger, Reply: make(chan daemonEventResult, 1)}
	}
	syncNow, shutdown := service.processEvents(t.Context(), &first)
	if !syncNow || shutdown || len(first.Reply) != 1 || len(service.Events) != 4 {
		t.Fatalf("batch did not yield: sync=%v shutdown=%v first=%d queued=%d", syncNow, shutdown, len(first.Reply), len(service.Events))
	}
	if next := <-service.Events; len(next.Reply) != 0 {
		t.Fatal("next batch's request was already replied to")
	}
}

func TestDaemonEventBatchSchedulesWorkRaisedDuringApply(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(&testApp{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second)
	service.daemonTimerEvents = make(chan corehost.Event, 4)
	service.daemonTimers = corehost.NewScheduler(corehost.NewClock(service.now), service.daemonTimerEvents)
	defer service.daemonTimers.Stop()
	var order []string
	service.Hooks.OnReconcileFlush = func(layer string) {
		order = append(order, layer)
		if layer == "routing" {
			service.firewallDirty = true
		}
	}
	service.notifyStateChanged()
	service.processEvents(t.Context(), nil)
	if !reflect.DeepEqual(order, []string{"firewall", "routing", "ipsec"}) {
		t.Fatalf("batch apply order = %v", order)
	}
	select {
	case event := <-service.daemonTimerEvents:
		fired, ok := event.(corehost.TimerFired)
		if !ok || fired.ID.Key != daemonTimerFirewall || !service.daemonTimers.Accept(fired) {
			t.Fatalf("follow-up work was not scheduled: %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("new work had no wakeup after yielding")
	}
}

func TestDaemonIPsecApplyWakesConsumersWithoutPeriodicTimers(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4000, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	setTestIPsecOverlayIntent(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", appConfig.IPsec.LinkGroups[0], now)
	service := newTestDaemonFromOwners(&testApp{Config: appConfig, Clock: func() time.Time { return now }}, verified, checkpoint, runtime, config, time.Second)
	defer service.Close()
	if service.routingReconcileInterval() != 0 || service.firewallReconcileInterval() != 0 {
		t.Fatal("fixture must have no periodic consumer timers")
	}
	service.daemonTimerEvents = make(chan corehost.Event, 4)
	service.daemonTimers = corehost.NewScheduler(corehost.NewClock(service.now), service.daemonTimerEvents)
	defer service.daemonTimers.Stop()
	var order []string
	service.Hooks.OnReconcileFlush = func(layer string) { order = append(order, layer) }
	service.ipsecDirty = true
	service.processEvents(t.Context(), nil)
	if !reflect.DeepEqual(order, []string{"ipsec"}) || !service.routingDirty || !service.firewallDirty {
		t.Fatalf("new IPsec link did not invalidate consumers: order=%v dirty=%v/%v", order, service.routingDirty, service.firewallDirty)
	}
	for pending := map[string]bool{daemonTimerRouting: true, daemonTimerFirewall: true}; len(pending) > 0; {
		select {
		case event := <-service.daemonTimerEvents:
			fired, ok := event.(corehost.TimerFired)
			if !ok || !pending[fired.ID.Key] || !service.daemonTimers.Accept(fired) {
				t.Fatalf("unexpected follow-up timer: %#v", event)
			}
			delete(pending, fired.ID.Key)
		case <-time.After(time.Second):
			t.Fatalf("consumer work has no wakeup: %v", pending)
		}
	}
	service.processEvents(t.Context(), nil)
	if !reflect.DeepEqual(order, []string{"ipsec", "firewall", "routing"}) || service.routingDirty || service.firewallDirty || service.ipsecDirty {
		t.Fatalf("follow-up did not settle: order=%v dirty=%v/%v/%v", order, service.routingDirty, service.firewallDirty, service.ipsecDirty)
	}
}
