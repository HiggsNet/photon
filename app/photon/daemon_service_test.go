package main

import (
	"context"
	"testing"
	"time"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestNewDaemonDefaultsInterval(t *testing.T) {
	service := newTestDaemonFromOwners(
		&testApp{}, &corestate.VerifiedState{}, nil, &photonlinux.LinuxState{}, &appConfig{}, 0,
	)
	if service.Interval != defaultDaemonInterval {
		t.Fatalf("default interval = %s, want %s", service.Interval, defaultDaemonInterval)
	}
	if service.Config == nil || service.gossipDriver == nil {
		t.Fatal("daemon app or gossip config is nil")
	}
}

func TestDaemonReplacesAndClosesSingleLinuxDriver(t *testing.T) {
	service := newTestDaemonFromOwners(
		&testApp{}, &corestate.VerifiedState{}, nil, &photonlinux.LinuxState{}, &appConfig{}, time.Second,
	)
	firstClosed := 0
	firstDriver := &ipsec.DryRunDriver{}
	first := newTestLinuxDriverWithOptions(photonlinux.LinuxDriverOptions{
		IPsecDriver: firstDriver,
		XFRMDriver:  firstDriver,
		Close: func() error {
			firstClosed++
			return nil
		},
	})
	if err := service.installLinuxDriver(first); err != nil {
		t.Fatalf("install first Linux driver: %v", err)
	}
	if service.linuxDriver != first {
		t.Fatal("first Linux driver was not installed")
	}

	secondClosed := 0
	secondDriver := &ipsec.DryRunDriver{}
	second := newTestLinuxDriverWithOptions(photonlinux.LinuxDriverOptions{
		IPsecDriver: secondDriver,
		XFRMDriver:  secondDriver,
		Close: func() error {
			secondClosed++
			return nil
		},
	})
	if err := service.installLinuxDriver(second); err != nil {
		t.Fatalf("replace Linux driver: %v", err)
	}
	if firstClosed != 1 {
		t.Fatalf("first driver close calls = %d, want 1", firstClosed)
	}
	if service.linuxDriver != second {
		t.Fatal("replacement Linux driver was not installed")
	}
	if err := service.closeLinuxDriver(); err != nil {
		t.Fatalf("close Linux driver: %v", err)
	}
	if secondClosed != 1 {
		t.Fatalf("second driver close calls = %d, want 1", secondClosed)
	}
	if service.linuxDriver != nil {
		t.Fatal("Linux driver remains installed after close")
	}
}

func TestDaemonStateChangedHook(t *testing.T) {
	service := newTestDaemonFromOwners(
		&testApp{},
		&corestate.VerifiedState{ManagedZone: "node-a.catofes."},
		nil,
		&photonlinux.LinuxState{},
		&appConfig{},
		time.Second,
	)
	var called bool
	service.Hooks.OnStateChanged = func() {
		called = true
	}
	service.notifyStateChanged()
	if !called {
		t.Fatal("state changed hook was not called")
	}
}

func TestDaemonStateChangedWithoutLinuxDriverSkipsPlatformReconcile(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(
		&testApp{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second,
	)
	if err := service.closeLinuxDriver(); err != nil {
		t.Fatalf("close Linux driver: %v", err)
	}
	var flushed []string
	service.Hooks.OnReconcileFlush = func(layer string) {
		flushed = append(flushed, layer)
	}

	service.notifyStateChanged()

	if len(flushed) != 0 {
		t.Fatalf("platform reconcile flushed without Linux driver: %v", flushed)
	}
	if service.ipsecDirty || service.routingDirty || service.firewallDirty {
		t.Fatalf("platform dirty flags set without Linux driver: ipsec:%v routing:%v firewall:%v", service.ipsecDirty, service.routingDirty, service.firewallDirty)
	}
}

func TestDaemonNotifyStateChangedDefersReconcileToEventLoop(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(
		&testApp{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second,
	)
	var flushed []string
	service.Hooks.OnReconcileFlush = func(layer string) {
		flushed = append(flushed, layer)
	}

	service.notifyStateChanged()

	if len(flushed) != 0 {
		t.Fatalf("reconcile flushed while draining events: %v", flushed)
	}
	if !service.ipsecDirty || !service.routingDirty || !service.firewallDirty {
		t.Fatalf("dirty flags = ipsec:%v routing:%v firewall:%v, want all true", service.ipsecDirty, service.routingDirty, service.firewallDirty)
	}
	service.processEvents(context.Background(), nil)
	if len(flushed) != 3 || flushed[0] != "firewall" || flushed[1] != "routing" || flushed[2] != "ipsec" {
		t.Fatalf("event loop flush order = %v, want firewall/routing/ipsec", flushed)
	}
	if service.ipsecDirty || service.routingDirty || service.firewallDirty {
		t.Fatal("event loop left unchanged platform state dirty")
	}
}

func TestEmptyFirewallAndRoutingFlushDoNotRepublishLegacyState(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(
		&testApp{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second,
	)
	beforeRevision := uint64(service.State.Common.VerifiedRevision())

	service.firewallDirty = true
	flushed, err := service.flushFirewallReconcileResult(context.Background())
	if err != nil {
		t.Fatalf("flushFirewallReconcileResult: %v", err)
	}
	if !flushed {
		t.Fatal("firewall reconcile was not flushed")
	}

	service.routingDirty = true
	flushed, err = service.flushRoutingReconcileResult(context.Background())
	if err != nil {
		t.Fatalf("flushRoutingReconcileResult: %v", err)
	}
	if !flushed {
		t.Fatal("routing reconcile was not flushed")
	}

	if revision := uint64(service.State.Common.VerifiedRevision()); revision != beforeRevision {
		t.Fatalf("empty reconciles changed revision from %d to %d", beforeRevision, revision)
	}
}

func TestRootCommandIncludesDaemon(t *testing.T) {
	for _, command := range rootCommand().Commands {
		if command.Name == "daemon" {
			return
		}
	}
	t.Fatal("root command does not include daemon")
}

func TestDaemonGossipChangeDefersPlatformWorkToEventLoop(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(&testApp{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second)
	flushes := 0
	service.Hooks.OnReconcileFlush = func(string) { flushes++ }
	if !service.observeSyncEventResult(corehost.GossipEventResult{Done: true, NetworkChanged: true}) {
		t.Fatal("Gossip change was not reported")
	}
	if flushes != 0 {
		t.Fatalf("Gossip callback performed %d reconciles", flushes)
	}
	_, _, ipsecFlushed, routingFlushed, firewallFlushed := service.processEvents(context.Background(), nil)
	if !ipsecFlushed || !routingFlushed || !firewallFlushed || flushes != 3 {
		t.Fatalf("next batch flushes = %v/%v/%v, count %d", ipsecFlushed, routingFlushed, firewallFlushed, flushes)
	}
}
