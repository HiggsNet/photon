package main

import (
	"context"
	"testing"
	"time"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
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
	flushed, err := service.flushFirewallReconcile(context.Background())
	if err != nil {
		t.Fatalf("flushFirewallReconcile: %v", err)
	}
	if !flushed {
		t.Fatal("firewall reconcile was not flushed")
	}

	service.routingDirty = true
	flushed, err = service.flushRoutingReconcile(context.Background())
	if err != nil {
		t.Fatalf("flushRoutingReconcile: %v", err)
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
	now := time.Unix(2230, 0)
	const peerID = "node-b.catofes."
	target := *verified
	target.Network = zone.CloneNetworkState(verified.Network)
	putVerifiedEndpointRecord(t, verified, "192.0.2.1", 33434, now)
	snapshot, err := corestate.Snapshot(verified.Network, peerID)
	if err != nil {
		t.Fatal(err)
	}
	root := corestate.ZoneRoot(verified.Network.Zones[peerID])
	service := newTestDaemonFromOwners(&testApp{Config: defaultAppConfig(), Clock: func() time.Time { return now }}, &target, checkpoint, runtime, config, time.Second)
	flushes := 0
	service.Hooks.OnReconcileFlush = func(string) { flushes++ }
	session := service.gossipDriver.Gossip.NewSession(peerID)
	_, _ = session.OnEvent(&gossip.SyncTimerEvent{PeerID: peerID}, now)
	_, _ = session.OnEvent(&gossip.CatalogPageReceivedEvent{PeerID: peerID, Page: &corestate.CatalogPage{
		CatalogRoot: []byte("catalog"),
		Entries: []corestate.ZoneDigest{
			{Zone: peerID, RootHash: root},
			{Zone: "node-c.catofes.", RootHash: []byte("other root")},
		},
	}}, now)
	result, err := service.handleGossipDriverEvent(t.Context(), corehost.GossipEvent{Value: &gossip.ObjectPullResultEvent{
		PeerID: peerID, Zone: peerID, Snapshot: snapshot,
	}})
	if err != nil || service.gossipDriver.Gossip.Session(peerID) != session || !result {
		t.Fatalf("Gossip result = %#v, error = %v", result, err)
	}
	if flushes != 0 {
		t.Fatalf("Gossip callback performed %d reconciles", flushes)
	}
	service.processEvents(context.Background(), nil)
	if flushes != 3 {
		t.Fatalf("next batch flush count = %d, want 3", flushes)
	}
	result, err = service.handleGossipDriverEvent(t.Context(), corehost.GossipEvent{Value: &gossip.RoundTimeoutEvent{PeerID: peerID}})
	if err != nil || service.gossipDriver.Gossip.Session(peerID) != nil || result {
		t.Fatalf("terminal Gossip result = %#v, error = %v", result, err)
	}
}
