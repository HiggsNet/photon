package main

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestIPsecObservationInvalidatesOnlyChangedConsumerInputs(t *testing.T) {
	for _, scenario := range []string{"create", "remove", "interface", "namespace", "staged", "rotate_cost", "partial_failure", "diagnostics"} {
		t.Run(scenario, func(t *testing.T) {
			verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
			service := newTestDaemonFromOwners(&testApp{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second)
			defer service.Close()
			previous := map[string]ipsec.LinkInstance{"link-a": {
				ID: "link-a", InterfaceName: "old", ActualState: ipsec.LinkStateUp,
				LocalTunnelAddr: netip.MustParseAddr("fe80::1"), PeerTunnelAddr: netip.MustParseAddr("fe80::2"),
				StagedInterfaceName: "new", RotatePhase: ipsec.RotatePhaseDualRunning,
			}}
			if scenario == "create" {
				previous = nil
			}
			service.publishIPsecObservation(100, previous, nil, nil, nil, nil, nil)
			service.processEvents(t.Context(), nil)
			revision := service.State.Common.VerifiedRevision()
			current := maps.Clone(previous)
			link := current["link-a"]
			var desired []ipsec.TransportLinkSpec
			var applyErr error
			switch scenario {
			case "create":
				current = map[string]ipsec.LinkInstance{"link-a": {ID: "link-a", InterfaceName: "created", ActualState: ipsec.LinkStateConnecting}}
			case "remove":
				delete(current, "link-a")
			case "interface", "partial_failure":
				link.InterfaceName = "replacement"
			case "namespace":
				desired = []ipsec.TransportLinkSpec{{LinkID: "link-a", InterfaceName: "old", LocalTunnelAddr: link.LocalTunnelAddr, NetNS: "other"}}
			case "staged":
				link.StagedInterfaceName = "next"
			case "rotate_cost":
				link.RotatePhase = ipsec.RotatePhaseDraining
			case "diagnostics":
				link.LastTransition = 101
				link.Endpoint = "198.51.100.2:4500"
			}
			if scenario != "create" && scenario != "remove" {
				current["link-a"] = link
			}
			if scenario == "partial_failure" {
				applyErr = errors.New("later interface failed")
			}
			service.publishIPsecObservation(101, current, desired, []ipsec.SAState{{InboundBytes: 1000}}, nil, nil, applyErr)
			changed := scenario != "diagnostics"
			if service.routingDirty != changed || service.firewallDirty != changed || service.ipsecDirty {
				t.Fatalf("consumer invalidation = routing:%v firewall:%v ipsec:%v, want changed=%v", service.routingDirty, service.firewallDirty, service.ipsecDirty, changed)
			}
			if service.State.Common.VerifiedRevision() != revision {
				t.Fatal("runtime observation changed signed state")
			}
			var flushed []string
			service.Hooks.OnReconcileFlush = func(layer string) { flushed = append(flushed, layer) }
			service.processEvents(t.Context(), nil)
			if changed && (len(flushed) != 2 || flushed[0] != "firewall" || flushed[1] != "routing") || !changed && len(flushed) != 0 {
				t.Fatalf("follow-up flush order = %v", flushed)
			}
		})
	}
}

func TestPublishIPsecObservationRefreshesLiveSACounters(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(
		&testApp{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second,
	)
	instances := map[string]ipsec.LinkInstance{
		"link-a": {ID: "link-a", IKEName: "ike-a", ActualState: ipsec.LinkStateUp},
	}
	first := ipsec.SAState{
		Name: "ike-a", IKEState: "ESTABLISHED", Established: true,
		IKEAgeSeconds: 10, ChildAgeSeconds: 8,
		InboundBytes: 100, InboundPackets: 4, InboundIdleSecs: 3, InboundKnown: true,
	}
	service.publishIPsecObservation(100, instances, nil, []ipsec.SAState{first}, nil, nil, nil)

	second := first
	second.IKEAgeSeconds = 70
	second.ChildAgeSeconds = 68
	second.InboundBytes = 1000
	second.InboundPackets = 40
	second.InboundIdleSecs = 1
	service.publishIPsecObservation(160, instances, nil, []ipsec.SAState{second}, nil, nil, nil)

	response := controlViewRequestViaPipe[inspect.LinksDebugView](t, service, controlRequest{Method: "links_view"})
	if !response.OK {
		t.Fatalf("links_view response = %#v", response)
	}
	if response.View.Inspection.LastRunUnix != 160 {
		t.Fatalf("links_view last run = %d, want 160", response.View.Inspection.LastRunUnix)
	}
	links := response.View.Inspection.Links
	if len(links) != 1 || links[0].ActualSA == nil {
		t.Fatalf("links_view links = %+v, want one link with an SA", links)
	}
	got := links[0].ActualSA
	if got.IKEAgeSeconds != second.IKEAgeSeconds || got.ChildAgeSeconds != second.ChildAgeSeconds ||
		got.InboundBytes != second.InboundBytes || got.InboundPackets != second.InboundPackets ||
		got.InboundIdleSecs != second.InboundIdleSecs {
		t.Fatalf("links_view SA = %+v, want latest counters from %+v", got, second)
	}
}

func TestRecordIPsecReconcileErrorRefreshesRepeatedObservation(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(3990, 0)
	rt := &testApp{Config: testConfigWithStatePath(defaultAppConfig(),
		filepath.Join(t.TempDir(), "photon.db")), Clock: func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	firstRev := uint64(service.State.Common.VerifiedRevision())
	service.recordIPsecReconcileError(now.Unix(), errors.New("vici unavailable"))
	committedRev := uint64(service.State.Common.VerifiedRevision())
	if committedRev != firstRev {
		t.Fatalf("first error verified revision = %d, want %d", committedRev, firstRev)
	}

	later := now.Add(time.Minute)
	service.recordIPsecReconcileError(later.Unix(), errors.New("vici unavailable"))
	if got := uint64(service.State.Common.VerifiedRevision()); got != committedRev {
		t.Fatalf("repeated identical error revision = %d, want unchanged %d", got, committedRev)
	}
	_, repeated := service.linuxObservation.ipsecSnapshot()
	if repeated == nil || repeated.LastRunUnix != later.Unix() || repeated.LastFailure == nil || repeated.LastFailure.Error() != "vici unavailable" {
		t.Fatalf("repeated IPsec failure observation = %+v, want refreshed timestamp and unchanged failure", repeated)
	}

	service.recordIPsecReconcileError(later.Unix(), errors.New("vici timeout"))
	if got := uint64(service.State.Common.VerifiedRevision()); got != committedRev {
		t.Fatalf("changed runtime error verified revision = %d, want %d", got, committedRev)
	}
	_, observation := service.linuxObservation.ipsecSnapshot()
	if observation == nil || observation.LastFailure == nil || observation.LastFailure.Error() != "vici timeout" {
		t.Fatalf("ipsec failure = %+v", observation)
	}
	inspection := buildStoredLinkInspection(service.Config, nil, observation, nil, nil)
	if inspection.Inspection.LastFailure == nil || inspection.Inspection.LastFailure.Code != inspect.FailureCodeIPsecReconcile || inspection.Inspection.LastFailure.Message != "vici timeout" {
		t.Fatalf("inspect failure = %+v", inspection.Inspection.LastFailure)
	}
}

func TestDaemonStateChangedReconcilesIPsecLinks(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4000, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
	}}
	rt := &testApp{Config: testConfigWithStatePath(appConfig,
		filepath.Join(t.TempDir(), "photon.db")), Clock: func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)

	service.notifyStateChanged(reconcileAll)
	service.processEvents(context.Background(), nil)

	latestLinks, latestReconcile := readTestIPsecObservation(service)
	if len(latestLinks) != 1 {
		t.Fatalf("link instances len = %d, want 1", len(latestLinks))
	}
	if latestReconcile == nil || len(latestReconcile.Desired) != 1 {
		t.Fatalf("ipsec reconcile = %+v, want one desired link", latestReconcile)
	}
	if len(latestReconcile.Actions) != 1 || latestReconcile.Actions[0].Action != ipsec.ReconcileActionCreate {
		t.Fatalf("actions = %+v, want create", latestReconcile.Actions)
	}
	for _, inst := range latestLinks {
		if inst.Owner.Manager != "photon" || inst.ActualState != ipsec.LinkStateConnecting {
			t.Fatalf("instance = %+v, want photon connecting", inst)
		}
	}

	service.notifyStateChanged(reconcileAll)
	service.processEvents(context.Background(), nil)
	reloadedLinks, reloadedReconcile := readTestIPsecObservation(service)
	if len(reloadedLinks) != 1 {
		t.Fatalf("second link instances len = %d, want 1", len(reloadedLinks))
	}
	if len(reloadedReconcile.Actions) != 1 || reloadedReconcile.Actions[0].Action != ipsec.ReconcileActionNoop {
		t.Fatalf("second actions = %+v, want noop", reloadedReconcile.Actions)
	}
}

func TestLongIPsecReconcileDoesNotBlockCommittedReaders(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4060, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	rt := &testApp{Config: testConfigWithStatePath(appConfig,
		filepath.Join(t.TempDir(), "photon.db")), Clock: func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	started := make(chan struct{})
	unblock := make(chan struct{})
	driver := &loadHookIPsecDriver{}
	driver.onLoadConnection = func(ipsec.TransportLinkSpec) {
		close(started)
		<-unblock
	}
	installTestIPsecDrivers(service, driver, driver)

	done := make(chan error, 1)
	go func() {
		done <- service.reconcileIPsecLinks(context.Background())
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("ipsec reconcile did not enter blocking LoadConnection")
	}

	committedRev := uint64(service.State.Common.VerifiedRevision())
	statusDone := make(chan controlViewResponse[inspect.DaemonStatusView], 1)
	go func() {
		statusDone <- controlViewRequestViaPipe[inspect.DaemonStatusView](t, service, controlRequest{Method: "daemon_status_view"})
	}()
	select {
	case status := <-statusDone:
		if !status.OK || status.View.StateRevision != committedRev {
			close(unblock)
			t.Fatalf("status response = %#v, want committed revision %d", status, committedRev)
		}
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("control status blocked behind IPsec reconcile apply")
	}

	linksDone := make(chan controlViewResponse[inspect.LinksDebugView], 1)
	go func() {
		linksDone <- controlViewRequestViaPipe[inspect.LinksDebugView](t, service, controlRequest{Method: "links_view"})
	}()
	select {
	case links := <-linksDone:
		if !links.OK {
			close(unblock)
			t.Fatalf("links_view response = %#v", links)
		}
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("links_view blocked behind IPsec reconcile apply")
	}

	close(unblock)
	if err := <-done; err != nil {
		t.Fatalf("reconcileIPsecLinks: %v", err)
	}
}

func TestDaemonStateChangedReconcilesIPsecPortRotation(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4000, 0)
	verified.Network.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nil)
	addTestIPsecRecords(t, verified.Network.Zones["node-a.catofes."], "node-a.catofes.", now, ipsec.RoleOut)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
	}}
	rt := &testApp{Config: testConfigWithStatePath(appConfig,
		filepath.Join(t.TempDir(), "photon.db")), Clock: func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	service.notifyStateChanged(reconcileAll)
	service.processEvents(context.Background(), nil)

	common := service.State.Common.ReadView()
	persistedRuntime := service.State.ReadLinux()
	latestLinks, latestReconcile := readTestIPsecObservation(service)
	var inst ipsec.LinkInstance
	for _, v := range latestLinks {
		inst = v
	}
	if inst.ActualState != ipsec.LinkStateConnecting {
		t.Fatalf("initial state = %q, want connecting", inst.ActualState)
	}

	// Simulate peer publishing generation 2 port record.
	zs := common.State.Network.Zones["node-b.catofes."]
	zs.Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, "node-b.catofes.", ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: 2,
			IKE:        ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort},
			NATT:       ipsec.PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	service = newTestDaemonFromOwners(rt, common.State, common.Gossip, persistedRuntime, config, time.Second)
	service.linuxObservation.replaceIPsec(latestLinks, latestReconcile)
	service.notifyStateChanged(reconcileAll)
	service.processEvents(context.Background(), nil)

	rotatedLinks, rotatedReconcile := readTestIPsecObservation(service)
	for _, v := range rotatedLinks {
		inst = v
	}
	if inst.RotatePhase != ipsec.RotatePhaseTestingNew {
		t.Fatalf("rotate phase = %q, want testing_new", inst.RotatePhase)
	}
	if inst.StagedGeneration != 2 {
		t.Fatalf("staged generation = %d, want 2", inst.StagedGeneration)
	}
	if inst.StagedIKEName != ipsec.RuntimeConnectionID(inst.LinkID, 2, inst.TransportKind) {
		t.Fatalf("staged ike name = %q", inst.StagedIKEName)
	}
	foundPrepare := false
	for _, action := range rotatedReconcile.Actions {
		if action.Action == ipsec.ReconcileActionPrepareRotate {
			foundPrepare = true
		}
	}
	if !foundPrepare {
		t.Fatalf("expected prepare_rotate action, got %+v", rotatedReconcile.Actions)
	}
}

func TestDaemonProcessEventsCoalescesIPsecReconcile(t *testing.T) {
	for _, mode := range []string{"queued", "received"} {
		t.Run(mode, func(t *testing.T) {
			verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
			now := time.Unix(4150, 0)
			addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
			appConfig := defaultAppConfig()
			appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
				ID:                 "main",
				Provider:           ipsec.ProviderStrongSwan,
				NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
				DefaultPathMode:    ipsec.PathModeFamilyRedundant,
				AddressSourceOrder: []string{ipsec.SourceManualAddress},
				ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
			}}
			rt := &testApp{Config: testConfigWithStatePath(appConfig,
				filepath.Join(t.TempDir(), "photon.db")), Clock: func() time.Time { return now },
			}
			driver := &countingIPsecDriver{}
			service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
			installTestIPsecDrivers(service, driver, driver)

			service.Events <- daemonEvent{
				Type: daemonEventCommonMutation,
				CommonIntent: corestate.PutRecordIntent{
					Zone:  "node-b.catofes.",
					Key:   "coalesce-a",
					Value: []byte("a"),
					Type:  "policy.string",
				},
			}
			service.Events <- daemonEvent{
				Type: daemonEventCommonMutation,
				CommonIntent: corestate.PutRecordIntent{
					Zone:  "node-b.catofes.",
					Key:   "coalesce-b",
					Value: []byte("b"),
					Type:  "policy.string",
				},
			}

			var first *daemonEvent
			if mode == "received" {
				event := <-service.Events
				first = &event
			}
			syncNow, shutdown := service.processEvents(context.Background(), first)
			if syncNow || shutdown {
				t.Fatalf("syncNow/shutdown = %v/%v, want false/false", syncNow, shutdown)
			}
			if driver.listCalls != 1 {
				t.Fatalf("ListSAs calls = %d, want 1", driver.listCalls)
			}
			if len(driver.Connections) != 1 {
				t.Fatalf("connections = %d, want one coalesced apply", len(driver.Connections))
			}
			common := service.State.Common.ReadView()
			_, latestReconcile := readTestIPsecObservation(service)
			if common.State.Network.Zones["node-b.catofes."].Records["coalesce-a"] == nil || common.State.Network.Zones["node-b.catofes."].Records["coalesce-b"] == nil {
				t.Fatalf("queued record puts were not both persisted")
			}
			if latestReconcile == nil || len(latestReconcile.Actions) != 1 || latestReconcile.Actions[0].Action != ipsec.ReconcileActionCreate {
				t.Fatalf("ipsec reconcile = %+v, want one create", latestReconcile)
			}
		})
	}
}

func TestDaemonVICILifecycleEventsOnlyTriggerCoalescedIPsecReconcile(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4160, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
	}}
	rt := &testApp{Config: testConfigWithStatePath(appConfig,
		filepath.Join(t.TempDir(), "photon.db")), Clock: func() time.Time { return now },
	}
	driver := &countingIPsecDriver{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestIPsecDrivers(service, driver, driver)

	service.Events <- daemonEvent{Type: daemonEventIPsecLifecycle, VICIEvent: ipsec.VICIEvent{Name: "child-updown", Connection: "ipsec-main-ab", ChildSA: "ipsec-main-ab-child", Up: true, XFRMIfID: 77}}
	service.Events <- daemonEvent{Type: daemonEventIPsecLifecycle, VICIEvent: ipsec.VICIEvent{Name: "child-updown", Connection: "ipsec-main-ab", ChildSA: "ipsec-main-ab-child", Up: false, XFRMIfID: 77}}

	syncNow, shutdown := service.processEvents(context.Background(), nil)
	if syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want false/false", syncNow, shutdown)
	}
	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want one coalesced reconcile", driver.listCalls)
	}
	if len(driver.Connections) != 1 {
		t.Fatalf("connections = %d, want one apply through reconcile", len(driver.Connections))
	}
	if len(driver.Interfaces) != 1 {
		t.Fatalf("interfaces = %d, want one apply through xfrm reconcile", len(driver.Interfaces))
	}
}

func TestDaemonIPsecReconcileInterval(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	appConfig := defaultAppConfig()
	service := newTestDaemonFromOwners(&testApp{Config: appConfig}, verified, checkpoint, runtime, config, time.Second)
	if interval := service.ipsecReconcileInterval(); interval != 0 {
		t.Fatalf("interval without link groups = %s, want 0", interval)
	}

	service.linuxObservation.replaceIPsec(map[string]ipsec.LinkInstance{"stale": {ID: "stale"}}, nil)
	if interval := service.ipsecReconcileInterval(); interval != defaultIPsecReconcileInterval {
		t.Fatalf("interval with observed instances = %s, want %s", interval, defaultIPsecReconcileInterval)
	}
	service.linuxObservation.replaceIPsec(nil, nil)

	defaultGroup := testIPsecLinkGroup()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{defaultGroup}
	if interval := service.ipsecReconcileInterval(); interval != defaultIPsecReconcileInterval {
		t.Fatalf("default interval = %s, want %s", interval, defaultIPsecReconcileInterval)
	}

	fastGroup := testIPsecLinkGroup()
	fastGroup.ID = "fast"
	fastGroup.Reconcile.IntervalSeconds = 5
	slowGroup := testIPsecLinkGroup()
	slowGroup.ID = "slow"
	slowGroup.Reconcile.IntervalSeconds = 60
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{slowGroup, fastGroup}
	if interval := service.ipsecReconcileInterval(); interval != 5*time.Second {
		t.Fatalf("minimum interval = %s, want 5s", interval)
	}
}
