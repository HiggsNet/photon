package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/HiggsNet/photon/internal/photonlinux"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestDaemonRecordPutEventSerializesWrite(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(2000, 0)
	rt := &AppContext{
		Config: defaultAppConfig(),
		Clock:  func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)

	result, syncNow, shutdown := service.handleEvent(daemonEvent{
		Type: daemonEventRecordPut,
		RecordPut: &daemonRecordPut{
			Zone:  zone.ZonePath("node-b.catofes."),
			Key:   "identity",
			Value: []byte("node-b"),
			Type:  "policy.string",
		},
	})
	if result.Error != nil {
		t.Fatalf("handleEvent(record_put): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	if result.Version != 1 {
		t.Fatalf("version = %d, want 1", result.Version)
	}
	latest := service.State.Common.ReadView()
	if latest.State.Network.Zones["node-b.catofes."].Records["identity"] == nil {
		t.Fatalf("record was not persisted")
	}
}

func TestDaemonEventLoopDispatchesRecordPut(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(2125, 0)
	rt := &AppContext{
		Config: defaultAppConfig(),
		Clock:  func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)

	reply := make(chan daemonEventResult, 1)
	service.Events <- daemonEvent{
		Type: daemonEventRecordPut,
		RecordPut: &daemonRecordPut{
			Zone:  zone.ZonePath("node-b.catofes."),
			Key:   "event-loop-record",
			Value: []byte("store"),
			Type:  "policy.string",
		},
		Reply: reply,
	}
	service.processEvents(context.Background())
	if result := <-reply; result.Error != nil {
		t.Fatalf("processEvents(record_put): %v", result.Error)
	}

	current := service.State.Common.ReadView()
	if got := current.State.Network.Zones["node-b.catofes."].Records["event-loop-record"]; got == nil {
		t.Fatal("common owner missing event-loop record")
	}
}

func TestDaemonEndpointTimerPublishesToCommonOwner(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-b.catofes."
	config.PeerID = string(verified.ManagedZone)
	config.ListenAddr = "198.51.100.20:4242"
	now := time.Unix(2150, 0)
	appConfig := defaultAppConfig()
	appConfig.ListenAddr = config.ListenAddr
	appConfig.AdvertiseAddrs = []string{"198.51.100.20:4242"}
	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)

	if _, err := service.handleEndpointTimerEvent(); err != nil {
		t.Fatalf("handleEndpointTimerEvent: %v", err)
	}
	current := service.State.Common.ReadView()
	if got := current.State.Network.Zones[verified.ManagedZone].Records[gossip.EndpointRecordKeyUDP]; got == nil {
		t.Fatal("common owner missing endpoint record")
	}
}

func TestDaemonIPsecPortRotateEventTriggersDataPlaneReconcile(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-b.catofes."
	config.PeerID = string(verified.ManagedZone)
	now := time.Unix(2000, 0)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	appConfig.IPsec.PortMode = ipsec.PortModeRange
	appConfig.IPsec.PortRange = ipsec.PortRange{From: 30000, To: 30099}
	appConfig.IPsec.PortPreviousGrace = 2 * time.Hour
	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	driver := &countingIPsecDriver{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestIPsecDrivers(service, driver, driver)
	if _, err := service.publishLocalProtocols(); err != nil {
		t.Fatalf("publishLocalProtocols: %v", err)
	}
	published := service.State.Common.ReadView()
	first, err := ipsec.ParsePortRecord(published.State.Network.Zones[published.State.ManagedZone].Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord(first): %v", err)
	}
	driver.listCalls = 0
	reply := make(chan daemonEventResult, 1)
	service.Events <- daemonEvent{Type: daemonEventIPsecPortRotate, Reply: reply}

	syncNow, shutdown, ipsecFlushed, _, firewallFlushed := service.processEvents(context.Background())
	if !syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	if !firewallFlushed || !ipsecFlushed {
		t.Fatalf("firewallFlushed/ipsecFlushed = %v/%v, want true/true", firewallFlushed, ipsecFlushed)
	}
	result := <-reply
	if result.Error != nil {
		t.Fatalf("ipsec port rotate event: %v", result.Error)
	}
	if result.PortRotate == nil || result.PortRotate.CurrentGeneration != first.Current.Generation+1 {
		t.Fatalf("port rotate result = %+v, want generation %d", result.PortRotate, first.Current.Generation+1)
	}
	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want 1", driver.listCalls)
	}
	rotatedState := service.State.Common.ReadView()
	rotated, err := ipsec.ParsePortRecord(rotatedState.State.Network.Zones[rotatedState.State.ManagedZone].Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord(rotated): %v", err)
	}
	if rotated.Current.Generation != first.Current.Generation+1 {
		t.Fatalf("generation = %d, want %d", rotated.Current.Generation, first.Current.Generation+1)
	}
	if len(rotated.Previous) != 1 || rotated.Previous[0].Generation != first.Current.Generation {
		t.Fatalf("previous grace = %+v, want generation %d", rotated.Previous, first.Current.Generation)
	}
}

func TestDaemonConcurrentRecordPutEventsAreSerialized(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(3000, 0)
	rt := &AppContext{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	ctx := t.Context()
	go pumpDaemonEvents(ctx, service)

	const writes = 8
	var wg sync.WaitGroup
	errs := make(chan error, writes)
	for i := range writes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			result := service.enqueueEvent(ctx, daemonEvent{
				Type: daemonEventRecordPut,
				RecordPut: &daemonRecordPut{
					Zone:  zone.ZonePath("node-b.catofes."),
					Key:   "identity",
					Value: []byte{byte('a' + i)},
					Type:  "policy.string",
				},
			})
			errs <- result.Error
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("record_put event failed: %v", err)
		}
	}
	latest := service.State.Common.ReadView()
	record := latest.State.Network.Zones["node-b.catofes."].Records["identity"]
	if record == nil {
		t.Fatal("identity record missing")
	}
	if record.Version != writes {
		t.Fatalf("latest version = %d, want %d", record.Version, writes)
	}
	if history := latest.State.Network.Zones["node-b.catofes."].RecordHistory["identity"]; len(history) != writes-1 {
		t.Fatalf("history length = %d, want %d", len(history), writes-1)
	}
}

func TestDaemonRecordPutKeepsCommittedStateAuthoritativeOverExternalDiskWrite(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-b.catofes."
	config.PeerID = string(verified.ManagedZone)
	now := time.Unix(4000, 0)
	rt := &AppContext{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	seedPartitionedStateDB(t, rt.StatePath, verified, checkpoint, runtime)
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)

	external, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews(external): %v", err)
	}
	externalRecord := &zone.Record{
		Zone: "node-b.catofes.", Key: "external", Value: []byte("kept"), Type: "policy.string", Timestamp: now.Unix(),
	}
	if err := photoncrypto.SignRecord(externalRecord, external.State.IdentityPrivateKey); err != nil {
		t.Fatalf("SignRecord(external): %v", err)
	}
	if err := external.State.Network.Put(externalRecord); err != nil {
		t.Fatalf("Put(external): %v", err)
	}
	replacePersistedCommonForTest(t, rt, external.State)

	result, _, _ := service.handleEvent(daemonEvent{
		Type: daemonEventRecordPut,
		RecordPut: &daemonRecordPut{
			Zone:  zone.ZonePath("node-b.catofes."),
			Key:   "daemon",
			Value: []byte("new"),
			Type:  "policy.string",
		},
	})
	if result.Error != nil {
		t.Fatalf("handleEvent(record_put): %v", result.Error)
	}
	latest := service.State.Common.ReadView()
	records := latest.State.Network.Zones["node-b.catofes."].Records
	if records["external"] != nil {
		t.Fatalf("out-of-band disk record replaced daemon committed authority")
	}
	if records["daemon"] == nil {
		t.Fatalf("daemon record missing")
	}
}

func TestBuildSignedRecordReturnsErrorWithoutLocalSigner(t *testing.T) {
	verified, _, _, _ := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-a.catofes."
	verified.IdentityPrivateKey = nil

	_, err := buildSignedRecordAt(verified.Network, verified.IdentityPrivateKey, "node-b.catofes.", "identity", []byte("node-b"), "policy.string", time.Unix(1, 0))
	if err == nil || !strings.Contains(err.Error(), "no local signing key") {
		t.Fatalf("buildSignedRecordAt error = %v, want missing signer", err)
	}
}

func TestDaemonAdminEventsIssueAcceptAndRevoke(t *testing.T) {
	now := time.Unix(6000, 0)
	rootRT := &AppContext{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "root.db"),
		Clock:     func() time.Time { return now },
	}
	if _, err := initializeRootState(rootRT); err != nil {
		t.Fatalf("initializeRootState: %v", err)
	}
	rootState, rootRuntime, err := loadOfflineOwnerViews(rootRT)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews(root): %v", err)
	}
	service := newTestDaemonFromOwners(rootRT, rootState.State, rootState.Gossip, rootRuntime,
		&appConfig{PeerID: "node-admin", ListenAddr: "127.0.0.1:0"}, time.Second)

	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	catofesRequest := &joinRequest{Version: 1, Zone: "catofes.", PublicKey: catofesPub}
	result, syncNow, shutdown := service.handleEvent(daemonEvent{Type: daemonEventDelegateIssue, JoinRequest: catofesRequest})
	if result.Error != nil {
		t.Fatalf("handleEvent(delegate_issue catofes): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("delegate_issue syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	if result.JoinBundle == nil || result.JoinBundle.Zone != "catofes." {
		t.Fatalf("delegate_issue bundle = %#v", result.JoinBundle)
	}

	catofesKey := &privateKeyFile{Type: "photon.ed25519.private.v1", PublicKey: catofesPub, PrivateKey: catofesPriv}
	service = newTestDaemonFromOwners(rootRT, &corestate.VerifiedState{Network: zone.NewNetworkState()},
		&corestate.GossipCheckpoint{}, &photonlinux.LinuxState{},
		&appConfig{PeerID: "catofes.", ListenAddr: "127.0.0.1:0"}, time.Second)
	result, syncNow, shutdown = service.handleEvent(daemonEvent{
		Type:       daemonEventJoinAccept,
		JoinBundle: result.JoinBundle,
		PrivateKey: catofesKey,
	})
	if result.Error != nil {
		t.Fatalf("handleEvent(join_accept catofes): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("join_accept syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	if result.Zone != "catofes." {
		t.Fatalf("join_accept zone = %s, want catofes.", result.Zone)
	}

	nodePub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-b): %v", err)
	}
	nodeRequest := &joinRequest{Version: 1, Zone: "node-b.catofes.", PublicKey: nodePub}
	result, _, _ = service.handleEvent(daemonEvent{Type: daemonEventDelegateIssue, JoinRequest: nodeRequest})
	if result.Error != nil {
		t.Fatalf("handleEvent(delegate_issue node-b): %v", result.Error)
	}
	if result.JoinBundle == nil || result.JoinBundle.Zone != "node-b.catofes." {
		t.Fatalf("node-b bundle = %#v", result.JoinBundle)
	}

	result, syncNow, shutdown = service.handleEvent(daemonEvent{
		Type:   daemonEventDelegateRevoke,
		Zone:   "node-b.catofes.",
		Reason: "test revoke",
	})
	if result.Error != nil {
		t.Fatalf("handleEvent(delegate_revoke): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("delegate_revoke syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	latest := service.State.Common.ReadView()
	parent := latest.State.Network.Zones[zone.ZonePath("catofes.")]
	if parent == nil || parent.Revocations["node-b.catofes."] == nil {
		t.Fatalf("node-b revocation was not persisted")
	}
	if parent.Delegations["node-b.catofes."] != nil {
		t.Fatalf("node-b delegation still active after revoke")
	}
}

func TestDaemonDelegateIssuePersistsThroughOwnerStore(t *testing.T) {
	now := time.Unix(6100, 0)
	rt := &AppContext{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "root.db"),
		Clock:     func() time.Time { return now },
	}
	if _, err := initializeRootState(rt); err != nil {
		t.Fatalf("initializeRootState: %v", err)
	}
	state, err := openState(rt)
	if err != nil {
		t.Fatalf("openState(root): %v", err)
	}
	rt.Config = &appConfig{PeerID: "node-admin", ListenAddr: "127.0.0.1:0"}
	service := newDaemon(rt, state, time.Second)
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	result, err := service.handleDelegateIssueEvent(&joinRequest{Version: 1, Zone: "catofes.", PublicKey: pub}, nil)
	if err != nil {
		t.Fatalf("handleDelegateIssueEvent: %v", err)
	}
	if result == nil || result.Bundle == nil || result.Bundle.Zone != "catofes." {
		t.Fatalf("delegate issue result = %#v", result)
	}
	if got := state.Common.ReadView().State.Network.Zones[zone.RootZone].Delegations["catofes."]; got == nil {
		t.Fatal("common owner missing catofes delegation")
	}
	if err := state.Close(); err != nil {
		t.Fatalf("close State: %v", err)
	}

	reopened, err := openState(rt)
	if err != nil {
		t.Fatalf("reopen Linux daemon state: %v", err)
	}
	defer reopened.Close()
	if got := reopened.Common.ReadView().State.Network.Zones[zone.RootZone].Delegations["catofes."]; got == nil {
		t.Fatal("reopened common owner missing persisted catofes delegation")
	}
}

func TestDaemonConcurrentAdminAndRecordEventsPreserveState(t *testing.T) {
	now := time.Unix(7000, 0)
	rt := &AppContext{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "catofes.db"),
		Clock:     func() time.Time { return now },
	}
	if _, err := initializeRootState(rt); err != nil {
		t.Fatalf("initializeRootState: %v", err)
	}
	state, runtime, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews(root): %v", err)
	}
	service := newTestDaemonFromOwners(rt, state.State, state.Gossip, runtime,
		&appConfig{PeerID: "zone-catofes-admin", ListenAddr: "127.0.0.1:0"}, time.Second)

	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	catofesIssue, err := service.handleDelegateIssueEvent(&joinRequest{Version: 1, Zone: "catofes.", PublicKey: catofesPub}, nil)
	if err != nil {
		t.Fatalf("handleDelegateIssueEvent(catofes): %v", err)
	}
	service = newTestDaemonFromOwners(rt, &corestate.VerifiedState{Network: zone.NewNetworkState()},
		&corestate.GossipCheckpoint{}, &photonlinux.LinuxState{},
		&appConfig{PeerID: "catofes.", ListenAddr: "127.0.0.1:0"}, time.Second)
	if _, err := service.handleJoinAcceptEvent(catofesIssue.Bundle, &privateKeyFile{Type: "photon.ed25519.private.v1", PublicKey: catofesPub, PrivateKey: catofesPriv}); err != nil {
		t.Fatalf("handleJoinAcceptEvent(catofes): %v", err)
	}

	nodeBPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-b): %v", err)
	}
	if _, err := service.handleDelegateIssueEvent(&joinRequest{Version: 1, Zone: "node-b.catofes.", PublicKey: nodeBPub}, nil); err != nil {
		t.Fatalf("handleDelegateIssueEvent(node-b): %v", err)
	}

	ctx := t.Context()
	go pumpDaemonEvents(ctx, service)

	nodeCPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-c): %v", err)
	}
	events := []daemonEvent{
		{
			Type: daemonEventRecordPut,
			RecordPut: &daemonRecordPut{
				Zone:  "catofes.",
				Key:   "admin-note",
				Value: []byte("kept"),
				Type:  "policy.string",
			},
		},
		{
			Type:        daemonEventDelegateIssue,
			JoinRequest: &joinRequest{Version: 1, Zone: "node-c.catofes.", PublicKey: nodeCPub},
		},
		{
			Type:   daemonEventDelegateRevoke,
			Zone:   "node-b.catofes.",
			Reason: "concurrent test",
		},
	}
	errs := make(chan error, len(events))
	var wg sync.WaitGroup
	for _, event := range events {
		wg.Add(1)
		go func(event daemonEvent) {
			defer wg.Done()
			errs <- service.enqueueEvent(ctx, event).Error
		}(event)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent daemon event failed: %v", err)
		}
	}

	latest := service.State.Common.ReadView()
	catofes := latest.State.Network.Zones[zone.ZonePath("catofes.")]
	if catofes.Records["admin-note"] == nil {
		t.Fatalf("record_put result missing after concurrent admin events")
	}
	if catofes.Delegations["node-c.catofes."] == nil {
		t.Fatalf("delegate_issue result missing after concurrent record_put")
	}
	if catofes.Revocations["node-b.catofes."] == nil {
		t.Fatalf("delegate_revoke result missing after concurrent record_put")
	}
}

func TestDaemonEndpointTimerNoChangeSkipsFlushAndSync(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-b.catofes."
	config.PeerID = string(verified.ManagedZone)
	config.ListenAddr = "198.51.100.20:4242"
	now := time.Unix(2200, 0)
	appConfig := defaultAppConfig()
	appConfig.ListenAddr = config.ListenAddr
	appConfig.AdvertiseAddrs = []string{"198.51.100.20:4242"}
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	oldCollect := collectSyncLocalEndpoints
	collectSyncLocalEndpoints = func(port uint16, _ []string, _ []string, _ time.Duration, _ bool) ([]gossip.LocalEndpoint, error) {
		return []gossip.LocalEndpoint{{IP: net.ParseIP("198.51.100.20"), Port: port, Scope: "global", Source: gossip.SourceAdvertise}}, nil
	}
	t.Cleanup(func() { collectSyncLocalEndpoints = oldCollect })
	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)

	// First publish: records are created, state is flushed.
	if _, err := service.handleEndpointTimerEvent(); err != nil {
		t.Fatalf("first handleEndpointTimerEvent: %v", err)
	}

	// Reset flush tracking and capture the revision after the initial publish.
	var flushed []string
	service.Hooks.OnReconcileFlush = func(layer string) {
		flushed = append(flushed, layer)
	}
	beforeRev := uint64(service.State.Common.VerifiedRevision())

	// Second publish at the same timestamp: nothing changed, so it should not
	// trigger a sync, layer flush, or state-store revision bump.
	result, syncNow, shutdown := service.handleEvent(daemonEvent{Type: daemonEventEndpointTimer})
	if result.Error != nil {
		t.Fatalf("second handleEvent(endpoint): %v", result.Error)
	}
	if syncNow {
		t.Fatalf("syncNow = true, want false on no-op endpoint timer")
	}
	if shutdown {
		t.Fatalf("shutdown = true, want false")
	}
	if len(flushed) != 0 {
		t.Fatalf("layer flushes on no-op endpoint timer: %v", flushed)
	}
	if afterRev := uint64(service.State.Common.VerifiedRevision()); afterRev != beforeRev {
		t.Fatalf("state revision changed on no-op endpoint timer: before=%d after=%d", beforeRev, afterRev)
	}
}

func TestPrepareStartupStateDoesNotPersistDerivedAdmission(t *testing.T) {
	dir := t.TempDir()
	verified, runtime, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", false)
	now := time.Unix(7250, 0)
	rt := &AppContext{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(dir, "photon.db"),
		Clock:     func() time.Time { return now },
	}
	rt.Config.PublishEndpoints = false
	config := &appConfig{PeerID: "node-b.catofes.", ListenAddr: "127.0.0.1:0"}
	service := newTestDaemonFromOwners(
		rt, verified, &corestate.GossipCheckpoint{}, runtime, config, time.Second,
	)
	beforeRev := uint64(service.State.Common.VerifiedRevision())

	changed, err := service.prepareStartupState()
	if err != nil {
		t.Fatalf("prepareStartupState: %v", err)
	}
	if changed {
		t.Fatal("prepareStartupState changed = true for derived admission-only state")
	}
	common := service.State.Common.ReadView()
	rev := uint64(common.Revision)
	if rev != beforeRev {
		t.Fatalf("verified revision = %d, want runtime-only startup to keep %d", rev, beforeRev)
	}
	changed, err = service.prepareStartupState()
	if err != nil {
		t.Fatalf("prepareStartupState(second): %v", err)
	}
	if changed {
		t.Fatal("prepareStartupState(second) changed = true, want no-op")
	}
	if got := uint64(service.State.Common.VerifiedRevision()); got != rev {
		t.Fatalf("state revision after no-op = %d, want %d", got, rev)
	}
}

func TestDaemonEndpointTimerRefreshDueStillTriggersSync(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-b.catofes."
	config.PeerID = string(verified.ManagedZone)
	config.ListenAddr = "198.51.100.20:4242"
	now := time.Unix(1000, 0)
	appConfig := defaultAppConfig()
	appConfig.ListenAddr = config.ListenAddr
	appConfig.AdvertiseAddrs = []string{"198.51.100.20:4242"}
	appConfig.EndpointRefresh = 30 * time.Minute
	appConfig.EndpointTTL = time.Hour
	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)

	// First publish: record is created.
	if _, err := service.handleEndpointTimerEvent(); err != nil {
		t.Fatalf("first handleEndpointTimerEvent: %v", err)
	}
	firstView := service.State.Common.ReadView()
	first := firstView.State.Network.Zones[verified.ManagedZone].Records[gossip.EndpointRecordKeyUDP]
	if first == nil {
		t.Fatal("first endpoint record missing")
	}

	// Second publish before refresh interval: no-op, no sync trigger.
	now = time.Unix(1300, 0)
	result, syncNow, shutdown := service.handleEvent(daemonEvent{Type: daemonEventEndpointTimer})
	if result.Error != nil {
		t.Fatalf("second handleEvent(endpoint): %v", result.Error)
	}
	if shutdown {
		t.Fatalf("shutdown = true, want false")
	}
	if syncNow {
		t.Fatalf("syncNow = true, want false before refresh interval")
	}

	// Third publish after refresh interval: record should be refreshed and sync
	// should be triggered so gossip can propagate the new lease timestamp.
	now = time.Unix(2800, 0)
	result, syncNow, shutdown = service.handleEvent(daemonEvent{Type: daemonEventEndpointTimer})
	if result.Error != nil {
		t.Fatalf("third handleEvent(endpoint): %v", result.Error)
	}
	if shutdown {
		t.Fatalf("shutdown = true, want false")
	}
	if !syncNow {
		t.Fatalf("syncNow = false, want true after refresh interval")
	}
	thirdView := service.State.Common.ReadView()
	third := thirdView.State.Network.Zones[verified.ManagedZone].Records[gossip.EndpointRecordKeyUDP]
	if third.Version != first.Version+1 {
		t.Fatalf("third version = %d, want %d (refreshed)", third.Version, first.Version+1)
	}
	var refreshed gossip.EndpointRecord
	if err := json.Unmarshal(third.Value, &refreshed); err != nil {
		t.Fatalf("Unmarshal(endpoint record): %v", err)
	}
	if refreshed.UpdatedAt != 2800 {
		t.Fatalf("refreshed updated_at = %d, want 2800", refreshed.UpdatedAt)
	}
}
