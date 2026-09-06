package host

import (
	"bytes"
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestGossipDriverHandleGossipSessionEventOwnsEngineToActionBridge(t *testing.T) {
	clock := newFakeClock(time.Unix(100, 0))
	controller := &memoryGossipController{}
	driver := NewGossipDriver(clock, 2, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}, trace: &controller.trace}, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	driver.Gossip.NewSession("peer-a")

	result, err := driver.handleGossipSessionEvent(context.Background(), &gossip.SyncTimerEvent{PeerID: "peer-a"}, clock.Now(), controller)
	if err != nil {
		t.Fatal(err)
	}
	if result.OldState != gossip.SyncSessionIdle || result.NewState != gossip.SyncSessionSummarySent || result.Done || result.ProtocolErr != nil {
		t.Fatalf("result = %#v", result)
	}
	if want := []string{"read", "send:ping"}; !reflect.DeepEqual(controller.trace, want) {
		t.Fatalf("trace = %#v, want %#v", controller.trace, want)
	}
}

func TestGossipDriverCatalogSummaryUpdatesSessionObservability(t *testing.T) {
	clock := newFakeClock(time.Unix(100, 0))
	peerID := "peer-a"
	driver := NewGossipDriver(clock, 2, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	bindMemoryGossipTransport(t, driver, peerID)
	driver.Gossip.SetSession(peerID, gossip.NewSyncSession(peerID))

	result, err := driver.HandleGossipHostEvent(context.Background(), GossipEvent{Value: &gossip.CatalogSummaryReceivedEvent{
		PeerID: peerID,
		Summary: &corestate.CatalogSummary{
			CatalogRoot: []byte{0x21, 0x22},
			ZoneCount:   2,
			NextCursor:  "next-page",
		},
	}}, clock.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Session.NetworkChanged {
		t.Fatal("metadata-only catalog event reported a Network change")
	}
	diagnostics, ok := driver.Observability.Snapshot(peerID, clock.Now())
	if !ok || diagnostics.DatagramStats == nil {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	stats := diagnostics.DatagramStats
	if stats.LastCatalogRootHex != "2122" || stats.LastCatalogZoneCount != 2 || stats.LastCatalogCursor != "next-page" {
		t.Fatalf("catalog stats = %#v", stats)
	}
	if diagnostics.ActivePullState != string(gossip.SyncSessionCatalogDiffing) || diagnostics.ActivePullLastEvent != "catalog_summary" {
		t.Fatalf("active pull = state %q event %q", diagnostics.ActivePullState, diagnostics.ActivePullLastEvent)
	}
}

func TestGossipDriverHandleGossipHostEventOwnsPacketTimerAndCompletionDispatch(t *testing.T) {
	clock := newFakeClock(time.Unix(100, 0))
	driver := NewGossipDriver(clock, 4, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	_, datagram := bindMemoryGossipTransport(t, driver, "peer-a", "peer-b")

	packet := &gossip.Packet{Message: &gossip.Message{Type: gossip.MessageFetchCatalogPage, PeerID: "peer-a", FetchCatalogPage: &gossip.FetchCatalogPage{}}}
	packetResult, err := driver.HandleGossipHostEvent(context.Background(), GossipPacketReceived{Packet: packet}, clock.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !packetResult.Handled || packetResult.Session.PeerID != "" || datagram.writeCount() != 1 {
		t.Fatalf("packet result = %#v, writes = %d", packetResult, datagram.writeCount())
	}

	driver.Gossip.NewSession("peer-a")
	if _, err := driver.ApplyGossipTimerAction(gossip.StartTimerAction{PeerID: "peer-a", Kind: gossip.TimerKindRound, Deadline: clock.Now().Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Second)
	timerResult, err := driver.HandleGossipHostEvent(context.Background(), <-driver.Events(), clock.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !timerResult.Handled || timerResult.Session.PeerID != "peer-a" {
		t.Fatalf("timer result = %#v", timerResult)
	}

	driver.Gossip.NewSession("peer-b")
	completion := &gossip.ObjectPullResultEvent{PeerID: "peer-b", Zone: "remote.catofes.", Err: errors.New("pull failed")}
	completionResult, err := driver.HandleGossipHostEvent(context.Background(), GossipEvent{Value: completion}, clock.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !completionResult.Handled || completionResult.Session.PeerID != "peer-b" {
		t.Fatalf("completion result = %#v", completionResult)
	}
}

func TestGossipDriverHandleGossipSessionEventRejectsMissingPeerOrSession(t *testing.T) {
	driver := NewGossipDriver(nil, 1, nil, GossipDriverConfig{})
	defer driver.Stop()
	controller := &memoryGossipController{}
	if _, err := driver.handleGossipSessionEvent(context.Background(), &gossip.PacketEvent{}, time.Now(), controller); !errors.Is(err, ErrGossipEventPeerRequired) {
		t.Fatalf("missing peer error = %v", err)
	}
	if _, err := driver.handleGossipSessionEvent(context.Background(), &gossip.SyncTimerEvent{PeerID: "missing"}, time.Now(), controller); !errors.Is(err, ErrGossipSessionNotFound) {
		t.Fatalf("missing session error = %v", err)
	}
}

func TestGossipDriverRoundTimeoutDropsOnlyItsPeerChunkAssemblies(t *testing.T) {
	driver := NewGossipDriver(nil, 2, &memoryGossipStateStore{views: []corestate.View{loadedGossipState("local.catofes.")}}, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	driver.Gossip.NewSession("peer-a")
	id := []byte("0123456789abcdef")
	first := &gossip.ObjectChunk{TransferID: id, Object: gossip.ObjectPullZone, Zone: "catofes.", ObjectHash: make([]byte, 32), Index: 0, Total: 2, Data: []byte("first")}
	if _, complete, err := driver.AddGossipObjectChunk("peer-a", first, time.Now()); err != nil || complete {
		t.Fatalf("first chunk: complete=%t err=%v", complete, err)
	}
	controller := &memoryGossipController{}
	if _, err := driver.handleGossipSessionEvent(context.Background(), &gossip.RoundTimeoutEvent{PeerID: "peer-a"}, time.Now(), controller); err != nil {
		t.Fatal(err)
	}
	second := &gossip.ObjectChunk{TransferID: id, Object: gossip.ObjectPullZone, Zone: "catofes.", ObjectHash: make([]byte, 32), Index: 1, Total: 2, Data: []byte("second")}
	if _, complete, err := driver.AddGossipObjectChunk("peer-a", second, time.Now()); err != nil || complete {
		t.Fatalf("chunk after timeout: complete=%t err=%v", complete, err)
	}
}

func TestGossipDriverHandleGossipSessionEventOwnsCatalogEnrichment(t *testing.T) {
	driver := NewGossipDriver(nil, 2, &memoryGossipStateStore{views: []corestate.View{loadedManagedGossipState("local.catofes.")}}, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	session := driver.Gossip.NewSession("peer-a")
	session.State = gossip.SyncSessionCatalogDiffing
	controller := &memoryGossipController{}
	event := &gossip.CatalogPageReceivedEvent{PeerID: "peer-a", Page: &corestate.CatalogPage{Entries: []corestate.ZoneDigest{
		{Zone: "local.catofes.", RootHash: []byte("local")},
		{Zone: "remote.catofes.", RootHash: []byte("remote")},
	}}}
	if _, err := driver.handleGossipSessionEvent(context.Background(), event, time.Now(), controller); err != nil {
		t.Fatal(err)
	}
	if len(event.Page.Entries) != 1 || event.Page.Entries[0].Zone != "remote.catofes." {
		t.Fatalf("event=%#v", event)
	}
}

func TestGossipDriverFinishesSessionAndStartsDeferredHint(t *testing.T) {
	now := time.Unix(100, 0)
	driver := NewGossipDriver(newFakeClock(now), 2, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, GossipDriverConfig{PeerID: "local.catofes."})
	defer driver.Stop()
	session := driver.Gossip.NewSession("peer-a")
	session.State = gossip.SyncSessionCompleted
	driver.Gossip.DeferHint("peer-a")

	result := GossipEventResult{PeerID: "peer-a", Done: true}
	driver.finishGossipSession(context.Background(), &result, now, nil)

	if !result.FollowupQueued || driver.Gossip.Session("peer-a") == nil {
		t.Fatalf("result=%#v session=%#v", result, driver.Gossip.Session("peer-a"))
	}
	event, ok := driver.GossipSessionEventFor(<-driver.Events())
	if !ok {
		t.Fatal("deferred hint did not queue a session event")
	}
	if timer, ok := event.(*gossip.SyncTimerEvent); !ok || timer.PeerID != "peer-a" || timer.LocalSummary == nil {
		t.Fatalf("follow-up event = %#v", event)
	}
}

func TestGossipDriverFinishesChangedSessionAndOwnsRelay(t *testing.T) {
	now := time.Unix(100, 0)
	view := loadedManagedGossipState("local.catofes.", "remote.catofes.")
	view.Gossip = &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{"peer-c": {}}}
	state := &memoryGossipStateStore{views: []corestate.View{view, view}}
	driver := NewGossipDriver(newFakeClock(now), 4, state, GossipDriverConfig{
		PeerID: "local.catofes.",
		Discovery: GossipDiscoveryConfig{
			Bootstrap:      map[string]*net.UDPAddr{"peer-c": {IP: net.ParseIP("127.0.0.1"), Port: 33434}},
			BootstrapPeers: []string{"peer-c"},
		},
	})
	defer driver.Stop()
	session := driver.Gossip.NewSession("peer-b")
	session.State = gossip.SyncSessionCompleted
	session.AccumulateNetworkChanged(true)

	result := GossipEventResult{PeerID: "peer-b", Done: true}
	driver.finishGossipSession(context.Background(), &result, now, nil)

	if !result.NetworkChanged || driver.Gossip.Session("peer-b") != nil {
		t.Fatalf("result=%#v source_session=%#v", result, driver.Gossip.Session("peer-b"))
	}
	event, ok := driver.GossipSessionEventFor(<-driver.Events())
	if !ok {
		t.Fatal("relay did not queue a session event")
	}
	timer, ok := event.(*gossip.SyncTimerEvent)
	if !ok || timer.PeerID != "peer-c" || timer.LocalSummary == nil {
		t.Fatalf("relay event = %#v", event)
	}
	wantRoot := corestate.CatalogRoot(corestate.ZoneDigests(view.State.Network))
	if !bytes.Equal(timer.LocalSummary.CatalogRoot, wantRoot) {
		t.Fatalf("relay root = %x, want %x", timer.LocalSummary.CatalogRoot, wantRoot)
	}
	if len(state.updates) != 1 || !state.updates[0]["peer-c"].LastRelayRootHex.Set {
		t.Fatalf("relay checkpoint updates = %#v", state.updates)
	}
	diagnostics, ok := driver.Observability.Snapshot("peer-c", now)
	if !ok || diagnostics.LastUpdateSource != "peer-b" || diagnostics.LastRelaySuppression != "" {
		t.Fatalf("relay diagnostics = %#v", diagnostics)
	}
}

func TestGossipDriverSchedulerDeliversChunkRepairThroughCommonEventBridge(t *testing.T) {
	clock := newFakeClock(time.Unix(100, 0))
	driver := NewGossipDriver(clock, 2, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	driver.Gossip.NewSession("peer-a")
	id := []byte("0123456789abcdef")
	chunk := &gossip.ObjectChunk{TransferID: id, Object: gossip.ObjectPullZone, Zone: "catofes.", ObjectHash: make([]byte, 32), Index: 0, Total: 2, Data: []byte("partial")}
	if _, complete, err := driver.AddGossipObjectChunk("peer-a", chunk, clock.Now()); err != nil || complete {
		t.Fatalf("add chunk: complete=%t err=%v", complete, err)
	}
	if err := driver.ScheduleGossipChunkRepair("peer-a", chunk); err != nil {
		t.Fatal(err)
	}
	clock.Advance(gossip.ChunkRepairQuiet)
	hostEvent := <-driver.Events()
	event, ok := driver.GossipSessionEventFor(hostEvent)
	if !ok {
		t.Fatalf("host event %#v was not a gossip event", hostEvent)
	}
	controller := &memoryGossipController{}
	if _, err := driver.handleGossipSessionEvent(context.Background(), event, clock.Now(), controller); err != nil {
		t.Fatal(err)
	}
	if want := []string{"send:object_chunk_nack"}; !reflect.DeepEqual(controller.trace, want) {
		t.Fatalf("trace = %#v, want %#v", controller.trace, want)
	}
}
