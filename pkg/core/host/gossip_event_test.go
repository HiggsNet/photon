package host

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestGossipDriverHandleGossipSessionEventOwnsEngineToActionBridge(t *testing.T) {
	clock := newFakeClock(time.Unix(100, 0))
	controller := &memoryGossipController{}
	driver := NewGossipDriver(clock, 2, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}, trace: &controller.trace}, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	driver.Gossip.NewSession("peer-a")

	result, _, err := driver.handleGossipSessionEvent(context.Background(), &gossip.SyncTimerEvent{PeerID: "peer-a"}, clock.Now(), controller)
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
		},
	}}, clock.Now())
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
	if stats.LastCatalogRootHex != "2122" || stats.LastCatalogZoneCount != 2 {
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
	packetResult, err := driver.HandleGossipHostEvent(context.Background(), GossipPacketReceived{Packet: packet}, clock.Now())
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
	timerResult, err := driver.HandleGossipHostEvent(context.Background(), <-driver.Completions(), clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !timerResult.Handled || timerResult.Session.PeerID != "peer-a" {
		t.Fatalf("timer result = %#v", timerResult)
	}

	driver.Gossip.NewSession("peer-b")
	completion := &gossip.ObjectPullResultEvent{PeerID: "peer-b", Zone: "remote.catofes.", Err: errors.New("pull failed")}
	completionResult, err := driver.HandleGossipHostEvent(context.Background(), GossipEvent{Value: completion}, clock.Now())
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
	if _, _, err := driver.handleGossipSessionEvent(context.Background(), &gossip.PacketEvent{}, time.Now(), controller); !errors.Is(err, ErrGossipEventPeerRequired) {
		t.Fatalf("missing peer error = %v", err)
	}
	if _, _, err := driver.handleGossipSessionEvent(context.Background(), &gossip.SyncTimerEvent{PeerID: "missing"}, time.Now(), controller); !errors.Is(err, errGossipSessionNotFound) {
		t.Fatalf("missing session error = %v", err)
	}
}

func TestGossipDriverDrainsQueuedRepliesAfterSessionCompletes(t *testing.T) {
	now := time.Unix(100, 0)
	driver := NewGossipDriver(newFakeClock(now), 4, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	_, datagram := bindMemoryGossipTransport(t, driver, "peer-a")
	driver.Gossip.NewSession("peer-a")
	ctx := context.Background()
	if _, err := driver.HandleGossipHostEvent(ctx, GossipEvent{Value: &gossip.SyncTimerEvent{PeerID: "peer-a"}}, now); err != nil {
		t.Fatal(err)
	}
	// Both packets arrive while the session exists. The first queued reply
	// completes it, leaving the second reply queued for a removed session.
	for i := 0; i < 2; i++ {
		packet := GossipPacketReceived{Packet: &gossip.Packet{Message: &gossip.Message{
			Type: gossip.MessagePong, PeerID: "peer-a", Pong: &gossip.Pong{Summary: corestate.CatalogSummaryFor(nil)},
		}}}
		driver.events <- packet
	}
	result, err := driver.HandleGossipHostEvent(ctx, <-driver.Events(), now)
	if err != nil || !result.Session.Done || driver.Gossip.Session("peer-a") != nil {
		t.Fatalf("completion = %#v, error = %v", result, err)
	}
	writes := datagram.writeCount()
	result, err = driver.HandleGossipHostEvent(ctx, <-driver.Events(), now)
	if err != nil || !result.Handled || result.Session != (GossipEventResult{}) {
		t.Fatalf("late reply = %#v, error = %v", result, err)
	}
	if driver.PendingEventCount() != 0 || driver.Gossip.Session("peer-a") != nil || datagram.writeCount() != writes {
		t.Fatal("late reply produced more gossip work")
	}
	// Draining a stale reply must not disable the read-only responder.
	packet := GossipPacketReceived{Packet: &gossip.Packet{Message: &gossip.Message{
		Type: gossip.MessageFetchCatalogPage, PeerID: "peer-a", FetchCatalogPage: &gossip.FetchCatalogPage{},
	}}}
	if _, err := driver.HandleGossipHostEvent(ctx, packet, now); err != nil {
		t.Fatal(err)
	}
	if datagram.writeCount() != writes+1 {
		t.Fatal("responder did not send a catalog page after session completion")
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
	if _, _, err := driver.handleGossipSessionEvent(context.Background(), &gossip.RoundTimeoutEvent{PeerID: "peer-a"}, time.Now(), controller); err != nil {
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
	if _, _, err := driver.handleGossipSessionEvent(context.Background(), event, time.Now(), controller); err != nil {
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
	driver.finishGossipSession(context.Background(), &result, now)

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
	writes := 0
	common := corestate.NewStoreWithCheckpoint(view.State, view.Gossip, nil,
		func(context.Context, map[string]*corestate.PeerCheckpoint, corestate.VerifiedRevision) error {
			writes++
			return nil
		})
	state := &countingCheckpointStore{GossipStateStore: common}
	driver := NewGossipDriver(newFakeClock(now), 2, state, GossipDriverConfig{
		PeerID: "local.catofes.",
		Discovery: GossipDiscoveryConfig{
			BootstrapPeers: []string{"peer-c", "peer-d", "peer-e"},
		},
	})
	defer driver.Stop()
	session := driver.Gossip.NewSession("peer-b")
	session.State = gossip.SyncSessionCompleted
	session.AccumulateNetworkChanged(true)

	result := GossipEventResult{PeerID: "peer-b", Done: true}
	driver.finishGossipSession(context.Background(), &result, now)

	if !result.NetworkChanged || driver.Gossip.Session("peer-b") != nil {
		t.Fatalf("result=%#v source_session=%#v", result, driver.Gossip.Session("peer-b"))
	}
	wantRoot := corestate.CatalogRoot(corestate.ZoneDigests(view.State.Network))
	if state.updates != 1 || writes != 0 {
		t.Fatalf("relay state updates = %d, writes = %d, want 1/0", state.updates, writes)
	}
	livePeers := common.PeerCheckpoints([]string{"peer-c", "peer-d", "peer-e"})
	for _, peerID := range []string{"peer-c", "peer-d"} {
		select {
		case queued := <-driver.Events():
			event, _ := driver.GossipSessionEventFor(queued)
			timer, ok := event.(*gossip.SyncTimerEvent)
			if !ok || timer.PeerID != peerID || timer.LocalSummary == nil || !bytes.Equal(timer.LocalSummary.CatalogRoot, wantRoot) {
				t.Fatalf("relay event for %s = %#v", peerID, event)
			}
		default:
			t.Fatalf("missing relay event for %s", peerID)
		}
		peer := livePeers[peerID]
		if peer.LastRelayCatalogRootHex != hex.EncodeToString(wantRoot) || peer.LastRelayUnix != now.Unix() {
			t.Fatalf("relay state for %s = %#v", peerID, peer)
		}
		diagnostics, ok := driver.Observability.Snapshot(peerID, now)
		if !ok || diagnostics.LastUpdateSource != "peer-b" || diagnostics.LastRelaySuppression != "" {
			t.Fatalf("relay diagnostics for %s = %#v", peerID, diagnostics)
		}
	}
	if _, recorded := livePeers["peer-e"]; recorded || driver.Gossip.Session("peer-e") != nil {
		t.Fatal("relay state was retained for the dropped event")
	}
	data, err := json.Marshal(livePeers["peer-c"])
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{}" {
		t.Fatalf("relay-only state appeared in the persistent JSON: %s", data)
	}
}

func TestGossipLocalRelaySkipsBackoffAndCountsOnlyQueuedPeers(t *testing.T) {
	now := time.Unix(100, 0)
	view := loadedManagedGossipState("local.catofes.", "remote.catofes.")
	view.Gossip = &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
		"offline.": {BackoffUntilUnix: now.Add(time.Minute).Unix()},
	}}
	common := corestate.NewStoreWithCheckpoint(view.State, view.Gossip, nil, nil)
	peers := []string{"offline."}
	for i := range 2 * DefaultGossipRelayFanout {
		peers = append(peers, fmt.Sprintf("peer-%d.", i))
	}
	driver := NewGossipDriver(newFakeClock(now), len(peers), common, GossipDriverConfig{
		PeerID: "local.catofes.", Discovery: GossipDiscoveryConfig{BootstrapPeers: peers},
	})
	defer driver.Stop()
	for _, peerID := range peers[1:DefaultGossipRelayFanout] {
		driver.Gossip.NewSession(peerID).State = gossip.SyncSessionSummarySent
	}

	driver.RelayGossipUpdate(t.Context(), "", now)
	if got := len(driver.Events()); got != DefaultGossipRelayFanout {
		t.Fatalf("queued %d relay events, want %d", got, DefaultGossipRelayFanout)
	}
	for _, wantPeer := range peers[DefaultGossipRelayFanout : 2*DefaultGossipRelayFanout] {
		event := (<-driver.Events()).(GossipEvent).Value
		if got := gossip.SyncEventPeerID(event); got != wantPeer {
			t.Fatalf("queued relay for %s, want %s", got, wantPeer)
		}
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
	hostEvent := <-driver.Completions()
	event, ok := driver.GossipSessionEventFor(hostEvent)
	if !ok {
		t.Fatalf("host event %#v was not a gossip event", hostEvent)
	}
	controller := &memoryGossipController{}
	if _, _, err := driver.handleGossipSessionEvent(context.Background(), event, clock.Now(), controller); err != nil {
		t.Fatal(err)
	}
	if want := []string{"send:object_chunk_nack"}; !reflect.DeepEqual(controller.trace, want) {
		t.Fatalf("trace = %#v, want %#v", controller.trace, want)
	}
}

func TestGossipDriverTimeoutAddressHealth(t *testing.T) {
	for _, state := range []gossip.SyncSessionState{gossip.SyncSessionSummarySent, gossip.SyncSessionCatalogDiffing, gossip.SyncSessionObjectPulling, gossip.SyncSessionChunkFallback} {
		t.Run(string(state), func(t *testing.T) {
			clock := newFakeClock(time.Unix(100, 0))
			driver := NewGossipDriver(clock, 4, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
			defer driver.Stop()
			transport, _ := bindMemoryGossipTransport(t, driver, "peer-a")
			driver.Gossip.NewSession("peer-a")
			if _, err := driver.HandleGossipHostEvent(context.Background(), GossipEvent{Value: &gossip.SyncTimerEvent{PeerID: "peer-a"}}, clock.Now()); err != nil {
				t.Fatal(err)
			}
			addr := transport.LastSendAddr("peer-a")
			if addr == nil {
				t.Fatal("initial ping did not record address")
			}
			driver.Gossip.Session("peer-a").State = state
			result, err := driver.HandleGossipHostEvent(context.Background(), GossipEvent{Value: &gossip.RoundTimeoutEvent{PeerID: "peer-a"}}, clock.Now())
			if err != nil || !result.Session.Done {
				t.Fatalf("result = %#v, error = %v", result, err)
			}
			want := 0
			if state == gossip.SyncSessionSummarySent || state == gossip.SyncSessionCatalogDiffing {
				want = 1
			}
			if got := transport.AddrFailureCount("peer-a", addr); got != want {
				t.Fatalf("failures = %d, want %d", got, want)
			}
		})
	}
}

func TestGossipBackoffTracksConsecutivePingTimeouts(t *testing.T) {
	const peerID = "peer-a."
	now := time.Unix(1000, 0)
	for _, bootstrap := range []bool{false, true} {
		store := corestate.NewStore(loadedGossipState().State, nil, nil)
		config := GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()}
		if bootstrap {
			config.Discovery.BootstrapPeers = []string{peerID}
		}
		driver := NewGossipDriver(newFakeClock(now), 4, store, config)
		t.Cleanup(driver.Stop)
		bindMemoryGossipTransport(t, driver, peerID)
		timeout := func(state gossip.SyncSessionState, seconds int64) {
			t.Helper()
			driver.Gossip.NewSession(peerID).State = state
			result, err := driver.HandleGossipHostEvent(t.Context(), GossipEvent{Value: &gossip.RoundTimeoutEvent{PeerID: peerID}}, now)
			peer := store.PeerCheckpoints([]string{peerID})[peerID]
			if err != nil || !result.Session.Done || peer.BackoffUntilUnix-now.Unix() != seconds {
				t.Fatalf("bootstrap=%v, %s: result=%+v, err=%v, backoff=%ds, want %ds", bootstrap, state, result, err, peer.BackoffUntilUnix-now.Unix(), seconds)
			}
		}
		for _, seconds := range []int64{2, 4, 8, 16, 32, 64, 128, 256, 300, 300} {
			if bootstrap {
				seconds = min(seconds, 64)
			}
			timeout(gossip.SyncSessionSummarySent, seconds)
		}
		if !bootstrap {
			timeout(gossip.SyncSessionObjectPulling, 2)
			timeout(gossip.SyncSessionSummarySent, 2)
		}
	}
}

func TestGossipHostRejectsRevokedPeerBeforeDiscoveryRefresh(t *testing.T) {
	const peer = zone.ZonePath("peer.")
	now := time.Unix(1000, 0)
	clock := newFakeClock(now)
	verified := loadedGossipState(zone.RootZone).State
	verified.Network.Zones[zone.RootZone].Revocations[peer] = &zone.DelegationRevocation{
		ParentZone: zone.RootZone, ChildZone: peer, RevokedAt: now.Add(time.Second).Unix(),
	}
	store := corestate.NewStore(verified, nil, nil)
	driver := NewGossipDriver(clock, 4, store, GossipDriverConfig{PeerID: "local."})
	t.Cleanup(driver.Stop)
	transport, datagram := bindMemoryGossipTransport(t, driver, peer.String())
	if err := driver.RefreshGossipDiscovery(now, transport); err != nil {
		t.Fatal(err)
	}
	if err := driver.StartGossipSession(peer.String(), "test"); err != nil {
		t.Fatal(err)
	}
	var queued Event
	select {
	case queued = <-driver.Events():
	default:
		t.Fatal("expected a session to be queued before revocation")
	}
	clock.Advance(time.Second)
	ping := GossipPacketReceived{Packet: &gossip.Packet{
		Addr:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 33434},
		Message: &gossip.Message{PeerID: peer.String(), Type: gossip.MessagePing, Ping: &gossip.Ping{}},
	}}
	for _, event := range []Event{ping, queued} {
		if result, err := driver.HandleGossipHostEvent(t.Context(), event, clock.Now()); err != nil || !result.Handled {
			t.Fatalf("result=%+v, error=%v", result, err)
		}
	}
	if datagram.writeCount() != 0 || driver.Gossip.Session(peer.String()) != nil {
		t.Fatal("revoked peer received traffic or retained its queued session")
	}
}

func TestGossipDriverPeriodicSyncRequiresTransport(t *testing.T) {
	driver := NewGossipDriver(newFakeClock(time.Unix(100, 0)), 4, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, GossipDriverConfig{})
	defer driver.Stop()
	if _, err := driver.SyncGossipPeers(context.Background(), time.Unix(100, 0), true); !errors.Is(err, ErrGossipTransportRequired) {
		t.Fatalf("error = %v", err)
	}
}

func TestGossipDriverPeriodicSyncPreservesActiveSessionsWithFullQueue(t *testing.T) {
	now := time.Unix(100, 0)
	driver := NewGossipDriver(newFakeClock(now), 1, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, GossipDriverConfig{
		PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits(),
		Discovery: GossipDiscoveryConfig{Bootstrap: map[string]*net.UDPAddr{"peer-a": {IP: net.ParseIP("127.0.0.1"), Port: 33434}}},
	})
	defer driver.Stop()
	bindMemoryGossipTransport(t, driver, "peer-a")
	for driver.PostGossip(&gossip.SyncTimerEvent{PeerID: "queued"}) == nil {
	}
	if _, err := driver.SyncGossipPeers(context.Background(), now, false); err != nil {
		t.Fatal(err)
	}
	session := driver.Gossip.Session("peer-a")
	if session == nil || session.State != gossip.SyncSessionSummarySent {
		t.Fatalf("session = %#v", session)
	}
	if _, err := driver.SyncGossipPeers(context.Background(), now, true); err != nil {
		t.Fatal(err)
	}
	if driver.Gossip.Session("peer-a") != session {
		t.Fatal("force replaced active session")
	}
}
