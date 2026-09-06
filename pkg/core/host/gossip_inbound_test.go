package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

type memoryInboundController struct {
	budget        int
	outbound      []gossip.OutboundMessage
	issues        []GossipExecutionIssue
	controllerErr error
}

func (controller *memoryInboundController) GossipDatagramBudget() int { return controller.budget }

func (controller *memoryInboundController) SendGossip(_ context.Context, outbound gossip.OutboundMessage) error {
	controller.outbound = append(controller.outbound, outbound)
	return controller.controllerErr
}

func TestGossipDriverInboundOwnsObservedCheckpointAndAddressBookPublication(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	path := zone.ZonePath("catofes.")
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	peerPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rootAuthority := &zone.ZoneAuthority{Zone: zone.RootZone, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{
		Key: rootPublic, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermDelegate}}},
	}}}
	peerAuthority := &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: peerPublic}}}
	delegation := &zone.Delegation{ZoneName: path, Scope: zone.DelegationScopeDirectChild, Authority: *peerAuthority}
	if err := photoncrypto.SignDelegation(delegation, zone.RootZone, rootPrivate); err != nil {
		t.Fatal(err)
	}
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	network.Zones[zone.RootZone].Delegations[path] = delegation
	network.Zones[path] = zone.NewZoneState(path, peerAuthority)
	verified := &corestate.VerifiedState{ManagedZone: "local.catofes.", Network: network}
	initial := corestate.View{State: verified, Gossip: &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{}}}
	committed := corestate.View{State: verified, Gossip: &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
		path.String(): {ObservedEndpoint: "198.51.100.10:33434", ObservedUntilUnix: now.Add(time.Minute).Unix()},
	}}}
	state := &memoryGossipStateStore{views: []corestate.View{initial, committed, committed}}
	driver := NewGossipDriver(newFakeClock(now), 2, state, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	transport, _ := bindMemoryGossipTransport(t, driver, path.String())
	packet := &gossip.Packet{
		Addr:    &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 33434},
		Message: &gossip.Message{Type: gossip.MessageFetchCatalogPage, PeerID: path.String(), FetchCatalogPage: &gossip.FetchCatalogPage{}},
	}
	if _, err := driver.HandleGossipHostEvent(context.Background(), GossipPacketReceived{Packet: packet}, now, nil); err != nil {
		t.Fatal(err)
	}
	if len(state.updates) != 1 || !state.updates[0][path.String()].ObservedEndpoint.Set {
		t.Fatalf("checkpoint updates = %#v", state.updates)
	}
	if observed := transport.ObservedPeerAddr(path.String()); observed == nil || observed.String() != packet.Addr.String() {
		t.Fatalf("observed publication = %v", observed)
	}
	diagnostics, ok := driver.Observability.Snapshot(path.String(), now)
	if !ok || diagnostics.ObservedSource != string(gossip.MessageFetchCatalogPage) {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestGossipDriverExecuteGossipPacketActionsPlansPingResponsesAndHint(t *testing.T) {
	driver := NewGossipDriver(newFakeClock(time.Unix(100, 0)), 2, &memoryGossipStateStore{views: []corestate.View{loadedGossipState("local.catofes.")}}, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	controller := &memoryInboundController{}
	packet := &gossip.Packet{Message: &gossip.Message{
		Type:   gossip.MessagePing,
		PeerID: "peer-a",
		Ping:   &gossip.Ping{Summary: &corestate.CatalogSummary{CatalogRoot: []byte("remote"), ZoneCount: 1}},
	}}
	actions := driver.Gossip.PlanInbound(packet)
	if err := driver.executeGossipPacketActions(context.Background(), actions, controller, controller.budget); err != nil {
		t.Fatalf("executeGossipPacketActions: %v", err)
	}
	if len(controller.outbound) != 2 || controller.outbound[0].Message.Type != gossip.MessagePong || controller.outbound[1].Message.Type != gossip.MessageFetchCatalogPage {
		t.Fatalf("outbound = %#v, want PONG then FETCH_CATALOG_PAGE", controller.outbound)
	}
	diagnostics, ok := driver.Observability.Snapshot("peer-a", time.Unix(100, 0))
	if !ok || diagnostics.DatagramStats == nil || diagnostics.DatagramStats.LastCatalogRootHex == "" || diagnostics.HintAccepted != 1 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestGossipDriverPingSummaryShortcutOwnsCheckpointAndSkipsSession(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	peerID := zone.ZonePath("peer.catofes.")
	network, _ := signedDiscoveryNetwork(t, peerID, true, nil, now)
	store := corestate.NewStore(&corestate.VerifiedState{ManagedZone: "local.catofes.", Network: network}, nil)
	driver := NewGossipDriver(newFakeClock(now), 2, store, GossipDriverConfig{PeerID: "local.catofes."})
	defer driver.Stop()
	bindMemoryGossipTransport(t, driver, peerID.String())
	summary := corestate.CatalogSummaryFor(network)

	result, err := driver.HandleGossipHostEvent(context.Background(), GossipPacketReceived{Packet: &gossip.Packet{
		Addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33434},
		Message: &gossip.Message{
			Type: gossip.MessagePing, PeerID: peerID.String(), Ping: &gossip.Ping{Summary: summary},
		},
	}}, now, nil)
	if err != nil || !result.Handled {
		t.Fatalf("HandleGossipHostEvent result/error = %#v/%v", result, err)
	}
	if driver.Gossip.Session(peerID.String()) != nil || driver.PendingEventCount() != 0 {
		t.Fatalf("matching summary created session/event: session=%#v events=%d", driver.Gossip.Session(peerID.String()), driver.PendingEventCount())
	}
	view := store.ReadView()
	peer := view.Gossip.Peers[peerID.String()]
	if view.Revision != 0 || peer.LastSyncUnix != now.Unix() || peer.BackoffUntilUnix != 0 || peer.ObservedEndpoint != "127.0.0.1:33434" {
		t.Fatalf("shortcut view = revision %d peer %#v", view.Revision, peer)
	}
	diagnostics, ok := driver.Observability.Snapshot(peerID.String(), now)
	if !ok || diagnostics.LastHintReason != "ping_summary_match" {
		t.Fatalf("shortcut diagnostics = %#v", diagnostics)
	}
}

func TestGossipDriverPingSummaryMismatchStartsCommonSession(t *testing.T) {
	now := time.Unix(1000, 0)
	store := corestate.NewStore(&corestate.VerifiedState{ManagedZone: "local.catofes.", Network: zone.NewNetworkState()}, nil)
	driver := NewGossipDriver(newFakeClock(now), 2, store, GossipDriverConfig{PeerID: "local.catofes."})
	defer driver.Stop()
	bindMemoryGossipTransport(t, driver, "peer-a")

	_, err := driver.HandleGossipHostEvent(context.Background(), GossipPacketReceived{Packet: &gossip.Packet{Message: &gossip.Message{
		Type: gossip.MessagePing, PeerID: "peer-a", Ping: &gossip.Ping{Summary: &corestate.CatalogSummary{CatalogRoot: []byte("mismatch"), ZoneCount: 99}},
	}}}, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if session := driver.Gossip.Session("peer-a"); session == nil || session.State != gossip.SyncSessionIdle {
		t.Fatalf("mismatch session = %#v", session)
	}
	if driver.PendingEventCount() != 1 {
		t.Fatalf("pending events = %d, want 1", driver.PendingEventCount())
	}
}

func TestGossipDriverAnnounceIsHintAndDefersWhileSessionActive(t *testing.T) {
	now := time.Unix(1000, 0)
	network := zone.NewNetworkState()
	store := corestate.NewStore(&corestate.VerifiedState{ManagedZone: "local.catofes.", Network: network}, nil)
	driver := NewGossipDriver(newFakeClock(now), 2, store, GossipDriverConfig{PeerID: "local.catofes."})
	defer driver.Stop()
	bindMemoryGossipTransport(t, driver, "peer-a")
	rootBefore := corestate.CatalogRoot(corestate.ZoneDigests(network))
	packet := GossipPacketReceived{Packet: &gossip.Packet{Message: &gossip.Message{
		Type: gossip.MessageAnnounce, PeerID: "peer-a",
		Announce: &gossip.Announce{Zones: []corestate.ZoneDigest{{Zone: "remote.catofes.", RootHash: []byte("remote")}}},
	}}}

	if _, err := driver.HandleGossipHostEvent(context.Background(), packet, now, nil); err != nil {
		t.Fatal(err)
	}
	if session := driver.Gossip.Session("peer-a"); session == nil || session.State != gossip.SyncSessionIdle {
		t.Fatalf("announce session = %#v", session)
	}
	if driver.PendingEventCount() != 1 {
		t.Fatalf("announce events = %d, want 1", driver.PendingEventCount())
	}
	if rootAfter := corestate.CatalogRoot(corestate.ZoneDigests(store.ReadView().State.Network)); !bytes.Equal(rootAfter, rootBefore) {
		t.Fatal("announce mutated verified network")
	}
	<-driver.Events()
	if _, err := driver.HandleGossipHostEvent(context.Background(), packet, now, nil); err != nil {
		t.Fatal(err)
	}
	if driver.PendingEventCount() != 0 || !driver.Gossip.PendingHint("peer-a") {
		t.Fatalf("active announce events/pending = %d/%t", driver.PendingEventCount(), driver.Gossip.PendingHint("peer-a"))
	}
}

func TestGossipDriverExecuteGossipPacketActionsBuildsBoundedCatalogPage(t *testing.T) {
	driver := NewGossipDriver(newFakeClock(time.Unix(100, 0)), 1, &memoryGossipStateStore{views: []corestate.View{loadedGossipState("a.catofes.", "b.catofes.")}}, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	controller := &memoryInboundController{
		budget: gossip.DefaultDatagramBudget,
	}
	packet := &gossip.Packet{Message: &gossip.Message{
		Type:             gossip.MessageFetchCatalogPage,
		PeerID:           "peer-a",
		FetchCatalogPage: &gossip.FetchCatalogPage{},
	}}
	if err := driver.executeGossipPacketActions(context.Background(), driver.Gossip.PlanInbound(packet), controller, controller.budget); err != nil {
		t.Fatalf("executeGossipPacketActions: %v", err)
	}
	if len(controller.outbound) != 1 || controller.outbound[0].Message.CatalogPage == nil {
		t.Fatalf("outbound = %#v", controller.outbound)
	}
	if size := gossip.MessageWireSize(controller.outbound[0].Message); size > controller.budget {
		t.Fatalf("catalog page size = %d, limit %d", size, controller.budget)
	}
}

func TestGossipDriverOwnsFetchZoneChunkSendAndNACKRepair(t *testing.T) {
	now := time.Unix(100, 0)
	view := loadedGossipState("remote.catofes.")
	view.State.Network.Zones["remote.catofes."].Records["large"] = &zone.Record{
		Zone: "remote.catofes.", Key: "large", Type: "test.data", Value: make([]byte, 3000), Version: 1,
	}
	driver := NewGossipDriver(newFakeClock(now), 4, &memoryGossipStateStore{views: []corestate.View{view}}, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	controller := &memoryInboundController{budget: gossip.DefaultDatagramBudget}
	fetch := &gossip.Message{
		Type: gossip.MessageFetchZone, PeerID: "peer-a",
		FetchZone: &gossip.FetchZone{Zone: "remote.catofes.", ChunkFallback: true},
	}
	if err := driver.executeGossipPacketActions(context.Background(), driver.Gossip.PlanInbound(&gossip.Packet{Message: fetch}), controller, controller.budget); err != nil {
		t.Fatalf("execute FETCH_ZONE: %v", err)
	}
	diagnostics, ok := driver.Observability.Snapshot("peer-a", now)
	if !ok || diagnostics.DatagramStats == nil || diagnostics.DatagramStats.ChunkFallbacks == 0 || diagnostics.LastResponderKind != "chunk_fallback" {
		t.Fatalf("fetch diagnostics = %#v", diagnostics)
	}
	var firstChunk *gossip.ObjectChunk
	for _, outbound := range controller.outbound {
		if outbound.Message != nil && outbound.Message.ObjectChunk != nil {
			firstChunk = outbound.Message.ObjectChunk
			break
		}
	}
	if firstChunk == nil {
		t.Fatalf("outbound = %#v, want object chunks", controller.outbound)
	}
	controller.outbound = nil
	nack := &gossip.Message{
		Type: gossip.MessageObjectChunkNACK, PeerID: "peer-a",
		ObjectChunkNACK: &gossip.ObjectChunkNACK{TransferID: append([]byte(nil), firstChunk.TransferID...), Missing: []uint16{firstChunk.Index}},
	}
	if err := driver.executeGossipPacketActions(context.Background(), driver.Gossip.PlanInbound(&gossip.Packet{Message: nack}), controller, controller.budget); err != nil {
		t.Fatalf("execute OBJECT_CHUNK_NACK: %v", err)
	}
	diagnostics, _ = driver.Observability.Snapshot("peer-a", now)
	if diagnostics.DatagramStats.ChunkRepairNACKs != 1 || diagnostics.DatagramStats.ChunkRepairChunks != 1 {
		t.Fatalf("NACK diagnostics = %#v", diagnostics.DatagramStats)
	}
	if len(controller.outbound) != 1 || controller.outbound[0].Message.ObjectChunk == nil || controller.outbound[0].Message.ObjectChunk.Index != firstChunk.Index {
		t.Fatalf("repair outbound = %#v", controller.outbound)
	}
}

func TestGossipDriverExecuteGossipPacketActionsRespondsToActivePingWhenQueueFull(t *testing.T) {
	controller := &memoryInboundController{}
	driver := NewGossipDriver(newFakeClock(time.Unix(100, 0)), 1, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, gossipConfigCapturingIssues(GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()}, &controller.issues))
	defer driver.Stop()
	driver.Gossip.NewSession("peer-a")
	if err := driver.PostGossip(&gossip.SyncTimerEvent{PeerID: "occupy"}); err != nil {
		t.Fatalf("fill queue: %v", err)
	}
	packet := &gossip.Packet{Message: &gossip.Message{
		Type:   gossip.MessagePing,
		PeerID: "peer-a",
		Ping:   &gossip.Ping{Summary: &corestate.CatalogSummary{CatalogRoot: []byte("remote")}},
	}}
	if err := driver.executeGossipPacketActions(context.Background(), driver.Gossip.PlanInbound(packet), controller, controller.budget); err != nil {
		t.Fatalf("executeGossipPacketActions: %v", err)
	}
	if len(controller.outbound) == 0 || controller.outbound[0].Message.Type != gossip.MessagePong {
		t.Fatalf("outbound = %#v, want responder PONG", controller.outbound)
	}
	if len(controller.issues) != 1 || !errors.Is(controller.issues[0].Err, ErrGossipEventQueueFull) {
		t.Fatalf("issues = %#v, want queue-full report", controller.issues)
	}
}
