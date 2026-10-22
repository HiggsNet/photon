package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

type lifecycleChunkSender struct {
	chunks    []*gossip.ObjectChunk
	announces int
	failure   error
}

func (s *lifecycleChunkSender) SendGossip(_ context.Context, out gossip.OutboundMessage) error {
	if out.Message.Announce != nil {
		s.announces++
	}
	if out.Message.ObjectChunk != nil {
		s.chunks = append(s.chunks, out.Message.ObjectChunk)
		return s.failure
	}
	return nil
}

func chunkLifecycleDriver(t *testing.T, large bool) (*GossipDriver, *fakeClock, []zone.ZonePath) {
	t.Helper()
	clock := newFakeClock(time.Unix(1000, 0))
	network := zone.NewNetworkState()
	var paths []zone.ZonePath
	for i := range 5 {
		path := zone.ZonePath(fmt.Sprintf("node%d.catofes.", i))
		paths = append(paths, path)
		network.Zones[path] = zone.NewZoneState(path, &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1})
		if large {
			network.Zones[path].Records["large"] = &zone.Record{Zone: path, Key: "large", Value: bytes.Repeat([]byte("x"), 128<<10)}
		}
	}
	store := corestate.NewStore(&corestate.VerifiedState{Network: network}, nil, nil)
	t.Cleanup(store.Close)
	driver := NewGossipDriver(clock, 64, store, GossipDriverConfig{PeerID: "sender.catofes."})
	t.Cleanup(driver.Stop)
	return driver, clock, paths
}

func TestGossipRepeatedFetchReusesTransferAndPreservesRepair(t *testing.T) {
	driver, clock, paths := chunkLifecycleDriver(t, false)
	sender := &lifecycleChunkSender{}
	var transferID []byte
	for range 20 {
		sender.chunks = nil
		if err := driver.respondGossipFetchZone(t.Context(), "receiver", &gossip.FetchZone{Zone: paths[0], ChunkFallback: true}, sender, gossip.DefaultDatagramBudget); err != nil {
			t.Fatal(err)
		}
		if len(sender.chunks) != 1 || len(driver.gossipChunkSends) != 0 {
			t.Fatal("small snapshot did not finish its initial send")
		}
		if transferID == nil {
			transferID = sender.chunks[0].TransferID
		} else if !bytes.Equal(transferID, sender.chunks[0].TransferID) {
			t.Fatal("same snapshot allocated another transfer")
		}
	}
	parts := driver.gossipSentChunks.Repair("receiver", &gossip.ObjectChunkNACK{TransferID: transferID, Missing: []uint16{0}}, clock.Now())
	if len(parts) != 1 {
		t.Fatal("finished send lost its repair cache")
	}
}

func TestGossipDuplicateFetchDoesNotRestartActiveSend(t *testing.T) {
	driver, clock, paths := chunkLifecycleDriver(t, true)
	sender := &lifecycleChunkSender{failure: &gossip.QuotaExceededError{ByteBurst: 1200, ObjectBurst: 128, ByteRate: 1200, ObjectRate: 128, RequestedBytes: 1200, RequestedObjects: 1}}
	request := &gossip.FetchZone{Zone: paths[0], ChunkFallback: true}
	if err := driver.respondGossipFetchZone(t.Context(), "receiver", request, sender, gossip.DefaultDatagramBudget); err != nil {
		t.Fatal(err)
	}
	id := gossipChunkSendTimerID("receiver", sender.chunks[0].TransferID)
	job := driver.gossipChunkSends[id]
	if job == nil {
		t.Fatal("quota pressure did not leave a paced send")
	}
	pending, expires := len(job.indexes), job.expires
	for range 10 {
		if err := driver.respondGossipFetchZone(t.Context(), "receiver", request, sender, gossip.DefaultDatagramBudget); err != nil {
			t.Fatal(err)
		}
	}
	if len(sender.chunks) != 1 || sender.announces != 1 || len(driver.gossipChunkSends) != 1 || len(job.indexes) != pending || !job.expires.Equal(expires) {
		t.Fatal("duplicate request amplified or prolonged the active send")
	}
	clock.Advance(gossip.ChunkTransferTTL)
	if err := driver.flushGossipChunkSend(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if len(driver.gossipChunkSends) != 0 || driver.gossipSentChunks.Chunk("receiver", job.transferID, 0, clock.Now()) != nil {
		t.Fatal("expired active send retained resources")
	}
}

// Exercise the current two-slot FSM, the real responder, chunk encoding and
// receiver assembly. Apply ACKs are synthetic; this tests transport lifecycle.
func TestGossipBoundedSessionReceivesFiveSequentialFallbacks(t *testing.T) {
	driver, clock, paths := chunkLifecycleDriver(t, false)
	session := gossip.NewSyncSession("sender")
	on := func(e gossip.SyncEvent) []gossip.SyncAction {
		t.Helper()
		actions, err := session.OnEvent(e, clock.Now())
		if err != nil {
			t.Fatal(err)
		}
		return actions
	}
	on(&gossip.SyncTimerEvent{PeerID: "sender"})
	work := on(&gossip.PongReceivedEvent{PeerID: "sender", Pong: &gossip.Pong{}, MissingZones: paths})
	completed := 0
	for len(work) > 0 {
		action := work[0]
		work = work[1:]
		switch action := action.(type) {
		case gossip.StartObjectPullAction:
			work = append(work, on(&gossip.ObjectPullResultEvent{PeerID: "sender", Zone: action.Zone, Unreachable: true, Err: errors.New("TCP unavailable")})...)
		case gossip.SendChunkFallbackAction:
			sender := &lifecycleChunkSender{}
			if err := driver.respondGossipFetchZone(t.Context(), "receiver", &gossip.FetchZone{Zone: action.Zone, ChunkFallback: true}, sender, gossip.DefaultDatagramBudget); err != nil {
				t.Fatalf("fallback after %d applies: %v", completed, err)
			}
			assembly := gossip.NewChunkAssemblyStore()
			for _, part := range sender.chunks {
				data, done, err := assembly.Add("sender", part, clock.Now())
				if err != nil {
					t.Fatal(err)
				}
				if done {
					snapshot, err := gossip.DecodeZoneSnapshotObject(data)
					if err != nil {
						t.Fatal(err)
					}
					work = append(work, on(&gossip.ObjectChunkEvent{PeerID: "sender", Zone: action.Zone, Snapshot: snapshot})...)
				}
			}
		case gossip.ApplySnapshotAction:
			completed++
			work = append(work, on(&gossip.SnapshotAppliedEvent{PeerID: "sender", Zone: action.Snapshot.Zone})...)
		}
	}
	if completed != 5 || session.State != gossip.SyncSessionCompleted || len(driver.gossipChunkSends) != 0 {
		t.Fatalf("completed=%d state=%s sends=%d", completed, session.State, len(driver.gossipChunkSends))
	}
}

func TestGossipPermanentChunkSendFailureReleasesCache(t *testing.T) {
	driver, clock, paths := chunkLifecycleDriver(t, false)
	failure := errors.New("permanent write failure")
	sender := &lifecycleChunkSender{failure: failure}
	for _, path := range paths {
		if err := driver.respondGossipFetchZone(t.Context(), "receiver", &gossip.FetchZone{Zone: path, ChunkFallback: true}, sender, gossip.DefaultDatagramBudget); !errors.Is(err, failure) {
			t.Fatalf("send %s: %v", path, err)
		}
		if driver.gossipSentChunks.Chunk("receiver", sender.chunks[len(sender.chunks)-1].TransferID, 0, clock.Now()) != nil {
			t.Fatal("permanent failure retained its cache")
		}
	}
	sender.failure = nil
	if err := driver.respondGossipFetchZone(t.Context(), "receiver", &gossip.FetchZone{Zone: paths[0], ChunkFallback: true}, sender, gossip.DefaultDatagramBudget); err != nil {
		t.Fatal(err)
	}
}

func TestGossipChunkCapacityWarningIsClassifiedThrottledAndHandled(t *testing.T) {
	driver, clock, paths := chunkLifecycleDriver(t, true)
	_, datagram := bindMemoryGossipTransport(t, driver, "receiver")
	var warnings []GossipDriverLog
	driver.gossipConfig.Log = func(event GossipDriverLog) {
		if event.Level == "warn" {
			warnings = append(warnings, event)
		}
	}
	fill := func() {
		t.Helper()
		for _, path := range paths[:4] {
			snapshot, _, err := driver.gossipState.ReadZoneSnapshot(path, clock.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := driver.buildGossipSnapshotChunks("receiver", snapshot, gossip.DefaultDatagramBudget, clock.Now()); err != nil {
				t.Fatal(err)
			}
		}
	}
	fill()
	packet := &gossip.Packet{Message: &gossip.Message{PeerID: "receiver", Type: gossip.MessageFetchZone, FetchZone: &gossip.FetchZone{Zone: paths[4], ChunkFallback: true}}}
	for range 6 {
		if _, err := driver.HandleGossipHostEvent(t.Context(), GossipPacketReceived{Packet: packet}, clock.Now(), nil); err != nil {
			t.Fatalf("capacity error escaped to platform logger: %v", err)
		}
	}
	if len(warnings) != 1 || datagram.writeCount() != 0 {
		t.Fatalf("warnings=%d announces before admission=%d", len(warnings), datagram.writeCount())
	}
	fields := warnings[0].Fields
	if fields["reason"] != "resource_limited" || fields["limit"] != "peer_active_transfers" || fields["zone"] != paths[4] || fields["peer_transfers"] != 4 || fields["cache_bytes"].(int) == 0 || fields["cache_byte_limit"] != gossip.MaxChunkSendCacheBytes {
		t.Fatalf("capacity diagnostics=%v", fields)
	}
	clock.Advance(30 * time.Second)
	fill()
	if _, err := driver.HandleGossipHostEvent(t.Context(), GossipPacketReceived{Packet: packet}, clock.Now(), nil); err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 2 || warnings[1].Fields["suppressed"] != 5 {
		t.Fatalf("suppression summary=%v", warnings)
	}
}
