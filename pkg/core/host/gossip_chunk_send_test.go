package host

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func chunkSendFixture(t *testing.T, quota gossip.QuotaConfig) (*GossipDriver, *fakeClock, *gossip.Transport, *memoryGossipDatagram, []*gossip.ObjectChunk) {
	t.Helper()
	clock := newFakeClock(time.Unix(100, 0))
	driver := NewGossipDriver(clock, 64, nil, GossipDriverConfig{PeerID: "local.catofes."})
	t.Cleanup(driver.Stop)
	datagram := &memoryGossipDatagram{}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33435}
	transport, err := gossip.NewTransport(gossip.Config{PeerID: "local.catofes.", KnownPeers: map[string]*net.UDPAddr{"peer": addr, "other": addr}, Clock: clock.Now, Quotas: gossip.NewPeerQuotas(quota)}, datagram)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.BindGossipTransport(transport); err != nil {
		t.Fatal(err)
	}
	snapshot := &corestate.ZoneSnapshot{Zone: "node.catofes.", Authority: &zone.ZoneAuthority{Zone: "node.catofes.", Epoch: 1, Threshold: 1}, Records: map[string]*zone.Record{"large": {Zone: "node.catofes.", Key: "large", Value: bytes.Repeat([]byte("x"), 128<<10)}}}
	chunks, err := driver.buildGossipSnapshotChunks("peer", snapshot, gossip.DefaultDatagramBudget, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) <= 128 {
		t.Fatalf("fixture has only %d chunks", len(chunks))
	}
	return driver, clock, transport, datagram, chunks
}

func consumeChunkSendTimer(t *testing.T, driver *GossipDriver, clock *fakeClock, after time.Duration) error {
	t.Helper()
	clock.Advance(after)
	event := receiveTimer(t, driver.Completions())
	result, err := driver.HandleGossipHostEvent(context.Background(), event, clock.Now(), nil)
	if !result.Handled {
		t.Fatalf("send timer not handled: %#v", event)
	}
	return err
}

func TestGossipChunkSendResumesAfterQuotaWithoutBlockingOtherPeers(t *testing.T) {
	driver, clock, transport, datagram, chunks := chunkSendFixture(t, gossip.QuotaConfig{ObjectRate: 16, ObjectBurst: 8})
	reply := &net.UDPAddr{IP: net.ParseIP("198.51.100.2"), Port: 45678}
	sender := gossipDriverSender{transport: transport, replyAddr: reply}
	if err := driver.queueGossipChunkSend(context.Background(), "peer", chunks, sender); err != nil {
		t.Fatal(err)
	}
	if datagram.writeCount() != 8 || len(driver.gossipChunkSends) != 1 {
		t.Fatalf("initial burst writes=%d pending=%d", datagram.writeCount(), len(driver.gossipChunkSends))
	}
	if err := transport.Send("other", &gossip.Message{Type: gossip.MessagePing, Ping: &gossip.Ping{}}); err != nil {
		t.Fatalf("other peer blocked: %v", err)
	}
	for i := 0; len(driver.gossipChunkSends) > 0 && i < 200; i++ {
		if err := consumeChunkSendTimer(t, driver, clock, 500*time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	if len(driver.gossipChunkSends) != 0 {
		t.Fatal("paced send did not complete")
	}
	assembly := gossip.NewChunkAssemblyStore()
	complete := false
	indexes := make(map[uint16]bool)
	for i, data := range datagram.writes {
		message, err := gossip.UnmarshalMessage(data)
		if err != nil {
			t.Fatal(err)
		}
		if message.ObjectChunk == nil {
			continue
		}
		if datagram.writeAddrs[i].String() != reply.String() {
			t.Fatalf("continuation lost request reply address: %v", datagram.writeAddrs[i])
		}
		if indexes[message.ObjectChunk.Index] {
			t.Fatal("duplicate initial chunk")
		}
		indexes[message.ObjectChunk.Index] = true
		_, complete, err = assembly.Add("sender", message.ObjectChunk, clock.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	if !complete || len(indexes) != len(chunks) {
		t.Fatalf("incomplete transfer: %d/%d", len(indexes), len(chunks))
	}
	// A full-sized repair request is one control operation, not 128 data
	// objects charged before those same chunks are sent again.
	clock.Advance(time.Second)
	missing := make([]uint16, 128)
	for i := range missing {
		missing[i] = uint16(i)
	}
	nack := &gossip.ObjectChunkNACK{TransferID: chunks[0].TransferID, Missing: missing}
	if err := transport.Send("peer", &gossip.Message{Type: gossip.MessageObjectChunkNACK, ObjectChunkNACK: nack}); err != nil {
		t.Fatalf("bounded NACK exhausted data quota: %v", err)
	}
	start := datagram.writeCount()
	if err := driver.handleGossipObjectChunkNACK(context.Background(), &gossip.Message{PeerID: "peer", ObjectChunkNACK: nack}, sender); err != nil {
		t.Fatal(err)
	}
	for i := 0; len(driver.gossipChunkSends) > 0 && i < 200; i++ {
		if err := consumeChunkSendTimer(t, driver, clock, 500*time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	if datagram.writeCount()-start != 128 || len(driver.gossipChunkSends) != 0 {
		t.Fatalf("repair incomplete: sent=%d pending=%d", datagram.writeCount()-start, len(driver.gossipChunkSends))
	}
	if err := consumeStaleSendTimer(driver, clock); err != nil {
		t.Fatal(err)
	}
}

func TestGossipChunkRepairMergesWithPendingInitialSend(t *testing.T) {
	driver, clock, transport, _, chunks := chunkSendFixture(t, gossip.QuotaConfig{ObjectRate: 16, ObjectBurst: 8})
	sender := gossipDriverSender{transport: transport}
	if err := driver.queueGossipChunkSend(context.Background(), "peer", chunks, sender); err != nil {
		t.Fatal(err)
	}
	nack := &gossip.ObjectChunkNACK{TransferID: chunks[0].TransferID, Missing: []uint16{0, 8, 9}}
	if err := driver.handleGossipObjectChunkNACK(context.Background(), &gossip.Message{PeerID: "peer", ObjectChunkNACK: nack}, sender); err != nil {
		t.Fatal(err)
	}
	for _, job := range driver.gossipChunkSends {
		if len(job.indexes) != len(chunks)-8+1 {
			t.Fatalf("repair duplicated pending parts: %d", len(job.indexes))
		}
	}
	clock.Advance(gossip.ChunkTransferTTL)
}

func consumeStaleSendTimer(driver *GossipDriver, clock *fakeClock) error {
	_, err := driver.HandleGossipHostEvent(context.Background(), TimerFired{ID: TimerID{Namespace: GossipChunkSendNamespace, Owner: "peer", Key: "stale"}, Generation: 1}, clock.Now(), nil)
	return err
}

func TestGossipChunkSendExpiresAndStops(t *testing.T) {
	driver, clock, transport, datagram, chunks := chunkSendFixture(t, gossip.QuotaConfig{ByteRate: 1, ByteBurst: 1200})
	if err := driver.queueGossipChunkSend(context.Background(), "peer", chunks, gossipDriverSender{transport: transport}); err != nil {
		t.Fatal(err)
	}
	writes := datagram.writeCount()
	if err := consumeChunkSendTimer(t, driver, clock, gossip.ChunkTransferTTL); err != nil {
		t.Fatal(err)
	}
	if len(driver.gossipChunkSends) != 0 || datagram.writeCount() != writes {
		t.Fatal("expired transfer resumed")
	}
	driver.Stop()
	if err := driver.queueGossipChunkSend(context.Background(), "peer", chunks, gossipDriverSender{transport: transport}); !errors.Is(err, ErrGossipDriverStopped) {
		t.Fatalf("stopped driver: %v", err)
	}
}

func TestGossipChunkSendRechecksPeerAndClearsPermanentFailure(t *testing.T) {
	driver, clock, transport, _, chunks := chunkSendFixture(t, gossip.QuotaConfig{ObjectRate: 16, ObjectBurst: 8})
	if err := driver.queueGossipChunkSend(context.Background(), "peer", chunks, gossipDriverSender{transport: transport, replyAddr: &net.UDPAddr{IP: net.ParseIP("198.51.100.2"), Port: 1234}}); err != nil {
		t.Fatal(err)
	}
	transport.SetPeers(nil)
	if err := consumeChunkSendTimer(t, driver, clock, time.Second); !errors.Is(err, gossip.ErrUnknownPeer) {
		t.Fatalf("removed peer still sent: %v", err)
	}
	if len(driver.gossipChunkSends) != 0 {
		t.Fatal("failed transfer retained")
	}
}

func TestGossipQuotaWarningIncludesDiagnosticsWithoutDebug(t *testing.T) {
	driver, _, transport, _, chunks := chunkSendFixture(t, gossip.QuotaConfig{ByteBurst: 1})
	var logs []GossipDriverLog
	driver.gossipConfig.Log = func(event GossipDriverLog) { logs = append(logs, event) }
	err := driver.queueGossipChunkSend(context.Background(), "peer", chunks, gossipDriverSender{transport: transport})
	if !errors.Is(err, gossip.ErrQuotaExceeded) || len(logs) != 1 {
		t.Fatalf("error/logs = %v/%d", err, len(logs))
	}
	fields := logs[0].Fields
	if logs[0].Level != "warn" || fields["message_type"] != gossip.MessageObjectChunk || fields["direction"] != "send" || fields["quota_byte_burst"] != int64(1) || fields["quota_requested_bytes"].(int64) <= 1 {
		t.Fatalf("missing diagnostics: %#v", logs[0])
	}
}
