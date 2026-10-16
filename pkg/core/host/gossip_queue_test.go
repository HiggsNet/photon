package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestGossipQueueFullInputCannotDropAcceptedPong(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	now := time.Unix(1000, 0)
	driver := NewGossipDriver(newFakeClock(now), DefaultEventBuffer,
		&memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, GossipDriverConfig{})
	defer driver.Stop()
	bindMemoryGossipTransport(t, driver, "peer-a")
	driver.Gossip.NewSession("peer-a").State = gossip.SyncSessionSummarySent
	packet := GossipPacketReceived{Packet: &gossip.Packet{Message: &gossip.Message{
		Type: gossip.MessagePong, PeerID: "peer-a", Pong: &gossip.Pong{},
	}}}
	for range DefaultEventBuffer {
		driver.events <- packet
	}
	// Reproduce even the old blocking receiver refilling the just-freed slot.
	started, done := make(chan struct{}), make(chan struct{})
	go func() {
		close(started)
		driver.events <- packet
		close(done)
	}()
	<-started
	runtime.Gosched()
	event := <-driver.Events()
	if len(driver.events) != DefaultEventBuffer {
		t.Fatal("waiting producer did not refill input queue")
	}
	<-done
	result, err := driver.HandleGossipHostEvent(t.Context(), event, now, nil)
	if err != nil || !result.Session.Done || driver.Gossip.HasActiveSession("peer-a") {
		t.Fatalf("PONG result/error = %#v/%v", result, err)
	}
	if len(driver.events) != DefaultEventBuffer || driver.internalPending.Load() != 0 {
		t.Fatal("processing the PONG consumed another input or stranded its result")
	}
}

func TestGossipQueueSnapshotResultSurvivesFullQueues(t *testing.T) {
	for _, failure := range []string{"", "zone", "commit"} {
		t.Run(failure, func(t *testing.T) {
			now := time.Unix(1000, 0)
			applyErr := errors.New("apply failed")
			store := &memoryGossipStateStore{
				views: []corestate.View{loadedManagedGossipState("local.catofes.")},
				applyResult: corestate.RemoteBatchResult{
					CommitResult: corestate.CommitResult{Committed: true, Changes: corestate.ChangeSet{NetworkChanged: failure == ""}},
					Outcomes:     []corestate.RemoteApplyOutcome{{Zone: "remote.catofes."}},
				},
			}
			if failure == "zone" {
				store.applyResult.Outcomes[0].Err = applyErr
			}
			if failure == "commit" {
				store.applyErr = applyErr
			}
			driver := NewGossipDriver(newFakeClock(now), 1, store, GossipDriverConfig{})
			defer driver.Stop()
			bindMemoryGossipTransport(t, driver, "peer-a")
			session := driver.Gossip.NewSession("peer-a")
			_, _ = session.OnEvent(&gossip.SyncTimerEvent{PeerID: "peer-a"}, now)
			_, _ = session.OnEvent(&gossip.PongReceivedEvent{PeerID: "peer-a", Pong: &gossip.Pong{}, MissingZones: []zone.ZonePath{"remote.catofes."}}, now)
			driver.events <- GossipPacketReceived{}
			for range cap(driver.completions) {
				driver.completions <- TimerFired{}
			}
			result, err := driver.HandleGossipHostEvent(t.Context(), GossipEvent{Value: &gossip.ObjectPullResultEvent{
				PeerID: "peer-a", Zone: "remote.catofes.", Snapshot: &corestate.ZoneSnapshot{Zone: "remote.catofes."},
			}}, now, nil)
			if err != nil || !result.Session.Done || driver.Gossip.Session("peer-a") != nil || len(store.batch) != 1 {
				t.Fatalf("apply result/error/batch = %#v/%v/%d", result, err, len(store.batch))
			}
			want := gossip.SyncSessionCompleted
			if failure != "" {
				want = gossip.SyncSessionFailed
			}
			if result.Session.NewState != want || result.NetworkChanged != (failure == "") {
				t.Fatalf("terminal result = %#v, want state %s", result, want)
			}
			if driver.internalPending.Load() != 0 || len(driver.events) != 1 || len(driver.completions) != cap(driver.completions) {
				t.Fatal("snapshot result depended on external queue capacity")
			}
		})
	}
}

func TestGossipQueueInternalBudgetYieldsAndRetainsAllResults(t *testing.T) {
	now := time.Unix(1000, 0)
	driver := NewGossipDriver(newFakeClock(now), 1,
		&memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, GossipDriverConfig{})
	defer driver.Stop()
	bindMemoryGossipTransport(t, driver, "peer-a", "peer-b")
	session := driver.Gossip.NewSession("peer-a")
	_, _ = session.OnEvent(&gossip.SyncTimerEvent{PeerID: "peer-a"}, now)
	missing := make([]zone.ZonePath, 40)
	for index := range missing {
		missing[index] = zone.ZonePath(fmt.Sprintf("node-%d.catofes.", index))
	}
	driver.events <- GossipPacketReceived{}
	// Workers are deliberately not started: every submit produces a local
	// failure result, which must reach the FSM despite a full input queue.
	_, err := driver.HandleGossipHostEvent(t.Context(), GossipEvent{Value: &gossip.PongReceivedEvent{
		PeerID: "peer-a", Pong: &gossip.Pong{}, MissingZones: missing,
	}}, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	remaining := len(missing) - (maxGossipEventBatch - 1)
	if session.InflightCount() != remaining || driver.internalPending.Load() != int64(remaining) {
		t.Fatalf("inflight/pending = %d/%d, want %d", session.InflightCount(), driver.internalPending.Load(), remaining)
	}
	if driver.Events() != nil {
		t.Fatal("new inputs must not grow an unfinished internal batch")
	}
	// Reliable completions remain consumable while the batch is paused. This
	// also checks aggregate changes aren't hidden by the last internal result.
	other := driver.Gossip.NewSession("peer-b")
	other.State = gossip.SyncSessionSummarySent
	other.AccumulateNetworkChanged(true)
	driver.completions <- GossipEvent{Value: &gossip.PongReceivedEvent{PeerID: "peer-b", Pong: &gossip.Pong{}}}
	result, err := driver.HandleGossipHostEvent(t.Context(), <-driver.Completions(), now, nil)
	if err != nil || !result.NetworkChanged || driver.Gossip.Session("peer-b") != nil || result.Session.PeerID != "peer-a" {
		t.Fatalf("interleaved completion result/error = %#v/%v", result, err)
	}
	for driver.internalPending.Load() > 0 {
		select {
		case event := <-driver.Continuations():
			if _, err := driver.HandleGossipHostEvent(t.Context(), event, now, nil); err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("internal batch did not wake the consumer")
		}
	}
	if session.InflightCount() != 0 || session.State != gossip.SyncSessionChunkFallback || driver.Events() == nil || len(driver.events) != 1 {
		t.Fatalf("final state/inflight = %s/%d", session.State, session.InflightCount())
	}
}

func TestGossipQueueTimerDeliveryIndependentOfFullInput(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	driver := NewGossipDriver(clock, 1, nil, GossipDriverConfig{})
	defer driver.Stop()
	driver.events <- GossipPacketReceived{}
	ids := make([]TimerID, 2*DefaultGossipCompletionBuffer)
	for index := range ids {
		ids[index] = TimerID{Namespace: GossipTimerNamespace, Owner: fmt.Sprintf("peer-%d", index), Key: gossip.TimerKindRound}
		if _, err := driver.scheduler.Schedule(ids[index], clock.Now()); err != nil {
			t.Fatal(err)
		}
	}
	// Cancel after delivery, before the consumer accepts the generation.
	first := receiveTimer(t, driver.Completions())
	driver.scheduler.Cancel(ids[0])
	if first.ID != ids[0] || driver.scheduler.Accept(first) {
		t.Fatalf("cancelled timer accepted: %#v", first)
	}
	for index := 1; index < len(ids); index++ {
		fired := receiveTimer(t, driver.Completions())
		if fired.ID != ids[index] || !driver.scheduler.Accept(fired) {
			t.Fatalf("timer %d = %#v", index, fired)
		}
	}
	if len(driver.events) != 1 {
		t.Fatal("timer delivery depended on consuming an input")
	}
}

func TestGossipQueueDatagramOverflowDropsAndContinues(t *testing.T) {
	warnings := make(chan GossipDriverLog, 8)
	driver := NewGossipDriver(nil, 1, nil, GossipDriverConfig{Log: func(log GossipDriverLog) { warnings <- log }})
	defer driver.Stop()
	driver.events <- GossipPacketReceived{}
	receiver := newFakeDatagramReceiver()
	receivedAll := make(chan struct{})
	finished := errors.New("finished burst")
	if err := driver.startGossipDatagramReceiver(t.Context(), receiver, func(err error) {
		if errors.Is(err, finished) {
			close(receivedAll)
		}
	}); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		receiver.results <- datagramReceiveResult{packet: &gossip.Packet{Message: &gossip.Message{Type: gossip.MessagePing}}}
	}
	receiver.results <- datagramReceiveResult{err: finished}
	select {
	case <-receivedAll:
	case <-time.After(time.Second):
		t.Fatal("receiver blocked instead of dropping excess inputs")
	}
	if driver.datagramDrops.Load() != 5 || len(driver.events) != 1 || len(warnings) != 1 {
		t.Fatalf("dropped/queued/warnings = %d/%d/%d", driver.datagramDrops.Load(), len(driver.events), len(warnings))
	}
	if warning := <-warnings; warning.Fields["reason"] != "input_queue_full" {
		t.Fatalf("drop warning = %#v", warning)
	}
	<-driver.Events()
	packet := &gossip.Packet{Message: &gossip.Message{Type: gossip.MessagePong}}
	receiver.results <- datagramReceiveResult{packet: packet}
	select {
	case event := <-driver.Events():
		if event.(GossipPacketReceived).Packet != packet {
			t.Fatal("receiver did not resume delivery")
		}
	case <-time.After(time.Second):
		t.Fatal("receiver stopped after overflow")
	}
}

func TestGossipQueueWaitingIODoesNotPauseInputs(t *testing.T) {
	driver := NewGossipDriver(nil, 1, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, GossipDriverConfig{})
	defer driver.Stop()
	_, datagram := bindMemoryGossipTransport(t, driver, "peer-a")
	client := &blockingObjectPullClient{entered: make(chan struct{}, 1)}
	executor := NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{
		Client: client, Discovery: func() GossipDiscoveryInput {
			return GossipDiscoveryInput{Network: zone.NewNetworkState(), Bootstrap: map[string]*net.UDPAddr{"peer-a": {IP: net.ParseIP("127.0.0.1"), Port: 1}}}
		},
	})
	if err := driver.StartGossipObjectPullWorkers(t.Context(), executor, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := driver.SubmitGossipObjectPull(gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "remote.catofes."}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.entered:
	case <-time.After(time.Second):
		t.Fatal("I/O did not start")
	}
	if driver.Events() == nil {
		t.Fatal("waiting on asynchronous I/O paused input admission")
	}
	driver.events <- GossipPacketReceived{Packet: &gossip.Packet{Message: &gossip.Message{Type: gossip.MessageFetchCatalogPage, PeerID: "peer-a", FetchCatalogPage: &gossip.FetchCatalogPage{}}}}
	if _, err := driver.HandleGossipHostEvent(context.Background(), <-driver.Events(), time.Now(), nil); err != nil || datagram.writeCount() != 1 {
		t.Fatalf("independent responder writes/error = %d/%v", datagram.writeCount(), err)
	}
}

func TestGossipQueueWorkerWaitsForCompletionCapacityAndCanStop(t *testing.T) {
	for _, stopBlocked := range []bool{false, true} {
		t.Run(fmt.Sprintf("stop=%t", stopBlocked), func(t *testing.T) {
			workerDone := make(chan struct{}, 1)
			driver := NewGossipDriver(nil, 1, nil, GossipDriverConfig{Log: func(log GossipDriverLog) {
				if log.Event == "worker_done" {
					workerDone <- struct{}{}
				}
			}})
			defer driver.Stop()
			driver.events <- GossipPacketReceived{}
			for range cap(driver.completions) {
				driver.completions <- TimerFired{}
			}
			pulls := make(chan gossip.StartObjectPullAction, 1)
			if err := driver.StartGossipObjectPullWorkers(t.Context(), memoryObjectPullExecutor(pulls), 1, 1); err != nil {
				t.Fatal(err)
			}
			if err := driver.SubmitGossipObjectPull(gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "remote.catofes."}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-workerDone:
			case <-time.After(time.Second):
				t.Fatal("worker did not finish I/O")
			}
			if driver.PendingGossipObjectPullCount() != 1 {
				t.Fatal("worker did not retain its result while the completion queue was full")
			}
			if stopBlocked {
				stopped := make(chan struct{})
				go func() {
					driver.Stop()
					close(stopped)
				}()
				select {
				case <-stopped:
				case <-time.After(time.Second):
					t.Fatal("stop blocked on undelivered completion")
				}
				if driver.PendingGossipObjectPullCount() != 0 {
					t.Fatal("stop did not cancel retained result")
				}
				return
			}
			for range cap(driver.completions) {
				<-driver.Completions()
			}
			select {
			case event := <-driver.Completions():
				completion := event.(GossipEvent).Value.(*gossip.ObjectPullResultEvent)
				if completion.Snapshot == nil || completion.Zone != "remote.catofes." || completion.Err != nil {
					t.Fatalf("completion = %#v", completion)
				}
			case <-time.After(time.Second):
				t.Fatal("worker dropped the result instead of waiting")
			}
			if len(driver.events) != 1 {
				t.Fatal("completion delivery consumed the full input queue")
			}
		})
	}
}
