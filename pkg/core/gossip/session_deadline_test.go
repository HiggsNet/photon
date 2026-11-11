package gossip

import (
	"errors"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestSyncSessionDeadlineAllowsSeveralSuccessfulPullWaves(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewSyncSession("peer")
	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer"}, now)
	actions, _ := s.OnEvent(testCatalogPage("peer", "a.", "b.", "c.", "d.", "e.", "f."), now)
	var deadline time.Time
	for _, action := range actions {
		if timer, ok := action.(StartTimerAction); ok && timer.Kind == TimerKindRound {
			deadline = timer.Deadline
		}
	}
	for i, path := range []zone.ZonePath{"a.", "b.", "c.", "d.", "e.", "f."} {
		at := now.Add(time.Duration(i/2+1) * 4 * time.Second)
		if !at.Before(deadline) {
			t.Fatalf("valid pull wave would be canceled at %v", deadline.Sub(now))
		}
		_, _ = s.OnEvent(&ObjectPullResultEvent{PeerID: "peer", Zone: path, Snapshot: &corestate.ZoneSnapshot{Zone: path}}, at)
		ack, _ := s.OnEvent(&SnapshotAppliedEvent{PeerID: "peer", Zone: path}, at)
		for _, action := range ack {
			if timer, ok := action.(StartTimerAction); ok && timer.Kind == TimerKindRound {
				t.Fatal("object progress extended the finite round deadline")
			}
		}
	}
	if s.State != SyncSessionCompleted {
		t.Fatalf("three successful waves ended in %s: %v", s.State, s.LastError())
	}
}

func TestSyncSessionUDPTimeoutCoversPacedObjectAndIgnoresLateTimeout(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewSyncSession("peer")
	_, _ = s.OnEvent(&SyncTimerEvent{PeerID: "peer"}, now)
	_, _ = s.OnEvent(testCatalogPage("peer", "a.", "b."), now)
	actions, _ := s.OnEvent(&ObjectPullResultEvent{PeerID: "peer", Zone: "a.", Unreachable: true, Err: errors.New("TCP unavailable")}, now)
	timer := actions[1].(StartTimerAction)
	if timer.Kind != TimerKindChunkPrefix+"a." || timer.Deadline.Sub(now) < 70*time.Second {
		t.Fatalf("UDP deadline cannot cover an 8 MiB paced transfer: %+v", timer)
	}
	_, _ = s.OnEvent(&ObjectChunkEvent{PeerID: "peer", Zone: "a.", Snapshot: &corestate.ZoneSnapshot{Zone: "a."}}, now.Add(time.Minute))
	_, _ = s.OnEvent(&ObjectChunkEvent{PeerID: "peer", Zone: "a.", Err: errors.New("late timeout")}, timer.Deadline)
	if s.Done() {
		t.Fatal("late UDP timeout invalidated an object already waiting for apply")
	}
	_, _ = s.OnEvent(&ObjectPullResultEvent{PeerID: "peer", Zone: "b.", Unreachable: true, Err: errors.New("TCP unavailable")}, now)
	_, _ = s.OnEvent(&ObjectChunkEvent{PeerID: "peer", Zone: "b.", Err: errors.New("chunk transfer timeout")}, timer.Deadline)
	if s.State != SyncSessionFailed {
		t.Fatal("missing UDP response escaped its own deadline")
	}
}
