package gossip

import (
	"errors"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestSyncSessionLocalAndSemanticPullFailuresBackOffWithoutUDP(t *testing.T) {
	for _, failure := range []error{
		ErrQuotaExceeded,
		errors.New("object-pull queue full"),
		errors.New("object pull per-peer inflight limit reached"),
		errors.New("object pull returned empty snapshot"),
		errors.New("object pull failed: zone revoked"),
	} {
		t.Run(failure.Error(), func(t *testing.T) {
			now := time.Unix(100, 0)
			session := NewSyncSession("peer")
			_, _ = session.OnEvent(&SyncTimerEvent{PeerID: "peer"}, now)
			_, _ = session.OnEvent(&PongReceivedEvent{PeerID: "peer", Pong: &Pong{}, MissingZones: []zone.ZonePath{"node.catofes."}}, now)
			actions, err := session.OnEvent(&ObjectPullResultEvent{PeerID: "peer", Zone: "node.catofes.", Err: failure}, now)
			if err != nil || session.State != SyncSessionFailed || !errors.Is(session.LastError(), failure) {
				t.Fatalf("state=%s last error=%v error=%v", session.State, session.LastError(), err)
			}
			if len(actions) != 1 {
				t.Fatalf("actions=%#v", actions)
			}
			if _, ok := actions[0].(RecordBackoffAction); !ok {
				t.Fatalf("failure triggered another transport: %#v", actions)
			}
		})
	}
}
