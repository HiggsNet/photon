package gossip

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestSyncSessionCatalogDriftWithVerifiedSnapshots(t *testing.T) {
	for _, outcome := range []string{"recovers", "changes again", "invalid signature"} {
		t.Run(outcome, func(t *testing.T) {
			now := time.Unix(1000, 0)
			network, _, privateKey := testNetworkWithKeys(t)
			network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
			store := corestate.NewStore(&corestate.VerifiedState{ManagedZone: "local.catofes.", Network: network}, nil, nil)
			var snapshots []*corestate.ZoneSnapshot
			var previous *zone.Record
			for version := uint64(1); version <= 3; version++ {
				var prevHash []byte
				if previous != nil {
					prevHash = photoncrypto.RecordHash(previous)
				}
				record := signedRecord(t, privateKey, "catofes.", EndpointRecordKeyUDP, []byte{byte(version)}, version, prevHash, now.Unix())
				if err := network.PutAt(record, now); err != nil {
					t.Fatal(err)
				}
				previous = record
				snapshot, err := corestate.Snapshot(network, "catofes.")
				if err != nil {
					t.Fatal(err)
				}
				snapshots = append(snapshots, snapshot)
			}
			s := NewSyncSession("peer-a")
			event := func(e SyncEvent) []SyncAction {
				t.Helper()
				actions, err := s.OnEvent(e, now)
				if err != nil {
					t.Fatal(err)
				}
				return actions
			}
			page := func(snapshot *corestate.ZoneSnapshot) []SyncAction {
				t.Helper()
				entries := []corestate.ZoneDigest{{Zone: snapshot.Zone, RootHash: corestate.ZoneRoot(corestate.ZoneStateFromSnapshot(snapshot))}}
				local, _ := store.ZoneDigests()
				return event(&CatalogPageReceivedEvent{PeerID: "peer-a", Page: &corestate.CatalogPage{CatalogRoot: corestate.CatalogRoot(entries), Entries: entries}, LocalEntries: local})
			}
			apply := func(snapshot *corestate.ZoneSnapshot) error {
				t.Helper()
				actions := event(&ObjectPullResultEvent{PeerID: "peer-a", Zone: snapshot.Zone, Snapshot: snapshot})
				assertActionTypes(t, actions, []string{"ApplySnapshotAction"})
				a := actions[0].(ApplySnapshotAction)
				result, err := store.ApplyRemoteBatch(context.Background(), a.PeerID, []corestate.RemoteSnapshot{{Snapshot: a.Snapshot, ExpectedRoot: a.ExpectedRoot, RefreshOnRootMismatch: a.RefreshOnRootMismatch}}, now)
				if err != nil {
					t.Fatal(err)
				}
				return result.Outcomes[0].Err
			}
			event(&SyncTimerEvent{PeerID: "peer-a"})
			assertActionTypes(t, page(snapshots[0]), []string{"StartObjectPullAction"})
			// The sender updates its endpoint after advertising v1, so the TCP
			// read returns v2. No snapshot is accepted on this mismatch.
			firstErr := apply(snapshots[1])
			if !errors.Is(firstErr, corestate.ErrSnapshotRootMismatch) {
				t.Fatalf("first result = %v", firstErr)
			}
			first := store.ReadView()
			if first.Revision != 0 || len(first.Gossip.Peers["peer-a"].RejectedObjects) != 0 {
				t.Fatal("first drift changed state or recorded rejection")
			}
			refresh := event(&SnapshotAppliedEvent{PeerID: "peer-a", Zone: "catofes.", Err: firstErr})
			assertActionTypes(t, refresh, []string{"SendFetchCatalogPageAction", "StartTimerAction"})
			if timer := refresh[1].(StartTimerAction); timer.Kind != TimerKindCatalogPage || !timer.Deadline.Equal(now.Add(s.catalogPageTimeout())) {
				t.Fatalf("refresh timer = %#v", timer)
			}
			fetched := snapshots[1]
			if outcome == "invalid signature" {
				fetched.Records[EndpointRecordKeyUDP].Signature[0] ^= 1
			}
			assertActionTypes(t, page(fetched), []string{"StartObjectPullAction"})
			if outcome == "changes again" {
				fetched = snapshots[2]
			}
			lastErr := apply(fetched)
			ack := event(&SnapshotAppliedEvent{PeerID: "peer-a", Zone: "catofes.", Err: lastErr})
			view := store.ReadView()
			if outcome == "recovers" {
				if lastErr != nil || s.State != SyncSessionCompleted || len(ack) != 0 || view.Revision != 1 || len(view.Gossip.Peers["peer-a"].RejectedObjects) != 0 {
					t.Fatalf("recovery: err=%v state=%s view=%#v", lastErr, s.State, view)
				}
				if !bytes.Equal(corestate.ZoneRoot(view.State.Network.Zones["catofes."]), corestate.ZoneRoot(corestate.ZoneStateFromSnapshot(fetched))) {
					t.Fatal("did not accept the refreshed verified snapshot")
				}
			} else {
				assertActionTypes(t, ack, []string{"RecordBackoffAction"})
				if lastErr == nil || s.State != SyncSessionFailed || view.Revision != 0 || len(view.Gossip.Peers["peer-a"].RejectedObjects) != 1 {
					t.Fatalf("failure: err=%v state=%s view=%#v", lastErr, s.State, view)
				}
			}
		})
	}
}

func TestSyncSessionCatalogRefreshDrainsOutstandingWork(t *testing.T) {
	for _, waiting := range []string{"tcp", "apply", "chunk", "page"} {
		t.Run(waiting, func(t *testing.T) {
			now := time.Unix(1000, 0)
			s := NewSyncSession("peer-a")
			s.State = SyncSessionObjectPulling
			s.pendingZones["changed.catofes."] = true
			s.pendingZones["waiting.catofes."] = true
			s.snapshotApplyPending["changed.catofes."] = true
			s.expectedDigests["changed.catofes."] = corestate.ZoneDigest{Zone: "changed.catofes.", RootHash: []byte("old")}
			switch waiting {
			case "tcp":
				s.objectPullInflight["waiting.catofes."] = true
			case "apply":
				s.snapshotApplyPending["waiting.catofes."] = true
			case "chunk":
				s.chunkFallbackZones["waiting.catofes."] = true
			case "page":
				s.lastCatalogCursor = "1"
			}
			// Learning the same root through another peer must not reuse a
			// slot while its earlier transport result can still arrive.
			if waiting != "page" {
				s.expectedDigests["waiting.catofes."] = corestate.ZoneDigest{Zone: "waiting.catofes.", RootHash: []byte("known")}
				s.ReconcilePendingWithDigests([]corestate.ZoneDigest{{Zone: "waiting.catofes.", RootHash: []byte("known")}})
				if !s.pendingZones["waiting.catofes."] {
					t.Fatal("reconciled away outstanding work")
				}
			}
			actions, err := s.OnEvent(&SnapshotAppliedEvent{PeerID: "peer-a", Zone: "changed.catofes.", Err: corestate.ErrSnapshotRootMismatch}, now)
			if err != nil {
				t.Fatal(err)
			}
			if len(actions) != 0 || s.catalogRefreshed || !s.catalogRefreshPending {
				t.Fatalf("refreshed before draining %s", waiting)
			}
			if waiting == "tcp" || waiting == "chunk" {
				var e SyncEvent = &ObjectPullResultEvent{PeerID: "peer-a", Zone: "waiting.catofes.", Snapshot: &corestate.ZoneSnapshot{Zone: "waiting.catofes."}}
				if waiting == "chunk" {
					e = &ObjectChunkEvent{PeerID: "peer-a", Zone: "waiting.catofes.", Snapshot: &corestate.ZoneSnapshot{Zone: "waiting.catofes."}}
				}
				actions, err = s.OnEvent(e, now)
				if err != nil {
					t.Fatal(err)
				}
				assertActionTypes(t, actions, []string{"ApplySnapshotAction"})
			}
			var e SyncEvent = &SnapshotAppliedEvent{PeerID: "peer-a", Zone: "waiting.catofes."}
			if waiting == "page" {
				e = &CatalogPageReceivedEvent{PeerID: "peer-a", Page: &corestate.CatalogPage{CatalogRoot: []byte("root")}}
			}
			actions, err = s.OnEvent(e, now)
			if err != nil {
				t.Fatal(err)
			}
			assertActionTypes(t, actions, []string{"SendFetchCatalogPageAction", "StartTimerAction"})
			if !s.catalogRefreshed || s.State != SyncSessionCatalogDiffing {
				t.Fatal("did not refresh after draining")
			}
		})
	}
}

func TestSyncSessionCatalogRefreshKeepsRoundTimeout(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewSyncSession("peer-a")
	s.State = SyncSessionObjectPulling
	s.pendingZones["catofes."] = true
	s.snapshotApplyPending["catofes."] = true
	refresh, err := s.OnEvent(&SnapshotAppliedEvent{PeerID: "peer-a", Zone: "catofes.", Err: corestate.ErrSnapshotRootMismatch}, now)
	if err != nil {
		t.Fatal(err)
	}
	assertActionTypes(t, refresh, []string{"SendFetchCatalogPageAction", "StartTimerAction"})
	actions, err := s.OnEvent(&RoundTimeoutEvent{PeerID: "peer-a"}, now)
	if err != nil {
		t.Fatal(err)
	}
	assertActionTypes(t, actions, []string{"RecordBackoffAction", "CancelTimerAction"})
	if s.State != SyncSessionFailed {
		t.Fatal("refresh escaped original round deadline")
	}
}
