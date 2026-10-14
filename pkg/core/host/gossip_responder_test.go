package host

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// The legacy builder read a detached full network before answering. Keep that
// read policy as a test oracle, including its record-history lookup order.
type fullNetworkObjectSource struct{ network *zone.NetworkState }

func (source fullNetworkObjectSource) ReadZoneSnapshot(path zone.ZonePath, now time.Time) (*corestate.ZoneSnapshot, bool, error) {
	revoked := source.network.IsZoneRevoked(path, now)
	snapshot, err := corestate.Snapshot(source.network, path)
	return snapshot, revoked, err
}

func (source fullNetworkObjectSource) ReadRecordSnapshot(path zone.ZonePath, key string, version uint64) (*corestate.RecordSnapshot, error) {
	return corestate.RecordSnapshotFor(source.network, path, key, version)
}

func TestGossipObjectProjectionsPreserveWireResponses(t *testing.T) {
	now := time.Unix(1000, 0)
	path := zone.ZonePath("peer.catofes.")
	network, _ := signedDiscoveryNetwork(t, path, true, nil, now)
	zs := network.Zones[path]
	zs.Records["value"] = &zone.Record{Zone: path, Key: "value", Version: 3, Value: []byte("current")}
	zs.RecordHistory["value"] = []*zone.Record{{Zone: path, Key: "value", Version: 1, Value: []byte("first")}, {Zone: path, Key: "value", Version: 2, Value: []byte("second")}}
	for _, revoked := range []bool{false, true} {
		if revoked {
			network.Zones["catofes."].Revocations[path] = &zone.DelegationRevocation{ParentZone: "catofes.", ChildZone: path, RevokedAt: 999, RevokedAuthorityEpoch: 1}
		}
		store := corestate.NewStore(&corestate.VerifiedState{Network: network}, nil, nil)
		driver := NewGossipDriver(NewClock(func() time.Time { return now }), 1, store, GossipDriverConfig{})
		t.Cleanup(driver.Stop)
		requests := []*gossip.ObjectPullRequest{
			nil,
			{Type: gossip.ObjectPullZone, Zone: path},
			{Type: gossip.ObjectPullZone, Zone: "missing.catofes."},
			{Type: gossip.ObjectPullZone, Zone: "invalid"},
			{Type: gossip.ObjectPullRecord, Zone: path},
			{Type: gossip.ObjectPullRecord, Zone: path, Key: "missing"},
			{Type: "unsupported", Zone: path},
		}
		for _, version := range []uint64{0, 1, 2, 3, 4} {
			requests = append(requests, &gossip.ObjectPullRequest{Type: gossip.ObjectPullRecord, Zone: path, Key: "value", Version: version})
		}
		for _, request := range requests {
			got := driver.GossipObjectPullResponse(request, now)
			want := gossip.BuildObjectPullResponse(fullNetworkObjectSource{network: store.ReadView().State.Network}, request, now)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("revoked=%v request=%+v: response=%+v, full-read=%+v", revoked, request, got, want)
			}
		}
		for _, budget := range []int{0, 1, gossip.DefaultDatagramBudget} {
			got := driver.gossipFetchZoneResponse(path, budget, now)
			wantPlan := gossip.PlanSnapshotDatagrams(network, []zone.ZonePath{path}, budget, now)
			if !got.Found || !reflect.DeepEqual(got.Plan, wantPlan) || (got.Snapshot == nil) != revoked {
				t.Fatalf("revoked=%v budget=%d: fetch=%s, plan=%+v", revoked, budget, fmt.Sprint(got), wantPlan)
			}
		}
	}
}

func TestGossipDriverBuildsFetchAndObjectPullResponsesFromBoundStore(t *testing.T) {
	now := time.Unix(1000, 0)
	path := zone.ZonePath("peer.catofes.")
	network := zone.NewNetworkState()
	network.Zones[path] = zone.NewZoneState(path, &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1})
	store := corestate.NewStore(&corestate.VerifiedState{ManagedZone: "local.catofes.", Network: network}, nil, nil)
	driver := NewGossipDriver(NewClock(func() time.Time { return now }), DefaultEventBuffer, store, GossipDriverConfig{PeerID: "local.catofes."})
	defer driver.Stop()

	fetch := driver.gossipFetchZoneResponse(path, gossip.DefaultDatagramBudget, now)
	if !fetch.Found || fetch.Snapshot == nil || fetch.Snapshot.Zone != path || len(fetch.Plan.Announces) != 1 {
		t.Fatalf("fetch response = %#v", fetch)
	}
	pull := driver.GossipObjectPullResponse(&gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: path}, now)
	if pull == nil || !pull.OK || pull.Snapshot == nil || pull.Snapshot.Zone != path {
		t.Fatalf("object pull response = %#v", pull)
	}
	if missing := driver.gossipFetchZoneResponse("missing.catofes.", gossip.DefaultDatagramBudget, now); missing.Found || missing.Snapshot != nil || len(missing.Plan.Announces) != 0 {
		t.Fatalf("missing fetch response = %#v", missing)
	}
}
