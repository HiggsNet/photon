package host

import (
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// The legacy builder read a detached full network before answering. Keep that
// read policy as a test oracle.
type fullNetworkObjectSource struct{ network *zone.NetworkState }

func (source fullNetworkObjectSource) ReadZoneSnapshot(path zone.ZonePath, now time.Time) (*corestate.ZoneSnapshot, bool, error) {
	revoked := source.network.IsZoneRevoked(path, now)
	snapshot, err := corestate.Snapshot(source.network, path)
	return snapshot, revoked, err
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
			{Type: "unsupported", Zone: path},
		}
		for _, request := range requests {
			got := driver.GossipObjectPullResponse(request, now)
			want := gossip.BuildObjectPullResponse(fullNetworkObjectSource{network: store.ReadView().State.Network}, request, now)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("revoked=%v request=%+v: response=%+v, full-read=%+v", revoked, request, got, want)
			}
		}
	}
}
