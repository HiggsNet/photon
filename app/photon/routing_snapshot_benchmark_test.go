package main

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
)

// The authorized route set is already computed by reconcileRouting. This
// benchmark measures its no-change auto-announce check with a populated store;
// record contents are unrelated to route announcements and need no verification.
func BenchmarkAutoAnnounceNoChange(b *testing.B) {
	network := zone.NewNetworkState()
	managed := zone.ZonePath("node-0.catofes.")
	for i := range 26 {
		path := zone.ZonePath(fmt.Sprintf("node-%d.catofes.", i))
		zs := zone.NewZoneState(path, &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1})
		network.Zones[path] = zs
		for j := range 10 {
			key := fmt.Sprintf("record-%d", j)
			for version := uint64(1); version <= 8; version++ {
				r := &zone.Record{Zone: path, Key: key, Version: version, Value: make([]byte, 256)}
				zs.RecordHistory[key] = append(zs.RecordHistory[key], r)
				zs.Records[key] = r
			}
		}
	}
	verified := &corestate.VerifiedState{ManagedZone: managed, Network: network}
	rt := &testApp{Config: &appConfig{}, Clock: func() time.Time { return time.Unix(1000, 0) }}
	d := newTestDaemonFromOwners(rt, verified, nil, &photonlinux.LinuxState{}, nil, time.Second)
	ars := &routing.AuthorizedRouteSet{Assignments: map[netip.Prefix]*routing.AssignmentEntry{}}
	// The caller has already read this snapshot before entering the timed check.
	common := d.State.Common.ReadView()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if changed, err := d.autoAnnounceAssignedIPsResult(common.State, ars); changed || err != nil {
			b.Fatalf("unexpected mutation: %v %v", changed, err)
		}
	}
}
