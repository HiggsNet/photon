package inspect

import (
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photonservice "github.com/HiggsNet/photon/pkg/service"
)

func TestBuildServiceInspectionIncludesLocalAndRemoteServices(t *testing.T) {
	network := zone.NewNetworkState()
	local := zone.ZonePath("node-a.catofes.")
	remote := zone.ZonePath("node-b.catofes.")
	network.Zones[local] = zone.NewZoneState(local, nil)
	network.Zones[remote] = zone.NewZoneState(remote, nil)
	network.Zones[local].Records["services/socks5"] = &zone.Record{
		Zone: local, Key: "services/socks5", Type: photonservice.RecordTypeSOCKS5, Version: 2, Timestamp: 200,
		Value: []byte(`{"type":"socks5","endpoints":[{"region":"local","address":"fd42:1::20","port":3128}]}`),
	}
	network.Zones[remote].Records["services/socks5"] = &zone.Record{
		Zone: remote, Key: "services/socks5", Type: photonservice.RecordTypeSOCKS5, Version: 3, Timestamp: 300,
		Value: []byte(`{"type":"socks5","endpoints":[{"region":"cn","address":"198.51.100.20","port":1080}],"active":false}`),
	}

	view := BuildServiceInspection(&corestate.VerifiedState{Network: network, ManagedZone: local}, time.Time{})
	if len(view.Services) != 2 {
		t.Fatalf("services = %d, want 2: %+v", len(view.Services), view.Services)
	}
	if got := view.Services[0]; got.Owner != local || !got.Local || got.Status != "active" || len(got.Endpoints) != 1 {
		t.Fatalf("local service = %+v", got)
	}
	if got := view.Services[1]; got.Owner != remote || got.Local || got.Status != "withdrawn" || len(got.Endpoints) != 1 {
		t.Fatalf("remote service = %+v", got)
	}
}

func TestBuildServiceInspectionReportsInvalidServiceRecord(t *testing.T) {
	network := zone.NewNetworkState()
	owner := zone.ZonePath("node-a.catofes.")
	network.Zones[owner] = zone.NewZoneState(owner, nil)
	network.Zones[owner].Records["services/socks5"] = &zone.Record{
		Zone: owner, Key: "services/socks5", Type: photonservice.RecordTypeSOCKS5,
		Value: []byte(`{"type":"socks5"}`),
	}

	view := BuildServiceInspection(&corestate.VerifiedState{Network: network, ManagedZone: owner}, time.Time{})
	if len(view.Services) != 1 || view.Services[0].Status != "invalid" || view.Services[0].Failure == nil || view.Services[0].Failure.Code != FailureCodeServiceRecord {
		t.Fatalf("invalid service view = %+v", view.Services)
	}
}
