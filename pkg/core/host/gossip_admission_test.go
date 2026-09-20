package host

import (
	"crypto/ed25519"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestAdmissionDiagnosisWithoutTransportMatchesOffline(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	view := corestate.View{
		State: &corestate.VerifiedState{ManagedZone: "child.example.", IdentityPrivateKey: key},
		Gossip: &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
			"bootstrap-list": {LastSyncUnix: 100},
			"bootstrap-map":  {LastSyncUnix: 200},
			"unrelated":      {LastSyncUnix: 300},
		}},
	}
	driver := NewGossipDriver(nil, 1, &memoryGossipStateStore{views: []corestate.View{view}}, GossipDriverConfig{
		Discovery: GossipDiscoveryConfig{BootstrapPeers: []string{"bootstrap-list"}, Bootstrap: map[string]*net.UDPAddr{"bootstrap-map": nil}},
	})
	defer driver.Stop()
	now := time.Unix(400, 0)
	got := driver.AdmissionDiagnosis(now)
	want := gossip.DiagnoseAutoJoinAdmission(view.State, view.Gossip, []string{"bootstrap-list", "bootstrap-map"}, now)
	if !reflect.DeepEqual(got, want) || got.LastBootstrapSyncUnix != 200 || got.Reason != gossip.AdmissionReasonMissingParentZone || got.JoinRequestB64 == "" {
		t.Fatalf("online = %+v, offline = %+v", got, want)
	}
	if driver.Transport() != nil || driver.PendingEventCount() != 0 {
		t.Fatal("diagnosis started transport or queued events")
	}
}
