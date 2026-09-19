package photonlinux

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestIPsecProjectionDetachesIdentityAndEndpoint(t *testing.T) {
	spec := ipsec.TransportLinkSpec{
		OverlayID: "main", LinkID: "link", PeerZone: "peer.example.",
		ContactPoints:   []ipsec.ContactPoint{{Host: "peer.example"}},
		LocalPrivateKey: []byte("private-key-sentinel"), LocalPrivateKeyAlgorithm: "private-algorithm-sentinel",
	}
	action := ipsec.ReconcileAction{Action: "update", Spec: &spec,
		Instance: &ipsec.LinkInstance{ID: "old", GroupID: "old", PeerZone: "old.example."}}
	desired := ProjectIPsecDesired([]ipsec.TransportLinkSpec{spec})
	actions := ProjectIPsecActions([]ipsec.ReconcileAction{action})
	if desired[0].Endpoint != "peer.example" || desired[0].LocalTunnelAddr != "-" || actions[0].InstanceID != ipsec.LinkInstanceID(spec) || actions[0].GroupID != "main" {
		t.Fatalf("projection lost endpoint, invalid-address handling or spec precedence: %+v %+v", desired, actions)
	}
	before, err := json.Marshal([]any{desired, actions})
	if err != nil {
		t.Fatal(err)
	}
	spec.ContactPoints[0].Host = "changed"
	spec.OverlayID = "changed"
	action.Instance.ID = "changed"
	after, err := json.Marshal([]any{desired, actions})
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) || strings.Contains(string(after), "private") {
		t.Fatal("projection retained source references or private fields")
	}
}

func TestIPsecSAProjectionRefreshesCounters(t *testing.T) {
	sas := []ipsec.SAState{{UniqueID: 7, InboundKnown: true, InboundBytes: 100, InboundPackets: 3, InboundIdleSecs: 1, IKEAgeSeconds: 10, ChildAgeSeconds: 5}}
	first := ProjectIPsecSAs(sas)
	sas[0].InboundBytes = 200
	sas[0].InboundIdleSecs = 2
	sas[0].IKEAgeSeconds = 11
	second := ProjectIPsecSAs(sas)
	if first[0].InboundBytes != 100 || second[0].InboundBytes != 200 || second[0].InboundIdleSecs != 2 || second[0].IKEAgeSeconds != 11 || !second[0].InboundKnown || second[0].InboundPackets != 3 || second[0].ChildAgeSeconds != 5 {
		t.Fatalf("stale or aliased counters: %+v %+v", first, second)
	}
}
