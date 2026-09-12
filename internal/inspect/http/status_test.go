package http

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestStatusResponsePreservesObserverSchema(t *testing.T) {
	got := StatusResponse{
		PeerID:             "node-a.catofes.",
		ManagedZone:        "node-a.catofes.",
		ListenAddr:         "127.0.0.1:33434",
		DaemonOnline:       true,
		StateRevision:      3,
		KnownZones:         4,
		KnownPeers:         2,
		LinkInstances:      1,
		DesiredLinks:       1,
		LastLinkFailure:    &inspect.FailureView{Code: inspect.FailureCodeIPsecReconcile, Message: "ipsec failed"},
		LastRoutingFailure: &inspect.FailureView{Code: inspect.FailureCodeRoutingReconcile, Message: "bird failed"},
		LastSyncUnix:       90,
		LastReconcileUnix:  95,
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded["peer_id"] != "node-a.catofes." || decoded["daemon_online"] != true {
		t.Fatalf("status fields missing: %#v", decoded)
	}
	if decoded["state_revision"] != float64(3) || decoded["link_instances"] != float64(1) {
		t.Fatalf("numeric fields missing: %#v", decoded)
	}
	if decoded["last_link_failure"].(map[string]any)["code"] != inspect.FailureCodeIPsecReconcile || decoded["last_routing_failure"].(map[string]any)["code"] != inspect.FailureCodeRoutingReconcile {
		t.Fatalf("failure codes missing: %#v", decoded)
	}
}

func TestStatusResponseUsesCanonicalLastReconcileProjection(t *testing.T) {
	got := inspect.BuildDaemonStatus(inspect.DaemonStatusInput{
		PeerID:             "node-a.catofes.",
		ManagedZone:        "node-a.catofes.",
		ListenAddr:         "127.0.0.1:33434",
		DaemonOnline:       true,
		StateRevision:      7,
		KnownZones:         3,
		KnownPeers:         2,
		LinkInstances:      4,
		DesiredLinks:       5,
		LastLinkFailure:    errors.New("ipsec failed"),
		LastRoutingFailure: errors.New("bird failed"),
		LastSyncUnix:       80,
		IPsecLastRunUnix:   90,
		RoutingLastRunUnix: 95,
	})
	if got.LastReconcileUnix != 95 {
		t.Fatalf("last reconcile = %d, want routing max 95", got.LastReconcileUnix)
	}
	if got.PeerID != "node-a.catofes." || got.StateRevision != 7 || got.LinkInstances != 4 {
		t.Fatalf("status fields not preserved: %#v", got)
	}
	if got.LastLinkFailure == nil || got.LastLinkFailure.Code != inspect.FailureCodeIPsecReconcile || got.LastLinkFailure.Message != "ipsec failed" || got.LastRoutingFailure == nil || got.LastRoutingFailure.Code != inspect.FailureCodeRoutingReconcile || got.LastRoutingFailure.Message != "bird failed" {
		t.Fatalf("status failures not projected: %#v", got)
	}
}
