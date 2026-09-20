package inspect

import (
	"testing"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func TestBuildStatusAutoJoinStageAndRequest(t *testing.T) {
	view := BuildStatus(StatusInput{Admission: gossip.AdmissionDiagnosis{
		Pending:        true,
		ManagedZone:    "node-b.example.",
		Reason:         gossip.AdmissionReasonMissingDelegation,
		JoinRequestB64: "request",
	}})
	if view.Mode != StatusModeAutoJoin || view.AutoJoinStage != "awaiting_delegation" {
		t.Fatalf("view = %+v, want auto-join awaiting_delegation", view)
	}
	if view.ManagedZone != "node-b.example." || view.Admission.JoinRequestB64 != "request" {
		t.Fatalf("view = %+v, want zone and request preserved", view)
	}
}

func TestBuildStatusSummarizesRunningPeersAndLinks(t *testing.T) {
	view := BuildStatus(StatusInput{
		ManagedZone: "node-a.example.",
		Peers: []PeerStatusInfo{
			{State: PeerStateActive, LastSyncUnix: 100},
			{State: PeerStateActive, LastSyncUnix: 200},
			{State: PeerStateOffline, LastSyncUnix: 50},
		},
		Links: LinkInspection{
			DesiredLinks:  3,
			LinkInstances: 2,
			Links: []LinkView{
				{State: "up", Health: &HealthSample{State: "healthy"}},
				{State: "connecting", Health: &HealthSample{State: "degraded"}},
			},
		},
	})
	if view.Mode != StatusModeRunning || view.Peers.Total != 3 || view.Peers.LastSync != 200 {
		t.Fatalf("view peers = %+v", view)
	}
	if view.Links.Desired != 3 || view.Links.Total != 2 || view.Links.Up != 1 {
		t.Fatalf("view links = %+v", view.Links)
	}
}

func TestAutoJoinStage(t *testing.T) {
	tests := map[string]string{
		gossip.AdmissionReasonMissingZoneKey:         "preparing_identity",
		gossip.AdmissionReasonNoBootstrapSync:        "syncing_parent",
		gossip.AdmissionReasonMissingParentZone:      "syncing_parent",
		gossip.AdmissionReasonMissingDelegation:      "awaiting_delegation",
		gossip.AdmissionReasonDelegationKeyMismatch:  "delegation_invalid",
		gossip.AdmissionReasonVerifyDelegationFailed: "delegation_invalid",
		gossip.AdmissionReasonWaitingForAdoption:     "adopting",
	}
	for reason, want := range tests {
		if got := AutoJoinStage(reason); got != want {
			t.Errorf("AutoJoinStage(%q) = %q, want %q", reason, got, want)
		}
	}
}
