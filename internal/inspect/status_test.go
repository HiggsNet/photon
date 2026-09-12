package inspect

import "testing"

func TestBuildStatusAutoJoinStageAndRequest(t *testing.T) {
	view := BuildStatus(StatusInput{Admission: AdmissionDiagnosis{
		Pending:        true,
		ManagedZone:    "node-b.example.",
		Reason:         AdmissionReasonMissingDelegation,
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
			Summary: LinkSummary{DesiredLinks: 3, LinkInstances: 2},
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
		AdmissionReasonMissingZoneKey:         "preparing_identity",
		AdmissionReasonNoBootstrapSync:        "syncing_parent",
		AdmissionReasonMissingParentZone:      "syncing_parent",
		AdmissionReasonMissingDelegation:      "awaiting_delegation",
		AdmissionReasonDelegationKeyMismatch:  "delegation_invalid",
		AdmissionReasonVerifyDelegationFailed: "delegation_invalid",
		AdmissionReasonWaitingForAdoption:     "adopting",
	}
	for reason, want := range tests {
		if got := AutoJoinStage(reason); got != want {
			t.Errorf("AutoJoinStage(%q) = %q, want %q", reason, got, want)
		}
	}
}
