package text

import (
	"bytes"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestWriteStatusAutoJoinShowsStageAndRequest(t *testing.T) {
	var buf bytes.Buffer
	view := inspect.BuildStatus(inspect.StatusInput{
		DaemonOnline: true,
		Admission: inspect.AdmissionDiagnosis{
			Pending:        true,
			ManagedZone:    "node-b.example.",
			ParentZone:     "example.",
			Reason:         inspect.AdmissionReasonMissingDelegation,
			JoinRequestB64: "encoded-request",
		},
	})
	if err := WriteStatus(&buf, view); err != nil {
		t.Fatalf("WriteStatus: %v", err)
	}
	for _, want := range []string{
		"daemon: online",
		"mode: auto-join",
		"stage: awaiting_delegation",
		"join_request: encoded-request",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output missing %q:\n%s", want, buf.String())
		}
	}
}

func TestWriteStatusRunningShowsPeerAndLinkSummary(t *testing.T) {
	var buf bytes.Buffer
	view := inspect.BuildStatus(inspect.StatusInput{
		ManagedZone: "node-a.example.",
		Peers: []inspect.PeerStatusInfo{
			{State: inspect.PeerStateActive},
			{State: inspect.PeerStateOffline},
		},
		Links: inspect.LinkInspection{
			Summary: inspect.LinkSummary{DesiredLinks: 2, LinkInstances: 1},
			Links:   []inspect.LinkView{{State: "up", Health: &inspect.HealthSample{State: "healthy"}}},
		},
	})
	if err := WriteStatus(&buf, view); err != nil {
		t.Fatalf("WriteStatus: %v", err)
	}
	for _, want := range []string{
		"mode: running",
		"peers: 2",
		"states: active=1, offline=1",
		"desired: 2",
		"total: 1",
		"up: 1",
		"health: healthy=1",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output missing %q:\n%s", want, buf.String())
		}
	}
}
