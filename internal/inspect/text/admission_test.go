package text

import (
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestWriteAdmissionDiagnosis(t *testing.T) {
	d := inspect.AdmissionDiagnosis{
		Pending:               true,
		ManagedZone:           "node-b.catofes.",
		ParentZone:            "catofes.",
		Reason:                inspect.AdmissionReasonMissingDelegation,
		ReasonDetail:          "parent zone has no delegation",
		JoinRequestB64:        "eyJqb2luIjoidGVzdCJ9",
		HasZonePrivateKey:     true,
		ParentZoneKnown:       true,
		ParentAuthorityKnown:  true,
		DelegationKnown:       false,
		LastBootstrapSyncUnix: time.Unix(5000, 0).Unix(),
	}
	var buf strings.Builder
	if err := WriteAdmissionDiagnosis(&buf, d); err != nil {
		t.Fatalf("WriteAdmissionDiagnosis: %v", err)
	}
	output := buf.String()
	required := []string{
		"managed_zone: node-b.catofes.",
		"parent_zone: catofes.",
		"pending: true",
		"reason: missing_delegation",
		"reason_detail: parent zone has no delegation",
		"has_zone_private_key: true",
		"last_bootstrap_sync: 1970-01-01T01:23:20Z",
		"join_request: eyJqb2luIjoidGVzdCJ9",
		"join_hint: photon gossip delegate issue <join_request> (on parent zone admin)",
		"boundary:",
	}
	for _, want := range required {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
