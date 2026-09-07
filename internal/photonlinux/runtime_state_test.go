package photonlinux

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestCloneRuntimeStateDeepCopiesMutableFields(t *testing.T) {
	original := &RuntimeState{
		PeerCleanups: map[string]photonstate.PeerLifecycleCleanupState{
			"peer-a": {LastActiveUnix: 10, CleanupUnix: 20, Reason: "offline"},
		},
		IPsecTransportKey: &photonstate.IPsecTransportKeyState{PublicKey: []byte("public"), PrivateKey: []byte("private")},
		IPsecPortRecord:   &photonstate.IPsecPortRecordState{Range: &ipsec.PortRange{From: 4500, To: 4510}},
		LinkInstances:     map[string]photonstate.LinkInstanceState{"link-a": {ID: "link-a", Owner: photonstate.LinkOwnerState{Token: "token-a"}}},
		IPsecReconcile: &photonstate.IPsecReconcileState{
			Desired:   []photonstate.DesiredLinkState{{InstanceID: "link-a", Endpoint: "198.51.100.10:4500"}},
			ActualSAs: []photonstate.LinkSAState{{Name: "sa-a"}},
			Actions:   []photonstate.LinkActionState{{Action: "create"}},
			Skipped:   []photonstate.LinkSkipState{{Reason: "revoked"}},
		},
		RoutingReconcile: &photonstate.RoutingReconcileState{LastError: "routing-error"},
		FirewallReconcile: &photonstate.FirewallReconcileState{Instances: map[string]*photonstate.FirewallReconcileInstance{
			"fw-a": {PolicyHash: "hash-a"},
			"nil":  nil,
		}},
		EndpointACLs: map[string]photonstate.EndpointACL{"api": {Selectors: []string{"zone:catofes."}}},
		BirdInstances: map[string]*photonstate.BirdInstanceState{
			"mesh": {Overlays: []string{"main"}},
			"nil":  nil,
		},
		Admission: &photonstate.AdmissionState{Pending: true, PendingReason: "missing_delegation"},
	}

	cloned := CloneRuntimeState(original)
	cloned.PeerCleanups["peer-a"] = photonstate.PeerLifecycleCleanupState{Reason: "changed"}
	cloned.IPsecTransportKey.PublicKey[0] = 'P'
	cloned.IPsecTransportKey.PrivateKey[0] = 'S'
	cloned.IPsecPortRecord.Range.From = 4600
	link := cloned.LinkInstances["link-a"]
	link.Owner.Token = "token-b"
	cloned.LinkInstances["link-a"] = link
	cloned.IPsecReconcile.Desired[0].Endpoint = "198.51.100.20:4500"
	cloned.IPsecReconcile.ActualSAs[0].Name = "sa-b"
	cloned.IPsecReconcile.Actions[0].Action = "delete"
	cloned.IPsecReconcile.Skipped[0].Reason = "changed"
	cloned.RoutingReconcile.LastError = "changed"
	cloned.FirewallReconcile.Instances["fw-a"].PolicyHash = "hash-b"
	cloned.EndpointACLs["api"].Selectors[0] = "zone:changed."
	cloned.BirdInstances["mesh"].Overlays[0] = "changed"
	cloned.Admission.PendingReason = "changed"

	if original.PeerCleanups["peer-a"].Reason != "offline" ||
		string(original.IPsecTransportKey.PublicKey) != "public" ||
		string(original.IPsecTransportKey.PrivateKey) != "private" ||
		original.IPsecPortRecord.Range.From != 4500 ||
		original.LinkInstances["link-a"].Owner.Token != "token-a" {
		t.Fatalf("top-level runtime fields share mutable state: %#v", original)
	}
	if original.IPsecReconcile.Desired[0].Endpoint != "198.51.100.10:4500" ||
		original.IPsecReconcile.ActualSAs[0].Name != "sa-a" ||
		original.IPsecReconcile.Actions[0].Action != "create" ||
		original.IPsecReconcile.Skipped[0].Reason != "revoked" {
		t.Fatalf("IPsec reconcile slices share mutable state: %#v", original.IPsecReconcile)
	}
	if original.RoutingReconcile.LastError != "routing-error" ||
		original.FirewallReconcile.Instances["fw-a"].PolicyHash != "hash-a" ||
		original.EndpointACLs["api"].Selectors[0] != "zone:catofes." ||
		original.BirdInstances["mesh"].Overlays[0] != "main" ||
		original.Admission.PendingReason != "missing_delegation" {
		t.Fatalf("nested runtime fields share mutable state: %#v", original)
	}
	if cloned.FirewallReconcile.Instances["nil"] != nil || cloned.BirdInstances["nil"] != nil {
		t.Fatalf("nil map entries were not preserved: firewall=%#v bird=%#v", cloned.FirewallReconcile.Instances, cloned.BirdInstances)
	}
}

func TestCloneRuntimeStatePreservesNilAndEmptyShape(t *testing.T) {
	original := &RuntimeState{
		PeerCleanups:      map[string]photonstate.PeerLifecycleCleanupState{},
		LinkInstances:     map[string]photonstate.LinkInstanceState{},
		EndpointACLs:      map[string]photonstate.EndpointACL{"empty": {Selectors: []string{}}},
		BirdInstances:     map[string]*photonstate.BirdInstanceState{},
		IPsecReconcile:    &photonstate.IPsecReconcileState{Desired: []photonstate.DesiredLinkState{}, Actions: []photonstate.LinkActionState{}},
		FirewallReconcile: &photonstate.FirewallReconcileState{Instances: map[string]*photonstate.FirewallReconcileInstance{}},
	}
	cloned := CloneRuntimeState(original)
	if cloned.PeerCleanups == nil || cloned.LinkInstances == nil || cloned.EndpointACLs == nil ||
		cloned.EndpointACLs["empty"].Selectors == nil || cloned.BirdInstances == nil ||
		cloned.IPsecReconcile.Desired == nil || cloned.IPsecReconcile.ActualSAs != nil ||
		cloned.IPsecReconcile.Actions == nil || cloned.IPsecReconcile.Skipped != nil ||
		cloned.FirewallReconcile.Instances == nil {
		t.Fatalf("nil/empty shape changed: %#v", cloned)
	}
	if got := CloneRuntimeState(nil); got == nil || !reflect.DeepEqual(got, &RuntimeState{}) {
		t.Fatalf("nil runtime clone = %#v, want empty runtime", got)
	}
}

func TestRuntimeStateSchemaGuard(t *testing.T) {
	want := []string{
		"PeerCleanups", "IPsecTransportKey", "IPsecPortRecord", "LinkInstances",
		"IPsecReconcile", "RoutingReconcile", "FirewallReconcile", "EndpointACLs", "BirdInstances", "Admission",
	}
	typ := reflect.TypeOf(RuntimeState{})
	if typ.NumField() != len(want) {
		t.Fatalf("RuntimeState field count = %d, want %d (%v)", typ.NumField(), len(want), want)
	}
	for index, name := range want {
		if got := typ.Field(index).Name; got != name {
			t.Fatalf("RuntimeState field %d = %s, want %s", index, got, name)
		}
	}
}

func TestRuntimeStateJSONDropsLegacyIdentityPath(t *testing.T) {
	var state RuntimeState
	if err := json.Unmarshal([]byte(`{"identity_key_path":"/old/key.json","endpoint_acls":{"api":{"name":"api"}}}`), &state); err != nil {
		t.Fatalf("decode old payload: %v", err)
	}
	payload, err := json.Marshal(&state)
	if err != nil {
		t.Fatalf("encode current payload: %v", err)
	}
	if strings.Contains(string(payload), "identity_key_path") || state.EndpointACLs["api"].Name != "api" {
		t.Fatalf("current state retained legacy identity path or lost durable fields: %s", payload)
	}
}
