package photonlinux

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	photonstate "github.com/HiggsNet/photon/internal/state"
)

func TestCloneRuntimeStateDeepCopiesMutableFields(t *testing.T) {
	original := &RuntimeState{
		PeerCleanups: map[string]photonstate.PeerLifecycleCleanupState{
			"peer-a": {LastActiveUnix: 10, CleanupUnix: 20, Reason: "offline"},
		},
		IPsecTransportKey: &photonstate.IPsecTransportKeyState{PublicKey: []byte("public"), PrivateKey: []byte("private")},
		RoutingReconcile:  &photonstate.RoutingReconcileState{LastError: "routing-error"},
		FirewallReconcile: &photonstate.FirewallReconcileState{Instances: map[string]*photonstate.FirewallReconcileInstance{
			"fw-a": {PolicyHash: "hash-a"},
			"nil":  nil,
		}},
		EndpointACLs: map[string]photonstate.EndpointACL{"api": {Selectors: []string{"zone:catofes."}}},
		BirdInstances: map[string]*photonstate.BirdInstanceState{
			"mesh": {Overlays: []string{"main"}},
			"nil":  nil,
		},
	}

	cloned := CloneRuntimeState(original)
	cloned.PeerCleanups["peer-a"] = photonstate.PeerLifecycleCleanupState{Reason: "changed"}
	cloned.IPsecTransportKey.PublicKey[0] = 'P'
	cloned.IPsecTransportKey.PrivateKey[0] = 'S'
	cloned.RoutingReconcile.LastError = "changed"
	cloned.FirewallReconcile.Instances["fw-a"].PolicyHash = "hash-b"
	cloned.EndpointACLs["api"].Selectors[0] = "zone:changed."
	cloned.BirdInstances["mesh"].Overlays[0] = "changed"

	if original.PeerCleanups["peer-a"].Reason != "offline" ||
		string(original.IPsecTransportKey.PublicKey) != "public" ||
		string(original.IPsecTransportKey.PrivateKey) != "private" {
		t.Fatalf("top-level runtime fields share mutable state: %#v", original)
	}
	if original.RoutingReconcile.LastError != "routing-error" ||
		original.FirewallReconcile.Instances["fw-a"].PolicyHash != "hash-a" ||
		original.EndpointACLs["api"].Selectors[0] != "zone:catofes." ||
		original.BirdInstances["mesh"].Overlays[0] != "main" {
		t.Fatalf("nested runtime fields share mutable state: %#v", original)
	}
	if cloned.FirewallReconcile.Instances["nil"] != nil || cloned.BirdInstances["nil"] != nil {
		t.Fatalf("nil map entries were not preserved: firewall=%#v bird=%#v", cloned.FirewallReconcile.Instances, cloned.BirdInstances)
	}
}

func TestCloneRuntimeStatePreservesNilAndEmptyShape(t *testing.T) {
	original := &RuntimeState{
		PeerCleanups:      map[string]photonstate.PeerLifecycleCleanupState{},
		EndpointACLs:      map[string]photonstate.EndpointACL{"empty": {Selectors: []string{}}},
		BirdInstances:     map[string]*photonstate.BirdInstanceState{},
		FirewallReconcile: &photonstate.FirewallReconcileState{Instances: map[string]*photonstate.FirewallReconcileInstance{}},
	}
	cloned := CloneRuntimeState(original)
	if cloned.PeerCleanups == nil || cloned.EndpointACLs == nil ||
		cloned.EndpointACLs["empty"].Selectors == nil || cloned.BirdInstances == nil ||
		cloned.FirewallReconcile.Instances == nil {
		t.Fatalf("nil/empty shape changed: %#v", cloned)
	}
	if got := CloneRuntimeState(nil); got == nil || !reflect.DeepEqual(got, &RuntimeState{}) {
		t.Fatalf("nil runtime clone = %#v, want empty runtime", got)
	}
}

func TestRuntimeStateSchemaGuard(t *testing.T) {
	want := []string{
		"PeerCleanups", "IPsecTransportKey", "RoutingReconcile",
		"FirewallReconcile", "EndpointACLs", "BirdInstances",
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

func TestRuntimeStateJSONDropsLegacyDerivedFields(t *testing.T) {
	var state RuntimeState
	if err := json.Unmarshal([]byte(`{"identity_key_path":"/old/key.json","admission":{"pending":true},"ipsec_port_record":{"generation":7},"link_instances":{"link-a":{"id":"link-a"}},"ipsec_reconcile":{"desired_links":1},"endpoint_acls":{"api":{"name":"api"}}}`), &state); err != nil {
		t.Fatalf("decode old payload: %v", err)
	}
	payload, err := json.Marshal(&state)
	if err != nil {
		t.Fatalf("encode current payload: %v", err)
	}
	if strings.Contains(string(payload), "identity_key_path") || strings.Contains(string(payload), "admission") || strings.Contains(string(payload), "ipsec_port_record") || strings.Contains(string(payload), "link_instances") || strings.Contains(string(payload), "ipsec_reconcile") || state.EndpointACLs["api"].Name != "api" {
		t.Fatalf("current state retained legacy derived fields or lost durable fields: %s", payload)
	}
}
