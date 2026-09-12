package photonlinux

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	photonstate "github.com/HiggsNet/photon/internal/state"
)

func TestCloneLinuxStateDeepCopiesMutableFields(t *testing.T) {
	original := &LinuxState{
		IPsecTransportKey: &photonstate.IPsecTransportKeyState{PublicKey: []byte("public"), PrivateKey: []byte("private")},
		EndpointACLs:      map[string]photonstate.EndpointACL{"api": {Selectors: []string{"zone:catofes."}}},
	}

	cloned := CloneLinuxState(original)
	cloned.IPsecTransportKey.PublicKey[0] = 'P'
	cloned.IPsecTransportKey.PrivateKey[0] = 'S'
	cloned.EndpointACLs["api"].Selectors[0] = "zone:changed."

	if string(original.IPsecTransportKey.PublicKey) != "public" ||
		string(original.IPsecTransportKey.PrivateKey) != "private" {
		t.Fatalf("top-level runtime fields share mutable state: %#v", original)
	}
	if original.EndpointACLs["api"].Selectors[0] != "zone:catofes." {
		t.Fatalf("nested runtime fields share mutable state: %#v", original)
	}
}

func TestCloneLinuxStatePreservesNilAndEmptyShape(t *testing.T) {
	original := &LinuxState{
		EndpointACLs: map[string]photonstate.EndpointACL{"empty": {Selectors: []string{}}},
	}
	cloned := CloneLinuxState(original)
	if cloned.EndpointACLs == nil ||
		cloned.EndpointACLs["empty"].Selectors == nil {
		t.Fatalf("nil/empty shape changed: %#v", cloned)
	}
	if got := CloneLinuxState(nil); got == nil || !reflect.DeepEqual(got, &LinuxState{}) {
		t.Fatalf("nil runtime clone = %#v, want empty runtime", got)
	}
}

func TestLinuxStateJSONSchemaGuard(t *testing.T) {
	want := []string{
		"IPsecTransportKey", "EndpointACLs",
	}
	typ := reflect.TypeOf(LinuxState{})
	if typ.NumField() != len(want) {
		t.Fatalf("LinuxState field count = %d, want %d (%v)", typ.NumField(), len(want), want)
	}
	for index, name := range want {
		if got := typ.Field(index).Name; got != name {
			t.Fatalf("LinuxState field %d = %s, want %s", index, got, name)
		}
	}
}

func TestLinuxStateJSONDropsLegacyDerivedFields(t *testing.T) {
	var state LinuxState
	if err := json.Unmarshal([]byte(`{"identity_key_path":"/old/key.json","admission":{"pending":true},"ipsec_port_record":{"generation":7},"link_instances":{"link-a":{"id":"link-a"}},"ipsec_reconcile":{"desired_links":1},"routing_reconcile":{"last_error":"old"},"firewall_reconcile":{"last_error":"old"},"bird_instances":{"mesh":{"state":"running"}},"peer_cleanups":{"peer":{"reason":"offline"}},"endpoint_acls":{"api":{"name":"api"}}}`), &state); err != nil {
		t.Fatalf("decode old payload: %v", err)
	}
	payload, err := json.Marshal(&state)
	if err != nil {
		t.Fatalf("encode current payload: %v", err)
	}
	if strings.Contains(string(payload), "identity_key_path") || strings.Contains(string(payload), "admission") || strings.Contains(string(payload), "ipsec_port_record") || strings.Contains(string(payload), "link_instances") || strings.Contains(string(payload), "ipsec_reconcile") || strings.Contains(string(payload), "routing_reconcile") || strings.Contains(string(payload), "firewall_reconcile") || strings.Contains(string(payload), "bird_instances") || strings.Contains(string(payload), "peer_cleanups") || state.EndpointACLs["api"].Name != "api" {
		t.Fatalf("current state retained legacy derived fields or lost durable fields: %s", payload)
	}
}
