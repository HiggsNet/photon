package photonwindows

import (
	"reflect"
	"strings"
	"testing"
)

func TestMarshalConfigUsesOneSchemaAndNormalizer(t *testing.T) {
	var options ConfigOptions
	options.SchemaVersion = ConfigSchemaVersion
	options.TrustedRootPublicKey, options.ManagedZone = strings.Repeat("01", 32), "node.catofes."
	options.State.Path = `C:\ProgramData\Photon\node.db`
	options.Overlay.ID, options.Overlay.SplitRoutes = "lab", []string{"10.42.0.0/16", "fd42::/16"}
	options.Gateway.AllowedZones = []string{"one.catofes.", "two.catofes."}
	options.Gateway.BootstrapHints = []BootstrapHintOptions{{Peer: "one.catofes.", Address: "bootstrap.example:33434"}, {Peer: "two.catofes.", Address: "[2001:db8::1]:33435"}}
	want, err := normalizeConfig(options)
	if err != nil {
		t.Fatal(err)
	}
	data, err := MarshalConfig(options)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseConfig(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("file parsing and form serialization apply different normalization rules")
	}
	options.SchemaVersion++
	if data, err := MarshalConfig(options); err == nil || data != nil {
		t.Fatal("unsupported schema serialized")
	}
	options.SchemaVersion = ConfigSchemaVersion
	options.Gateway.BootstrapHints[0].Peer = "unknown.catofes."
	if data, err := MarshalConfig(options); err == nil || data != nil {
		t.Fatal("unselected bootstrap peer serialized")
	}
}
