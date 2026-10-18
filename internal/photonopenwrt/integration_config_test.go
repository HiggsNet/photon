package photonopenwrt

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestIntegrationConfigDefaultsAndValidation(t *testing.T) {
	if (Config{}).Enabled() || (Config{}).Validate() != nil {
		t.Fatal("default integration must be disabled")
	}
	for _, config := range []Config{{AnnounceIPsec: true}, {AutoFirewall: true}, {WANNetworks: []string{"wan", "wan"}}, {WANNetworks: []string{"../wan"}}, {WANNetworks: []string{"wan; restart"}}} {
		if config.Validate() == nil {
			t.Fatalf("accepted %+v", config)
		}
	}
	config, err := integrationConfigFromYAML("data_dir: /etc/photon\n")
	if err != nil || config.Enabled() || len(config.WANNetworks) != 0 {
		t.Fatalf("defaults = %+v %v", config, err)
	}
}

func TestIntegrationConfigNodeEditPreservesOtherConfiguration(t *testing.T) {
	before := "# root comment\nidentity_key_path: &identity '/etc/photon/private.pem' # keep identity\ncopy: *identity\nnetwork:\n  nested: [1, 2, 3]\nopenwrt:\n  # keep block comment\n  wan_networks: [old]\n  future_setting: retained\n  announce_ipsec: false\n"
	settings := Config{WANNetworks: []string{"wan", "wan6"}, AnnounceIPsec: true, AutoFirewall: true}
	after, err := updateIntegrationConfig(before, settings)
	if err != nil {
		t.Fatal(err)
	}
	var oldMap, newMap map[string]any
	if err := yaml.Unmarshal([]byte(before), &oldMap); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(after), &newMap); err != nil {
		t.Fatal(err)
	}
	delete(oldMap, "openwrt")
	block := newMap["openwrt"].(map[string]any)
	delete(newMap, "openwrt")
	if !reflect.DeepEqual(oldMap, newMap) || block["future_setting"] != "retained" {
		t.Fatalf("unrelated configuration changed: %s", after)
	}
	for _, comment := range []string{"# root comment", "# keep identity", "# keep block comment"} {
		if !strings.Contains(after, comment) {
			t.Fatalf("lost comment %q: %s", comment, after)
		}
	}
	read, err := integrationConfigFromYAML(after)
	if err != nil || !reflect.DeepEqual(read, settings) {
		t.Fatalf("roundtrip = %+v %v", read, err)
	}
	for _, bad := range []string{"[]", "data_dir: /a\n---\nopenwrt: {}\n", "openwrt: {}\nopenwrt: {}\n"} {
		if _, err := updateIntegrationConfig(bad, settings); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
