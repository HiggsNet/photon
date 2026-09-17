package main

import (
	"strings"
	"testing"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestParseConfigYAMLNetNSDefault(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.Netns.Default != "default" {
		t.Fatalf("Netns.Default = %q, want default", config.Netns.Default)
	}
	spec := config.Netns.Names["default"]
	if spec.Kind != ipsec.NetNSName || spec.Name != "photontesth2" || !spec.Create {
		t.Fatalf("Netns.Names[default] = %+v", spec)
	}
}

func TestParseConfigYAMLRejectsLegacyDefaultNetNS(t *testing.T) {
	for _, input := range []string{`
ipsec:
  default_netns:
    kind: name
    name: legacytesth2
    create: true
`, `
overlay:
  default_netns:
    kind: name
    name: legacytesth2
    create: true
`} {
		config := defaultAppConfig()
		if err := parseConfigYAML(input, config); err == nil || !strings.Contains(err.Error(), "field default_netns not found") {
			t.Fatalf("expected unknown default_netns field error, got %v for %s", err, input)
		}
	}
}

func TestParseConfigYAMLRejectsFirewallForwarding(t *testing.T) {
	config := defaultAppConfig()
	err := parseConfigYAML(`
firewall:
  instances:
    - id: mesh
      forwarding:
        transit: true
`, config)
	if err == nil || !strings.Contains(err.Error(), "field forwarding not found") {
		t.Fatalf("expected unknown forwarding field error, got %v", err)
	}
}
