package main

import (
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"testing"
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

func TestParseConfigYAMLNetNSDefaultsAndCreateOverride(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    name: photontesth2
  existing:
    name: existing
    create: false
  forwarded:
    name: forwarded
    forwarding: {}
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	for name, wantCreate := range map[string]bool{"default": true, "existing": false} {
		spec := config.Netns.Names[name]
		if spec.Kind != ipsec.NetNSName || spec.Create != wantCreate {
			t.Fatalf("netns.%s = %+v, want kind=name create=%t", name, spec, wantCreate)
		}
	}
	if policy := config.Netns.ForwardingPolicy("default"); policy.Transit {
		t.Fatalf("default forwarding policy = %+v, want non-transit", policy)
	}
	if policy := config.Netns.ForwardingPolicy("forwarded"); !policy.Transit {
		t.Fatalf("forwarded forwarding policy = %+v, want transit", policy)
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
		if err := parseConfigYAML(input, config); err == nil {
			t.Fatalf("parseConfigYAML should reject legacy default_netns: %s", input)
		}
	}
}

func TestParseConfigYAMLNetNSNamedSiblings(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
  edge:
    kind: name
    name: edge
    create: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if spec, ok := config.Netns.Names["default"]; !ok || spec.Name != "photontesth2" || !spec.Create {
		t.Fatalf("netns.default = %+v, ok=%t", spec, ok)
	}
	if spec, ok := config.Netns.Names["edge"]; !ok || spec.Name != "edge" || !spec.Create {
		t.Fatalf("netns.edge = %+v, ok=%t", spec, ok)
	}
}

func TestParseConfigYAMLNetNSForwarding(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
    forwarding:
      allow_prefixes:
        - 10.42.0.0/16
      deny_prefixes:
        - 10.42.99.0/24
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	for _, key := range []string{"default", "photontesth2"} {
		policy := config.Netns.Forwarding[key]
		if !policy.Transit || len(policy.AllowPrefixes) != 1 || len(policy.DenyPrefixes) != 1 {
			t.Fatalf("Netns.Forwarding[%q] = %+v", key, policy)
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
	if err == nil {
		t.Fatal("parseConfigYAML should reject forwarding under firewall instance")
	}
}

func TestParseConfigYAMLNamedNetNSForwardingUsesTargetAlias(t *testing.T) {
	config := defaultAppConfig()
	if err := parseConfigYAML(`
netns:
  edge:
    kind: name
    name: physical-edge
    create: true
    forwarding:
      transit: true
`, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if !config.Netns.ForwardingPolicy("edge").Transit || !config.Netns.ForwardingPolicy("physical-edge").Transit {
		t.Fatal("named netns policy should be available by config key and resolved target")
	}
}
