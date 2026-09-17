package photonlinux

import (
	"strings"
	"testing"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"gopkg.in/yaml.v3"
)

func TestParseNetNSDefaultsAndCreateOverride(t *testing.T) {
	input := `
default:
  name: photontesth2
existing:
  name: existing
  create: false
forwarded:
  name: forwarded
  forwarding: {}
`
	var raw NetNSConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	config, err := ParseNetNSConfig(&raw, ipsec.NetNSSpec{})
	if err != nil {
		t.Fatalf("ParseNetNSConfig: %v", err)
	}
	for name, wantCreate := range map[string]bool{"default": true, "existing": false} {
		spec := config.Names[name]
		if spec.Kind != ipsec.NetNSName || spec.Create != wantCreate {
			t.Fatalf("netns.%s = %+v, want kind=name create=%t", name, spec, wantCreate)
		}
	}
	if policy := config.ForwardingPolicy("default"); policy.Transit {
		t.Fatalf("default forwarding policy = %+v, want non-transit", policy)
	}
	if policy := config.ForwardingPolicy("forwarded"); !policy.Transit {
		t.Fatalf("forwarded forwarding policy = %+v, want transit", policy)
	}
}

func TestParseNetNSNamedSiblings(t *testing.T) {
	input := `
default:
  kind: name
  name: photontesth2
  create: true
edge:
  kind: name
  name: edge
  create: true
`
	var raw NetNSConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	config, err := ParseNetNSConfig(&raw, ipsec.NetNSSpec{})
	if err != nil {
		t.Fatalf("ParseNetNSConfig: %v", err)
	}
	if spec, ok := config.Names["default"]; !ok || spec.Name != "photontesth2" || !spec.Create {
		t.Fatalf("netns.default = %+v, ok=%t", spec, ok)
	}
	if spec, ok := config.Names["edge"]; !ok || spec.Name != "edge" || !spec.Create {
		t.Fatalf("netns.edge = %+v, ok=%t", spec, ok)
	}
}

func TestParseNetNSForwarding(t *testing.T) {
	input := `
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
	var raw NetNSConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	config, err := ParseNetNSConfig(&raw, ipsec.NetNSSpec{})
	if err != nil {
		t.Fatalf("ParseNetNSConfig: %v", err)
	}
	for _, key := range []string{"default", "photontesth2"} {
		policy := config.Forwarding[key]
		if !policy.Transit || len(policy.AllowPrefixes) != 1 || len(policy.DenyPrefixes) != 1 {
			t.Fatalf("Netns.Forwarding[%q] = %+v", key, policy)
		}
	}
}

func TestParseNamedNetNSForwardingUsesTargetAlias(t *testing.T) {
	input := `
edge:
  kind: name
  name: physical-edge
  create: true
  forwarding:
    transit: true
`
	var raw NetNSConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	config, err := ParseNetNSConfig(&raw, ipsec.NetNSSpec{})
	if err != nil {
		t.Fatalf("ParseNetNSConfig: %v", err)
	}
	if !config.ForwardingPolicy("edge").Transit || !config.ForwardingPolicy("physical-edge").Transit {
		t.Fatal("named netns policy should be available by config key and resolved target")
	}
}
func TestParseRejectsInvalidNetNSDefault(t *testing.T) {
	input := `
default:
  kind: host
  create: true
`
	var raw NetNSConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	_, err := ParseNetNSConfig(&raw, ipsec.NetNSSpec{})
	if err == nil || !strings.Contains(err.Error(), "host netns must not set name, path, or create") {
		t.Fatalf("expected host netns create error, got %v", err)
	}
}
