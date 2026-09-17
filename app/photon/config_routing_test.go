package main

import (
	"path/filepath"
	"testing"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestParseConfigYAMLRoutingInstancesRejectsLegacyProtocolAlias(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
routing:
  instances:
    - id: main
      netns: photontesth2
      protocol: bird
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatal("parseConfigYAML should reject routing.instances[].protocol")
	}
}

func TestParseConfigYAMLRoutingInstanceDefaultsToDefaultNetNS(t *testing.T) {
	config := defaultAppConfig()
	input := `
data_dir: /tmp/photon-config-test
netns:
  default:
    kind: name
    name: photontesth2
    create: true
routing:
  instances:
    - id: main
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.Routing.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Routing.Instances))
	}
	inst := config.Routing.Instances[0]
	if inst.Bird.NetNSName != "photontesth2" {
		t.Fatalf("inst.NetNS = %q, want resolved default photontesth2", inst.Bird.NetNSName)
	}
	if inst.Bird.ControlSocketPath != filepath.Join(config.DataDir, "bird", "bird-photontesth2.ctl") {
		t.Fatalf("inst.ControlSocket = %q, want resolved-netns-derived path", inst.Bird.ControlSocketPath)
	}
	if inst.Bird.PIDFilePath != filepath.Join(config.DataDir, "bird", "bird-photontesth2.pid") {
		t.Fatalf("inst.PIDFile = %q, want resolved-netns-derived path", inst.Bird.PIDFilePath)
	}
	if inst.Bird.ConfigPath != filepath.Join(config.DataDir, "bird", "bird-photontesth2.conf") {
		t.Fatalf("inst.ConfigFile = %q, want resolved-netns-derived path", inst.Bird.ConfigPath)
	}
}

func TestParseConfigYAMLRoutingUpstreamDefaultUsesResolvedDefaultNetNS(t *testing.T) {
	config := defaultAppConfig()
	input := `
routing:
  instances:
    - id: main
      upstream: {}
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.Routing.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Routing.Instances))
	}
	inst := config.Routing.Instances[0]
	if inst.Bird.NetNSName != ipsec.DefaultNetNSName {
		t.Fatalf("inst.NetNS = %q, want default netns target %q", inst.Bird.NetNSName, ipsec.DefaultNetNSName)
	}
	if inst.Upstream == nil || !inst.Upstream.Enabled {
		t.Fatal("upstream should be enabled")
	}
	if inst.Upstream.Veth.MeshNetns != inst.Bird.NetNSName {
		t.Fatalf("upstream namespace = %q, want routing namespace %q", inst.Upstream.Veth.MeshNetns, inst.Bird.NetNSName)
	}
}
