package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestParseConfigYAMLRoutingInstances(t *testing.T) {
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
      provider: bird
      mode: external
      shutdown_policy: stop
      control_socket: /run/photon/bird-main.ctl
      pid_file: /run/photon/bird-main.pid
      config_file: /etc/photon/bird-main.conf
      table: "254"
      metric_base: 150
      metric_staged: 250
      metric_draining: 550
      rtt_cost: 80
      rtt_min: 5ms
      rtt_max: 450ms
      rtt_decay: 9
      hello_interval: 2s
      update_interval: 20s
      ecmp: false
      ecmp_limit: 8
      interface_pattern: phx*
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.Routing.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Routing.Instances))
	}
	inst := config.Routing.Instances[0]
	if inst.ID != "main" {
		t.Fatalf("inst.ID = %q, want main", inst.ID)
	}
	if inst.NetNS != "photontesth2" {
		t.Fatalf("inst.NetNS = %q, want photontesth2", inst.NetNS)
	}
	if !inst.Enabled {
		t.Fatalf("inst.Enabled = false, want true")
	}
	if inst.Protocol != "bird" {
		t.Fatalf("inst.Protocol = %q, want bird", inst.Protocol)
	}
	if inst.Mode != ipsec.RoutingModeExternal {
		t.Fatalf("inst.Mode = %q, want external", inst.Mode)
	}
	if inst.ShutdownPolicy != routingShutdownPolicyStop {
		t.Fatalf("inst.ShutdownPolicy = %q, want stop", inst.ShutdownPolicy)
	}
	if inst.ControlSocket != "/run/photon/bird-main.ctl" {
		t.Fatalf("inst.ControlSocket = %q", inst.ControlSocket)
	}
	if inst.PIDFile != "/run/photon/bird-main.pid" {
		t.Fatalf("inst.PIDFile = %q", inst.PIDFile)
	}
	if inst.ConfigFile != "/etc/photon/bird-main.conf" {
		t.Fatalf("inst.ConfigFile = %q", inst.ConfigFile)
	}
	if inst.TableID != "254" {
		t.Fatalf("inst.TableID = %q, want 254", inst.TableID)
	}
	if inst.MetricBase != 150 {
		t.Fatalf("inst.MetricBase = %d, want 150", inst.MetricBase)
	}
	if inst.MetricStaged != 250 {
		t.Fatalf("inst.MetricStaged = %d, want 250", inst.MetricStaged)
	}
	if inst.MetricDraining != 550 {
		t.Fatalf("inst.MetricDraining = %d, want 550", inst.MetricDraining)
	}
	if inst.RTTCost != 80 || inst.RTTMin != 5*time.Millisecond || inst.RTTMax != 450*time.Millisecond || inst.RTTDecay != 9 {
		t.Fatalf("inst RTT tuning = cost %d min %s max %s decay %d", inst.RTTCost, inst.RTTMin, inst.RTTMax, inst.RTTDecay)
	}
	if inst.HelloInterval != 2*time.Second || inst.UpdateInterval != 20*time.Second {
		t.Fatalf("inst Babel intervals = hello %s update %s", inst.HelloInterval, inst.UpdateInterval)
	}
	if inst.ECMP {
		t.Fatalf("inst.ECMP = true, want false")
	}
	if inst.ECMPLimit != 8 {
		t.Fatalf("inst.ECMPLimit = %d, want 8", inst.ECMPLimit)
	}
	if inst.InterfacePat != "phx*" {
		t.Fatalf("inst.InterfacePat = %q, want phx*", inst.InterfacePat)
	}
}

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

func TestParseConfigYAMLRoutingInstancesDefaults(t *testing.T) {
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
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.Routing.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Routing.Instances))
	}
	inst := config.Routing.Instances[0]
	if inst.Mode != ipsec.RoutingModeManaged {
		t.Fatalf("inst.Mode = %q, want managed", inst.Mode)
	}
	if inst.ShutdownPolicy != routingShutdownPolicyPersist {
		t.Fatalf("inst.ShutdownPolicy = %q, want persist", inst.ShutdownPolicy)
	}
	if inst.Protocol != "bird" {
		t.Fatalf("inst.Protocol = %q, want bird", inst.Protocol)
	}
	if inst.TableID != "main" {
		t.Fatalf("inst.TableID = %q, want main", inst.TableID)
	}
	if inst.MetricBase != 100 {
		t.Fatalf("inst.MetricBase = %d, want 100", inst.MetricBase)
	}
	if inst.MetricStaged != 1200 {
		t.Fatalf("inst.MetricStaged = %d, want 1200", inst.MetricStaged)
	}
	if inst.MetricDraining != 2400 {
		t.Fatalf("inst.MetricDraining = %d, want 2400", inst.MetricDraining)
	}
	if inst.RTTCost != bird.DefaultBabelRTTCost || inst.RTTMin != bird.DefaultBabelRTTMin || inst.RTTMax != bird.DefaultBabelRTTMax || inst.RTTDecay != bird.DefaultBabelRTTDecay {
		t.Fatalf("inst default RTT tuning = cost %d min %s max %s decay %d", inst.RTTCost, inst.RTTMin, inst.RTTMax, inst.RTTDecay)
	}
	if inst.MetricBase+inst.RTTCost >= inst.MetricStaged {
		t.Fatalf("normal metric plus max RTT penalty must stay below staged metric")
	}
	if inst.MetricStaged+inst.RTTCost >= inst.MetricDraining {
		t.Fatalf("staged metric plus max RTT penalty must stay below draining metric")
	}
	if inst.HelloInterval != bird.DefaultBabelHelloInterval || inst.UpdateInterval != bird.DefaultBabelUpdateInterval {
		t.Fatalf("inst default Babel intervals = hello %s update %s", inst.HelloInterval, inst.UpdateInterval)
	}
	if !inst.ECMP {
		t.Fatalf("inst.ECMP = false, want true")
	}
	if inst.ECMPLimit != 16 {
		t.Fatalf("inst.ECMPLimit = %d, want 16", inst.ECMPLimit)
	}
	if inst.InterfacePat != "phx*" {
		t.Fatalf("inst.InterfacePat = %q, want phx*", inst.InterfacePat)
	}
}

func TestParseConfigYAMLRoutingInstancesRejectsInvalidShutdownPolicy(t *testing.T) {
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
      shutdown_policy: drain
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatal("parseConfigYAML should reject unsupported routing.instances[].shutdown_policy")
	}
}

func TestParseConfigYAMLRoutingInstancesRejectsInvalidBabelTuning(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config string
	}{
		{name: "RTT cost too large", config: "rtt_cost: 65535"},
		{name: "RTT max before min", config: "rtt_min: 20ms\n      rtt_max: 10ms"},
		{name: "RTT decay too large", config: "rtt_decay: 257"},
		{name: "sub-millisecond interval", config: "hello_interval: 500us"},
		{name: "negative update interval", config: "update_interval: -1s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
      ` + tc.config + "\n"
			if err := parseConfigYAML(input, config); err == nil {
				t.Fatalf("parseConfigYAML should reject:\n%s", input)
			}
		})
	}
}

func TestParseConfigYAMLRoutingInstanceDefaultsToDefaultNetNS(t *testing.T) {
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
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.Routing.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Routing.Instances))
	}
	inst := config.Routing.Instances[0]
	if inst.NetNS != "photontesth2" {
		t.Fatalf("inst.NetNS = %q, want resolved default photontesth2", inst.NetNS)
	}
	if inst.ControlSocket != filepath.Join(config.DataDir, "bird", "bird-photontesth2.ctl") {
		t.Fatalf("inst.ControlSocket = %q, want resolved-netns-derived path", inst.ControlSocket)
	}
	if inst.PIDFile != filepath.Join(config.DataDir, "bird", "bird-photontesth2.pid") {
		t.Fatalf("inst.PIDFile = %q, want resolved-netns-derived path", inst.PIDFile)
	}
	if inst.ConfigFile != filepath.Join(config.DataDir, "bird", "bird-photontesth2.conf") {
		t.Fatalf("inst.ConfigFile = %q, want resolved-netns-derived path", inst.ConfigFile)
	}
}

func TestParseRoutingInstanceShortensLongDefaultControlSocket(t *testing.T) {
	dataDir := t.TempDir()
	netnsName := "photon-bird-adopt-1785506688595201909"
	netns := photonlinux.NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"default": {Kind: ipsec.NetNSName, Name: netnsName},
	}}
	instance, err := parseRoutingInstance(routingInstanceYAML{ID: "main"}, netns, dataDir)
	if err != nil {
		t.Fatalf("parseRoutingInstance: %v", err)
	}
	raw := filepath.Join(dataDir, "bird", "bird-"+netnsName+".ctl")
	if len(raw) <= bird.MaxControlSocketPathBytes {
		t.Fatalf("test fixture raw socket path = %d bytes, want over %d", len(raw), bird.MaxControlSocketPathBytes)
	}
	if len(instance.ControlSocket) > bird.MaxControlSocketPathBytes {
		t.Fatalf("shortened control socket = %d bytes: %s", len(instance.ControlSocket), instance.ControlSocket)
	}
	if instance.ControlSocket == raw || !strings.HasPrefix(filepath.Base(instance.ControlSocket), "bird-") || filepath.Ext(instance.ControlSocket) != ".ctl" {
		t.Fatalf("shortened control socket = %q, want stable bird hash filename", instance.ControlSocket)
	}

	again, err := parseRoutingInstance(routingInstanceYAML{ID: "main"}, netns, dataDir)
	if err != nil {
		t.Fatalf("parseRoutingInstance(second): %v", err)
	}
	if again.ControlSocket != instance.ControlSocket {
		t.Fatalf("shortened control socket is not stable: %q != %q", again.ControlSocket, instance.ControlSocket)
	}
	if instance.PIDFile != filepath.Join(dataDir, "bird", "bird-"+netnsName+".pid") ||
		instance.ConfigFile != filepath.Join(dataDir, "bird", "bird-"+netnsName+".conf") {
		t.Fatal("non-socket BIRD paths were unexpectedly shortened")
	}
}

func TestParseRoutingInstanceUsesRuntimeSocketWhenDataDirIsTooLong(t *testing.T) {
	netns := photonlinux.NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"default": {Kind: ipsec.NetNSName, Name: "photon-test"},
	}}
	longDataDir := filepath.Join("/tmp", strings.Repeat("d", bird.MaxControlSocketPathBytes))
	instance, err := parseRoutingInstance(routingInstanceYAML{ID: "main"}, netns, longDataDir)
	if err != nil {
		t.Fatalf("parseRoutingInstance long data dir: %v", err)
	}
	if !strings.HasPrefix(instance.ControlSocket, "/run/photon/bird/bird-") || len(instance.ControlSocket) > bird.MaxControlSocketPathBytes {
		t.Fatalf("runtime control socket = %q", instance.ControlSocket)
	}
	other, err := parseRoutingInstance(routingInstanceYAML{ID: "main"}, netns, longDataDir+"-other")
	if err != nil {
		t.Fatalf("parseRoutingInstance other long data dir: %v", err)
	}
	if other.ControlSocket == instance.ControlSocket {
		t.Fatal("different data dirs produced the same runtime control socket")
	}
}

func TestParseRoutingInstanceRejectsExplicitOverlongControlSocket(t *testing.T) {
	netns := photonlinux.NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"default": {Kind: ipsec.NetNSName, Name: "photon-test"},
	}}
	tooLong := "/" + strings.Repeat("x", bird.MaxControlSocketPathBytes) + ".ctl"
	_, err := parseRoutingInstance(routingInstanceYAML{ID: "main", ControlSocket: tooLong}, netns, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "exceeds Linux limit") {
		t.Fatalf("parseRoutingInstance explicit long socket error = %v", err)
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
	if inst.NetNS != ipsec.DefaultNetNSName {
		t.Fatalf("inst.NetNS = %q, want default netns target %q", inst.NetNS, ipsec.DefaultNetNSName)
	}
	if inst.Upstream == nil || !inst.Upstream.Enabled {
		t.Fatal("upstream should be enabled")
	}
	if !inst.Upstream.CreateVeth {
		t.Fatal("upstream create_veth should default to true")
	}
	if inst.Upstream.MeshInterface != "phv2host" || inst.Upstream.ExternalInterface != "phv2mesh" {
		t.Fatalf("upstream interfaces = %q/%q, want phv2host/phv2mesh", inst.Upstream.MeshInterface, inst.Upstream.ExternalInterface)
	}
}

func TestParseConfigYAMLRoutingInstanceDisabled(t *testing.T) {
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
      disabled: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.Routing.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Routing.Instances))
	}
	if config.Routing.Instances[0].Enabled {
		t.Fatalf("routing instance should be disabled")
	}
}

func TestParseConfigYAMLRejectsConflictingEnabledDisabled(t *testing.T) {
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
      enabled: true
      disabled: true
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatal("parseConfigYAML should reject conflicting enabled/disabled")
	}
}
