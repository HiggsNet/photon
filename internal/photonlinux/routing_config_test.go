package photonlinux

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"gopkg.in/yaml.v3"
)

func TestParseUpstreamConfig(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: photontesth2
    upstream:
      create_veth: true
      mesh:
        interface: phv2host
        ipv4_ll: "169.254.0.1/30"
        ipv6_ll: "fe80::1/64"
      external:
        interface: phv2mesh
        netns: ""
        ipv4_ll: "169.254.0.2/30"
        ipv6_ll: "fe80::2/64"
`
	var yamlCfg RoutingConfigYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"photontesth2": {Kind: "name", Name: "photontesth2", Create: true},
	}}
	cfg, err := ParseRoutingConfig(yamlCfg.Instances, netnsCfg, "/tmp")
	if err != nil {
		t.Fatalf("ParseRoutingConfig: %v", err)
	}
	if len(cfg.Instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(cfg.Instances))
	}
	inst := cfg.Instances[0]
	if inst.Upstream == nil {
		t.Fatal("upstream is nil")
	}
	if !inst.Upstream.Enabled {
		t.Error("upstream not enabled")
	}
	if inst.Upstream.Mode != UpstreamModeStatic {
		t.Errorf("mode = %q, want static", inst.Upstream.Mode)
	}
	if !inst.Upstream.InstallSourceAddresses {
		t.Error("static mode should install source addresses by default")
	}
	if inst.Upstream.Veth.MeshInterface != "phv2host" {
		t.Errorf("mesh interface = %q, want phv2host", inst.Upstream.Veth.MeshInterface)
	}
	if !inst.Upstream.CreateVeth {
		t.Error("create_veth not set")
	}
	if inst.Upstream.Veth.PeerInterface != "phv2mesh" {
		t.Errorf("external interface = %q, want phv2mesh", inst.Upstream.Veth.PeerInterface)
	}
	if inst.Upstream.Veth.PeerNetns != "" {
		t.Errorf("external netns = %q, want empty", inst.Upstream.Veth.PeerNetns)
	}
	if inst.Upstream.Veth.MeshIPv4LL != "169.254.0.1/30" {
		t.Errorf("mesh ipv4_ll = %q, want 169.254.0.1/30", inst.Upstream.Veth.MeshIPv4LL)
	}
	if inst.Upstream.Veth.PeerIPv4LL != "169.254.0.2/30" {
		t.Errorf("external ipv4_ll = %q, want 169.254.0.2/30", inst.Upstream.Veth.PeerIPv4LL)
	}
	if inst.Upstream.Veth.MeshIPv6LL != "fe80::1/64" {
		t.Errorf("mesh ipv6_ll = %q, want fe80::1/64", inst.Upstream.Veth.MeshIPv6LL)
	}
	if inst.Upstream.Veth.PeerIPv6LL != "fe80::2/64" {
		t.Errorf("external ipv6_ll = %q, want fe80::2/64", inst.Upstream.Veth.PeerIPv6LL)
	}
}

func TestParseUpstreamConfigExternalMode(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: photontesth2
    upstream:
      mode: external
      install_source_addresses: true
`
	var yamlCfg RoutingConfigYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"photontesth2": {Kind: "name", Name: "photontesth2", Create: true},
	}}
	cfg, err := ParseRoutingConfig(yamlCfg.Instances, netnsCfg, "/tmp")
	if err != nil {
		t.Fatalf("ParseRoutingConfig: %v", err)
	}
	inst := cfg.Instances[0]
	if inst.Upstream == nil || inst.Upstream.Mode != UpstreamModeExternal {
		t.Fatalf("upstream mode = %#v, want external", inst.Upstream)
	}
	if !inst.Upstream.InstallSourceAddresses {
		t.Fatal("install_source_addresses = false, want explicit true")
	}
}

func TestParseUpstreamConfigExternalModeDoesNotInstallSourceAddressesByDefault(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: photontesth2
    upstream:
      mode: external
`
	var yamlCfg RoutingConfigYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"photontesth2": {Kind: "name", Name: "photontesth2", Create: true},
	}}
	cfg, err := ParseRoutingConfig(yamlCfg.Instances, netnsCfg, "/tmp")
	if err != nil {
		t.Fatalf("ParseRoutingConfig: %v", err)
	}
	if cfg.Instances[0].Upstream.InstallSourceAddresses {
		t.Fatal("external mode should not install source addresses by default")
	}
}

func TestParseUpstreamConfigRejectsInvalidMode(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: photontesth2
    upstream:
      mode: dynamic
`
	var yamlCfg RoutingConfigYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"photontesth2": {Kind: "name", Name: "photontesth2", Create: true},
	}}
	if _, err := ParseRoutingConfig(yamlCfg.Instances, netnsCfg, "/tmp"); err == nil {
		t.Fatal("expected invalid upstream mode error")
	}
}

func TestParseUpstreamConfigDisabled(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: photontesth2
    upstream:
      disabled: true
`
	var yamlCfg RoutingConfigYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"photontesth2": {Kind: "name", Name: "photontesth2", Create: true},
	}}
	cfg, err := ParseRoutingConfig(yamlCfg.Instances, netnsCfg, "/tmp")
	if err != nil {
		t.Fatalf("ParseRoutingConfig: %v", err)
	}
	inst := cfg.Instances[0]
	if inst.Upstream == nil {
		t.Fatal("upstream is nil")
	}
	if inst.Upstream.Enabled {
		t.Error("upstream should be disabled")
	}
}

func TestParseUpstreamConfigNil(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: photontesth2
`
	var yamlCfg RoutingConfigYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"photontesth2": {Kind: "name", Name: "photontesth2", Create: true},
	}}
	cfg, err := ParseRoutingConfig(yamlCfg.Instances, netnsCfg, "/tmp")
	if err != nil {
		t.Fatalf("ParseRoutingConfig: %v", err)
	}
	inst := cfg.Instances[0]
	if inst.Upstream != nil {
		t.Errorf("upstream should be nil, got %+v", inst.Upstream)
	}
}

func TestParseUpstreamConfigDefaults(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: photontesth2
    upstream: {}
`
	var yamlCfg RoutingConfigYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"photontesth2": {Kind: "name", Name: "photontesth2", Create: true},
	}}
	cfg, err := ParseRoutingConfig(yamlCfg.Instances, netnsCfg, "/tmp")
	if err != nil {
		t.Fatalf("ParseRoutingConfig: %v", err)
	}
	inst := cfg.Instances[0]
	if inst.Upstream == nil || !inst.Upstream.Enabled {
		t.Fatal("upstream should be enabled")
	}
	if inst.Upstream.Veth.MeshInterface != "phv2host" {
		t.Errorf("default mesh interface = %q, want phv2host", inst.Upstream.Veth.MeshInterface)
	}
	if inst.Upstream.Veth.PeerInterface != "phv2mesh" {
		t.Errorf("default external interface = %q, want phv2mesh", inst.Upstream.Veth.PeerInterface)
	}
	if !inst.Upstream.CreateVeth {
		t.Error("default create_veth = false, want true")
	}
	if inst.Upstream.Veth.PeerNetns != "" {
		t.Errorf("default external netns = %q, want empty host/init netns", inst.Upstream.Veth.PeerNetns)
	}
	if inst.Upstream.Veth.MeshIPv4LL != defaultMeshIPv4LL {
		t.Errorf("default mesh ipv4_ll = %q, want %q", inst.Upstream.Veth.MeshIPv4LL, defaultMeshIPv4LL)
	}
	if inst.Upstream.Veth.MeshIPv6LL != defaultMeshIPv6LL {
		t.Errorf("default mesh ipv6_ll = %q, want %q", inst.Upstream.Veth.MeshIPv6LL, defaultMeshIPv6LL)
	}
	if inst.Upstream.Veth.PeerIPv4LL != defaultExternalIPv4LL {
		t.Errorf("default external ipv4_ll = %q, want %q", inst.Upstream.Veth.PeerIPv4LL, defaultExternalIPv4LL)
	}
	if inst.Upstream.Veth.PeerIPv6LL != defaultExternalIPv6LL {
		t.Errorf("default external ipv6_ll = %q, want %q", inst.Upstream.Veth.PeerIPv6LL, defaultExternalIPv6LL)
	}
}

func TestParseUpstreamConfigCreateVethCanBeDisabled(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: photontesth2
    upstream:
      create_veth: false
`
	var yamlCfg RoutingConfigYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"photontesth2": {Kind: "name", Name: "photontesth2", Create: true},
	}}
	cfg, err := ParseRoutingConfig(yamlCfg.Instances, netnsCfg, "/tmp")
	if err != nil {
		t.Fatalf("ParseRoutingConfig: %v", err)
	}
	inst := cfg.Instances[0]
	if inst.Upstream == nil || !inst.Upstream.Enabled {
		t.Fatal("upstream should be enabled")
	}
	if inst.Upstream.CreateVeth {
		t.Error("create_veth = true, want explicit false")
	}
}

func TestParseUpstreamConfigInvalidIPv4(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: photontesth2
    upstream:
      mesh:
        ipv4_ll: "not-a-cidr"
`
	var yamlCfg RoutingConfigYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"photontesth2": {Kind: "name", Name: "photontesth2", Create: true},
	}}
	_, err := ParseRoutingConfig(yamlCfg.Instances, netnsCfg, "/tmp")
	if err == nil {
		t.Fatal("expected error for invalid mesh.ipv4_ll")
	}
}

func TestParseUpstreamConfigInvalidIPv6(t *testing.T) {
	yamlInput := `
instances:
  - id: main
    netns: photontesth2
    upstream:
      external:
        ipv6_ll: "not-a-cidr"
`
	var yamlCfg RoutingConfigYAML
	if err := yaml.Unmarshal([]byte(yamlInput), &yamlCfg); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}

	netnsCfg := NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"photontesth2": {Kind: "name", Name: "photontesth2", Create: true},
	}}
	_, err := ParseRoutingConfig(yamlCfg.Instances, netnsCfg, "/tmp")
	if err == nil {
		t.Fatal("expected error for invalid external.ipv6_ll")
	}
}

func TestParseRoutingInstanceShortensLongDefaultControlSocket(t *testing.T) {
	dataDir := t.TempDir()
	netnsName := "photon-bird-adopt-1785506688595201909"
	netns := NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"default": {Kind: ipsec.NetNSName, Name: netnsName},
	}}
	instance, err := parseRoutingInstance(RoutingInstanceYAML{ID: "main"}, netns, dataDir)
	if err != nil {
		t.Fatalf("parseRoutingInstance: %v", err)
	}
	raw := filepath.Join(dataDir, "bird", "bird-"+netnsName+".ctl")
	if len(raw) <= bird.MaxControlSocketPathBytes {
		t.Fatalf("test fixture raw socket path = %d bytes, want over %d", len(raw), bird.MaxControlSocketPathBytes)
	}
	if len(instance.Bird.ControlSocketPath) > bird.MaxControlSocketPathBytes {
		t.Fatalf("shortened control socket = %d bytes: %s", len(instance.Bird.ControlSocketPath), instance.Bird.ControlSocketPath)
	}
	if instance.Bird.ControlSocketPath == raw || !strings.HasPrefix(filepath.Base(instance.Bird.ControlSocketPath), "bird-") || filepath.Ext(instance.Bird.ControlSocketPath) != ".ctl" {
		t.Fatalf("shortened control socket = %q, want stable bird hash filename", instance.Bird.ControlSocketPath)
	}

	again, err := parseRoutingInstance(RoutingInstanceYAML{ID: "main"}, netns, dataDir)
	if err != nil {
		t.Fatalf("parseRoutingInstance(second): %v", err)
	}
	if again.Bird.ControlSocketPath != instance.Bird.ControlSocketPath {
		t.Fatalf("shortened control socket is not stable: %q != %q", again.Bird.ControlSocketPath, instance.Bird.ControlSocketPath)
	}
	if instance.Bird.PIDFilePath != filepath.Join(dataDir, "bird", "bird-"+netnsName+".pid") ||
		instance.Bird.ConfigPath != filepath.Join(dataDir, "bird", "bird-"+netnsName+".conf") {
		t.Fatal("non-socket BIRD paths were unexpectedly shortened")
	}
}

func TestParseRoutingInstanceUsesRuntimeSocketWhenDataDirIsTooLong(t *testing.T) {
	netns := NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"default": {Kind: ipsec.NetNSName, Name: "photon-test"},
	}}
	longDataDir := filepath.Join("/tmp", strings.Repeat("d", bird.MaxControlSocketPathBytes))
	instance, err := parseRoutingInstance(RoutingInstanceYAML{ID: "main"}, netns, longDataDir)
	if err != nil {
		t.Fatalf("parseRoutingInstance long data dir: %v", err)
	}
	if !strings.HasPrefix(instance.Bird.ControlSocketPath, "/run/photon/bird/bird-") || len(instance.Bird.ControlSocketPath) > bird.MaxControlSocketPathBytes {
		t.Fatalf("runtime control socket = %q", instance.Bird.ControlSocketPath)
	}
	other, err := parseRoutingInstance(RoutingInstanceYAML{ID: "main"}, netns, longDataDir+"-other")
	if err != nil {
		t.Fatalf("parseRoutingInstance other long data dir: %v", err)
	}
	if other.Bird.ControlSocketPath == instance.Bird.ControlSocketPath {
		t.Fatal("different data dirs produced the same runtime control socket")
	}
}

func TestParseRoutingInstanceRejectsExplicitOverlongControlSocket(t *testing.T) {
	netns := NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"default": {Kind: ipsec.NetNSName, Name: "photon-test"},
	}}
	tooLong := "/" + strings.Repeat("x", bird.MaxControlSocketPathBytes) + ".ctl"
	_, err := parseRoutingInstance(RoutingInstanceYAML{ID: "main", ControlSocket: tooLong}, netns, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "exceeds Linux limit") {
		t.Fatalf("parseRoutingInstance explicit long socket error = %v", err)
	}
}

func TestRoutingNamespaceTargets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spec  ipsec.NetNSSpec
		label string
		want  string
	}{
		{name: "host", spec: ipsec.NetNSSpec{Kind: ipsec.NetNSHost}, want: "host"},
		{name: "named alias", spec: ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "mesh-real"}, want: "mesh-real"},
		{name: "path", spec: ipsec.NetNSSpec{Kind: ipsec.NetNSPath, Path: "/run/netns/mesh"}, label: "mesh-stable", want: "/run/netns/mesh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseRoutingConfig([]RoutingInstanceYAML{{ID: "main", NetNS: "alias", RouterIDLabel: tc.label}}, NetNSConfig{Names: map[string]ipsec.NetNSSpec{"alias": tc.spec}}, "/tmp")
			if err != nil {
				t.Fatal(err)
			}
			inst := cfg.Instances[0]
			if inst.Bird.NetNSName != tc.want || NetNSTarget(tc.spec) != inst.Bird.NetNSName {
				t.Fatalf("routing and overlay namespace differ: instance=%q overlay=%q want=%q", inst.Bird.NetNSName, NetNSTarget(tc.spec), tc.want)
			}
			if inst.RouterIDLabel != tc.label {
				t.Fatalf("router ID label = %q, want %q", inst.RouterIDLabel, tc.label)
			}
		})
	}
	_, err := ParseRoutingConfig([]RoutingInstanceYAML{{ID: "main"}}, NetNSConfig{Names: map[string]ipsec.NetNSSpec{"default": {Kind: ipsec.NetNSPath, Path: "/run/netns/mesh"}}}, "/tmp")
	if err == nil {
		t.Fatal("path namespace without stable router ID label accepted")
	}
}

func TestParseRoutingInstances(t *testing.T) {
	input := `
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
	var raw RoutingConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatalf("decode routing YAML: %v", err)
	}
	namespaces := NetNSConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	config, err := ParseRoutingConfig(raw.Instances, namespaces, "/tmp")
	if err != nil {
		t.Fatalf("ParseRoutingConfig: %v", err)
	}
	if len(config.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Instances))
	}
	inst := config.Instances[0]
	if inst.ID != "main" {
		t.Fatalf("inst.ID = %q, want main", inst.ID)
	}
	if inst.Bird.NetNSName != "photontesth2" {
		t.Fatalf("inst.NetNS = %q, want photontesth2", inst.Bird.NetNSName)
	}
	if !inst.Enabled {
		t.Fatalf("inst.Enabled = false, want true")
	}
	if inst.Protocol != "bird" {
		t.Fatalf("inst.Protocol = %q, want bird", inst.Protocol)
	}
	if inst.Bird.Mode != ipsec.RoutingModeExternal {
		t.Fatalf("inst.Mode = %q, want external", inst.Bird.Mode)
	}
	if inst.ShutdownPolicy != RoutingShutdownPolicyStop {
		t.Fatalf("inst.ShutdownPolicy = %q, want stop", inst.ShutdownPolicy)
	}
	if inst.Bird.ControlSocketPath != "/run/photon/bird-main.ctl" {
		t.Fatalf("inst.ControlSocket = %q", inst.Bird.ControlSocketPath)
	}
	if inst.Bird.PIDFilePath != "/run/photon/bird-main.pid" {
		t.Fatalf("inst.PIDFile = %q", inst.Bird.PIDFilePath)
	}
	if inst.Bird.ConfigPath != "/etc/photon/bird-main.conf" {
		t.Fatalf("inst.ConfigFile = %q", inst.Bird.ConfigPath)
	}
	if inst.Bird.TableID != "254" {
		t.Fatalf("inst.TableID = %q, want 254", inst.Bird.TableID)
	}
	if inst.Bird.MetricBase != 150 {
		t.Fatalf("inst.MetricBase = %d, want 150", inst.Bird.MetricBase)
	}
	if inst.Bird.MetricStaged != 250 {
		t.Fatalf("inst.MetricStaged = %d, want 250", inst.Bird.MetricStaged)
	}
	if inst.Bird.MetricDraining != 550 {
		t.Fatalf("inst.MetricDraining = %d, want 550", inst.Bird.MetricDraining)
	}
	if inst.Bird.BabelRTTCost != 80 || inst.Bird.BabelRTTMin != 5*time.Millisecond || inst.Bird.BabelRTTMax != 450*time.Millisecond || inst.Bird.BabelRTTDecay != 9 {
		t.Fatalf("inst RTT tuning = cost %d min %s max %s decay %d", inst.Bird.BabelRTTCost, inst.Bird.BabelRTTMin, inst.Bird.BabelRTTMax, inst.Bird.BabelRTTDecay)
	}
	if inst.Bird.BabelHelloInterval != 2*time.Second || inst.Bird.BabelUpdateInterval != 20*time.Second {
		t.Fatalf("inst Babel intervals = hello %s update %s", inst.Bird.BabelHelloInterval, inst.Bird.BabelUpdateInterval)
	}
	if inst.Bird.ECMP {
		t.Fatalf("inst.ECMP = true, want false")
	}
	if inst.Bird.ECMPLimit != 8 {
		t.Fatalf("inst.ECMPLimit = %d, want 8", inst.Bird.ECMPLimit)
	}
	if len(inst.Bird.InterfacePatterns) != 1 || inst.Bird.InterfacePatterns[0] != "phx*" {
		t.Fatalf("inst.InterfacePat = %q, want phx*", inst.Bird.InterfacePatterns)
	}
}

func TestParseRoutingInstancesDefaults(t *testing.T) {
	input := `
instances:
  - id: main
    netns: photontesth2
`
	var raw RoutingConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatalf("decode routing YAML: %v", err)
	}
	namespaces := NetNSConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	config, err := ParseRoutingConfig(raw.Instances, namespaces, "/tmp")
	if err != nil {
		t.Fatalf("ParseRoutingConfig: %v", err)
	}
	if len(config.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Instances))
	}
	inst := config.Instances[0]
	if inst.Bird.Mode != ipsec.RoutingModeManaged {
		t.Fatalf("inst.Mode = %q, want managed", inst.Bird.Mode)
	}
	if inst.ShutdownPolicy != RoutingShutdownPolicyPersist {
		t.Fatalf("inst.ShutdownPolicy = %q, want persist", inst.ShutdownPolicy)
	}
	if inst.Protocol != "bird" {
		t.Fatalf("inst.Protocol = %q, want bird", inst.Protocol)
	}
	if inst.Bird.TableID != "main" {
		t.Fatalf("inst.TableID = %q, want main", inst.Bird.TableID)
	}
	if inst.Bird.MetricBase != 100 {
		t.Fatalf("inst.MetricBase = %d, want 100", inst.Bird.MetricBase)
	}
	if inst.Bird.MetricStaged != 1200 {
		t.Fatalf("inst.MetricStaged = %d, want 1200", inst.Bird.MetricStaged)
	}
	if inst.Bird.MetricDraining != 2400 {
		t.Fatalf("inst.MetricDraining = %d, want 2400", inst.Bird.MetricDraining)
	}
	if inst.Bird.BabelRTTCost != bird.DefaultBabelRTTCost || inst.Bird.BabelRTTMin != bird.DefaultBabelRTTMin || inst.Bird.BabelRTTMax != bird.DefaultBabelRTTMax || inst.Bird.BabelRTTDecay != bird.DefaultBabelRTTDecay {
		t.Fatalf("inst default RTT tuning = cost %d min %s max %s decay %d", inst.Bird.BabelRTTCost, inst.Bird.BabelRTTMin, inst.Bird.BabelRTTMax, inst.Bird.BabelRTTDecay)
	}
	if inst.Bird.MetricBase+inst.Bird.BabelRTTCost >= inst.Bird.MetricStaged {
		t.Fatalf("normal metric plus max RTT penalty must stay below staged metric")
	}
	if inst.Bird.MetricStaged+inst.Bird.BabelRTTCost >= inst.Bird.MetricDraining {
		t.Fatalf("staged metric plus max RTT penalty must stay below draining metric")
	}
	if inst.Bird.BabelHelloInterval != bird.DefaultBabelHelloInterval || inst.Bird.BabelUpdateInterval != bird.DefaultBabelUpdateInterval {
		t.Fatalf("inst default Babel intervals = hello %s update %s", inst.Bird.BabelHelloInterval, inst.Bird.BabelUpdateInterval)
	}
	if !inst.Bird.ECMP {
		t.Fatalf("inst.ECMP = false, want true")
	}
	if inst.Bird.ECMPLimit != 16 {
		t.Fatalf("inst.ECMPLimit = %d, want 16", inst.Bird.ECMPLimit)
	}
	if len(inst.Bird.InterfacePatterns) != 1 || inst.Bird.InterfacePatterns[0] != "phx*" {
		t.Fatalf("inst.InterfacePat = %q, want phx*", inst.Bird.InterfacePatterns)
	}
}

func TestParseRoutingInstancesRejectsInvalidShutdownPolicy(t *testing.T) {
	input := `
instances:
  - id: main
    netns: photontesth2
    shutdown_policy: drain
`
	var raw RoutingConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatalf("decode routing YAML: %v", err)
	}
	namespaces := NetNSConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	if _, err := ParseRoutingConfig(raw.Instances, namespaces, "/tmp"); err == nil {
		t.Fatal("ParseRoutingConfig should reject unsupported routing.instances[].shutdown_policy")
	}
}

func TestParseRoutingInstancesRejectsInvalidBabelTuning(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config string
	}{
		{name: "RTT cost too large", config: "rtt_cost: 65535"},
		{name: "RTT max before min", config: "rtt_min: 20ms\n    rtt_max: 10ms"},
		{name: "RTT decay too large", config: "rtt_decay: 257"},
		{name: "sub-millisecond interval", config: "hello_interval: 500us"},
		{name: "negative update interval", config: "update_interval: -1s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := `
instances:
  - id: main
    netns: photontesth2
    ` + tc.config + "\n"
			var raw RoutingConfigYAML
			if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
				t.Fatalf("decode routing YAML: %v", err)
			}
			namespaces := NetNSConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
			if _, err := ParseRoutingConfig(raw.Instances, namespaces, "/tmp"); err == nil {
				t.Fatalf("ParseRoutingConfig should reject:\n%s", input)
			}
		})
	}
}

func TestParseRoutingInstanceDisabled(t *testing.T) {
	input := `
instances:
  - id: main
    netns: photontesth2
    disabled: true
`
	var raw RoutingConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatalf("decode routing YAML: %v", err)
	}
	namespaces := NetNSConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	config, err := ParseRoutingConfig(raw.Instances, namespaces, "/tmp")
	if err != nil {
		t.Fatalf("ParseRoutingConfig: %v", err)
	}
	if len(config.Instances) != 1 {
		t.Fatalf("Routing.Instances len = %d, want 1", len(config.Instances))
	}
	if config.Instances[0].Enabled {
		t.Fatalf("routing instance should be disabled")
	}
}

func TestParseRoutingConfigRejectsConflictingEnabledDisabled(t *testing.T) {
	input := `
instances:
  - id: main
    netns: photontesth2
    enabled: true
    disabled: true
`
	var raw RoutingConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatalf("decode routing YAML: %v", err)
	}
	namespaces := NetNSConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	if _, err := ParseRoutingConfig(raw.Instances, namespaces, "/tmp"); err == nil {
		t.Fatal("ParseRoutingConfig should reject conflicting enabled/disabled")
	}
}
