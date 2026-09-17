package photonlinux

import (
	"strings"
	"testing"

	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"gopkg.in/yaml.v3"
)

func TestFirewallInstancesEnabled(t *testing.T) {
	config := FirewallConfig{
		Instances: []firewall.FirewallInstanceSpec{
			{ID: "a", Enabled: true, Mode: firewall.ModeManaged},
			{ID: "b", Enabled: false, Mode: firewall.ModeManaged},
			{ID: "c", Enabled: true, Mode: firewall.ModeDisabled},
			{ID: "d", Enabled: true, Mode: firewall.ModeExternal},
		},
	}
	enabled := config.ManagedInstances()
	if len(enabled) != 1 {
		t.Fatalf("expected 1 enabled, got %d", len(enabled))
	}
	if enabled[0].ID != "a" {
		t.Errorf("expected instance a, got %s", enabled[0].ID)
	}
}

func TestParseFirewallInstanceSpec(t *testing.T) {
	spec, err := parseFirewallInstance(firewallInstanceYAML{
		ID: "host", NetNS: "host",
		LocalServices: []localServiceYAML{{Proto: "tcp", Port: 443}},
		ListenAddrs:   []string{"192.0.2.1"},
	}, map[string]ipsec.NetNSSpec{"host": {Kind: ipsec.NetNSHost}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if spec.ID != "host" || spec.CharonIKEPort != 500 || spec.CharonNATTPort != 4500 {
		t.Fatalf("unexpected instance or charon ports: %+v", spec)
	}
	if len(spec.LocalServices) != 1 || spec.LocalServices[0].Port != 443 || len(spec.ListenAddrs) != 1 || spec.ListenAddrs[0].String() != "192.0.2.1" {
		t.Fatalf("services or listen addresses lost: %+v", spec)
	}
	if len(spec.EndpointServices) != 0 {
		t.Fatal("runtime endpoint services present in parsed config")
	}
}

func TestParseFirewallOverlay(t *testing.T) {
	input := `
instances:
  - id: photontesth2
    netns: photontesth2
    mode: managed
    backend: auto
    default_policy: drop
    xfrm_tunnel_pattern: "phx*"
    local_services:
      - proto: tcp
        port: 8080
        sources:
          - 10.42.0.0/16
`
	var raw FirewallConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	namespaces := map[string]ipsec.NetNSSpec{"default": {Kind: ipsec.NetNSName, Name: "photon"}, "photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2"}}
	config, err := ParseFirewallConfig(&raw, namespaces, "")
	if err != nil {
		t.Fatalf("ParseFirewallConfig: %v", err)
	}
	if len(config.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Instances))
	}
	inst := config.Instances[0]
	if inst.ID != "photontesth2" {
		t.Errorf("ID = %s, want photontesth2", inst.ID)
	}
	if inst.Mode != firewall.ModeManaged {
		t.Errorf("Mode = %s, want managed", inst.Mode)
	}
	if inst.DefaultPolicy != firewall.DefaultPolicyDrop {
		t.Errorf("DefaultPolicy = %s, want drop", inst.DefaultPolicy)
	}
	if len(inst.LocalServices) != 1 {
		t.Fatalf("expected 1 local service, got %d", len(inst.LocalServices))
	}
	if inst.LocalServices[0].Port != 8080 {
		t.Errorf("service port = %d, want 8080", inst.LocalServices[0].Port)
	}
}

func TestParseFirewallInlineHooks(t *testing.T) {
	input := `
instances:
  - id: photon
    backend: auto
    nft_hooks:
      pre_input:
        - 'tcp dport 22 accept'
    iptables_hooks:
      ipv4:
        pre_input:
          - '-s 10.20.0.0/16 -j ACCEPT'
          - '-s 10.30.0.0/16 -j ACCEPT'
      ipv6:
        pre_input:
          - '-s 2001:db8::/32 -j ACCEPT'
`
	var raw FirewallConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	namespaces := map[string]ipsec.NetNSSpec{"default": {Kind: ipsec.NetNSName, Name: "photon"}, "photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2"}}
	config, err := ParseFirewallConfig(&raw, namespaces, "")
	if err != nil {
		t.Fatalf("ParseFirewallConfig: %v", err)
	}
	got := config.Instances[0].NativeHooks
	if len(got.NFT.PreInput) != 1 || len(got.IPTables.IPv4.PreInput) != 2 || len(got.IPTables.IPv6.PreInput) != 1 {
		t.Fatalf("parsed inline hooks = %+v", got)
	}
}

func TestParseFirewallPriorities(t *testing.T) {
	input := `
instances:
  - id: photon
    priority:
      filter: "filter - 1"
      prerouting: "dstnat - 2"
      postrouting: "srcnat + 3"
`
	var raw FirewallConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	namespaces := map[string]ipsec.NetNSSpec{"default": {Kind: ipsec.NetNSName, Name: "photon"}, "photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2"}}
	config, err := ParseFirewallConfig(&raw, namespaces, "")
	if err != nil {
		t.Fatalf("ParseFirewallConfig: %v", err)
	}
	priorities := config.Instances[0].Priorities
	if got := priorities.Filter.String(); got != "filter - 1" {
		t.Fatalf("filter priority = %q", got)
	}
	if got := priorities.Prerouting.String(); got != "dstnat - 2" {
		t.Fatalf("prerouting priority = %q", got)
	}
	if got := priorities.Postrouting.String(); got != "srcnat + 3" {
		t.Fatalf("postrouting priority = %q", got)
	}
}

func TestParseFirewallPrioritiesRejectInvalidBase(t *testing.T) {
	input := `
instances:
  - id: photon
    priority:
      prerouting: "raw - 1"
`
	var raw FirewallConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	namespaces := map[string]ipsec.NetNSSpec{"default": {Kind: ipsec.NetNSName, Name: "photon"}, "photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2"}}
	_, err := ParseFirewallConfig(&raw, namespaces, "")
	if err == nil || !strings.Contains(err.Error(), `priority: prerouting: must use "dstnat"`) {
		t.Fatalf("ParseFirewallConfig error = %v", err)
	}
}

func TestParseFirewallHost(t *testing.T) {
	input := `
instances:
  - id: host-ipsec
    host: true
    mode: managed
    backend: nft
    host_ports:
      ike: true
      natt: true
    redirect_grace: {}
`
	var raw FirewallConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	namespaces := map[string]ipsec.NetNSSpec{"default": {Kind: ipsec.NetNSName, Name: "photon"}, "photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2"}}
	config, err := ParseFirewallConfig(&raw, namespaces, "")
	if err != nil {
		t.Fatalf("ParseFirewallConfig: %v", err)
	}
	if len(config.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Instances))
	}
	inst := config.Instances[0]
	if !inst.IsHost {
		t.Error("expected IsHost=true")
	}
	if inst.NetNS != "host" {
		t.Errorf("NetNS = %s, want host", inst.NetNS)
	}
	if !inst.HostPorts.IKE {
		t.Error("IKE should be true")
	}
	if !inst.HostPorts.NATT {
		t.Error("NATT should be true")
	}
	if !inst.RedirectGrace.Enabled {
		t.Error("redirect grace should be enabled")
	}
}

func TestParseFirewallHostListenAddrs(t *testing.T) {
	input := `
instances:
  - id: host-ipsec
    host: true
    listen_addrs:
      - 172.17.16.168
      - "[2408:400a:101:3801:6cbd:8fb4:ae31:750a]:4500"
`
	var raw FirewallConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	namespaces := map[string]ipsec.NetNSSpec{"default": {Kind: ipsec.NetNSName, Name: "photon"}, "photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2"}}
	config, err := ParseFirewallConfig(&raw, namespaces, "")
	if err != nil {
		t.Fatalf("ParseFirewallConfig: %v", err)
	}
	if len(config.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Instances))
	}
	inst := config.Instances[0]
	if len(inst.ListenAddrs) != 2 {
		t.Fatalf("expected 2 listen addrs, got %d: %+v", len(inst.ListenAddrs), inst.ListenAddrs)
	}
	if inst.ListenAddrs[0].String() != "172.17.16.168" {
		t.Errorf("listen addr[0] = %s, want 172.17.16.168", inst.ListenAddrs[0])
	}
	if inst.ListenAddrs[1].String() != "2408:400a:101:3801:6cbd:8fb4:ae31:750a" {
		t.Errorf("listen addr[1] = %s, want 2408:400a:101:3801:6cbd:8fb4:ae31:750a", inst.ListenAddrs[1])
	}
}

func TestParseFirewallHostListenAddrsInvalid(t *testing.T) {
	input := `
instances:
  - id: host-ipsec
    host: true
    listen_addrs:
      - not-an-address
`
	var raw FirewallConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	namespaces := map[string]ipsec.NetNSSpec{"default": {Kind: ipsec.NetNSName, Name: "photon"}, "photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2"}}
	_, err := ParseFirewallConfig(&raw, namespaces, "")
	if err == nil {
		t.Fatal("expected error for invalid listen_addrs")
	}
	if !strings.Contains(err.Error(), "listen_addrs") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFirewallDisabled(t *testing.T) {
	input := `
instances:
  - id: photontesth2
    netns: photontesth2
    disabled: true
`
	var raw FirewallConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	namespaces := map[string]ipsec.NetNSSpec{"default": {Kind: ipsec.NetNSName, Name: "photon"}, "photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2"}}
	config, err := ParseFirewallConfig(&raw, namespaces, "")
	if err != nil {
		t.Fatalf("ParseFirewallConfig: %v", err)
	}
	if len(config.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Instances))
	}
	if config.Instances[0].Enabled {
		t.Fatal("firewall instance should be disabled")
	}
}

func TestParseFirewallRejectsHostNetnsConflict(t *testing.T) {
	input := `
instances:
  - id: ambiguous
    host: true
    netns: photontesth2
`
	var raw FirewallConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	namespaces := map[string]ipsec.NetNSSpec{"default": {Kind: ipsec.NetNSName, Name: "photon"}, "photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2"}}
	_, err := ParseFirewallConfig(&raw, namespaces, "")
	if err == nil {
		t.Fatal("expected error for host/netns conflict")
	}
	if !strings.Contains(err.Error(), "host: true conflicts with netns") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFirewallInvalidMode(t *testing.T) {
	input := `
instances:
  - id: photontesth2
    netns: photontesth2
    mode: bogus
`
	var raw FirewallConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	namespaces := map[string]ipsec.NetNSSpec{"default": {Kind: ipsec.NetNSName, Name: "photon"}, "photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2"}}
	_, err := ParseFirewallConfig(&raw, namespaces, "")
	if err == nil || !strings.Contains(err.Error(), "unsupported firewall mode") {
		t.Errorf("expected invalid mode error, got %v", err)
	}
}

func TestParseFirewallInvalidBackend(t *testing.T) {
	input := `
instances:
  - id: photontesth2
    netns: photontesth2
    backend: bogus
`
	var raw FirewallConfigYAML
	if err := yaml.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	namespaces := map[string]ipsec.NetNSSpec{"default": {Kind: ipsec.NetNSName, Name: "photon"}, "photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2"}}
	_, err := ParseFirewallConfig(&raw, namespaces, "")
	if err == nil || !strings.Contains(err.Error(), "unsupported firewall backend") {
		t.Errorf("expected invalid backend error, got %v", err)
	}
}
