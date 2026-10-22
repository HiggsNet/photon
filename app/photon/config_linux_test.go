package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestParsedNamespaceDefaultReachesXFRMOwner(t *testing.T) {
	for _, test := range []struct {
		name, namespace string
		want            ipsec.NetNSSpec
	}{
		{"implicit", "", ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: ipsec.DefaultNetNSName, Create: true}},
		{"host", "netns:\n  default:\n    kind: host\n", ipsec.NetNSSpec{Kind: ipsec.NetNSHost}},
		{"named", "netns:\n  default:\n    kind: name\n    name: isolated\n    create: false\n", ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "isolated"}},
		{"path", "netns:\n  default:\n    kind: path\n    path: /run/netns/isolated\n", ipsec.NetNSSpec{Kind: ipsec.NetNSPath, Path: "/run/netns/isolated"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := defaultAppConfig()
			if err := parseConfigYAML(test.namespace+"overlays:\n  - id: main\n    provider: strongswan\n    netns: default\n", config); err != nil {
				t.Fatal(err)
			}
			normalizeAppConfig(config)
			if config.IPsec.DefaultNetNS != test.want || config.IPsec.LinkGroups[0].NetNS != test.want {
				t.Fatalf("XFRM default %+v differs from configured overlay %+v; want %+v", config.IPsec.DefaultNetNS, config.IPsec.LinkGroups[0].NetNS, test.want)
			}
		})
	}
}

func TestHostNamespaceConfigDoesNotCreateOrEnterNamedNamespace(t *testing.T) {
	config := defaultAppConfig()
	if err := parseConfigYAML("netns:\n  default:\n    kind: host\noverlays:\n  - id: main\n    provider: strongswan\n    netns: default\n", config); err != nil {
		t.Fatal(err)
	}
	// Exercise the same constructor and empty host target used by the Linux
	// composition, recording system commands instead of mutating the test host.
	driver := ipsec.NewSystemXFRMDriver(config.IPsec.DefaultNetNS)
	created, up := false, false
	driver.Command = func(_ context.Context, name string, args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		for _, arg := range args {
			if arg == "netns" {
				t.Fatalf("host-owned interface escaped into namespace command: %s %s", name, command)
			}
		}
		if command == "link show dev phx-config-host" {
			return nil, errors.New("interface does not exist yet")
		}
		created = created || strings.Contains(command, "link add phx-config-host type xfrm if_id 42")
		up = up || command == "link set phx-config-host up"
		return nil, nil
	}
	spec := ipsec.TransportLinkSpec{InterfaceName: "phx-config-host", XFRMIfID: 42, NetNS: config.IPsec.LinkGroups[0].NetNS.Target()}
	if err := driver.EnsureInterface(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	if !created || !up {
		t.Fatalf("host interface was not created and brought up: created=%v up=%v", created, up)
	}
}

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

func TestParseConfigYAMLOverlayUsesDefaultNetNSReference(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
overlays:
  - name: ipsec-main
    provider: strongswan
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	group := config.IPsec.LinkGroups[0]
	if group.NetNS.Kind != ipsec.NetNSName || group.NetNS.Name != "photontesth2" || !group.NetNS.Create {
		t.Fatalf("group netns = %+v, want netns.default photontesth2", group.NetNS)
	}
}

func TestParseConfigYAMLOverlayRejectsUnknownNetNSReference(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
overlays:
  - name: ipsec-main
    provider: strongswan
    netns: missing
`
	err := parseConfigYAML(input, config)
	if err == nil {
		t.Fatal("expected unknown overlay netns reference error")
	}
	if !strings.Contains(err.Error(), `unknown netns "missing"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseConfigYAMLIPsecWiring(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  driver: strongswan
  vici_socket: /tmp/charon.vici
  announce_gossip_endpoints: false
  announce_dns_reconnect_after: 0s
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.IPsec.Driver != photonlinux.IPsecDriverStrongSwan || config.IPsec.VICISocket != "/tmp/charon.vici" {
		t.Fatalf("IPsec driver config = %+v", config.IPsec)
	}
	if config.IPsec.AnnounceGossipEndpoints || config.IPsec.AnnounceDNSReconnectAfter != 0 {
		t.Fatalf("application normalization lost explicit false/zero: %+v", config.IPsec)
	}
}

func TestParseConfigYAMLRejectsPortGraceBelowOverlayRetention(t *testing.T) {
	config := defaultAppConfig()
	err := parseConfigYAML("ipsec:\n  port_previous_grace: 10m\noverlays:\n  - name: ipsec-main\n    reconcile:\n      rotate_retention: 1h\n", config)
	if err == nil || !strings.Contains(err.Error(), "ipsec.port_previous_grace") {
		t.Fatalf("parseConfigYAML: %v, want port grace error", err)
	}
}
