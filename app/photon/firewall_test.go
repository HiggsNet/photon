package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/internal/observer"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestFirewallObservationDoesNotAdvancePersistentRevision(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	summary := &firewall.FirewallObservation{
		Backend:     firewall.BackendNone,
		LastRunUnix: 200,
		Instances: map[string]*firewall.FirewallInstanceObservation{
			"overlay": {Backend: firewall.BackendNone, Generation: 1, LastRunUnix: 200, PolicyHash: "same"},
		},
	}
	rt := &AppContext{Config: defaultAppConfig()}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	rev := uint64(service.State.Common.VerifiedRevision())
	service.publishFirewallObservation(rev, summary)
	if got := uint64(service.State.Common.VerifiedRevision()); got != rev {
		t.Fatalf("firewall observation revision = %d, want unchanged %d", got, rev)
	}
	got := service.linuxObservation.firewallSnapshot()
	if got == nil || got.LastRunUnix != 200 || got.Instances["overlay"].PolicyHash != "same" {
		t.Fatalf("firewall observation = %+v", got)
	}
	summary.Instances["overlay"].PolicyHash = "mutated-input"
	got.Instances["overlay"].PolicyHash = "mutated-snapshot"
	if latest := service.linuxObservation.firewallSnapshot(); latest.Instances["overlay"].PolicyHash != "same" {
		t.Fatalf("firewall observation shares mutable entries: %+v", latest)
	}
}

func TestParseConfigYAMLFirewallOverlay(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
    forwarding:
      transit: false
      allow_prefixes:
        - 10.42.0.0/16
firewall:
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
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	inst := config.Firewall.Instances[0]
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
	policy := netnsForwardingPolicy(config, inst.NetNS)
	if policy.Transit {
		t.Error("transit should be false")
	}
	if len(policy.AllowPrefixes) != 1 {
		t.Errorf("allow_prefixes len = %d, want 1", len(policy.AllowPrefixes))
	}
}

func TestParseConfigYAMLFirewallInlineHooks(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photon
firewall:
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
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	got := config.Firewall.Instances[0].NativeHooks
	if len(got.NFT.PreInput) != 1 || len(got.IPTables.IPv4.PreInput) != 2 || len(got.IPTables.IPv6.PreInput) != 1 {
		t.Fatalf("parsed inline hooks = %+v", got)
	}
}

func TestParseConfigYAMLFirewallPriorities(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photon
firewall:
  instances:
    - id: photon
      priority:
        filter: "filter - 1"
        prerouting: "dstnat - 2"
        postrouting: "srcnat + 3"
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	priorities := config.Firewall.Instances[0].Priorities
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

func TestParseConfigYAMLFirewallPrioritiesRejectInvalidBase(t *testing.T) {
	config := defaultAppConfig()
	err := parseConfigYAML(`
netns:
  default:
    kind: name
    name: photon
firewall:
  instances:
    - id: photon
      priority:
        prerouting: "raw - 1"
`, config)
	if err == nil || !strings.Contains(err.Error(), `priority: prerouting: must use "dstnat"`) {
		t.Fatalf("parseConfigYAML error = %v", err)
	}
}

func TestParseConfigYAMLFirewallInlineHooksRejectsBothFamily(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photon
firewall:
  instances:
    - id: photon
      iptables_hooks:
        both:
          pre_input:
            - '-j ACCEPT'
`
	err := parseConfigYAML(input, config)
	if err == nil || !strings.Contains(err.Error(), "field both not found") {
		t.Fatalf("parseConfigYAML error = %v, want strict rejection of both", err)
	}
}

func TestParseConfigYAMLFirewallRejectsRemovedExternalChainHooks(t *testing.T) {
	config := defaultAppConfig()
	err := parseConfigYAML(`
netns:
  default:
    kind: name
    name: photon
firewall:
  instances:
    - id: photon
      hooks:
        pre_input: admin_input
`, config)
	if err == nil || !strings.Contains(err.Error(), "field hooks not found") {
		t.Fatalf("parseConfigYAML error = %v, want strict rejection of removed hooks", err)
	}
}

func TestParseConfigYAMLFirewallOverlayDefaultsToDefaultNetNS(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
firewall:
  instances:
    - id: photontesth2
      mode: managed
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	inst := config.Firewall.Instances[0]
	if inst.NetNS != "default" {
		t.Fatalf("NetNS = %s, want default", inst.NetNS)
	}
	if inst.IsHost {
		t.Fatal("defaulted netns instance should not be host")
	}
}

func TestParseConfigYAMLFirewallHost(t *testing.T) {
	config := defaultAppConfig()
	input := `
firewall:
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
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	inst := config.Firewall.Instances[0]
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

func TestParseConfigYAMLFirewallHostDefaultsForIPsecRange(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  port_mode: range
  port_range:
    from: 30000
    to: 30099
firewall:
  instances:
    - id: host-ipsec
      host: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	inst := config.Firewall.Instances[0]
	if !inst.HostPorts.IKE || !inst.HostPorts.NATT {
		t.Fatalf("range mode host ports = %+v, want IKE/NATT enabled by default", inst.HostPorts)
	}
	if !inst.RedirectGrace.Enabled {
		t.Fatal("range mode should enable redirect_grace by default")
	}
}

func TestParseConfigYAMLFirewallHostRangeDefaultsCanBeDisabled(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  port_mode: range
  port_range:
    from: 30000
    to: 30099
firewall:
  instances:
    - id: host-ipsec
      host: true
      host_ports:
        ike: false
        natt: false
      redirect_grace:
        disabled: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	inst := config.Firewall.Instances[0]
	if inst.HostPorts.IKE || inst.HostPorts.NATT {
		t.Fatalf("explicit host port disables ignored: %+v", inst.HostPorts)
	}
	if inst.RedirectGrace.Enabled {
		t.Fatal("explicit redirect_grace disabled should override range default")
	}
}

func TestParseConfigYAMLFirewallHostListenAddrs(t *testing.T) {
	config := defaultAppConfig()
	input := `
firewall:
  instances:
    - id: host-ipsec
      host: true
      listen_addrs:
        - 172.17.16.168
        - "[2408:400a:101:3801:6cbd:8fb4:ae31:750a]:4500"
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	inst := config.Firewall.Instances[0]
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

func TestParseConfigYAMLFirewallHostListenAddrsInvalid(t *testing.T) {
	config := defaultAppConfig()
	input := `
firewall:
  instances:
    - id: host-ipsec
      host: true
      listen_addrs:
        - not-an-address
`
	err := parseConfigYAML(input, config)
	if err == nil {
		t.Fatal("expected error for invalid listen_addrs")
	}
	if !strings.Contains(err.Error(), "listen_addrs") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseConfigYAMLFirewallDisabled(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
firewall:
  instances:
    - id: photontesth2
      netns: photontesth2
      disabled: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	if config.Firewall.Instances[0].Enabled {
		t.Fatal("firewall instance should be disabled")
	}
}

func TestParseConfigYAMLFirewallRejectsHostNetnsConflict(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
firewall:
  instances:
    - id: ambiguous
      host: true
      netns: photontesth2
`
	err := parseConfigYAML(input, config)
	if err == nil {
		t.Fatal("expected error for host/netns conflict")
	}
	if !strings.Contains(err.Error(), "host: true conflicts with netns") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseConfigYAMLFirewallInvalidMode(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
firewall:
  instances:
    - id: photontesth2
      netns: photontesth2
      mode: bogus
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestParseConfigYAMLFirewallInvalidBackend(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
firewall:
  instances:
    - id: photontesth2
      netns: photontesth2
      backend: bogus
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Error("expected error for invalid backend")
	}
}

func TestParseConfigYAMLFirewallUnknownNetns(t *testing.T) {
	config := defaultAppConfig()
	input := `
firewall:
  instances:
    - id: photontesth2
      netns: nonexistent
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Error("expected error for unknown netns")
	}
}

func TestParseConfigYAMLFirewallRejectsIndependentUpstreamPattern(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photon
firewall:
  instances:
    - id: photon
      upstream_patterns: ["phv*"]
`
	err := parseConfigYAML(input, config)
	if err == nil || !strings.Contains(err.Error(), "upstream_patterns") {
		t.Fatalf("error = %v, want upstream_patterns rejected; configure routing.instances[].upstream.mesh.interface", err)
	}
}

func TestFirewallInstancesEnabled(t *testing.T) {
	config := &appConfig{
		Firewall: firewallConfig{
			Instances: []FirewallInstanceConfig{
				{ID: "a", Enabled: true, Mode: firewall.ModeManaged},
				{ID: "b", Enabled: false, Mode: firewall.ModeManaged},
				{ID: "c", Enabled: true, Mode: firewall.ModeDisabled},
				{ID: "d", Enabled: true, Mode: firewall.ModeExternal},
			},
		},
	}
	enabled := firewallInstancesEnabled(config)
	if len(enabled) != 1 {
		t.Fatalf("expected 1 enabled, got %d", len(enabled))
	}
	if enabled[0].ID != "a" {
		t.Errorf("expected instance a, got %s", enabled[0].ID)
	}
}

func TestFirewallInstanceSpecFromConfig(t *testing.T) {
	inst := FirewallInstanceConfig{
		ID: "photontesth2", NetNS: "photontesth2", IsHost: false,
		Enabled: true, Mode: firewall.ModeManaged,
		Backend: firewall.BackendNFT, DefaultPolicy: firewall.DefaultPolicyDrop,
		OwnerPrefix: "photon", XFRMTunnelPattern: "phx*",
		LocalServices: []firewall.LocalService{{Proto: "tcp", Port: 443}},
	}
	spec := firewallInstanceSpecFromConfig(inst, nil, 500, 4500)
	if spec.ID != "photontesth2" {
		t.Errorf("ID = %s", spec.ID)
	}
	if spec.CharonIKEPort != 500 {
		t.Errorf("IKEPort = %d", spec.CharonIKEPort)
	}
	if len(spec.LocalServices) != 1 {
		t.Errorf("local services = %d", len(spec.LocalServices))
	}
}

func TestReconcileFirewall_NoInstances(t *testing.T) {
	d := &Daemon{
		State: newState(nil, corestate.NewStore(&corestate.VerifiedState{}, nil), &photonlinux.LinuxState{}),
		App:   &AppContext{Config: &appConfig{}},
	}
	if err := d.reconcileFirewall(context.Background()); err != nil {
		t.Fatalf("reconcileFirewall with no instances: %v", err)
	}
}

func TestBuildFirewallPolicyInputHostRedirectGracePorts(t *testing.T) {
	verified, _, runtime, _ := buildTestDaemonOwners(t)
	now := time.Unix(6000, 0)
	verified.ManagedZone = "node-b.catofes."
	verified.Network.Zones[verified.ManagedZone].Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, verified.ManagedZone, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: 3,
			IKE:        ipsec.PortBinding{Local: 1500, Advertised: 1500},
			NATT:       ipsec.PortBinding{Local: 14500, Advertised: 14500},
		},
		Previous: []ipsec.PortSelection{
			{
				Generation: 2,
				IKE:        ipsec.PortBinding{Local: 1400, Advertised: 1400},
				NATT:       ipsec.PortBinding{Local: 14400, Advertised: 14400},
				ValidUntil: now.Add(time.Minute).Unix(),
			},
			{
				Generation: 1,
				IKE:        ipsec.PortBinding{Local: 1300, Advertised: 1300},
				NATT:       ipsec.PortBinding{Local: 14300, Advertised: 14300},
				ValidUntil: now.Add(-time.Second).Unix(),
			},
		},
		UpdatedAt: now.Unix(),
	})
	input := buildFirewallPolicyInput(
		firewall.FirewallInstanceSpec{ID: "host", IsHost: true},
		&routing.AuthorizedRouteSet{},
		verified,
		runtime,
		nil,
		nil,
		defaultAppConfig(),
		now,
	)
	if len(input.AdvertisedCurrentIKEPorts) != 1 || input.AdvertisedCurrentIKEPorts[0] != 1500 {
		t.Fatalf("current IKE ports = %v, want [1500]", input.AdvertisedCurrentIKEPorts)
	}
	if len(input.AdvertisedCurrentNATTPorts) != 1 || input.AdvertisedCurrentNATTPorts[0] != 14500 {
		t.Fatalf("current NAT-T ports = %v, want [14500]", input.AdvertisedCurrentNATTPorts)
	}
	if len(input.AdvertisedPreviousIKEPorts) != 1 || input.AdvertisedPreviousIKEPorts[0] != 1400 {
		t.Fatalf("previous IKE ports = %v, want [1400]", input.AdvertisedPreviousIKEPorts)
	}
	if len(input.AdvertisedPreviousNATTPorts) != 1 || input.AdvertisedPreviousNATTPorts[0] != 14400 {
		t.Fatalf("previous NAT-T ports = %v, want [14400]", input.AdvertisedPreviousNATTPorts)
	}
}

func TestBuildFirewallPolicyInputIncludesLocalSharedAssignment(t *testing.T) {
	prefix := netip.MustParsePrefix("2a0d:2905::/96")
	ars := &routing.AuthorizedRouteSet{
		Assignments: map[netip.Prefix]*routing.AssignmentEntry{
			prefix: {
				Prefix:     prefix,
				AssignedTo: "node-a.catofes.",
				Shared:     true,
			},
		},
		AllAssignments: []*routing.AssignmentEntry{
			{Prefix: prefix, AssignedTo: "node-a.catofes.", Shared: true},
			{Prefix: prefix, AssignedTo: "node-b.catofes.", Shared: true},
		},
	}

	input := buildFirewallPolicyInput(
		firewall.FirewallInstanceSpec{ID: "photon", NetNS: "photon"},
		ars,
		&corestate.VerifiedState{ManagedZone: "node-b.catofes."},
		&photonlinux.LinuxState{},
		nil,
		nil,
		defaultAppConfig(),
		time.Now(),
	)

	if len(input.LocalAssigned) != 1 || input.LocalAssigned[0] != prefix {
		t.Fatalf("local assigned = %v, want shared prefix %s", input.LocalAssigned, prefix)
	}
}

func TestBuildFirewallPolicyInputScopesInterfacesByNetNS(t *testing.T) {
	verified := &corestate.VerifiedState{ManagedZone: "node-a.catofes."}
	runtime := &photonlinux.LinuxState{}
	links := map[string]ipsec.LinkInstance{
		"a": {
			ID:              "a",
			ActualState:     "up",
			InterfaceName:   "phx11111111",
			LocalTunnelAddr: netip.MustParseAddr("fe80::1"),
		},
		"b": {
			ID:              "b",
			ActualState:     "up",
			InterfaceName:   "phx22222222",
			LocalTunnelAddr: netip.MustParseAddr("fe80::2"),
		},
	}
	config := defaultAppConfig()
	config.Netns.Names = map[string]ipsec.NetNSSpec{
		"default": {Kind: ipsec.NetNSName, Name: "photon"},
		"photon":  {Kind: ipsec.NetNSName, Name: "photon"},
		"h3":      {Kind: ipsec.NetNSName, Name: "h3"},
	}
	config.Routing.Instances = []RoutingInstance{
		{ID: "photon", NetNS: "photon", Enabled: true, Upstream: &UpstreamConfig{Enabled: true, MeshInterface: "phv2host"}},
		{ID: "h3", NetNS: "h3", Enabled: true, Upstream: &UpstreamConfig{Enabled: true, MeshInterface: "phv3host"}},
	}

	input := buildFirewallPolicyInput(
		firewall.FirewallInstanceSpec{ID: "photon", NetNS: "default"},
		&routing.AuthorizedRouteSet{},
		verified,
		runtime,
		links,
		&ipsecObservationSummary{Desired: []photonstate.DesiredLinkState{
			{InstanceID: "a", LocalTunnelAddr: "fe80::1%phx11111111 netns=photon"},
			{InstanceID: "b", LocalTunnelAddr: "fe80::2%phx22222222 netns=h3"},
		}},
		config,
		time.Now(),
	)
	if len(input.LiveInterfaces) != 1 || input.LiveInterfaces[0] != "phx11111111" {
		t.Fatalf("live interfaces = %v, want photon interface only", input.LiveInterfaces)
	}
	if len(input.UpstreamInterfaces) != 1 || input.UpstreamInterfaces[0] != "phv2host" {
		t.Fatalf("upstream interfaces = %v, want routing-owned photon interface only", input.UpstreamInterfaces)
	}
}

type captureFirewallOwnerDriver struct {
	firewall.DryRunDriver
	owners  []firewall.Owner
	onApply func()
}

func (d *captureFirewallOwnerDriver) ListOwned(ctx context.Context, owner firewall.Owner) (firewall.FirewallObservedState, error) {
	d.owners = append(d.owners, owner)
	return firewall.FirewallObservedState{}, nil
}

func (d *captureFirewallOwnerDriver) Apply(ctx context.Context, plan firewall.FirewallPlan, desired *firewall.FirewallDesiredState) (firewall.FirewallApplyResult, error) {
	if d.onApply != nil {
		d.onApply()
	}
	return d.DryRunDriver.Apply(ctx, plan, desired)
}

type blockingFirewallDriver struct {
	firewall.DryRunDriver
	started chan struct{}
	unblock chan struct{}
}

func (d *blockingFirewallDriver) Apply(ctx context.Context, plan firewall.FirewallPlan, desired *firewall.FirewallDesiredState) (firewall.FirewallApplyResult, error) {
	close(d.started)
	select {
	case <-d.unblock:
	case <-ctx.Done():
		return firewall.FirewallApplyResult{}, ctx.Err()
	}
	return d.DryRunDriver.Apply(ctx, plan, desired)
}

func TestReconcileFirewallUsesScopeForOwnedObjects(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	appConfig := defaultAppConfig()
	appConfig.Firewall.Instances = []FirewallInstanceConfig{
		{
			ID:            "photon",
			NetNS:         "default",
			Enabled:       true,
			Mode:          firewall.ModeManaged,
			Backend:       firewall.BackendNone,
			DefaultPolicy: firewall.DefaultPolicyDrop,
		},
		{
			ID:        "host-ipsec",
			NetNS:     "host",
			IsHost:    true,
			Enabled:   true,
			Mode:      firewall.ModeManaged,
			Backend:   firewall.BackendNone,
			HostPorts: firewall.HostPortConfig{IKE: true, NATT: true},
		},
	}
	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return time.Unix(7000, 0) },
	}
	driver := &captureFirewallOwnerDriver{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestFirewallDriver(service, driver)
	if err := service.reconcileFirewall(context.Background()); err != nil {
		t.Fatalf("reconcileFirewall: %v", err)
	}
	if len(driver.owners) != 2 {
		t.Fatalf("owners = %+v, want two instances", driver.owners)
	}
	if driver.owners[0].InstanceID != "default" {
		t.Fatalf("overlay owner scope = %q, want default", driver.owners[0].InstanceID)
	}
	if driver.owners[1].InstanceID != "host" {
		t.Fatalf("host owner scope = %q, want host", driver.owners[1].InstanceID)
	}
}

func TestLongFirewallReconcileDoesNotBlockCommittedReaders(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	appConfig := defaultAppConfig()
	appConfig.Observer.Enabled = true
	appConfig.Firewall.Instances = []FirewallInstanceConfig{{
		ID:            "photontesth2",
		NetNS:         "photontesth2",
		Enabled:       true,
		Mode:          firewall.ModeManaged,
		Backend:       firewall.BackendNone,
		DefaultPolicy: firewall.DefaultPolicyDrop,
	}}
	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return time.Unix(7020, 0) },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	driver := &blockingFirewallDriver{
		started: make(chan struct{}),
		unblock: make(chan struct{}),
	}
	installTestFirewallDriver(service, driver)

	done := make(chan error, 1)
	go func() {
		done <- service.reconcileFirewall(context.Background())
	}()
	select {
	case <-driver.started:
	case <-time.After(time.Second):
		close(driver.unblock)
		t.Fatal("firewall reconcile did not enter blocking apply")
	}

	committedRev := uint64(service.State.Common.VerifiedRevision())
	statusDone := make(chan controlViewResponse[inspect.DaemonStatusView], 1)
	go func() {
		statusDone <- controlViewRequestViaPipe[inspect.DaemonStatusView](t, service, controlRequest{Method: "daemon_status_view"})
	}()
	select {
	case status := <-statusDone:
		if !status.OK || status.View.StateRevision != committedRev {
			close(driver.unblock)
			t.Fatalf("status response = %#v, want committed revision %d", status, committedRev)
		}
	case <-time.After(time.Second):
		close(driver.unblock)
		t.Fatal("control status blocked behind firewall reconcile apply")
	}

	srv := newObserverServer(service, appConfig.Observer)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	observerDone := make(chan struct{})
	go func() {
		srv.handler().ServeHTTP(rr, req)
		close(observerDone)
	}()
	select {
	case <-observerDone:
		if rr.Code != http.StatusOK {
			close(driver.unblock)
			t.Fatalf("observer status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		var resp observer.APIResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			close(driver.unblock)
			t.Fatalf("decode observer status: %v", err)
		}
		data := resp.Data.(map[string]any)
		if data["state_revision"] != float64(committedRev) {
			close(driver.unblock)
			t.Fatalf("observer status data = %#v, want committed revision %d", data, committedRev)
		}
	case <-time.After(time.Second):
		close(driver.unblock)
		t.Fatal("observer status blocked behind firewall reconcile apply")
	}

	close(driver.unblock)
	if err := <-done; err != nil {
		t.Fatalf("reconcileFirewall: %v", err)
	}
}

func TestReconcileFirewallStaleCommitPreservesNewRevision(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	appConfig := defaultAppConfig()
	appConfig.Firewall.Instances = []FirewallInstanceConfig{{
		ID:            "photontesth2",
		NetNS:         "photontesth2",
		Enabled:       true,
		Mode:          firewall.ModeManaged,
		Backend:       firewall.BackendNone,
		DefaultPolicy: firewall.DefaultPolicyDrop,
	}}
	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return time.Unix(7010, 0) },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	baseRev := uint64(service.State.Common.VerifiedRevision())
	driver := &captureFirewallOwnerDriver{}
	driver.onApply = func() {
		if _, err := advanceTestVerifiedRevision(service.State.Common, time.Unix(7010, 1)); err != nil {
			t.Fatalf("advance state revision during firewall apply: %v", err)
		}
		driver.onApply = nil
	}
	installTestFirewallDriver(service, driver)

	if err := service.reconcileFirewall(context.Background()); err != nil {
		t.Fatalf("reconcileFirewall: %v", err)
	}
	if !service.firewallDirty {
		t.Fatal("firewallDirty = false, want stale firewall summary commit to schedule another reconcile")
	}
	common := service.State.Common.ReadView()
	rev := uint64(common.Revision)
	if rev != baseRev+1 {
		t.Fatalf("state revision = %d, want only external update at %d", rev, baseRev+1)
	}
	if observation := service.linuxObservation.firewallSnapshot(); observation != nil {
		t.Fatalf("firewall observation = %+v, want stale summary discarded", observation)
	}
}

func TestFirewallReconcileDirtyIntervalAndRecover(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	appConfig := defaultAppConfig()
	appConfig.Firewall.Instances = []FirewallInstanceConfig{{
		ID:            "photontesth2",
		NetNS:         "photontesth2",
		Enabled:       true,
		Mode:          firewall.ModeManaged,
		Backend:       firewall.BackendNone,
		DefaultPolicy: firewall.DefaultPolicyDrop,
	}}
	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return time.Unix(7000, 0) },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)

	if service.firewallReconcileInterval() != defaultFirewallReconcileInterval {
		t.Fatalf("firewall interval = %s, want %s", service.firewallReconcileInterval(), defaultFirewallReconcileInterval)
	}
	base := time.Unix(7000, 0)
	if got := nextFirewallReconcileTime(base, 5*time.Second); !got.Equal(base.Add(5 * time.Second)) {
		t.Fatalf("nextFirewallReconcileTime = %s, want %s", got, base.Add(5*time.Second))
	}
	if got := nextFirewallReconcileTime(base, 0); !got.IsZero() {
		t.Fatalf("nextFirewallReconcileTime disabled = %s, want zero", got)
	}
	if service.flushFirewallReconcile(context.Background()) {
		t.Fatal("flushFirewallReconcile should be false when not dirty")
	}

	service.recoverFirewallOnStart(context.Background())
	if service.firewallDirty {
		t.Fatal("recoverFirewallOnStart should flush and clear firewallDirty")
	}
	observation := service.linuxObservation.firewallSnapshot()
	if observation == nil || observation.Instances["photontesth2"] == nil {
		t.Fatalf("firewall observation missing after recover: %+v", observation)
	}
	entry := observation.Instances["photontesth2"]
	if entry.PolicyHash == "" || entry.OwnedObjects == 0 || entry.LastRunUnix != 7000 {
		t.Fatalf("firewall reconcile entry = %+v, want hash/objects/last run", entry)
	}
}

func TestBuildFirewallDebugView(t *testing.T) {
	instances := []FirewallInstanceConfig{
		{ID: "photontesth2", NetNS: "photontesth2", IsHost: false, Enabled: true, Mode: firewall.ModeManaged, Backend: firewall.BackendAuto, DefaultPolicy: firewall.DefaultPolicyDrop,
			NativeHooks: firewall.NativeHooks{
				NFT:      firewall.InlineHookRules{PreInput: []string{"counter"}},
				IPTables: firewall.IPTablesInlineHooks{IPv4: firewall.InlineHookRules{PreInput: []string{"-j ACCEPT"}}},
			}},
		{ID: "host", NetNS: "host", IsHost: true, Enabled: true, Mode: firewall.ModeManaged, HostPorts: firewall.HostPortConfig{IKE: true, NATT: true}, RedirectGrace: firewall.RedirectGrace{Enabled: true}},
	}
	snapshot := &firewall.FirewallObservation{
		Backend: "dry-run",
		Instances: map[string]*firewall.FirewallInstanceObservation{
			"photontesth2": {Backend: firewall.BackendNFT, Generation: 5, OwnedObjects: 10, PolicyHash: "abc123"},
		},
	}
	view := buildFirewallDebugView(nil, instances, snapshot)
	if view.Backend != "dry-run" {
		t.Fatalf("backend = %q, want dry-run", view.Backend)
	}
	if len(view.Instances) != 2 {
		t.Fatalf("instances = %d, want 2", len(view.Instances))
	}
	if got := view.Instances[0]; got.ID != "photontesth2" || got.Generation != 5 || got.OwnedObjects != 10 || got.PolicyHash != "abc123" {
		t.Fatalf("first instance = %+v, want reconcile fields", got)
	}
	if got := view.Instances[0]; got.ResolvedBackend != firewall.BackendNFT || len(got.InlineHooks) != 2 || got.InlineHooks[0].State != "active" || got.InlineHooks[1].State != "inactive" {
		t.Fatalf("first instance inline hooks = %+v, resolved backend %q", got.InlineHooks, got.ResolvedBackend)
	}
	if got := view.Instances[1]; !got.IsHost || !got.HostIKE || !got.HostNATT || !got.RedirectGrace {
		t.Fatalf("host instance = %+v, want host flags", got)
	}
}

func TestFilterFirewallDebugInstances(t *testing.T) {
	instances := []FirewallInstanceConfig{
		{ID: "overlay", NetNS: "photon"},
		{ID: "host-ipsec", NetNS: "host", IsHost: true},
	}
	if got := filterFirewallDebugInstances(instances, "photon", false); len(got) != 1 || got[0].ID != "overlay" {
		t.Fatalf("netns filter = %+v", got)
	}
	if got := filterFirewallDebugInstances(instances, "", true); len(got) != 1 || got[0].ID != "host-ipsec" {
		t.Fatalf("host filter = %+v", got)
	}
}
