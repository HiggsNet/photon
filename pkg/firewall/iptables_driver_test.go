package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestIPTablesDriver_Preflight(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	pf, err := d.Preflight(context.Background(), FirewallInstanceSpec{ID: "photontesth2"})
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if pf.Backend == "" {
		t.Error("backend should be set")
	}
}

func TestIPTablesDriver_ApplyOverlay(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "photontesth2", NetNS: "photontesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "phx*",
		OwnerPrefix: "photon",
	}
	input := FirewallPolicyInput{
		MeshAuthorized: []netip.Prefix{mustPrefix(t, "10.42.0.0/24")},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	result, err := d.Apply(context.Background(), desired)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.Applied == 0 {
		t.Error("expected non-zero applied count")
	}
	if len(runner.commands) == 0 {
		t.Fatal("expected commands to be executed")
	}
	foundChainCreate := false
	for _, cmd := range runner.commands {
		if cmd.name == "iptables" && len(cmd.args) >= 2 && cmd.args[0] == "-N" {
			foundChainCreate = true
		}
	}
	if !foundChainCreate {
		t.Error("expected iptables -N chain creation")
	}
}

func TestIPTablesDriver_UsesGenerationIPSetsForLargePrefixSets(t *testing.T) {
	runner := &fakeCommandRunner{}
	driver := &IPTablesDriver{Command: runner.run}
	prefixes := make([]netip.Prefix, 0, 30)
	for i := range 30 {
		prefixes = append(prefixes, netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/64", i)))
	}
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "photon", NetNS: "photon", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "phx*", OwnerPrefix: "photon",
	}, FirewallPolicyInput{
		MeshAuthorized: prefixes,
		LiveInterfaces: []string{"phx1", "phx2", "phx3"},
		Forwarding: ForwardingPolicy{
			Transit:       true,
			AllowPrefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
		},
	})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := driver.Apply(context.Background(), desired); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	if len(runner.ipsets) != 1 {
		t.Fatalf("managed ipsets = %v, want one shared source/destination set", runner.ipsets)
	}
	for name, members := range runner.ipsetMembers {
		if len(members) != 30 {
			t.Fatalf("ipset %s has %d members, want 30", name, len(members))
		}
	}
	transitRules := 0
	for _, command := range runner.commands {
		text := commandText(command)
		if command.name == "ip6tables" && strings.Contains(text, "xfrm transit (transit enabled)") {
			transitRules++
			if !strings.Contains(text, "-i phx+ -o phx+") ||
				strings.Count(text, "--match-set") != 2 ||
				!strings.Contains(text, " src ") ||
				!strings.Contains(text, " dst ") {
				t.Fatalf("transit rule does not use source and destination ipset lookups: %s", text)
			}
		}
	}
	if transitRules != 1 {
		t.Fatalf("transit rule count = %d, want 1", transitRules)
	}

	firstSets := make(map[string]bool, len(runner.ipsets))
	for name := range runner.ipsets {
		firstSets[name] = true
	}
	runner.commands = nil
	if _, err := driver.Apply(context.Background(), desired); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if len(runner.ipsets) != 1 {
		t.Fatalf("ipsets after generation cutover = %v, want only active generation", runner.ipsets)
	}
	for name := range firstSets {
		if runner.ipsets[name] {
			t.Fatalf("stale generation ipset %s survived cutover", name)
		}
	}
}

func TestIPTablesDriver_IPSetPreparationFailureKeepsActiveGeneration(t *testing.T) {
	runner := &fakeCommandRunner{}
	driver := &IPTablesDriver{Command: runner.run}
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.1.0.0/24"),
		netip.MustParsePrefix("10.2.0.0/24"),
	}
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "photon", NetNS: "photon", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "phx*", OwnerPrefix: "photon",
	}, FirewallPolicyInput{
		MeshAuthorized: prefixes,
		Forwarding:     ForwardingPolicy{Transit: true, AllowPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
	})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := driver.Apply(context.Background(), desired); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	activeSets := make(map[string]bool, len(runner.ipsets))
	for name := range runner.ipsets {
		activeSets[name] = true
	}

	runner.failContains = "add "
	if _, err := driver.Apply(context.Background(), desired); err == nil {
		t.Fatal("second Apply succeeded despite injected ipset population failure")
	}
	if len(runner.ipsets) != len(activeSets) {
		t.Fatalf("ipsets after failed staging = %v, want active %v", runner.ipsets, activeSets)
	}
	for name := range activeSets {
		if !runner.ipsets[name] {
			t.Fatalf("active ipset %s was removed after failed staging", name)
		}
	}
}

func TestIPTablesDriver_ExternalDoesNotApply(t *testing.T) {
	runner := &fakeCommandRunner{}
	desired, err := BuildDesiredState(FirewallInstanceSpec{ID: "external", NetNS: "photon", Mode: ModeExternal}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := (&IPTablesDriver{Command: runner.run}).Apply(context.Background(), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("external apply executed commands: %+v", runner.commands)
	}
}

func TestIPTablesDriver_ApplyHostWithNATRedirect(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "host", NetNS: "host", IsHost: true, Enabled: true, Mode: ModeManaged,
		OwnerPrefix:   "photon",
		HostPorts:     HostPortConfig{IKE: true, NATT: true},
		RedirectGrace: RedirectGrace{Enabled: true},
	}
	input := FirewallPolicyInput{
		AdvertisedPreviousIKEPorts:  []uint16{450},
		AdvertisedPreviousNATTPorts: []uint16{5000, 5500},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	_, err = d.Apply(context.Background(), desired)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	foundNatRedirect := false
	for _, cmd := range runner.commands {
		argsStr := strings.Join(cmd.args, " ")
		if strings.Contains(argsStr, "REDIRECT") && strings.Contains(argsStr, "--to-ports") {
			foundNatRedirect = true
		}
	}
	if !foundNatRedirect {
		t.Error("expected iptables NAT REDIRECT rule")
	}
}

func TestIPTablesDriver_ApplyHostWithNATSourceRewrite(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "host", NetNS: "host", IsHost: true, Enabled: true, Mode: ModeManaged,
		OwnerPrefix:   "photon",
		HostPorts:     HostPortConfig{IKE: true, NATT: true},
		RedirectGrace: RedirectGrace{Enabled: true},
	}
	input := FirewallPolicyInput{
		AdvertisedCurrentNATTPorts: []uint16{33403},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := d.Apply(context.Background(), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	assertCommandContains(t, runner.commands, "iptables", "-t nat -A photon_host_s_")
	assertCommandContains(t, runner.commands, "iptables", "-p udp --sport 4500 -j MASQUERADE --to-ports 33403")
}

func TestIPTablesDriver_HostAddressFamilyCommands(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID:            "host",
		NetNS:         "host",
		IsHost:        true,
		Enabled:       true,
		Mode:          ModeManaged,
		OwnerPrefix:   "photon",
		HostPorts:     HostPortConfig{IKE: true},
		RedirectGrace: RedirectGrace{Enabled: true},
		ListenAddrs: []netip.Addr{
			netip.MustParseAddr("192.0.2.10"),
			netip.MustParseAddr("2001:db8::10"),
		},
	}
	input := FirewallPolicyInput{
		AdvertisedCurrentIKEPorts: []uint16{30001},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := d.Apply(context.Background(), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for _, cmd := range runner.commands {
		args := strings.Join(cmd.args, " ")
		if cmd.name == "iptables" && strings.Contains(args, "2001:db8::10") {
			t.Fatalf("IPv6 address rendered into iptables command: %s %s", cmd.name, args)
		}
		if cmd.name == "ip6tables" && strings.Contains(args, "192.0.2.10") {
			t.Fatalf("IPv4 address rendered into ip6tables command: %s %s", cmd.name, args)
		}
	}
	assertCommandContains(t, runner.commands, "iptables", "-d 192.0.2.10")
	assertCommandContains(t, runner.commands, "ip6tables", "-d 2001:db8::10")
	assertCommandContains(t, runner.commands, "iptables", "--dport 30001 -d 192.0.2.10")
	assertCommandContains(t, runner.commands, "ip6tables", "--dport 30001 -d 2001:db8::10")
}

func TestIPTablesDriver_ListOwned(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	state, err := d.ListOwned(context.Background(), Owner{OwnerPrefix: "photon", InstanceID: "photontesth2"})
	if err != nil {
		t.Fatalf("ListOwned: %v", err)
	}
	if len(state.Objects) != 0 {
		t.Errorf("expected 0 objects from empty output, got %d", len(state.Objects))
	}
}

func TestParseIPTablesChains(t *testing.T) {
	output := "-N photon_photontesth2_INPUT\n-A photon_photontesth2_INPUT -p udp --dport 500 -j ACCEPT\n-N photon_photontesth2_FORWARD\n-N photon_photontesth2_pre_user\n-A INPUT -j photon_photontesth2_INPUT\n-N other_chain"
	refs := parseIPTablesChains(output, "photon_photontesth2", "filter")
	if len(refs) != 2 {
		t.Fatalf("expected 2 photon-owned chains, got %d", len(refs))
	}
	for _, ref := range refs {
		if !strings.HasPrefix(ref.Name, "photon_photontesth2") {
			t.Errorf("non-photon chain in result: %s", ref.Name)
		}
	}
	natRefs := parseIPTablesChains(
		"-N photon_photontesth2_prerouting\n-N photon_photontesth2_postrouting\n-N photon_photontesth2_nat_user",
		"photon_photontesth2", "nat",
	)
	if len(natRefs) != 2 || natRefs[0].Kind != "nat_redirect" || natRefs[1].Kind != "nat_source" {
		t.Fatalf("nat refs = %+v, want redirect/source managed objects only", natRefs)
	}
}

func TestBuildDesiredState_HostRedirectGraceHeuristic(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID:            "host",
		NetNS:         "host",
		IsHost:        true,
		Enabled:       true,
		Mode:          ModeManaged,
		HostPorts:     HostPortConfig{IKE: true, NATT: true},
		RedirectGrace: RedirectGrace{Enabled: true},
	}
	input := FirewallPolicyInput{
		AdvertisedPreviousIKEPorts:  []uint16{450},
		AdvertisedPreviousNATTPorts: []uint16{5000},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if len(desired.NatRedirects) != 2 {
		t.Fatalf("expected 2 NAT redirect rules, got %d", len(desired.NatRedirects))
	}
	foundIKERedirect := false
	foundNATTRedirect := false
	for _, nr := range desired.NatRedirects {
		if nr.OriginalDst == 450 && nr.RedirectTo == 500 {
			foundIKERedirect = true
		}
		if nr.OriginalDst == 5000 && nr.RedirectTo == 4500 {
			foundNATTRedirect = true
		}
	}
	if !foundIKERedirect {
		t.Error("expected IKE redirect 450 -> 500")
	}
	if !foundNATTRedirect {
		t.Error("expected NAT-T redirect 5000 -> 4500")
	}
}

func TestBuildDesiredState_HostRedirectCurrentAndPreviousPorts(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID:            "host",
		NetNS:         "host",
		IsHost:        true,
		Enabled:       true,
		Mode:          ModeManaged,
		HostPorts:     HostPortConfig{IKE: true, NATT: true},
		RedirectGrace: RedirectGrace{Enabled: true},
	}
	input := FirewallPolicyInput{
		AdvertisedCurrentIKEPorts:   []uint16{30001},
		AdvertisedCurrentNATTPorts:  []uint16{30002},
		AdvertisedPreviousIKEPorts:  []uint16{29001},
		AdvertisedPreviousNATTPorts: []uint16{29002},
		AdvertisedPreviousWGPorts:   []uint16{},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if len(desired.NatRedirects) != 4 {
		t.Fatalf("expected 4 NAT redirect rules, got %d: %+v", len(desired.NatRedirects), desired.NatRedirects)
	}
	assertNatRedirect(t, desired, 30001, 500, "redirect current")
	assertNatRedirect(t, desired, 30002, 4500, "redirect current")
	assertNatRedirect(t, desired, 29001, 500, "redirect grace")
	assertNatRedirect(t, desired, 29002, 4500, "redirect grace")
	assertNatSource(t, desired, 500, 30001, "source current")
	assertNatSource(t, desired, 4500, 30002, "source current")
}

func TestBuildDesiredState_HostRedirectCoversAllListenAddrs(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID:            "host",
		NetNS:         "host",
		IsHost:        true,
		Enabled:       true,
		Mode:          ModeManaged,
		HostPorts:     HostPortConfig{IKE: true},
		RedirectGrace: RedirectGrace{Enabled: true},
		ListenAddrs: []netip.Addr{
			netip.MustParseAddr("192.0.2.10"),
			netip.MustParseAddr("192.0.2.11"),
			netip.MustParseAddr("2001:db8::10"),
		},
	}
	input := FirewallPolicyInput{
		AdvertisedCurrentIKEPorts: []uint16{30001},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if len(desired.NatRedirects) != 3 {
		t.Fatalf("expected one redirect per listen addr, got %d: %+v", len(desired.NatRedirects), desired.NatRedirects)
	}
	assertNatRedirectAddr(t, desired, 30001, 500, "192.0.2.10")
	assertNatRedirectAddr(t, desired, 30001, 500, "192.0.2.11")
	assertNatRedirectAddr(t, desired, 30001, 500, "2001:db8::10")
}

func TestBuildDesiredState_HostRedirectGraceSkipCurrentPorts(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID:            "host",
		NetNS:         "host",
		IsHost:        true,
		Enabled:       true,
		Mode:          ModeManaged,
		HostPorts:     HostPortConfig{IKE: true, NATT: true},
		RedirectGrace: RedirectGrace{Enabled: true},
	}
	input := FirewallPolicyInput{
		AdvertisedPreviousIKEPorts:  []uint16{500},
		AdvertisedPreviousNATTPorts: []uint16{4500},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if len(desired.NatRedirects) != 0 {
		t.Errorf("expected 0 redirect rules for current ports, got %d", len(desired.NatRedirects))
	}
	if len(desired.NatSources) != 0 {
		t.Errorf("expected 0 source rewrite rules for current ports, got %d", len(desired.NatSources))
	}
}

func assertCommandContains(t *testing.T, commands []executedCommand, binary, fragment string) {
	t.Helper()
	for _, cmd := range commands {
		if cmd.name == binary && strings.Contains(strings.Join(cmd.args, " "), fragment) {
			return
		}
	}
	t.Fatalf("missing %s command containing %q in %+v", binary, fragment, commands)
}

func assertNatRedirect(t *testing.T, desired *FirewallDesiredState, original, target uint16, comment string) {
	t.Helper()
	for _, nr := range desired.NatRedirects {
		if nr.OriginalDst == original && nr.RedirectTo == target && strings.Contains(nr.Comment, comment) {
			return
		}
	}
	t.Fatalf("missing redirect %d -> %d comment containing %q in %+v", original, target, comment, desired.NatRedirects)
}

func assertNatRedirectAddr(t *testing.T, desired *FirewallDesiredState, original, target uint16, addr string) {
	t.Helper()
	want := netip.MustParseAddr(addr)
	for _, nr := range desired.NatRedirects {
		if nr.OriginalDst == original && nr.RedirectTo == target && nr.DstAddr == want {
			return
		}
	}
	t.Fatalf("missing redirect %d -> %d for %s in %+v", original, target, addr, desired.NatRedirects)
}

func assertNatSource(t *testing.T, desired *FirewallDesiredState, original, target uint16, comment string) {
	t.Helper()
	for _, ns := range desired.NatSources {
		if ns.OriginalSrc == original && ns.RewriteTo == target && strings.Contains(ns.Comment, comment) {
			return
		}
	}
	t.Fatalf("missing source rewrite %d -> %d comment containing %q in %+v", original, target, comment, desired.NatSources)
}

func TestIPTablesDriver_CtStateCommands(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "photontesth2", NetNS: "photontesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "phx*",
		OwnerPrefix: "photon",
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := d.Apply(context.Background(), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Conntrack rules install for both address families.
	for _, binary := range []string{"iptables", "ip6tables"} {
		assertCommandContains(t, runner.commands, binary, "-m conntrack --ctstate INVALID -j DROP")
		assertCommandContains(t, runner.commands, binary, "--ctstate ESTABLISHED,RELATED -j ACCEPT")
	}
}

func TestIPTablesDriver_FamilyNeutralAndICMPCommands(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "photontesth2", NetNS: "photontesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "phx*",
		OwnerPrefix: "photon",
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := d.Apply(context.Background(), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// ICMP rules render per family with an explicit protocol match.
	assertCommandContains(t, runner.commands, "iptables", "-p icmp -j ACCEPT")
	assertCommandContains(t, runner.commands, "ip6tables", "-p icmpv6 -j ACCEPT")

	// Family-neutral rules (loopback, babel control, default policy) install
	// for both address families.
	for _, binary := range []string{"iptables", "ip6tables"} {
		assertCommandContains(t, runner.commands, binary, "-i lo -j ACCEPT")
		assertCommandContains(t, runner.commands, binary, "-p udp --dport 6696 -j ACCEPT")
		assertCommandContains(t, runner.commands, binary, "-i phx+ -o phx+ -j DROP")
	}

	// No cross-family ICMP rendering.
	for _, cmd := range runner.commands {
		args := strings.Join(cmd.args, " ")
		if cmd.name == "iptables" && strings.Contains(args, "-p icmpv6") {
			t.Fatalf("icmpv6 rendered into iptables command: %s %s", cmd.name, args)
		}
		if cmd.name == "ip6tables" && strings.Contains(args, "-p icmp ") {
			t.Fatalf("icmp rendered into ip6tables command: %s %s", cmd.name, args)
		}
	}

	// Every accept rule in the overlay INPUT chain must carry at least one
	// match; an unconditional accept before the default policy would nullify
	// the default drop.
	chain := "photon_photontesth2_input"
	for _, cmd := range runner.commands {
		args := strings.Join(cmd.args, " ")
		if !strings.Contains(args, "-A "+chain) || !strings.Contains(args, "-j ACCEPT") {
			continue
		}
		matched := false
		for _, flag := range []string{"-p ", "-i ", "-o ", "-s ", "-d ", "-m "} {
			if strings.Contains(args, flag) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("unconditional accept in %s: %s %s", chain, cmd.name, args)
		}
	}
}

func TestIPTablesDriverInlineHooksKeepFamiliesAndOrderSeparate(t *testing.T) {
	runner := &fakeCommandRunner{}
	driver := &IPTablesDriver{Command: runner.run}
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "photon", NetNS: "photon", Mode: ModeManaged, Backend: BackendIptables, OwnerPrefix: "photon",
		NativeHooks: NativeHooks{IPTables: IPTablesInlineHooks{
			IPv4: InlineHookRules{PreInput: []string{
				`-s 10.20.0.0/16 -p tcp --dport 22 -j ACCEPT`,
				`-s 10.30.0.0/16 -p tcp --dport 443 -j ACCEPT`,
			}},
			IPv6: InlineHookRules{PreInput: []string{
				`-s 2001:db8:20::/48 -p tcp --dport 22 -j ACCEPT`,
			}},
		}},
	}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := driver.Apply(context.Background(), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	first := commandIndex(runner.commands, "iptables", "-s 10.20.0.0/16")
	second := commandIndex(runner.commands, "iptables", "-s 10.30.0.0/16")
	if first < 0 || second < 0 || first >= second {
		t.Fatalf("IPv4 inline rule order incorrect: first=%d second=%d", first, second)
	}
	assertCommandContains(t, runner.commands, "ip6tables", "-s 2001:db8:20::/48")
	for _, command := range runner.commands {
		args := strings.Join(command.args, " ")
		if command.name == "ip6tables" && (strings.Contains(args, "10.20.0.0/16") || strings.Contains(args, "10.30.0.0/16")) {
			t.Fatalf("IPv4 inline rule copied to ip6tables: %s", args)
		}
		if command.name == "iptables" && strings.Contains(args, "2001:db8:20::/48") {
			t.Fatalf("IPv6 inline rule copied to iptables: %s", args)
		}
	}
}

func TestIPTablesDriverHostPreroutingInlineRuleUsesNATTable(t *testing.T) {
	runner := &fakeCommandRunner{}
	driver := &IPTablesDriver{Command: runner.run}
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "host", NetNS: "host", IsHost: true, Mode: ModeManaged, Backend: BackendIptables, OwnerPrefix: "photon",
		NativeHooks: NativeHooks{IPTables: IPTablesInlineHooks{
			IPv4: InlineHookRules{HostPrePrerouting: []string{`-p tcp --dport 8080 -j ACCEPT`}},
		}},
	}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := driver.Apply(context.Background(), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	assertCommandContains(t, runner.commands, "iptables", "-t nat -A photon_host_r_")
	assertCommandContains(t, runner.commands, "iptables", "-p tcp --dport 8080 -j ACCEPT")
}

func TestIPTablesDriver_ReconcileExistingManagedChains(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "photontesth2", NetNS: "photontesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "phx*",
		OwnerPrefix: "photon",
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := d.Apply(context.Background(), desired); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	observed, err := d.ListOwned(context.Background(), Owner{OwnerPrefix: "photon", InstanceID: spec.NetNS})
	if err != nil {
		t.Fatalf("ListOwned after first apply: %v", err)
	}
	if len(observed.Objects) != len(DesiredObjects(desired)) {
		t.Fatalf("observed = %+v, want canonical desired objects %+v", observed.Objects, DesiredObjects(desired))
	}

	runner.commands = nil
	if _, err := d.Apply(context.Background(), desired); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	tableName := iptablesTableName(desired)
	hash := DesiredStateHash(desired)
	oldInput := iptablesGenerationChain(tableName, "i", hash, 'a')
	newInput := iptablesGenerationChain(tableName, "i", hash, 'b')
	populateAt := commandIndex(runner.commands, "iptables", "-A "+newInput)
	activateAt := commandIndex(runner.commands, "iptables", "-I INPUT -j "+newInput)
	removeOldAt := commandIndex(runner.commands, "iptables", "-D INPUT -j "+oldInput)
	flushOldAt := commandIndex(runner.commands, "iptables", "-F "+oldInput)
	if populateAt < 0 || activateAt < 0 || removeOldAt < 0 || flushOldAt < 0 {
		t.Fatalf("missing generation cutover commands: %+v", runner.commands)
	}
	if !(populateAt < activateAt && activateAt < removeOldAt && removeOldAt < flushOldAt) {
		t.Fatalf("unsafe cutover order: populate=%d activate=%d removeOld=%d flushOld=%d", populateAt, activateAt, removeOldAt, flushOldAt)
	}
	for _, binary := range []string{"iptables", "ip6tables"} {
		oldKey := binary + ":filter:" + oldInput
		newKey := binary + ":filter:" + newInput
		if runner.existingChains[oldKey] {
			t.Errorf("%s old generation still exists after cutover", binary)
		}
		if !runner.existingChains[newKey] {
			t.Errorf("%s new generation missing after cutover", binary)
		}
	}
	assertCommandContains(t, runner.commands, "iptables", "--ctstate ESTABLISHED,RELATED -j ACCEPT")
}

func TestIPTablesDriver_PrepareFailureKeepsActiveGeneration(t *testing.T) {
	runner := &fakeCommandRunner{}
	driver := &IPTablesDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "photontesth2", NetNS: "photontesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "phx*", OwnerPrefix: "photon",
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := driver.Apply(context.Background(), desired); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	tableName := iptablesTableName(desired)
	hash := DesiredStateHash(desired)
	activeInput := iptablesGenerationChain(tableName, "i", hash, 'a')
	stagingInput := iptablesGenerationChain(tableName, "i", hash, 'b')
	runner.commands = nil
	runner.failContains = "--ctstate ESTABLISHED,RELATED"
	result, err := driver.Apply(context.Background(), desired)
	if err == nil {
		t.Fatal("second Apply succeeded despite injected staging failure")
	}
	if result.Failed == 0 {
		t.Fatalf("result = %+v, want a reported failure", result)
	}
	for _, binary := range []string{"iptables", "ip6tables"} {
		if !runner.existingChains[binary+":filter:"+activeInput] {
			t.Errorf("%s active generation was removed after staging failure", binary)
		}
		jump := []string{"INPUT", "-j", activeInput, "-m", "comment", "--comment", "photon-photontesth2"}
		key := binary + ":filter:" + strings.Join(jump, "\x00")
		if !runner.existingRules[key] {
			t.Errorf("%s active jump was removed after staging failure", binary)
		}
		if runner.existingChains[binary+":filter:"+stagingInput] {
			t.Errorf("%s failed staging generation was not discarded", binary)
		}
	}
	if commandIndex(runner.commands, "iptables", "-I INPUT -j "+stagingInput) >= 0 {
		t.Fatal("failed staging generation was activated")
	}
}

func TestIPTablesDriver_ActivationFailureRollsBackOtherFamily(t *testing.T) {
	runner := &fakeCommandRunner{}
	driver := &IPTablesDriver{Command: runner.run}
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "photontesth2", NetNS: "photontesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "phx*", OwnerPrefix: "photon",
	}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := driver.Apply(context.Background(), desired); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	tableName := iptablesTableName(desired)
	hash := DesiredStateHash(desired)
	activeInput := iptablesGenerationChain(tableName, "i", hash, 'a')
	stagingInput := iptablesGenerationChain(tableName, "i", hash, 'b')
	runner.commands = nil
	failed := false
	driver.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if !failed && name == "ip6tables" && strings.Contains(strings.Join(args, " "), "-I INPUT -j "+stagingInput) {
			failed = true
			runner.commands = append(runner.commands, executedCommand{name: name, args: append([]string(nil), args...)})
			return nil, errors.New("injected activation failure")
		}
		return runner.run(ctx, name, args...)
	}
	if _, err := driver.Apply(context.Background(), desired); err == nil {
		t.Fatal("second Apply succeeded despite injected activation failure")
	}
	if !failed {
		t.Fatal("activation failure was not injected")
	}
	for _, binary := range []string{"iptables", "ip6tables"} {
		activeJump := []string{"INPUT", "-j", activeInput, "-m", "comment", "--comment", "photon-photontesth2"}
		if !runner.existingRules[binary+":filter:"+strings.Join(activeJump, "\x00")] {
			t.Errorf("%s old active jump missing after activation rollback", binary)
		}
		stagingJump := []string{"INPUT", "-j", stagingInput, "-m", "comment", "--comment", "photon-photontesth2"}
		if runner.existingRules[binary+":filter:"+strings.Join(stagingJump, "\x00")] {
			t.Errorf("%s staging jump remained after activation rollback", binary)
		}
		if runner.existingChains[binary+":filter:"+stagingInput] {
			t.Errorf("%s staging chain remained after activation rollback", binary)
		}
	}
}

func TestIPTablesDriver_MigrationDrainsAllLegacyDuplicateJumps(t *testing.T) {
	runner := &fakeCommandRunner{}
	const duplicates = 12
	legacy := "photon_photontesth2_INPUT"
	jump := []string{"INPUT", "-j", legacy, "-m", "comment", "--comment", "photon-photontesth2"}
	for _, binary := range []string{"iptables", "ip6tables"} {
		runner.seedIPTablesChain(binary, "filter", legacy)
		for range duplicates {
			runner.seedIPTablesRule(binary, "filter", jump)
		}
	}
	driver := &IPTablesDriver{Command: runner.run}
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "photontesth2", NetNS: "photontesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "phx*", OwnerPrefix: "photon",
	}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := driver.Apply(context.Background(), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, binary := range []string{"iptables", "ip6tables"} {
		if runner.existingChains[binary+":filter:"+legacy] {
			t.Errorf("%s legacy chain remains after migration", binary)
		}
		deletes := 0
		for _, command := range runner.commands {
			if command.name == binary && strings.Contains(strings.Join(command.args, " "), "-D INPUT -j "+legacy) {
				deletes++
			}
		}
		// One final failed delete terminates the drain loop.
		if deletes != duplicates+1 {
			t.Errorf("%s attempted %d duplicate-jump deletes, want %d", binary, deletes, duplicates+1)
		}
	}
}

func TestIPTablesGenerationChainNameIsBoundedAndRecognized(t *testing.T) {
	tableName := "photon_a_very_long_network_namespace_name"
	chain := iptablesGenerationChain(tableName, "i", "0123456789abcdef", 'a')
	if len(chain) > 28 {
		t.Fatalf("generation chain %q has length %d, want <= 28", chain, len(chain))
	}
	ref, builtin, ok := managedIPTablesChainIdentity(tableName, "filter", chain)
	if !ok || builtin != "INPUT" {
		t.Fatalf("generation chain identity = (%+v, %q, %v)", ref, builtin, ok)
	}
	if ref.Name != tableName+"_input" {
		t.Fatalf("logical ref = %q, want %q", ref.Name, tableName+"_input")
	}
}

func commandIndex(commands []executedCommand, binary, fragment string) int {
	for i, command := range commands {
		if command.name == binary && strings.Contains(strings.Join(command.args, " "), fragment) {
			return i
		}
	}
	return -1
}

func TestIPTablesInterfaceMatchArgSetsExpandsExactSets(t *testing.T) {
	rule := Rule{
		IfacesIn:  []string{"phx1", "phx2"},
		IfacesOut: []string{"phx1", "phx2"},
	}
	matches := iptablesInterfaceMatchArgSets(rule)
	if len(matches) != 4 {
		t.Fatalf("interface set expansion produced %d matches, want 4: %v", len(matches), matches)
	}
}

func TestIPTablesInterfaceMatchArgSetsPrefersPortableSelectors(t *testing.T) {
	rule := Rule{
		IfaceIn:   "phx*",
		IfaceOut:  "phx*",
		IfacesIn:  []string{"phx1", "phx2"},
		IfacesOut: []string{"phx1", "phx2"},
	}
	matches := iptablesInterfaceMatchArgSets(rule)
	if len(matches) != 1 {
		t.Fatalf("portable selectors produced %d matches, want 1: %v", len(matches), matches)
	}
	got := strings.Join(matches[0], " ")
	if got != "-i phx+ -o phx+" {
		t.Fatalf("portable selectors rendered as %q, want %q", got, "-i phx+ -o phx+")
	}
}

func TestIPTablesRuleCommandsWithIPSetsKeepsFamiliesSeparate(t *testing.T) {
	v4 := []netip.Prefix{
		netip.MustParsePrefix("10.1.0.0/24"),
		netip.MustParsePrefix("10.2.0.0/24"),
	}
	v6 := []netip.Prefix{
		netip.MustParsePrefix("2001:db8:1::/64"),
		netip.MustParsePrefix("2001:db8:2::/64"),
	}
	rule := Rule{
		Action:   ActionAccept,
		IfaceIn:  "phx*",
		IfaceOut: "phx*",
		Src:      append(append([]netip.Prefix{}, v4...), v6...),
		Dst:      append(append([]netip.Prefix{}, v4...), v6...),
	}
	rendered := iptablesRuleCommandsWithIPSets("photon_h2", "photon_h2_f_deadbeef0000a", rule, "photon-photon")
	if len(rendered.commands) != 2 || len(rendered.ipsets) != 2 {
		t.Fatalf("dual-stack rendering = %d commands, %d sets; want 2 and 2", len(rendered.commands), len(rendered.ipsets))
	}
	families := make(map[string]bool)
	for _, spec := range rendered.ipsets {
		families[spec.family] = true
		if len(spec.name) > 31 {
			t.Fatalf("ipset name %q exceeds 31 characters", spec.name)
		}
	}
	if !families["inet"] || !families["inet6"] {
		t.Fatalf("ipset families = %v, want inet and inet6", families)
	}
}

func TestPlanDiffKeepsObservedNATChains(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "host", NetNS: "host", IsHost: true, Enabled: true, Mode: ModeManaged,
		OwnerPrefix: "photon", RedirectGrace: RedirectGrace{Enabled: true},
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{
		AdvertisedCurrentNATTPorts: []uint16{33403},
	})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	observed := FirewallObservedState{Objects: []FirewallObjectRef{
		{Kind: "table", Family: "inet", Name: "photon_host"},
		{Kind: "chain", Family: "inet", Name: "photon_host_input"},
		{Kind: "nat_redirect", Family: "inet", Name: "photon_host_prerouting"},
		{Kind: "nat_source", Family: "inet", Name: "photon_host_postrouting"},
	}}
	for _, action := range PlanDiff(spec.ID, desired, observed).Actions {
		if action.Action == "delete" {
			t.Fatalf("current NAT object planned for deletion: %+v", action)
		}
	}
}

func TestIPTablesApplyRemovesDisabledNATChainsFromNATTable(t *testing.T) {
	spec := FirewallInstanceSpec{
		ID: "host", NetNS: "host", IsHost: true, Enabled: true, Mode: ModeManaged,
		OwnerPrefix: "photon",
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	runner := &fakeCommandRunner{}
	for _, binary := range []string{"iptables", "ip6tables"} {
		runner.seedIPTablesChain(binary, "nat", "photon_host_prerouting")
		runner.seedIPTablesRule(binary, "nat", []string{"PREROUTING", "-j", "photon_host_prerouting", "-m", "comment", "--comment", "photon-host"})
		runner.seedIPTablesChain(binary, "nat", "photon_host_postrouting")
		runner.seedIPTablesRule(binary, "nat", []string{"POSTROUTING", "-j", "photon_host_postrouting", "-m", "comment", "--comment", "photon-host"})
	}
	driver := &IPTablesDriver{Command: runner.run}
	if _, err := driver.Apply(context.Background(), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, want := range []string{
		"-t nat -D PREROUTING -j photon_host_prerouting",
		"-t nat -F photon_host_prerouting",
		"-t nat -X photon_host_prerouting",
		"-t nat -D POSTROUTING -j photon_host_postrouting",
		"-t nat -F photon_host_postrouting",
		"-t nat -X photon_host_postrouting",
	} {
		found := false
		for _, cmd := range runner.commands {
			if strings.Contains(strings.Join(cmd.args, " "), want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing NAT stale cleanup containing %q in %+v", want, runner.commands)
		}
	}
}

func TestLegacyNATRuleNumbersDescending(t *testing.T) {
	output := `Chain PREROUTING (policy ACCEPT)
num  target     prot opt source destination
1    REDIRECT   udp  --  0.0.0.0/0 0.0.0.0/0 /* other */ redir ports 500
2    REDIRECT   udp  --  0.0.0.0/0 0.0.0.0/0 /* photon-host:old one */ redir ports 500
5    REDIRECT   udp  --  0.0.0.0/0 0.0.0.0/0 /* photon-host:old two */ redir ports 4500`
	got := legacyNATRuleNumbers(output, "photon-host")
	if len(got) != 2 || got[0] != 5 || got[1] != 2 {
		t.Fatalf("legacy rule numbers = %v, want [5 2]", got)
	}
}
