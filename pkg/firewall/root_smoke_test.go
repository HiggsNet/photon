package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestFilterIPTablesOwnedDumpSelectsActiveOwnerGeneration(t *testing.T) {
	const (
		scope  = "shared-scope"
		tableA = "hfi_shared-scope"
		tableB = "hfir_shared-scope"
		setA   = "set_a"
		setB   = "set_b"
	)
	chainA := iptablesGenerationChain(tableA, "i", "aaaaaaaaaaaa", 'a')
	chainB := iptablesGenerationChain(tableB, "i", "bbbbbbbbbbbb", 'a')
	rules := strings.Join([]string{
		fmt.Sprintf("-A INPUT -m comment --comment photon-%s -j %s", scope, chainA),
		fmt.Sprintf("-A INPUT -m comment --comment photon-%s -j %s", scope, chainB),
		"-N " + chainA,
		"-N " + chainB,
		fmt.Sprintf("-A %s -s 198.51.100.1/32 -m comment --comment inline-a -j ACCEPT", chainA),
		fmt.Sprintf("-A %s -m set --match-set %s src -j ACCEPT", chainA, setA),
		fmt.Sprintf("-A %s -s 198.51.100.2/32 -m comment --comment inline-b -j ACCEPT", chainB),
		fmt.Sprintf("-A %s -m set --match-set %s src -j ACCEPT", chainB, setB),
	}, "\n")
	ipsets := strings.Join([]string{
		"create " + setA + " hash:net family inet",
		"add " + setA + " 10.42.0.0/24",
		"create " + setB + " hash:net family inet",
		"add " + setB + " 10.43.0.0/24",
	}, "\n")

	got := filterIPTablesOwnedDump(rules, ipsets, tableA, "photon-"+scope)
	for _, want := range []string{chainA, "inline-a", "10.42.0.0/24"} {
		if !strings.Contains(got, want) {
			t.Fatalf("filtered dump missing %q:\n%s", want, got)
		}
	}
	for _, reject := range []string{chainB, "inline-b", "10.43.0.0/24"} {
		if strings.Contains(got, reject) {
			t.Fatalf("filtered dump unexpectedly contains %q:\n%s", reject, got)
		}
	}
}

func TestFirewallBackendsRootSmoke(t *testing.T) {
	if os.Getenv("PHOTON_FIREWALL_SMOKE") != "1" {
		t.Skip("set PHOTON_FIREWALL_SMOKE=1 to run the root/system firewall smoke")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
	nsName := "hfw" + suffix
	if err := runCmd(ctx, "ip", "netns", "add", nsName); err != nil {
		t.Fatalf("ip netns add %s: %v", nsName, err)
	}
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", nsName).Run()
	})
	if err := runCmd(ctx, "ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up"); err != nil {
		t.Fatalf("set lo up in %s: %v", nsName, err)
	}

	if _, err := exec.LookPath("nft"); err == nil {
		t.Run("nft", func(t *testing.T) {
			runFirewallBackendRootSmoke(t, ctx, nsName, "nft")
		})
	} else {
		t.Log("nft not found; skipping nft backend root smoke")
	}

	_, iptablesErr := exec.LookPath("iptables")
	_, ip6tablesErr := exec.LookPath("ip6tables")
	_, ipsetErr := exec.LookPath("ipset")
	if iptablesErr == nil && ip6tablesErr == nil && ipsetErr == nil {
		t.Run("iptables", func(t *testing.T) {
			runFirewallBackendRootSmoke(t, ctx, nsName, "iptables")
		})
	} else {
		t.Log("iptables/ip6tables/ipset not all available; skipping iptables backend root smoke")
	}
}

func runFirewallBackendRootSmoke(t *testing.T, ctx context.Context, nsName, backend string) {
	t.Helper()

	ownerPrefix := "hfn"
	if backend == BackendIptables {
		ownerPrefix = "hfi"
	}
	spec := FirewallInstanceSpec{
		ID:                backend + "-overlay",
		NetNS:             nsName,
		Enabled:           true,
		Mode:              ModeManaged,
		Backend:           backend,
		DefaultPolicy:     DefaultPolicyDrop,
		OwnerPrefix:       ownerPrefix,
		XFRMTunnelPattern: "phx+",
		LocalServices: []LocalService{
			{Proto: ProtoTCP, Port: 8080},
		},
	}
	inlineWant := []string{}
	switch backend {
	case BackendNFT:
		spec.NativeHooks.NFT.PreInput = []string{
			`ip saddr 198.51.100.7 counter comment "photon-inline-nft-v4"`,
			`ip6 saddr 2001:db8:ffff::7 counter comment "photon-inline-nft-v6"`,
		}
		inlineWant = append(inlineWant, "photon-inline-nft-v4", "photon-inline-nft-v6")
	case BackendIptables:
		spec.NativeHooks.IPTables.IPv4.PreInput = []string{
			`-s 198.51.100.7/32 -m comment --comment "photon-inline-iptables-v4" -j ACCEPT`,
		}
		spec.NativeHooks.IPTables.IPv6.PreInput = []string{
			`-s 2001:db8:ffff::7/128 -m comment --comment "photon-inline-iptables-v6" -j ACCEPT`,
		}
		inlineWant = append(inlineWant, "photon-inline-iptables-v4", "photon-inline-iptables-v6")
	}
	input := FirewallPolicyInput{
		LocalAssigned:      []netip.Prefix{mustPrefix(t, "10.42.0.2/32")},
		MeshAuthorized:     []netip.Prefix{mustPrefix(t, "10.42.0.1/32"), mustPrefix(t, "10.43.0.0/24")},
		Revoked:            []netip.Prefix{mustPrefix(t, "10.99.0.0/24")},
		LiveInterfaces:     []string{"phx0"},
		UpstreamInterfaces: []string{"up0"},
		Forwarding: ForwardingPolicy{
			Transit:       true,
			AllowPrefixes: []netip.Prefix{mustPrefix(t, "10.42.0.1/32"), mustPrefix(t, "10.42.0.2/32")},
		},
	}
	desired, err := BuildDesiredState(spec, input)
	if err != nil {
		t.Fatalf("BuildDesiredState overlay: %v", err)
	}

	cleanupFirewallBackend(t, ctx, nsName, backend, ownerPrefix, spec.NetNS)
	driver := newRootSmokeDriver(backend, nsName)
	observed, err := driver.ListOwned(ctx, Owner{OwnerPrefix: ownerPrefix, InstanceID: spec.NetNS})
	if err != nil {
		t.Fatalf("ListOwned overlay: %v", err)
	}
	plan, err := driver.Plan(ctx, desired, observed)
	if err != nil {
		t.Fatalf("Plan overlay: %v", err)
	}
	result, err := driver.Apply(ctx, plan, desired)
	if err != nil {
		t.Fatalf("Apply overlay failed after %d applied/%d failed: %v", result.Applied, result.Failed, err)
	}
	assertFirewallBackendState(t, ctx, nsName, backend, ownerPrefix, spec.NetNS, append([]string{"10.42.0.1", "10.43.0.0/24"}, inlineWant...), []string{"10.99.0.0/24"})

	revokedSpec := spec
	revokedSpec.OwnerPrefix = ownerPrefix + "r"
	revokedInput := input
	revokedInput.Revoked = append(revokedInput.Revoked, mustPrefix(t, "10.43.0.0/24"))
	revokedDesired, err := BuildDesiredState(revokedSpec, revokedInput)
	if err != nil {
		t.Fatalf("BuildDesiredState revoked overlay: %v", err)
	}
	cleanupFirewallBackend(t, ctx, nsName, backend, revokedSpec.OwnerPrefix, revokedSpec.NetNS)
	plan, err = driver.Plan(ctx, revokedDesired, FirewallObservedState{})
	if err != nil {
		t.Fatalf("Plan revoked overlay: %v", err)
	}
	result, err = driver.Apply(ctx, plan, revokedDesired)
	if err != nil {
		t.Fatalf("Apply revoked overlay failed after %d applied/%d failed: %v", result.Applied, result.Failed, err)
	}
	assertFirewallBackendState(t, ctx, nsName, backend, revokedSpec.OwnerPrefix, revokedSpec.NetNS, []string{"10.42.0.1"}, []string{"10.43.0.0/24", "10.99.0.0/24"})

	hostOwnerPrefix := ownerPrefix + "h"
	hostSpec := FirewallInstanceSpec{
		ID:             backend + "-host",
		NetNS:          "host",
		IsHost:         true,
		Enabled:        true,
		Mode:           ModeManaged,
		Backend:        backend,
		OwnerPrefix:    hostOwnerPrefix,
		HostPorts:      HostPortConfig{IKE: true, NATT: true},
		RedirectGrace:  RedirectGrace{Enabled: true},
		ListenAddrs:    []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		CharonIKEPort:  1500,
		CharonNATTPort: 14500,
	}
	hostInlineWant := []string{}
	switch backend {
	case BackendNFT:
		hostSpec.NativeHooks.NFT.HostPreInput = []string{`udp dport 16000 counter comment "photon-inline-host-input"`}
		hostSpec.NativeHooks.NFT.HostPrePrerouting = []string{`tcp dport 18080 counter comment "photon-inline-host-prerouting"`}
		hostInlineWant = append(hostInlineWant, "photon-inline-host-input", "photon-inline-host-prerouting")
	case BackendIptables:
		hostSpec.NativeHooks.IPTables.IPv4.HostPreInput = []string{`-p udp --dport 16000 -m comment --comment "photon-inline-host-input"`}
		hostSpec.NativeHooks.IPTables.IPv4.HostPrePrerouting = []string{`-p tcp --dport 18080 -m comment --comment "photon-inline-host-prerouting"`}
		hostInlineWant = append(hostInlineWant, "photon-inline-host-input", "photon-inline-host-prerouting")
	}
	hostInput := FirewallPolicyInput{
		AdvertisedPreviousIKEPorts:  []uint16{500},
		AdvertisedPreviousNATTPorts: []uint16{4500},
	}
	hostDesired, err := BuildDesiredState(hostSpec, hostInput)
	if err != nil {
		t.Fatalf("BuildDesiredState host: %v", err)
	}
	cleanupFirewallBackend(t, ctx, nsName, backend, hostOwnerPrefix, "host")
	hostObserved, err := driver.ListOwned(ctx, Owner{OwnerPrefix: hostOwnerPrefix, InstanceID: "host"})
	if err != nil {
		t.Fatalf("ListOwned host: %v", err)
	}
	hostPlan, err := driver.Plan(ctx, hostDesired, hostObserved)
	if err != nil {
		t.Fatalf("Plan host: %v", err)
	}
	hostResult, err := driver.Apply(ctx, hostPlan, hostDesired)
	if err != nil {
		t.Fatalf("Apply host failed after %d applied/%d failed: %v", hostResult.Applied, hostResult.Failed, err)
	}
	assertFirewallBackendState(t, ctx, nsName, backend, hostOwnerPrefix, "host", append([]string{"1500", "14500"}, hostInlineWant...), nil)
}

func newRootSmokeDriver(backend, nsName string) FirewallDriver {
	switch backend {
	case BackendNFT:
		return &NFTDriver{NetNS: nsName}
	case BackendIptables:
		return &IPTablesDriver{NetNS: nsName}
	default:
		return NewDryRunDriver()
	}
}

func assertFirewallBackendState(t *testing.T, ctx context.Context, nsName, backend, ownerPrefix, scope string, want, reject []string) {
	t.Helper()
	out := firewallBackendDump(t, ctx, nsName, backend, ownerPrefix, scope)
	for _, needle := range want {
		if !strings.Contains(out, needle) {
			t.Fatalf("%s %s dump missing %q:\n%s", backend, scope, needle, out)
		}
	}
	for _, needle := range reject {
		if strings.Contains(out, needle) {
			t.Fatalf("%s %s dump unexpectedly contains %q:\n%s", backend, scope, needle, out)
		}
	}
}

func firewallBackendDump(t *testing.T, ctx context.Context, nsName, backend, ownerPrefix, scope string) string {
	t.Helper()
	tableName := ownerPrefix + "_" + scope
	switch backend {
	case BackendNFT:
		out, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "nft", "list", "table", "inet", tableName).CombinedOutput()
		if err != nil {
			t.Fatalf("nft list table inet %s: %v\noutput: %s", tableName, err, string(out))
		}
		return string(out)
	case BackendIptables:
		var ruleDumps []string
		for _, binary := range []string{"iptables", "ip6tables"} {
			out, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-S").CombinedOutput()
			if err != nil {
				t.Fatalf("%s -S: %v\noutput: %s", binary, err, string(out))
			}
			nat, _ := exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-t", "nat", "-S").CombinedOutput()
			ruleDumps = append(ruleDumps, string(out), string(nat))
		}
		ipsets, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "ipset", "save").CombinedOutput()
		if err != nil {
			t.Fatalf("ipset save: %v\noutput: %s", err, string(ipsets))
		}
		return filterIPTablesOwnedDump(strings.Join(ruleDumps, "\n"), string(ipsets), tableName, "photon-"+scope)
	default:
		return ""
	}
}

func filterIPTablesOwnedDump(rules, ipsets, tableName, ownerMarker string) string {
	chains := make(map[string]struct{})
	for line := range strings.SplitSeq(rules, "\n") {
		if !strings.Contains(line, ownerMarker) {
			continue
		}
		if target := iptablesJumpTarget(line); isIPTablesSmokeChain(tableName, target) {
			chains[target] = struct{}{}
		}
	}

	// Follow generation-chain jumps as well, so this remains correct if the
	// driver later splits a hook across multiple private chains.
	for changed := true; changed; {
		changed = false
		for line := range strings.SplitSeq(rules, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[0] != "-A" {
				continue
			}
			if _, ok := chains[fields[1]]; !ok {
				continue
			}
			target := iptablesJumpTarget(line)
			if target == "" {
				continue
			}
			if _, ok := chains[target]; !ok {
				chains[target] = struct{}{}
				changed = true
			}
		}
	}

	sets := make(map[string]struct{})
	var selected []string
	for line := range strings.SplitSeq(rules, "\n") {
		fields := strings.Fields(line)
		owned := false
		if len(fields) >= 2 && (fields[0] == "-N" || fields[0] == "-A") {
			_, owned = chains[fields[1]]
		}
		if !owned {
			continue
		}
		selected = append(selected, line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "--match-set" {
				sets[fields[i+1]] = struct{}{}
			}
		}
	}
	for line := range strings.SplitSeq(ipsets, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, ok := sets[fields[1]]; ok {
			selected = append(selected, line)
		}
	}
	return strings.Join(selected, "\n")
}

func isIPTablesSmokeChain(tableName, chain string) bool {
	for _, code := range []string{"i", "f", "o", "r", "s"} {
		if isIPTablesGenerationChain(tableName, code, chain) {
			return true
		}
	}
	return false
}

func iptablesJumpTarget(line string) string {
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "-j" {
			return fields[i+1]
		}
	}
	return ""
}

func cleanupFirewallBackend(t *testing.T, ctx context.Context, nsName, backend, ownerPrefix, scope string) {
	t.Helper()
	t.Cleanup(func() {
		cleanupFirewallBackendNow(context.Background(), nsName, backend, ownerPrefix, scope)
	})
	cleanupFirewallBackendNow(ctx, nsName, backend, ownerPrefix, scope)
}

func cleanupFirewallBackendNow(ctx context.Context, nsName, backend, ownerPrefix, scope string) {
	tableName := ownerPrefix + "_" + scope
	switch backend {
	case BackendNFT:
		_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "nft", "delete", "table", "inet", tableName).Run()
	case BackendIptables:
		for _, binary := range []string{"iptables", "ip6tables"} {
			for _, chain := range []string{
				tableName + "_input", tableName + "_forward", tableName + "_output",
				tableName + "_INPUT", tableName + "_FORWARD", tableName + "_OUTPUT",
			} {
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-D", "INPUT", "-j", chain).Run()
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-D", "FORWARD", "-j", chain).Run()
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-D", "OUTPUT", "-j", chain).Run()
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-F", chain).Run()
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-X", chain).Run()
			}
			for _, item := range []struct {
				builtin string
				chain   string
			}{
				{"PREROUTING", tableName + "_prerouting"},
				{"POSTROUTING", tableName + "_postrouting"},
			} {
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-t", "nat", "-D", item.builtin, "-j", item.chain).Run()
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-t", "nat", "-F", item.chain).Run()
				_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, binary, "-t", "nat", "-X", item.chain).Run()
			}
		}
		_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "500", "-d", "127.0.0.1", "-j", "REDIRECT", "--to-ports", "1500").Run()
		_ = exec.CommandContext(ctx, "ip", "netns", "exec", nsName, "iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "4500", "-d", "127.0.0.1", "-j", "REDIRECT", "--to-ports", "14500").Run()
	}
}

func runCmd(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\noutput: %s", name, strings.Join(args, " "), err, string(out))
	}
	return nil
}
