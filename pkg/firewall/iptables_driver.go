package firewall

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// IPTablesDriver implements FirewallDriver using iptables/ip6tables CLI.
// It is the fallback backend for Phase 6.3.6 when nftables is not available.
//
// Design:
//   - All Photon-owned rules use a comment marker "photon-<scope>" for ownership tracking.
//   - Chains are created with a Photon-specific name prefix.
//   - ListOwned parses `iptables -S` / `iptables -t nat -S` output.
//   - Apply populates an inactive generation chain before switching the
//     built-in-chain jump, so preparation failures keep the old policy active.
//
// The driver is designed to be testable by injecting CommandRunner.
type IPTablesDriver struct {
	Command CommandRunner
	NetNS   string
}

// NewIPTablesDriver creates an IPTablesDriver with the default command runner.
func NewIPTablesDriver() *IPTablesDriver {
	return &IPTablesDriver{Command: nftExecCommand}
}

func (d *IPTablesDriver) runner() CommandRunner {
	if d.Command != nil {
		return d.Command
	}
	return nftExecCommand
}

func (d *IPTablesDriver) run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	runner := d.runner()
	if d.NetNS != "" {
		full := append([]string{"netns", "exec", d.NetNS, binary}, args...)
		return runner(ctx, "ip", full...)
	}
	return runner(ctx, binary, args...)
}

func (d *IPTablesDriver) Preflight(ctx context.Context, spec FirewallInstanceSpec) (FirewallPreflight, error) {
	pf := PreflightProbe(ctx)
	if IPTablesAvailable(pf) {
		if _, err := d.run(ctx, "iptables", "-L", "INPUT"); err != nil {
			pf.Iptables = "permission_denied"
			if pf.Backend == BackendIptables {
				pf.Backend = BackendNone
			}
		}
		if _, err := d.run(ctx, "ip6tables", "-L", "INPUT"); err != nil {
			pf.IptablesV6 = "permission_denied"
			if pf.Backend == BackendIptables {
				pf.Backend = BackendNone
			}
		}
		if _, err := d.run(ctx, "ipset", "list", "-name"); err != nil {
			pf.IPSet = "permission_denied"
			if pf.Backend == BackendIptables {
				pf.Backend = BackendNone
			}
		}
	}
	return pf, nil
}

func (d *IPTablesDriver) Plan(ctx context.Context, desired *FirewallDesiredState, observed FirewallObservedState) (FirewallPlan, error) {
	if desired == nil {
		return FirewallPlan{}, fmt.Errorf("desired state is nil")
	}
	return PlanDiff(desired.Instance.ID, desired, observed), nil
}

func (d *IPTablesDriver) Apply(ctx context.Context, plan FirewallPlan, desired *FirewallDesiredState) (FirewallApplyResult, error) {
	result := FirewallApplyResult{}
	if desired == nil {
		return result, fmt.Errorf("desired state is nil")
	}
	if desired.Instance.Mode == ModeExternal || desired.Instance.Mode == ModeDisabled {
		return result, nil
	}
	_ = plan // generation-chain apply converges from the live kernel state.

	marker := iptablesOwnerMarker(desired)
	tableName := iptablesTableName(desired)
	hash := DesiredStateHash(desired)
	specs := buildIPTablesManagedChainSpecs(desired, marker)
	var prepared []preparedIPTablesChain

	// Build every inactive generation chain completely before changing a
	// built-in-chain jump. A preparation error leaves the active generation
	// untouched and therefore cannot create a fail-open window.
	for _, spec := range specs {
		for _, binary := range []string{"iptables", "ip6tables"} {
			item, applied, err := d.prepareIPTablesGeneration(ctx, binary, tableName, marker, hash, spec)
			result.Applied += applied
			if err != nil {
				d.discardPreparedIPTablesChains(ctx, append(prepared, item))
				return iptablesApplyFailure(result, err.Error())
			}
			prepared = append(prepared, item)
		}
	}

	// Cut over only after all IPv4 and IPv6 staging chains are complete. New
	// jumps are inserted before old jumps, so a cutover failure leaves at
	// least the old policy (and possibly the new policy) active.
	for i := range prepared {
		item := &prepared[i]
		args := iptablesArgs(item.spec.table, "-I", item.spec.builtin, "-j", item.generation, "-m", "comment", "--comment", marker)
		if _, err := d.run(ctx, item.binary, args...); err != nil {
			rollbackErrs := d.rollbackPreparedIPTablesChains(ctx, prepared, marker)
			message := fmt.Sprintf("%s activate %s: %v", item.binary, item.generation, err)
			if len(rollbackErrs) > 0 {
				message += "; rollback: " + strings.Join(rollbackErrs, "; ")
			}
			return iptablesApplyFailure(result, message)
		}
		item.activated = true
		result.Applied++
	}

	active := make(map[string]bool, len(prepared))
	for _, item := range prepared {
		active[iptablesChainKey(item.binary, item.spec.table, item.generation)] = true
	}
	cleaned, cleanupErrs := d.cleanupOldIPTablesGenerations(ctx, tableName, marker, active)
	result.Applied += cleaned

	// Migrate rules written directly into built-in NAT chains only after the
	// replacement NAT generation is active.
	legacyApplied, legacyErrs := d.deleteLegacyNATBaseRules(ctx, marker)
	result.Applied += legacyApplied
	cleanupErrs = append(cleanupErrs, legacyErrs...)
	if len(cleanupErrs) > 0 {
		result.Failed += len(cleanupErrs)
		result.Generation = 1
		return result, fmt.Errorf("iptables apply cleanup had %d errors: %s", len(cleanupErrs), strings.Join(cleanupErrs, "; "))
	}
	result.Generation = 1
	return result, nil
}

type iptablesManagedChainSpec struct {
	table     string
	builtin   string
	canonical string
	code      string
	rules     func(chain string) (iptablesRenderedRules, error)
}

type preparedIPTablesChain struct {
	binary     string
	spec       iptablesManagedChainSpec
	generation string
	ipsets     []string
	activated  bool
}

type iptablesRenderedRules struct {
	commands []iptablesCommand
	ipsets   []iptablesSetSpec
}

type iptablesSetSpec struct {
	name     string
	family   string
	prefixes []netip.Prefix
}

func iptablesApplyFailure(result FirewallApplyResult, message string) (FirewallApplyResult, error) {
	result.Failed++
	result.Generation = 1
	return result, fmt.Errorf("iptables apply failed: %s", message)
}

func iptablesTableName(desired *FirewallDesiredState) string {
	prefix := desired.Instance.OwnerPrefix
	if prefix == "" {
		prefix = "photon"
	}
	scope := desired.Instance.NetNS
	if desired.Instance.IsHost {
		scope = "host"
	}
	return prefix + "_" + scope
}

func buildIPTablesManagedChainSpecs(desired *FirewallDesiredState, marker string) []iptablesManagedChainSpec {
	if desired.Instance.Mode == ModeDisabled || desired.Instance.Mode == ModeExternal {
		return nil
	}
	tableName := iptablesTableName(desired)
	ruleBuilder := func(rules []Rule, insertions ...iptablesHookInsertion) func(string) (iptablesRenderedRules, error) {
		return func(chain string) (iptablesRenderedRules, error) {
			var ipsets []iptablesSetSpec
			commands, err := buildIPTablesInterleavedCommands("", chain, len(rules), func(i int) []iptablesCommand {
				rendered := iptablesRuleCommandsWithIPSets(tableName, chain, rules[i], marker)
				ipsets = append(ipsets, rendered.ipsets...)
				return rendered.commands
			}, insertions...)
			return iptablesRenderedRules{commands: commands, ipsets: dedupIPTablesSetSpecs(ipsets)}, err
		}
	}

	if !desired.Instance.IsHost {
		return []iptablesManagedChainSpec{
			{builtin: "INPUT", canonical: tableName + "_input", code: "i", rules: ruleBuilder(desired.InputRules,
				iptablesHookInsertion{index: desired.HookPositions.PreInput, ipv4: desired.NativeHooks.IPTables.IPv4.PreInput, ipv6: desired.NativeHooks.IPTables.IPv6.PreInput},
				iptablesHookInsertion{index: desired.HookPositions.PostInput, ipv4: desired.NativeHooks.IPTables.IPv4.PostInput, ipv6: desired.NativeHooks.IPTables.IPv6.PostInput})},
			{builtin: "FORWARD", canonical: tableName + "_forward", code: "f", rules: ruleBuilder(desired.ForwardRules,
				iptablesHookInsertion{index: desired.HookPositions.PreForward, ipv4: desired.NativeHooks.IPTables.IPv4.PreForward, ipv6: desired.NativeHooks.IPTables.IPv6.PreForward},
				iptablesHookInsertion{index: desired.HookPositions.PostForward, ipv4: desired.NativeHooks.IPTables.IPv4.PostForward, ipv6: desired.NativeHooks.IPTables.IPv6.PostForward})},
			{builtin: "OUTPUT", canonical: tableName + "_output", code: "o", rules: ruleBuilder(desired.OutputRules,
				iptablesHookInsertion{index: desired.HookPositions.PreOutput, ipv4: desired.NativeHooks.IPTables.IPv4.PreOutput, ipv6: desired.NativeHooks.IPTables.IPv6.PreOutput},
				iptablesHookInsertion{index: desired.HookPositions.PostOutput, ipv4: desired.NativeHooks.IPTables.IPv4.PostOutput, ipv6: desired.NativeHooks.IPTables.IPv6.PostOutput})},
		}
	}

	inputRules := func(chain string) (iptablesRenderedRules, error) {
		commands, err := buildIPTablesInterleavedCommands("", chain, len(desired.HostIngress), func(i int) []iptablesCommand {
			hi := desired.HostIngress[i]
			var commands []iptablesCommand
			args := []string{"-A", chain, "-p", iptablesProto(hi.Proto)}
			if hi.Port > 0 {
				args = append(args, "--dport", fmt.Sprintf("%d", hi.Port))
			}
			if hi.DstAddr.IsValid() {
				args = append(args, "-d", hi.DstAddr.String())
			}
			args = append(args, "-j", "ACCEPT", "-m", "comment", "--comment", marker+":"+hi.Comment)
			for _, binary := range iptablesBinariesForAddr(hi.DstAddr) {
				commands = append(commands, iptablesCommand{binary: binary, args: args})
			}
			return commands
		},
			iptablesHookInsertion{index: desired.HookPositions.HostPreInput, ipv4: desired.NativeHooks.IPTables.IPv4.HostPreInput, ipv6: desired.NativeHooks.IPTables.IPv6.HostPreInput},
			iptablesHookInsertion{index: desired.HookPositions.HostPostInput, ipv4: desired.NativeHooks.IPTables.IPv4.HostPostInput, ipv6: desired.NativeHooks.IPTables.IPv6.HostPostInput},
		)
		return iptablesRenderedRules{commands: commands}, err
	}
	specs := []iptablesManagedChainSpec{
		{builtin: "INPUT", canonical: tableName + "_input", code: "i", rules: inputRules},
	}
	if len(desired.ForwardRules) > 0 {
		specs = append(specs, iptablesManagedChainSpec{
			builtin: "FORWARD", canonical: tableName + "_forward", code: "f", rules: ruleBuilder(desired.ForwardRules),
		})
	}
	if len(desired.NatRedirects) > 0 || len(desired.NativeHooks.IPTables.IPv4.HostPrePrerouting) > 0 || len(desired.NativeHooks.IPTables.IPv4.HostPostPrerouting) > 0 || len(desired.NativeHooks.IPTables.IPv6.HostPrePrerouting) > 0 || len(desired.NativeHooks.IPTables.IPv6.HostPostPrerouting) > 0 {
		specs = append(specs, iptablesManagedChainSpec{
			table: "nat", builtin: "PREROUTING", canonical: tableName + "_prerouting", code: "r",
			rules: func(chain string) (iptablesRenderedRules, error) {
				commands, err := buildIPTablesInterleavedCommands("nat", chain, len(desired.NatRedirects), func(i int) []iptablesCommand {
					nr := desired.NatRedirects[i]
					var commands []iptablesCommand
					args := []string{"-t", "nat", "-A", chain, "-p", iptablesProto(nr.Proto)}
					if nr.OriginalDst > 0 {
						args = append(args, "--dport", fmt.Sprintf("%d", nr.OriginalDst))
					}
					if nr.DstAddr.IsValid() {
						args = append(args, "-d", nr.DstAddr.String())
					}
					args = append(args, "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", nr.RedirectTo), "-m", "comment", "--comment", marker+":"+nr.Comment)
					for _, binary := range iptablesBinariesForAddr(nr.DstAddr) {
						commands = append(commands, iptablesCommand{binary: binary, args: args})
					}
					return commands
				},
					iptablesHookInsertion{index: desired.HookPositions.HostPrePrerouting, ipv4: desired.NativeHooks.IPTables.IPv4.HostPrePrerouting, ipv6: desired.NativeHooks.IPTables.IPv6.HostPrePrerouting},
					iptablesHookInsertion{index: desired.HookPositions.HostPostPrerouting, ipv4: desired.NativeHooks.IPTables.IPv4.HostPostPrerouting, ipv6: desired.NativeHooks.IPTables.IPv6.HostPostPrerouting},
				)
				return iptablesRenderedRules{commands: commands}, err
			},
		})
	}
	if len(desired.NatSources) > 0 {
		specs = append(specs, iptablesManagedChainSpec{
			table: "nat", builtin: "POSTROUTING", canonical: tableName + "_postrouting", code: "s",
			rules: func(chain string) (iptablesRenderedRules, error) {
				var commands []iptablesCommand
				for _, ns := range desired.NatSources {
					args := []string{"-t", "nat", "-A", chain, "-p", iptablesProto(ns.Proto)}
					if ns.OriginalSrc > 0 {
						args = append(args, "--sport", fmt.Sprintf("%d", ns.OriginalSrc))
					}
					if ns.DstPort > 0 {
						args = append(args, "--dport", fmt.Sprintf("%d", ns.DstPort))
					}
					if ns.DstAddr.IsValid() {
						args = append(args, "-d", ns.DstAddr.String())
					}
					args = append(args, "-j", "MASQUERADE", "--to-ports", fmt.Sprintf("%d", ns.RewriteTo), "-m", "comment", "--comment", marker+":"+ns.Comment)
					for _, binary := range iptablesBinariesForAddr(ns.DstAddr) {
						commands = append(commands, iptablesCommand{binary: binary, args: args})
					}
				}
				return iptablesRenderedRules{commands: commands}, nil
			},
		})
	}
	return specs
}

func iptablesGenerationChain(tableName, code, hash string, slot byte) string {
	const generationHashLength = 12
	if len(hash) > generationHashLength {
		hash = hash[:generationHashLength]
	}
	suffix := "_" + code + "_" + hash + string(slot)
	const maxChainName = 28
	prefixLen := max(maxChainName-len(suffix), 1)
	prefix := tableName
	if len(prefix) > prefixLen {
		prefix = prefix[:prefixLen]
	}
	return prefix + suffix
}

func (d *IPTablesDriver) prepareIPTablesGeneration(
	ctx context.Context,
	binary, tableName, marker, hash string,
	spec iptablesManagedChainSpec,
) (preparedIPTablesChain, int, error) {
	a := iptablesGenerationChain(tableName, spec.code, hash, 'a')
	b := iptablesGenerationChain(tableName, spec.code, hash, 'b')
	aActive := d.iptablesJumpExists(ctx, binary, spec.table, spec.builtin, a, marker)
	bActive := d.iptablesJumpExists(ctx, binary, spec.table, spec.builtin, b, marker)
	if aActive && bActive {
		// Both slots represent the same desired hash. Keep a active while b is
		// rebuilt, then normal cleanup removes the duplicate a jump.
		if _, err := d.run(ctx, binary, iptablesArgs(spec.table, "-D", spec.builtin, "-j", b, "-m", "comment", "--comment", marker)...); err != nil {
			return preparedIPTablesChain{}, 0, fmt.Errorf("%s remove duplicate active slot %s: %w", binary, b, err)
		}
		bActive = false
	}
	generation := a
	if aActive {
		generation = b
	} else if bActive {
		generation = a
	}
	item := preparedIPTablesChain{binary: binary, spec: spec, generation: generation}
	applied := 0

	existsArgs := iptablesArgs(spec.table, "-S", generation)
	if _, err := d.run(ctx, binary, existsArgs...); err == nil {
		if _, err := d.run(ctx, binary, iptablesArgs(spec.table, "-F", generation)...); err != nil {
			return item, applied, fmt.Errorf("%s flush inactive generation %s: %w", binary, generation, err)
		}
		applied++
	} else {
		if _, err := d.run(ctx, binary, iptablesArgs(spec.table, "-N", generation)...); err != nil {
			return item, applied, fmt.Errorf("%s create generation %s: %w", binary, generation, err)
		}
		applied++
	}

	rendered, err := spec.rules(generation)
	if err != nil {
		return item, applied, fmt.Errorf("%s render generation %s: %w", binary, generation, err)
	}
	for _, setSpec := range rendered.ipsets {
		if (binary == "iptables") != (setSpec.family == "inet") {
			continue
		}
		item.ipsets = append(item.ipsets, setSpec.name)
		setApplied, err := d.prepareIPSet(ctx, setSpec)
		applied += setApplied
		if err != nil {
			return item, applied, fmt.Errorf("%s prepare ipset %s: %w", binary, setSpec.name, err)
		}
	}
	for _, command := range rendered.commands {
		if command.binary != binary {
			continue
		}
		if _, err := d.run(ctx, binary, command.args...); err != nil {
			return item, applied, fmt.Errorf("%s populate generation %s: %w", binary, generation, err)
		}
		applied++
	}
	return item, applied, nil
}

func (d *IPTablesDriver) prepareIPSet(ctx context.Context, spec iptablesSetSpec) (int, error) {
	applied := 0
	if _, err := d.run(ctx, "ipset", "create", spec.name, "hash:net", "family", spec.family, "-exist"); err != nil {
		return applied, err
	}
	applied++
	if _, err := d.run(ctx, "ipset", "flush", spec.name); err != nil {
		return applied, err
	}
	applied++
	for _, prefix := range spec.prefixes {
		if _, err := d.run(ctx, "ipset", "add", spec.name, prefix.String(), "-exist"); err != nil {
			return applied, err
		}
		applied++
	}
	return applied, nil
}

func (d *IPTablesDriver) iptablesJumpExists(ctx context.Context, binary, table, builtin, target, marker string) bool {
	_, err := d.run(ctx, binary, iptablesArgs(table, "-C", builtin, "-j", target, "-m", "comment", "--comment", marker)...)
	return err == nil
}

func (d *IPTablesDriver) discardPreparedIPTablesChains(ctx context.Context, prepared []preparedIPTablesChain) {
	for _, item := range prepared {
		if item.activated || item.binary == "" || item.generation == "" {
			continue
		}
		_, _ = d.run(ctx, item.binary, iptablesArgs(item.spec.table, "-F", item.generation)...)
		if _, err := d.run(ctx, item.binary, iptablesArgs(item.spec.table, "-X", item.generation)...); err == nil {
			d.destroyIPSets(ctx, item.ipsets)
		}
	}
}

func (d *IPTablesDriver) rollbackPreparedIPTablesChains(ctx context.Context, prepared []preparedIPTablesChain, marker string) []string {
	var errs []string
	for _, item := range slices.Backward(prepared) {

		if item.binary == "" || item.generation == "" {
			continue
		}
		if item.activated {
			args := iptablesArgs(item.spec.table, "-D", item.spec.builtin, "-j", item.generation, "-m", "comment", "--comment", marker)
			if _, err := d.run(ctx, item.binary, args...); err != nil {
				errs = append(errs, fmt.Sprintf("%s deactivate %s: %v", item.binary, item.generation, err))
				continue
			}
		}
		if _, err := d.run(ctx, item.binary, iptablesArgs(item.spec.table, "-F", item.generation)...); err != nil {
			errs = append(errs, fmt.Sprintf("%s flush %s: %v", item.binary, item.generation, err))
			continue
		}
		if _, err := d.run(ctx, item.binary, iptablesArgs(item.spec.table, "-X", item.generation)...); err != nil {
			errs = append(errs, fmt.Sprintf("%s delete %s: %v", item.binary, item.generation, err))
			continue
		}
		d.destroyIPSets(ctx, item.ipsets)
	}
	return errs
}

func (d *IPTablesDriver) destroyIPSets(ctx context.Context, names []string) {
	for _, name := range names {
		_, _ = d.run(ctx, "ipset", "destroy", name)
	}
}

func iptablesChainKey(binary, table, chain string) string {
	if table == "" {
		table = "filter"
	}
	return binary + ":" + table + ":" + chain
}

func (d *IPTablesDriver) cleanupOldIPTablesGenerations(
	ctx context.Context,
	tableName, marker string,
	active map[string]bool,
) (int, []string) {
	applied := 0
	var errs []string
	for _, binary := range []string{"iptables", "ip6tables"} {
		for _, table := range []string{"", "nat"} {
			out, err := d.run(ctx, binary, iptablesArgs(table, "-S")...)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s list %s table for cleanup: %v", binary, iptablesTableLabel(table), err))
				continue
			}
			for _, chain := range parseManagedIPTablesActualChains(string(out), tableName, table) {
				if active[iptablesChainKey(binary, table, chain.name)] {
					continue
				}
				deleteArgs := iptablesArgs(table, "-D", chain.builtin, "-j", chain.name, "-m", "comment", "--comment", marker)
				for range 4096 {
					if _, err := d.run(ctx, binary, deleteArgs...); err != nil {
						break
					}
					applied++
				}
				if d.iptablesJumpExists(ctx, binary, table, chain.builtin, chain.name, marker) {
					errs = append(errs, fmt.Sprintf("%s too many references to stale chain %s", binary, chain.name))
					continue
				}
				after, err := d.run(ctx, binary, iptablesArgs(table, "-S")...)
				if err != nil {
					errs = append(errs, fmt.Sprintf("%s verify references to stale chain %s: %v", binary, chain.name, err))
					continue
				}
				if iptablesChainReferenced(string(after), chain.name) {
					errs = append(errs, fmt.Sprintf("%s stale chain %s still has non-Photon references", binary, chain.name))
					continue
				}
				if _, err := d.run(ctx, binary, iptablesArgs(table, "-F", chain.name)...); err != nil {
					errs = append(errs, fmt.Sprintf("%s flush stale chain %s: %v", binary, chain.name, err))
					continue
				}
				applied++
				if _, err := d.run(ctx, binary, iptablesArgs(table, "-X", chain.name)...); err != nil {
					errs = append(errs, fmt.Sprintf("%s delete stale chain %s: %v", binary, chain.name, err))
					continue
				}
				applied++
			}
		}
	}
	cleaned, setErrs := d.cleanupOrphanIPSets(ctx, tableName)
	applied += cleaned
	errs = append(errs, setErrs...)
	return applied, errs
}

func (d *IPTablesDriver) cleanupOrphanIPSets(ctx context.Context, tableName string) (int, []string) {
	out, err := d.run(ctx, "ipset", "list", "-name")
	if err != nil {
		return 0, []string{fmt.Sprintf("ipset list for cleanup: %v", err)}
	}
	referenced := make(map[string]bool)
	for _, binary := range []string{"iptables", "ip6tables"} {
		for _, table := range []string{"", "nat"} {
			rules, listErr := d.run(ctx, binary, iptablesArgs(table, "-S")...)
			if listErr != nil {
				return 0, []string{fmt.Sprintf("%s list %s table for ipset cleanup: %v", binary, iptablesTableLabel(table), listErr)}
			}
			for _, name := range referencedIPSets(string(rules)) {
				referenced[name] = true
			}
		}
	}
	prefix := iptablesIPSetPrefix(tableName)
	applied := 0
	var errs []string
	for name := range strings.FieldsSeq(string(out)) {
		if !strings.HasPrefix(name, prefix) || referenced[name] {
			continue
		}
		if _, err := d.run(ctx, "ipset", "destroy", name); err != nil {
			errs = append(errs, fmt.Sprintf("destroy stale ipset %s: %v", name, err))
			continue
		}
		applied++
	}
	return applied, errs
}

func referencedIPSets(rules string) []string {
	seen := make(map[string]bool)
	var out []string
	for line := range strings.SplitSeq(rules, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] != "--match-set" || seen[fields[i+1]] {
				continue
			}
			seen[fields[i+1]] = true
			out = append(out, fields[i+1])
		}
	}
	return out
}

func iptablesTableLabel(table string) string {
	if table == "" {
		return "filter"
	}
	return table
}

type managedIPTablesActualChain struct {
	name    string
	builtin string
}

func parseManagedIPTablesActualChains(output, tableName, table string) []managedIPTablesActualChain {
	seen := make(map[string]bool)
	var chains []managedIPTablesActualChain
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 || fields[0] != "-N" {
			continue
		}
		name := fields[1]
		_, builtin, ok := managedIPTablesChainIdentity(tableName, table, name)
		if !ok || seen[name] {
			continue
		}
		seen[name] = true
		chains = append(chains, managedIPTablesActualChain{name: name, builtin: builtin})
	}
	sort.Slice(chains, func(i, j int) bool { return chains[i].name < chains[j].name })
	return chains
}

func iptablesChainReferenced(output, target string) bool {
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "-j" && fields[i+1] == target {
				return true
			}
		}
	}
	return false
}

func iptablesOwnerMarker(desired *FirewallDesiredState) string {
	scope := desired.Instance.NetNS
	if desired.Instance.IsHost {
		scope = "host"
	}
	return "photon-" + scope
}

func (d *IPTablesDriver) deleteLegacyNATBaseRules(ctx context.Context, marker string) (int, []string) {
	applied := 0
	var errs []string
	for _, binary := range []string{"iptables", "ip6tables"} {
		for _, chain := range []string{"PREROUTING", "POSTROUTING"} {
			out, err := d.run(ctx, binary, "-t", "nat", "-L", chain, "--line-numbers", "-n")
			if err != nil {
				// Some installations do not expose IPv6 NAT. Lack of a list
				// result cannot imply that a legacy rule exists.
				continue
			}
			for _, number := range legacyNATRuleNumbers(string(out), marker) {
				if _, err := d.run(ctx, binary, "-t", "nat", "-D", chain, strconv.Itoa(number)); err != nil {
					errs = append(errs, fmt.Sprintf("%s delete legacy nat %s rule %d: %v", binary, chain, number, err))
					continue
				}
				applied++
			}
		}
	}
	return applied, errs
}

func legacyNATRuleNumbers(output, marker string) []int {
	var numbers []int
	for line := range strings.SplitSeq(output, "\n") {
		if !strings.Contains(line, marker+":") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		number, err := strconv.Atoi(fields[0])
		if err == nil {
			numbers = append(numbers, number)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(numbers)))
	return numbers
}

func (d *IPTablesDriver) ListOwned(ctx context.Context, owner Owner) (FirewallObservedState, error) {
	prefix := owner.OwnerPrefix
	if prefix == "" {
		prefix = "photon"
	}
	tableName := prefix + "_" + owner.InstanceID
	var state FirewallObservedState

	// Check filter table chains.
	out, _ := d.run(ctx, "iptables", "-S")
	state.Objects = append(state.Objects, parseIPTablesChains(string(out), tableName, "filter")...)

	out6, _ := d.run(ctx, "ip6tables", "-S")
	state.Objects = append(state.Objects, parseIPTablesChains(string(out6), tableName, "filter")...)

	// Check nat table chains.
	outNat, _ := d.run(ctx, "iptables", "-t", "nat", "-S")
	state.Objects = append(state.Objects, parseIPTablesChains(string(outNat), tableName, "nat")...)

	outNat6, _ := d.run(ctx, "ip6tables", "-t", "nat", "-S")
	state.Objects = append(state.Objects, parseIPTablesChains(string(outNat6), tableName, "nat")...)

	state.Objects = dedupFirewallObjectRefs(state.Objects)
	// Always report the synthetic table ref if any owned objects exist.
	if len(state.Objects) > 0 {
		state.Objects = append([]FirewallObjectRef{{Kind: "table", Family: "inet", Name: tableName}}, state.Objects...)
	}
	return state, nil
}

func (d *IPTablesDriver) DeleteStale(ctx context.Context, refs []FirewallObjectRef) error {
	wanted := make(map[string]map[string]bool)
	for _, ref := range refs {
		tableName, ok := iptablesObjectTableName(ref)
		if !ok {
			continue
		}
		if wanted[tableName] == nil {
			wanted[tableName] = make(map[string]bool)
		}
		wanted[tableName][objKey(ref)] = true
	}
	var errs []string
	for tableName, keys := range wanted {
		for _, binary := range []string{"iptables", "ip6tables"} {
			for _, table := range []string{"", "nat"} {
				out, err := d.run(ctx, binary, iptablesArgs(table, "-S")...)
				if err != nil {
					errs = append(errs, fmt.Sprintf("%s list %s table: %v", binary, iptablesTableLabel(table), err))
					continue
				}
				for _, chain := range parseManagedIPTablesActualChains(string(out), tableName, table) {
					ref, _, ok := managedIPTablesChainIdentity(tableName, table, chain.name)
					if !ok {
						continue
					}
					if !keys[objKey(ref)] && !keys[objKey(FirewallObjectRef{Kind: ref.Kind, Family: "inet", Name: chain.name})] {
						continue
					}
					for _, args := range matchingIPTablesJumpDeletes(string(out), chain.builtin, chain.name) {
						if _, err := d.run(ctx, binary, iptablesArgs(table, args...)...); err != nil {
							errs = append(errs, fmt.Sprintf("%s remove jump to %s: %v", binary, chain.name, err))
						}
					}
					if _, err := d.run(ctx, binary, iptablesArgs(table, "-F", chain.name)...); err != nil {
						errs = append(errs, fmt.Sprintf("%s flush %s: %v", binary, chain.name, err))
						continue
					}
					if _, err := d.run(ctx, binary, iptablesArgs(table, "-X", chain.name)...); err != nil {
						errs = append(errs, fmt.Sprintf("%s delete %s: %v", binary, chain.name, err))
					}
				}
			}
		}
		_, setErrs := d.cleanupOrphanIPSets(ctx, tableName)
		errs = append(errs, setErrs...)
	}
	if len(errs) > 0 {
		return fmt.Errorf("iptables stale cleanup: %s", strings.Join(errs, "; "))
	}
	return nil
}

func iptablesObjectTableName(ref FirewallObjectRef) (string, bool) {
	suffixes := []string{"_prerouting", "_postrouting", "_forward", "_output", "_input"}
	lower := strings.ToLower(ref.Name)
	for _, suffix := range suffixes {
		if strings.HasSuffix(lower, suffix) {
			return ref.Name[:len(ref.Name)-len(suffix)], true
		}
	}
	return "", false
}

func matchingIPTablesJumpDeletes(output, builtin, target string) [][]string {
	var deletes [][]string
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 || fields[0] != "-A" || fields[1] != builtin {
			continue
		}
		matches := false
		for i := 2; i+1 < len(fields); i++ {
			if fields[i] == "-j" && fields[i+1] == target {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		fields[0] = "-D"
		deletes = append(deletes, fields)
	}
	return deletes
}

// iptablesCommand represents a single iptables/ip6tables invocation.
type iptablesCommand struct {
	binary string
	args   []string
}

type iptablesHookInsertion struct {
	index int
	ipv4  []string
	ipv6  []string
}

func buildIPTablesInterleavedCommands(table, chain string, genericCount int, renderGeneric func(int) []iptablesCommand, insertions ...iptablesHookInsertion) ([]iptablesCommand, error) {
	var commands []iptablesCommand
	for i := 0; i <= genericCount; i++ {
		for _, insertion := range insertions {
			if insertion.index != i {
				continue
			}
			for _, family := range []struct {
				binary string
				rules  []string
			}{
				{binary: "iptables", rules: insertion.ipv4},
				{binary: "ip6tables", rules: insertion.ipv6},
			} {
				for _, expression := range family.rules {
					args, err := splitIPTablesRule(expression)
					if err != nil {
						return nil, err
					}
					args = append(iptablesArgs(table, "-A", chain), args...)
					commands = append(commands, iptablesCommand{binary: family.binary, args: args})
				}
			}
		}
		if i < genericCount {
			commands = append(commands, renderGeneric(i)...)
		}
	}
	return commands, nil
}

func iptablesRuleCommandsWithIPSets(tableName, chain string, r Rule, marker string) iptablesRenderedRules {
	var rendered iptablesRenderedRules
	bases := iptablesInterfaceMatchArgSets(r)
	for _, family := range iptablesFamiliesForRule(r) {
		srcs := prefixesForIPTablesFamily(r.Src, family.is4)
		dsts := prefixesForIPTablesFamily(r.Dst, family.is4)
		for _, base := range bases {
			args := append([]string{"-A", chain}, base...)
			args, rendered.ipsets = appendIPTablesPrefixMatch(
				args, rendered.ipsets, tableName, chain, "s", "src", family.ipsetFamily, srcs,
			)
			args, rendered.ipsets = appendIPTablesPrefixMatch(
				args, rendered.ipsets, tableName, chain, "d", "dst", family.ipsetFamily, dsts,
			)
			args = append(args, "-j", strings.ToUpper(r.Action), "-m", "comment", "--comment", marker+":"+r.Comment)
			rendered.commands = append(rendered.commands, iptablesCommand{binary: family.binary, args: args})
		}
	}
	rendered.ipsets = dedupIPTablesSetSpecs(rendered.ipsets)
	return rendered
}

type iptablesRuleFamily struct {
	binary      string
	ipsetFamily string
	is4         bool
}

func iptablesFamiliesForRule(r Rule) []iptablesRuleFamily {
	candidates := []iptablesRuleFamily{
		{binary: "iptables", ipsetFamily: "inet", is4: true},
		{binary: "ip6tables", ipsetFamily: "inet6", is4: false},
	}
	var out []iptablesRuleFamily
	for _, family := range candidates {
		if r.Proto == ProtoICMPv6 && family.is4 {
			continue
		}
		if r.Proto == ProtoICMP && !family.is4 {
			continue
		}
		if len(r.Src) > 0 && len(prefixesForIPTablesFamily(r.Src, family.is4)) == 0 {
			continue
		}
		if len(r.Dst) > 0 && len(prefixesForIPTablesFamily(r.Dst, family.is4)) == 0 {
			continue
		}
		out = append(out, family)
	}
	return out
}

func prefixesForIPTablesFamily(prefixes []netip.Prefix, is4 bool) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix.IsValid() && prefix.Addr().Is4() == is4 {
			out = append(out, prefix)
		}
	}
	return out
}

func appendIPTablesPrefixMatch(
	args []string,
	ipsets []iptablesSetSpec,
	tableName, chain string,
	side, direction, family string,
	prefixes []netip.Prefix,
) ([]string, []iptablesSetSpec) {
	switch len(prefixes) {
	case 0:
		return args, ipsets
	case 1:
		return append(args, "-"+side, prefixes[0].String()), ipsets
	default:
		name := iptablesIPSetName(tableName, chain, family, prefixes)
		args = append(args, "-m", "set", "--match-set", name, direction)
		ipsets = append(ipsets, iptablesSetSpec{name: name, family: family, prefixes: append([]netip.Prefix(nil), prefixes...)})
		return args, ipsets
	}
}

func iptablesIPSetName(tableName, chain, family string, prefixes []netip.Prefix) string {
	scopeHash := sha256.Sum256([]byte(tableName))
	var material strings.Builder
	fmt.Fprintf(&material, "%s|%s", chain, family)
	for _, prefix := range prefixes {
		material.WriteByte('|')
		material.WriteString(prefix.String())
	}
	setHash := sha256.Sum256([]byte(material.String()))
	// ipset names are limited to 31 characters. The scope component prevents
	// cross-instance cleanup; the content component includes generation/slot.
	return fmt.Sprintf("phs_%x_%x", scopeHash[:4], setHash[:8])
}

func iptablesIPSetPrefix(tableName string) string {
	scopeHash := sha256.Sum256([]byte(tableName))
	return fmt.Sprintf("phs_%x_", scopeHash[:4])
}

func dedupIPTablesSetSpecs(specs []iptablesSetSpec) []iptablesSetSpec {
	seen := make(map[string]bool, len(specs))
	out := make([]iptablesSetSpec, 0, len(specs))
	for _, spec := range specs {
		if seen[spec.name] {
			continue
		}
		seen[spec.name] = true
		out = append(out, spec)
	}
	return out
}

func iptablesBinariesForAddr(addr netip.Addr) []string {
	if !addr.IsValid() {
		return []string{"iptables", "ip6tables"}
	}
	if addr.Is6() {
		return []string{"ip6tables"}
	}
	return []string{"iptables"}
}

func iptablesInterfaceMatchArgSets(r Rule) [][]string {
	ins := iptablesInterfaceSelectors(r.IfaceIn, r.IfacesIn)
	outs := iptablesInterfaceSelectors(r.IfaceOut, r.IfacesOut)
	out := make([][]string, 0, len(ins)*len(outs))
	for _, in := range ins {
		for _, ifaceOut := range outs {
			scalar := r
			scalar.IfaceIn = in
			scalar.IfaceOut = ifaceOut
			scalar.IfacesIn = nil
			scalar.IfacesOut = nil
			out = append(out, iptablesBaseMatchArgs(scalar))
		}
	}
	return out
}

func iptablesInterfaceSelectors(portable string, exact []string) []string {
	if portable != "" {
		return []string{portable}
	}
	if len(exact) > 0 {
		return exact
	}
	return []string{""}
}

func iptablesBaseMatchArgs(r Rule) []string {
	var args []string
	if r.Proto != "" {
		args = append(args, "-p", iptablesProto(r.Proto))
	}
	if r.Port > 0 && r.Proto != "icmp" && r.Proto != "ipv6-icmp" {
		args = append(args, "--dport", fmt.Sprintf("%d", r.Port))
	}
	if r.IfaceIn != "" {
		args = append(args, "-i", iptablesIfacePattern(r.IfaceIn))
	}
	if r.IfaceOut != "" {
		args = append(args, "-o", iptablesIfacePattern(r.IfaceOut))
	}
	if len(r.CtStates) > 0 {
		args = append(args, "-m", "conntrack", "--ctstate", strings.ToUpper(strings.Join(r.CtStates, ",")))
	}
	return args
}

func iptablesIfacePattern(pattern string) string {
	// nft uses shell-style trailing '*', while xtables expresses an interface
	// prefix wildcard with trailing '+'.
	if strings.HasSuffix(pattern, "*") && strings.Count(pattern, "*") == 1 {
		return strings.TrimSuffix(pattern, "*") + "+"
	}
	return pattern
}

func iptablesProto(proto string) string {
	switch proto {
	case ProtoICMP:
		return "icmp"
	case ProtoICMPv6:
		return "icmpv6"
	}
	return proto
}

// parseIPTablesChains parses `iptables -S` output and returns only exact
// Photon-managed chain names. Prefix matching is intentionally insufficient:
// unrelated administrator-owned chains may share the instance prefix.
func parseIPTablesChains(output, tableName, table string) []FirewallObjectRef {
	var refs []FirewallObjectRef
	seen := make(map[string]bool)
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		// Lines like "-N photon_h2_INPUT" or "-A photon_h2_INPUT ..."
		if !strings.HasPrefix(line, "-N ") && !strings.HasPrefix(line, "-A ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		chainName := fields[1]
		ref, ok := managedIPTablesObject(tableName, table, chainName)
		if !ok {
			continue
		}
		if seen[chainName] {
			continue
		}
		seen[chainName] = true
		refs = append(refs, ref)
	}
	return refs
}

func managedIPTablesObject(tableName, table, chainName string) (FirewallObjectRef, bool) {
	ref, _, ok := managedIPTablesChainIdentity(tableName, table, chainName)
	if !ok {
		return FirewallObjectRef{}, false
	}
	return ref, true
}

func managedIPTablesChainIdentity(tableName, table, chainName string) (FirewallObjectRef, string, bool) {
	type identity struct {
		code      string
		kind      string
		suffix    string
		builtin   string
		legacyCap string
	}
	var identities []identity
	switch table {
	case "", "filter":
		identities = []identity{
			{code: "i", kind: "chain", suffix: "_input", builtin: "INPUT", legacyCap: "_INPUT"},
			{code: "f", kind: "chain", suffix: "_forward", builtin: "FORWARD", legacyCap: "_FORWARD"},
			{code: "o", kind: "chain", suffix: "_output", builtin: "OUTPUT", legacyCap: "_OUTPUT"},
		}
	case "nat":
		identities = []identity{
			{code: "r", kind: "nat_redirect", suffix: "_prerouting", builtin: "PREROUTING"},
			{code: "s", kind: "nat_source", suffix: "_postrouting", builtin: "POSTROUTING"},
		}
	default:
		return FirewallObjectRef{}, "", false
	}
	for _, id := range identities {
		canonical := tableName + id.suffix
		if chainName == canonical {
			return FirewallObjectRef{Kind: id.kind, Family: "inet", Name: canonical}, id.builtin, true
		}
		if id.legacyCap != "" && chainName == tableName+id.legacyCap {
			// Preserve the actual uppercase name so Plan reports it as stale.
			return FirewallObjectRef{Kind: id.kind, Family: "inet", Name: chainName}, id.builtin, true
		}
		if isIPTablesGenerationChain(tableName, id.code, chainName) {
			// Generation chains implement the canonical desired object. Hide
			// the active slot/hash from the backend-neutral planner.
			return FirewallObjectRef{Kind: id.kind, Family: "inet", Name: canonical}, id.builtin, true
		}
	}
	return FirewallObjectRef{}, "", false
}

func isIPTablesGenerationChain(tableName, code, chainName string) bool {
	// Generation names use a twelve-hex desired hash plus an a/b staging slot.
	const hashLength = 12
	hashPlaceholder := strings.Repeat("0", hashLength)
	example := iptablesGenerationChain(tableName, code, hashPlaceholder, 'a')
	prefix := strings.TrimSuffix(example, hashPlaceholder+"a")
	if !strings.HasPrefix(chainName, prefix) {
		return false
	}
	tail := strings.TrimPrefix(chainName, prefix)
	if len(tail) != hashLength+1 || (tail[hashLength] != 'a' && tail[hashLength] != 'b') {
		return false
	}
	for _, c := range tail[:hashLength] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func dedupFirewallObjectRefs(refs []FirewallObjectRef) []FirewallObjectRef {
	seen := make(map[string]bool, len(refs))
	out := make([]FirewallObjectRef, 0, len(refs))
	for _, ref := range refs {
		key := objKey(ref)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool {
		return objKey(out[i]) < objKey(out[j])
	})
	return out
}

func iptablesArgs(table string, args ...string) []string {
	if table == "" {
		return append([]string(nil), args...)
	}
	out := []string{"-t", table}
	return append(out, args...)
}
