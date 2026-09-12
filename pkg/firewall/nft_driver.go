package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// CommandRunner executes a command and returns combined output.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// NFTDriver implements FirewallDriver using the `nft` CLI (nftables).
// It is the primary backend for Phase 6.3.6.
//
// Design:
//   - All Photon-owned objects live in an inet table named "<prefix>_<scope>".
//   - Chains within the table handle input/forward/output/prerouting.
//   - Prefix sets are nft sets; rules reference them.
//   - ListOwned parses `nft list table` output for Photon-owned objects.
//   - Apply renders one nft batch file so the kernel commits the whole ruleset
//     transaction atomically.
//
// The driver is designed to be testable by injecting CommandRunner.
type NFTDriver struct {
	// Command executes an external command. Defaults to exec.CommandContext.
	Command CommandRunner
	// NetNS overrides the network namespace for `nft` execution (via ip netns exec).
	NetNS string
}

// NewNFTDriver creates an NFTDriver with the default command runner.
func NewNFTDriver() *NFTDriver {
	return &NFTDriver{Command: nftExecCommand}
}

func nftExecCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (d *NFTDriver) runner() CommandRunner {
	if d.Command != nil {
		return d.Command
	}
	return nftExecCommand
}

func (d *NFTDriver) run(ctx context.Context, args ...string) ([]byte, error) {
	runner := d.runner()
	if d.NetNS != "" {
		full := append([]string{"netns", "exec", d.NetNS, "nft"}, args...)
		return runner(ctx, "ip", full...)
	}
	return runner(ctx, "nft", args...)
}

func (d *NFTDriver) Preflight(ctx context.Context, spec FirewallInstanceSpec) (FirewallPreflight, error) {
	pf := PreflightProbe(ctx)
	if pf.NFTNetlink == "ok" {
		if _, err := d.run(ctx, "list", "tables"); err != nil {
			pf.NFTNetlink = "permission_denied"
			pf.Backend = BackendNone
		}
	}
	_ = spec
	return pf, nil
}

func (d *NFTDriver) Plan(ctx context.Context, desired *FirewallDesiredState, observed FirewallObservedState) (FirewallPlan, error) {
	if desired == nil {
		return FirewallPlan{}, fmt.Errorf("desired state is nil")
	}
	return PlanDiff(desired.Instance.ID, desired, observed), nil
}

func (d *NFTDriver) Apply(ctx context.Context, plan FirewallPlan, desired *FirewallDesiredState) (FirewallApplyResult, error) {
	result := FirewallApplyResult{}
	if desired == nil {
		return result, fmt.Errorf("desired state is nil")
	}
	if desired.Instance.Mode == ModeExternal || desired.Instance.Mode == ModeDisabled {
		return result, nil
	}
	commands := buildNFTApplyCommands(plan, desired)
	if len(commands) == 0 {
		result.Generation = 1
		return result, nil
	}

	script := renderNFTBatch(commands)
	path, err := writeNFTBatch(script)
	if err != nil {
		result.Failed = 1
		return result, fmt.Errorf("prepare nft transaction: %w", err)
	}
	defer os.Remove(path)

	output, err := d.run(ctx, "-f", path)
	if err != nil {
		message := fmt.Sprintf("nft transaction: %v", err)
		if detail := strings.TrimSpace(string(output)); detail != "" {
			message += ": " + detail
		}
		result.Failed = 1
		result.Generation = 1
		return result, errors.New(message)
	}
	result.Applied = len(commands)
	result.Generation = 1
	return result, nil
}

func renderNFTBatch(commands [][]string) string {
	var b strings.Builder
	for _, command := range commands {
		if len(command) == 0 {
			continue
		}
		b.WriteString(strings.Join(command, " "))
		b.WriteByte('\n')
	}
	return b.String()
}

func writeNFTBatch(script string) (string, error) {
	file, err := os.CreateTemp("", "photon-nft-*.nft")
	if err != nil {
		return "", err
	}
	path := file.Name()
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.WriteString(script); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	remove = false
	return path, nil
}

func (d *NFTDriver) ListOwned(ctx context.Context, owner Owner) (FirewallObservedState, error) {
	prefix := owner.OwnerPrefix
	if prefix == "" {
		prefix = "photon"
	}
	scope := owner.InstanceID
	tableName := prefix + "_" + scope
	out, err := d.run(ctx, "list", "table", "inet", tableName)
	if err != nil {
		return FirewallObservedState{}, nil
	}
	return parseNFTListOutput(string(out), tableName), nil
}

func (d *NFTDriver) DeleteStale(ctx context.Context, refs []FirewallObjectRef) error {
	for _, ref := range refs {
		var args []string
		switch ref.Kind {
		case "table":
			args = []string{"delete", "table", ref.Family, ref.Name}
		case "chain", "nat_redirect", "nat_source":
			args = []string{"delete", "chain", ref.Family, ref.Name}
		case "set":
			args = []string{"delete", "set", ref.Family, ref.Name}
		default:
			continue
		}
		_, _ = d.run(ctx, args...)
	}
	return nil
}

// buildNFTApplyCommands generates sequential nft CLI commands to realize a plan.
func buildNFTApplyCommands(plan FirewallPlan, desired *FirewallDesiredState) [][]string {
	prefix := desired.Instance.OwnerPrefix
	if prefix == "" {
		prefix = "photon"
	}
	scope := desired.Instance.NetNS
	if desired.Instance.IsHost {
		scope = "host"
	}
	tableName := prefix + "_" + scope

	var commands [][]string

	tableObserved := false
	for _, a := range plan.Actions {
		if a.Object.Kind == "table" && a.Object.Family == "inet" && a.Object.Name == tableName && (a.Action == "adopt" || a.Action == "delete") {
			tableObserved = true
			break
		}
	}
	if tableObserved {
		commands = append(commands, []string{"delete", "table", "inet", tableName})
	}

	// Process deletes first.
	for _, a := range plan.Actions {
		if a.Action != "delete" {
			continue
		}
		if tableObserved {
			// The table delete removes all chains, sets, and rules below it.
			continue
		}
		switch a.Object.Kind {
		case "table":
			commands = append(commands, []string{"delete", "table", a.Object.Family, a.Object.Name})
		case "chain", "nat_redirect", "nat_source":
			commands = append(commands, []string{"delete", "chain", a.Object.Family, a.Object.Name})
		case "set":
			commands = append(commands, []string{"delete", "set", a.Object.Family, a.Object.Name})
		}
	}

	if !desiredHasTable(desired, tableName) {
		return commands
	}

	// Create table.
	commands = append(commands, []string{"add", "table", "inet", tableName})

	// Create sets for mesh prefixes.
	if len(desired.Prefixes.MeshAuthorizedV4) > 0 {
		commands = append(commands, []string{"add", "set", "inet", tableName, tableName + "_mesh_v4", "{ type ipv4_addr; flags interval; }"})
		for _, p := range desired.Prefixes.MeshAuthorizedV4 {
			commands = append(commands, []string{"add", "element", "inet", tableName, tableName + "_mesh_v4", "{ " + p.String() + " }"})
		}
	}
	if len(desired.Prefixes.MeshAuthorizedV6) > 0 {
		commands = append(commands, []string{"add", "set", "inet", tableName, tableName + "_mesh_v6", "{ type ipv6_addr; flags interval; }"})
		for _, p := range desired.Prefixes.MeshAuthorizedV6 {
			commands = append(commands, []string{"add", "element", "inet", tableName, tableName + "_mesh_v6", "{ " + p.String() + " }"})
		}
	}

	// Render chains.
	if desired.Instance.IsHost {
		commands = append(commands, buildNFTHostChainCommands(tableName, desired)...)
	} else {
		commands = append(commands, buildNFTOverlayChainCommands(tableName, desired)...)
	}

	return commands
}

func desiredHasTable(desired *FirewallDesiredState, tableName string) bool {
	for _, ref := range DesiredObjects(desired) {
		if ref.Kind == "table" && ref.Family == "inet" && ref.Name == tableName {
			return true
		}
	}
	return false
}

func buildNFTOverlayChainCommands(tableName string, desired *FirewallDesiredState) [][]string {
	var commands [][]string
	priority := desired.Instance.Priorities.Normalized().Filter.String()

	inputChain := tableName + "_input"
	forwardChain := tableName + "_forward"
	outputChain := tableName + "_output"

	commands = append(commands, []string{"add", "chain", "inet", tableName, inputChain, "{ type filter hook input priority " + priority + "; policy accept; }"})
	commands = append(commands, buildNFTChainRules(tableName, inputChain, len(desired.InputRules), func(i int) string {
		return renderNFTRule(desired.InputRules[i])
	},
		nftHookInsertion{index: desired.HookPositions.PreInput, rules: desired.NativeHooks.NFT.PreInput},
		nftHookInsertion{index: desired.HookPositions.PostInput, rules: desired.NativeHooks.NFT.PostInput},
	)...)

	commands = append(commands, []string{"add", "chain", "inet", tableName, forwardChain, "{ type filter hook forward priority " + priority + "; policy accept; }"})
	commands = append(commands, buildNFTChainRules(tableName, forwardChain, len(desired.ForwardRules), func(i int) string {
		return renderNFTRule(desired.ForwardRules[i])
	},
		nftHookInsertion{index: desired.HookPositions.PreForward, rules: desired.NativeHooks.NFT.PreForward},
		nftHookInsertion{index: desired.HookPositions.PostForward, rules: desired.NativeHooks.NFT.PostForward},
	)...)

	commands = append(commands, []string{"add", "chain", "inet", tableName, outputChain, "{ type filter hook output priority " + priority + "; policy accept; }"})
	commands = append(commands, buildNFTChainRules(tableName, outputChain, len(desired.OutputRules), func(i int) string {
		return renderNFTRule(desired.OutputRules[i])
	},
		nftHookInsertion{index: desired.HookPositions.PreOutput, rules: desired.NativeHooks.NFT.PreOutput},
		nftHookInsertion{index: desired.HookPositions.PostOutput, rules: desired.NativeHooks.NFT.PostOutput},
	)...)

	return commands
}

func buildNFTHostChainCommands(tableName string, desired *FirewallDesiredState) [][]string {
	var commands [][]string
	priorities := desired.Instance.Priorities.Normalized()
	filterPriority := priorities.Filter.String()

	inputChain := tableName + "_input"
	commands = append(commands, []string{"add", "chain", "inet", tableName, inputChain, "{ type filter hook input priority " + filterPriority + "; policy accept; }"})
	commands = append(commands, buildNFTChainRules(tableName, inputChain, len(desired.HostIngress), func(i int) string {
		return renderNFTHostIngressRule(desired.HostIngress[i])
	},
		nftHookInsertion{index: desired.HookPositions.HostPreInput, rules: desired.NativeHooks.NFT.HostPreInput},
		nftHookInsertion{index: desired.HookPositions.HostPostInput, rules: desired.NativeHooks.NFT.HostPostInput},
	)...)
	if len(desired.ForwardRules) > 0 {
		forwardChain := tableName + "_forward"
		commands = append(commands, []string{"add", "chain", "inet", tableName, forwardChain, "{ type filter hook forward priority " + filterPriority + "; policy accept; }"})
		for _, rule := range desired.ForwardRules {
			commands = append(commands, []string{"add", "rule", "inet", tableName, forwardChain, renderNFTRule(rule)})
		}
	}

	if len(desired.NatRedirects) > 0 || len(desired.NativeHooks.NFT.HostPrePrerouting) > 0 || len(desired.NativeHooks.NFT.HostPostPrerouting) > 0 {
		preroutingChain := tableName + "_prerouting"
		commands = append(commands, []string{"add", "chain", "inet", tableName, preroutingChain, "{ type nat hook prerouting priority " + priorities.Prerouting.String() + "; }"})
		commands = append(commands, buildNFTChainRules(tableName, preroutingChain, len(desired.NatRedirects), func(i int) string {
			return renderNFTNatRedirectRule(desired.NatRedirects[i])
		},
			nftHookInsertion{index: desired.HookPositions.HostPrePrerouting, rules: desired.NativeHooks.NFT.HostPrePrerouting},
			nftHookInsertion{index: desired.HookPositions.HostPostPrerouting, rules: desired.NativeHooks.NFT.HostPostPrerouting},
		)...)
	}
	if len(desired.NatSources) > 0 {
		postroutingChain := tableName + "_postrouting"
		commands = append(commands, []string{"add", "chain", "inet", tableName, postroutingChain, "{ type nat hook postrouting priority " + priorities.Postrouting.String() + "; }"})
		for _, ns := range desired.NatSources {
			rule := renderNFTNatSourceRule(ns)
			commands = append(commands, []string{"add", "rule", "inet", tableName, postroutingChain, rule})
		}
	}

	return commands
}

type nftHookInsertion struct {
	index int
	rules []string
}

func buildNFTChainRules(tableName, chainName string, genericCount int, renderGeneric func(int) string, insertions ...nftHookInsertion) [][]string {
	var commands [][]string
	for i := 0; i <= genericCount; i++ {
		for _, insertion := range insertions {
			if insertion.index != i {
				continue
			}
			for _, expression := range insertion.rules {
				commands = append(commands, []string{"add", "rule", "inet", tableName, chainName, expression})
			}
		}
		if i < genericCount {
			commands = append(commands, []string{"add", "rule", "inet", tableName, chainName, renderGeneric(i)})
		}
	}
	return commands
}

func renderNFTRule(r Rule) string {
	var parts []string
	if match := renderNFTIfaceMatch("iifname", r.IfaceIn, r.IfacesIn); match != "" {
		parts = append(parts, match)
	}
	if match := renderNFTIfaceMatch("oifname", r.IfaceOut, r.IfacesOut); match != "" {
		parts = append(parts, match)
	}
	switch r.Proto {
	case ProtoTCP:
		parts = append(parts, "tcp")
	case ProtoUDP:
		parts = append(parts, "udp")
	case ProtoICMP:
		parts = append(parts, "ip protocol icmp")
	case ProtoICMPv6:
		parts = append(parts, "ip6 nexthdr icmpv6")
	}
	if r.Port > 0 && (r.Proto == ProtoTCP || r.Proto == ProtoUDP) {
		parts = append(parts, fmt.Sprintf("dport %d", r.Port))
	}
	if len(r.Src) > 0 {
		parts = append(parts, prefixNFTMatch("saddr", r.Src))
	}
	if len(r.Dst) > 0 {
		parts = append(parts, prefixNFTMatch("daddr", r.Dst))
	}
	if len(r.CtStates) > 0 {
		if len(r.CtStates) == 1 {
			parts = append(parts, "ct state "+r.CtStates[0])
		} else {
			parts = append(parts, fmt.Sprintf("ct state { %s }", strings.Join(r.CtStates, ", ")))
		}
	}
	parts = append(parts, r.Action)
	if r.Comment != "" {
		parts = append(parts, fmt.Sprintf("comment %s", quoteNFTVal(r.Comment)))
	}
	return strings.Join(parts, " ")
}

func renderNFTIfaceMatch(keyword, single string, values []string) string {
	if len(values) == 0 {
		if single == "" {
			return ""
		}
		return keyword + " " + quoteNFTVal(single)
	}
	if len(values) == 1 {
		return keyword + " " + quoteNFTVal(values[0])
	}
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, quoteNFTVal(value))
	}
	return fmt.Sprintf("%s { %s }", keyword, strings.Join(quoted, ", "))
}

func renderNFTHostIngressRule(hi HostIngressRule) string {
	var parts []string
	parts = append(parts, nftProtoName(hi.Proto))
	if hi.Port > 0 {
		parts = append(parts, fmt.Sprintf("dport %d", hi.Port))
	}
	if hi.DstAddr.IsValid() {
		if hi.DstAddr.Is4() {
			parts = append(parts, fmt.Sprintf("ip daddr %s", hi.DstAddr.String()))
		} else {
			parts = append(parts, fmt.Sprintf("ip6 daddr %s", hi.DstAddr.String()))
		}
	}
	parts = append(parts, "accept")
	if hi.Comment != "" {
		parts = append(parts, fmt.Sprintf("comment %s", quoteNFTVal(hi.Comment)))
	}
	return strings.Join(parts, " ")
}

func renderNFTNatRedirectRule(nr NatRedirectRule) string {
	var parts []string
	parts = append(parts, nftProtoName(nr.Proto))
	if nr.OriginalDst > 0 {
		parts = append(parts, fmt.Sprintf("dport %d", nr.OriginalDst))
	}
	if nr.DstAddr.IsValid() {
		if nr.DstAddr.Is4() {
			parts = append(parts, fmt.Sprintf("ip daddr %s", nr.DstAddr.String()))
		} else {
			parts = append(parts, fmt.Sprintf("ip6 daddr %s", nr.DstAddr.String()))
		}
	}
	parts = append(parts, fmt.Sprintf("redirect to :%d", nr.RedirectTo))
	if nr.Comment != "" {
		parts = append(parts, fmt.Sprintf("comment %s", quoteNFTVal(nr.Comment)))
	}
	return strings.Join(parts, " ")
}

func renderNFTNatSourceRule(ns NatSourceRule) string {
	var parts []string
	parts = append(parts, nftProtoName(ns.Proto))
	if ns.OriginalSrc > 0 {
		parts = append(parts, fmt.Sprintf("sport %d", ns.OriginalSrc))
	}
	if ns.DstPort > 0 {
		parts = append(parts, fmt.Sprintf("dport %d", ns.DstPort))
	}
	if ns.DstAddr.IsValid() {
		if ns.DstAddr.Is4() {
			parts = append(parts, fmt.Sprintf("ip daddr %s", ns.DstAddr.String()))
		} else {
			parts = append(parts, fmt.Sprintf("ip6 daddr %s", ns.DstAddr.String()))
		}
	}
	parts = append(parts, fmt.Sprintf("masquerade to :%d", ns.RewriteTo))
	if ns.Comment != "" {
		parts = append(parts, fmt.Sprintf("comment %s", quoteNFTVal(ns.Comment)))
	}
	return strings.Join(parts, " ")
}

func prefixNFTMatch(direction string, prefixes []netip.Prefix) string {
	var v4, v6 []string
	for _, p := range prefixes {
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	var parts []string
	if len(v4) > 0 {
		parts = append(parts, fmt.Sprintf("ip %s { %s }", direction, strings.Join(v4, ", ")))
	}
	if len(v6) > 0 {
		parts = append(parts, fmt.Sprintf("ip6 %s { %s }", direction, strings.Join(v6, ", ")))
	}
	return strings.Join(parts, " ")
}

func nftProtoName(proto string) string {
	switch proto {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	case ProtoICMPv6:
		return "icmpv6"
	}
	return proto
}

func quoteNFTVal(s string) string {
	if strings.ContainsAny(s, " *?+\"") {
		return "\"" + strings.ReplaceAll(s, "\"", "\\\"") + "\""
	}
	return s
}

// parseNFTListOutput parses `nft list table` output to extract owned objects.
func parseNFTListOutput(output, tableName string) FirewallObservedState {
	var state FirewallObservedState
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "table ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				state.Objects = append(state.Objects, FirewallObjectRef{
					Kind: "table", Family: fields[1], Name: fields[2],
				})
			}
		}
		if strings.HasPrefix(line, "chain ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kind := "chain"
				switch fields[1] {
				case tableName + "_prerouting":
					kind = "nat_redirect"
				case tableName + "_postrouting":
					kind = "nat_source"
				}
				state.Objects = append(state.Objects, FirewallObjectRef{
					Kind: kind, Family: "inet", Name: fields[1],
				})
			}
		}
		if strings.HasPrefix(line, "set ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				state.Objects = append(state.Objects, FirewallObjectRef{
					Kind: "set", Family: "inet", Name: fields[1],
				})
			}
		}
	}
	sort.Slice(state.Objects, func(i, j int) bool {
		return objKey(state.Objects[i]) < objKey(state.Objects[j])
	})
	return state
}
