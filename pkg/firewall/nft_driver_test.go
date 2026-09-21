package firewall

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"sort"
	"strings"
	"testing"
)

// fakeCommandRunner captures all commands executed by a driver for assertions.
type fakeCommandRunner struct {
	nftListOutput string
	commands      []executedCommand
	// failOnNew lists chain names whose `-N` creation should fail, simulating
	// an already-existing chain.
	failOnNew      map[string]bool
	existingChains map[string]bool
	existingRules  map[string]bool
	ruleArgs       map[string][]string
	ruleCounts     map[string]int
	ipsets         map[string]bool
	ipsetMembers   map[string]map[string]bool
	failContains   string
	nftBatchErr    error
}

type executedCommand struct {
	name string
	args []string
	// input contains the nft batch file contents for `nft -f <path>`.
	input string
}

func (f *fakeCommandRunner) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := executedCommand{name: name, args: args}
	if name == "nft" && len(args) == 2 && args[0] == "-f" {
		contents, err := os.ReadFile(args[1])
		if err != nil {
			return nil, err
		}
		command.input = string(contents)
		f.commands = append(f.commands, command)
		if f.nftBatchErr != nil {
			return []byte("batch rejected"), f.nftBatchErr
		}
		return []byte(""), nil
	}
	f.commands = append(f.commands, command)
	if name == "iptables" || name == "ip6tables" {
		return f.runIPTables(name, args)
	}
	if name == "ipset" {
		return f.runIPSet(args)
	}
	// Return the simulated nft listing.
	if len(args) >= 1 && args[0] == "list" {
		return []byte(f.nftListOutput), nil
	}
	return []byte(""), nil
}

func (f *fakeCommandRunner) runIPSet(args []string) ([]byte, error) {
	if f.ipsets == nil {
		f.ipsets = make(map[string]bool)
	}
	if f.ipsetMembers == nil {
		f.ipsetMembers = make(map[string]map[string]bool)
	}
	if f.failContains != "" && strings.Contains(strings.Join(args, " "), f.failContains) {
		return nil, errors.New("injected ipset failure")
	}
	if len(args) == 0 {
		return nil, errors.New("missing ipset operation")
	}
	switch args[0] {
	case "list":
		if len(args) >= 2 && args[1] == "-name" {
			var names []string
			for name := range f.ipsets {
				names = append(names, name)
			}
			sort.Strings(names)
			return []byte(strings.Join(names, "\n")), nil
		}
	case "create":
		if len(args) < 2 {
			return nil, errors.New("missing ipset name")
		}
		f.ipsets[args[1]] = true
		if f.ipsetMembers[args[1]] == nil {
			f.ipsetMembers[args[1]] = make(map[string]bool)
		}
	case "flush":
		if len(args) < 2 || !f.ipsets[args[1]] {
			return nil, errors.New("ipset does not exist")
		}
		f.ipsetMembers[args[1]] = make(map[string]bool)
	case "add":
		if len(args) < 3 || !f.ipsets[args[1]] {
			return nil, errors.New("ipset does not exist")
		}
		f.ipsetMembers[args[1]][args[2]] = true
	case "destroy":
		if len(args) < 2 || !f.ipsets[args[1]] {
			return nil, errors.New("ipset does not exist")
		}
		delete(f.ipsets, args[1])
		delete(f.ipsetMembers, args[1])
	}
	return []byte(""), nil
}

func commandText(command executedCommand) string {
	return strings.TrimSpace(strings.Join(command.args, " ") + "\n" + command.input)
}

func (f *fakeCommandRunner) seedIPTablesChain(binary, table, chain string) {
	if f.existingChains == nil {
		f.existingChains = make(map[string]bool)
	}
	f.existingChains[binary+":"+table+":"+chain] = true
}

func (f *fakeCommandRunner) seedIPTablesRule(binary, table string, args []string) {
	if f.existingRules == nil {
		f.existingRules = make(map[string]bool)
	}
	if f.ruleArgs == nil {
		f.ruleArgs = make(map[string][]string)
	}
	if f.ruleCounts == nil {
		f.ruleCounts = make(map[string]int)
	}
	key := binary + ":" + table + ":" + strings.Join(args, "\x00")
	f.existingRules[key] = true
	f.ruleArgs[key] = append([]string(nil), args...)
	f.ruleCounts[key]++
}

func (f *fakeCommandRunner) runIPTables(binary string, args []string) ([]byte, error) {
	if f.existingChains == nil {
		f.existingChains = make(map[string]bool)
	}
	if f.existingRules == nil {
		f.existingRules = make(map[string]bool)
	}
	if f.ruleArgs == nil {
		f.ruleArgs = make(map[string][]string)
	}
	if f.ruleCounts == nil {
		f.ruleCounts = make(map[string]int)
	}
	table := "filter"
	opIndex := 0
	if len(args) >= 2 && args[0] == "-t" {
		table = args[1]
		opIndex = 2
	}
	if opIndex >= len(args) {
		return []byte(""), nil
	}
	op := args[opIndex]
	rest := args[opIndex+1:]
	chainKey := func(chain string) string { return binary + ":" + table + ":" + chain }
	switch op {
	case "-S":
		if len(rest) == 0 {
			var lines []string
			prefix := binary + ":" + table + ":"
			for key := range f.existingChains {
				if after, ok := strings.CutPrefix(key, prefix); ok {
					lines = append(lines, "-N "+after)
				}
			}
			for key, args := range f.ruleArgs {
				if strings.HasPrefix(key, prefix) {
					count := f.ruleCounts[key]
					if count == 0 && f.existingRules[key] {
						count = 1
					}
					for i := 0; i < count; i++ {
						lines = append(lines, "-A "+strings.Join(args, " "))
					}
				}
			}
			sort.Strings(lines)
			return []byte(strings.Join(lines, "\n")), nil
		}
		if f.existingChains[chainKey(rest[0])] {
			lines := []string{"-N " + rest[0]}
			prefix := binary + ":" + table + ":"
			for key, args := range f.ruleArgs {
				if strings.HasPrefix(key, prefix) && len(args) > 0 && args[0] == rest[0] {
					count := f.ruleCounts[key]
					if count == 0 && f.existingRules[key] {
						count = 1
					}
					for i := 0; i < count; i++ {
						lines = append(lines, "-A "+strings.Join(args, " "))
					}
				}
			}
			sort.Strings(lines)
			return []byte(strings.Join(lines, "\n")), nil
		}
		return nil, errors.New("chain does not exist")
	case "-N":
		if len(rest) == 0 {
			return nil, errors.New("missing chain")
		}
		if f.failOnNew[rest[0]] || f.existingChains[chainKey(rest[0])] {
			return nil, errors.New("chain already exists")
		}
		f.existingChains[chainKey(rest[0])] = true
	case "-F":
		if len(rest) > 0 && !f.existingChains[chainKey(rest[0])] {
			return nil, errors.New("chain does not exist")
		}
		if len(rest) > 0 {
			prefix := binary + ":" + table + ":"
			for key, args := range f.ruleArgs {
				if strings.HasPrefix(key, prefix) && len(args) > 0 && args[0] == rest[0] {
					delete(f.ruleArgs, key)
					delete(f.existingRules, key)
					delete(f.ruleCounts, key)
				}
			}
		}
	case "-X":
		if len(rest) > 0 && !f.existingChains[chainKey(rest[0])] {
			return nil, errors.New("chain does not exist")
		}
		prefix := binary + ":" + table + ":"
		for key, args := range f.ruleArgs {
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			for i := 0; i+1 < len(args); i++ {
				if args[i] == "-j" && args[i+1] == rest[0] {
					return nil, errors.New("chain is referenced")
				}
			}
		}
		if len(rest) > 0 {
			delete(f.existingChains, chainKey(rest[0]))
		}
	case "-C":
		key := binary + ":" + table + ":" + strings.Join(rest, "\x00")
		if !f.existingRules[key] && f.ruleCounts[key] == 0 {
			return nil, errors.New("rule does not exist")
		}
	case "-A", "-I":
		if f.failContains != "" && strings.Contains(strings.Join(rest, " "), f.failContains) {
			return nil, errors.New("injected rule failure")
		}
		key := binary + ":" + table + ":" + strings.Join(rest, "\x00")
		f.existingRules[key] = true
		f.ruleArgs[key] = append([]string(nil), rest...)
		f.ruleCounts[key]++
	case "-D":
		key := binary + ":" + table + ":" + strings.Join(rest, "\x00")
		count := f.ruleCounts[key]
		if count == 0 && f.existingRules[key] {
			count = 1
		}
		if count == 0 {
			return nil, errors.New("rule does not exist")
		}
		count--
		if count == 0 {
			delete(f.existingRules, key)
			delete(f.ruleArgs, key)
			delete(f.ruleCounts, key)
		} else {
			f.ruleCounts[key] = count
		}
	}
	return []byte(""), nil
}

func TestNFTDriver_Preflight(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &NFTDriver{Command: runner.run}
	pf, err := d.Preflight(context.Background(), FirewallInstanceSpec{ID: "photontesth2"})
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if pf.Backend == "" {
		t.Error("backend should be set")
	}
}

func TestNFTDriver_ApplyOverlay(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &NFTDriver{Command: runner.run}
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
	// Empty observed state -> all objects are create.
	result, err := d.Apply(context.Background(), desired)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.Applied == 0 {
		t.Error("expected non-zero applied count")
	}
	if len(runner.commands) != 2 {
		t.Fatalf("commands = %v, want one observation and one atomic nft transaction", runner.commands)
	}
	batch := commandText(runner.commands[1])
	if !strings.Contains(batch, "add table inet photon_photontesth2") {
		t.Errorf("expected table creation in nft batch:\n%s", batch)
	}
	for _, want := range []string{
		"hook input",
		"hook forward",
		"hook output",
	} {
		if !strings.Contains(batch, want) {
			t.Errorf("expected nft overlay chain with %s hook", want)
		}
	}
}

func TestNFTDriver_ExternalDoesNotApply(t *testing.T) {
	runner := &fakeCommandRunner{}
	desired, err := BuildDesiredState(FirewallInstanceSpec{ID: "external", NetNS: "photon", Mode: ModeExternal}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := (&NFTDriver{Command: runner.run}).Apply(context.Background(), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("external apply executed commands: %+v", runner.commands)
	}
}

func TestNFTDriver_ApplyHostWithNATRedirect(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &NFTDriver{Command: runner.run}
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
	if len(desired.NatRedirects) != 3 {
		t.Fatalf("expected 3 NAT redirect rules, got %d", len(desired.NatRedirects))
	}
	result, err := d.Apply(context.Background(), desired)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.Applied == 0 {
		t.Error("expected non-zero applied count")
	}
	// Check for host input and nat prerouting base-chain creation.
	foundNatChain := false
	foundInputChain := false
	for _, cmd := range runner.commands {
		argsStr := commandText(cmd)
		if strings.Contains(argsStr, "prerouting") && strings.Contains(argsStr, "nat") {
			foundNatChain = true
		}
		if strings.Contains(argsStr, "photon_host_input") && strings.Contains(argsStr, "hook input") {
			foundInputChain = true
		}
	}
	if !foundNatChain {
		t.Error("expected NAT prerouting chain creation")
	}
	if !foundInputChain {
		t.Error("expected host input base-chain creation")
	}
}

func TestNFTDriver_RendersConfiguredPriorities(t *testing.T) {
	runner := &fakeCommandRunner{}
	spec := FirewallInstanceSpec{
		ID: "host", NetNS: "host", IsHost: true, Mode: ModeManaged,
		HostPorts:     HostPortConfig{IKE: true},
		RedirectGrace: RedirectGrace{Enabled: true},
		Priorities: ChainPriorities{
			Filter:      ChainPriority{Base: "filter", Offset: -1},
			Prerouting:  ChainPriority{Base: "dstnat", Offset: -2},
			Postrouting: ChainPriority{Base: "srcnat", Offset: 3},
		},
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{
		AdvertisedCurrentIKEPorts:  []uint16{1500},
		AdvertisedPreviousIKEPorts: []uint16{450},
	})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := (&NFTDriver{Command: runner.run}).Apply(context.Background(), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	batch := commandText(runner.commands[1])
	for _, want := range []string{"priority filter - 1", "priority dstnat - 2", "priority srcnat + 3"} {
		if !strings.Contains(batch, want) {
			t.Fatalf("nft batch missing %q:\n%s", want, batch)
		}
	}
}

func TestNFTDriver_ApplyHostWithNATSourceRewrite(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &NFTDriver{Command: runner.run}
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
	foundPostrouting := false
	foundMasquerade := false
	for _, cmd := range runner.commands {
		argsStr := commandText(cmd)
		if strings.Contains(argsStr, "postrouting") && strings.Contains(argsStr, "srcnat") {
			foundPostrouting = true
		}
		if strings.Contains(argsStr, "sport 4500") && strings.Contains(argsStr, "masquerade to :33403") {
			foundMasquerade = true
		}
	}
	if !foundPostrouting {
		t.Error("expected NAT postrouting chain creation")
	}
	if !foundMasquerade {
		t.Error("expected NAT source-port rewrite rule")
	}
}

func TestNFTDriver_ApplyRebuildsObservedTable(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &NFTDriver{Command: runner.run}
	spec := FirewallInstanceSpec{
		ID: "host-ipsec", IsHost: true, Enabled: true, Mode: ModeManaged,
		OwnerPrefix: "photon",
		HostPorts:   HostPortConfig{IKE: true, NATT: true},
	}
	desired, err := BuildDesiredState(spec, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	runner.nftListOutput = "table inet photon_host {\n chain photon_host_input {\n }\n}\n"
	if _, err := d.Apply(context.Background(), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("commands = %v, want one observation and one atomic nft transaction", runner.commands)
	}
	if got := commandText(runner.commands[0]); got != "list table inet photon_host" {
		t.Fatalf("observed scope = %q, want host table rather than display ID", got)
	}
	batch := runner.commands[1].input
	if !strings.HasPrefix(batch, "delete table inet photon_host\n") {
		t.Fatalf("batch = %q, want table delete first", batch)
	}
	if !strings.Contains(batch, "add table inet photon_host\n") {
		t.Fatalf("missing table rebuild in transaction:\n%s", batch)
	}
}

func TestNFTDriver_ApplyTransactionFailureReportsNoAppliedCommands(t *testing.T) {
	runner := &fakeCommandRunner{nftBatchErr: errors.New("syntax error")}
	d := &NFTDriver{Command: runner.run}
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "photontesth2", NetNS: "photontesth2", Enabled: true, Mode: ModeManaged,
		DefaultPolicy: DefaultPolicyDrop, XFRMTunnelPattern: "phx*",
	}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	result, err := d.Apply(context.Background(), desired)
	if err == nil {
		t.Fatal("Apply succeeded despite rejected nft transaction")
	}
	if result.Applied != 0 || result.Failed != 1 {
		t.Fatalf("result = %+v, want zero applied and one failed transaction", result)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("commands = %v, want one observation and one transaction attempt", runner.commands)
	}
}

func TestNFTDriver_ListOwned(t *testing.T) {
	// Simulate nft list table output.
	output := `table inet photon_photontesth2 {
	chain photon_photontesth2_input { type filter hook input priority 0; policy accept; }
	chain photon_photontesth2_forward { type filter hook forward priority 0; policy accept; }
	set photon_photontesth2_mesh_v4 { type ipv4_addr; }
}`
	state := parseNFTListOutput(output, "photon_photontesth2")
	if len(state.Objects) == 0 {
		t.Fatal("expected owned objects")
	}
	foundTable := false
	foundChain := false
	foundSet := false
	for _, obj := range state.Objects {
		switch obj.Kind {
		case "table":
			foundTable = true
		case "chain":
			foundChain = true
		case "set":
			foundSet = true
		}
	}
	if !foundTable {
		t.Error("missing table object")
	}
	if !foundChain {
		t.Error("missing chain object")
	}
	if !foundSet {
		t.Error("missing set object")
	}
}

func TestNFTDriver_NetNSExecution(t *testing.T) {
	runner := &fakeCommandRunner{}
	d := &NFTDriver{Command: runner.run, NetNS: "photontesth2"}
	_, _ = d.run(context.Background(), "list", "tables")
	if len(runner.commands) == 0 {
		t.Fatal("expected command execution")
	}
	cmd := runner.commands[0]
	if cmd.name != "ip" {
		t.Errorf("expected ip command for netns exec, got %s", cmd.name)
	}
	if len(cmd.args) < 4 || cmd.args[0] != "netns" || cmd.args[1] != "exec" || cmd.args[2] != "photontesth2" {
		t.Errorf("expected ip netns exec photontesth2 nft, got %v", cmd.args)
	}
}

func TestRenderNFTRuleCtState(t *testing.T) {
	invalid := renderNFTRule(Rule{Action: ActionDrop, CtStates: []string{CtStateInvalid}, Comment: "invalid drop"})
	if !strings.Contains(invalid, "ct state invalid drop") {
		t.Errorf("invalid drop rendered as %q", invalid)
	}
	est := renderNFTRule(Rule{Action: ActionAccept, CtStates: []string{CtStateEstablished, CtStateRelated}, Comment: "established related"})
	if !strings.Contains(est, "ct state { established, related } accept") {
		t.Errorf("established/related rendered as %q", est)
	}
}

func TestRenderNFTRuleInterfaceSets(t *testing.T) {
	rendered := renderNFTRule(Rule{
		IfaceIn:   "phx*",
		IfaceOut:  "phx*",
		Action:    ActionAccept,
		IfacesIn:  []string{"phx11111111", "phx22222222"},
		IfacesOut: []string{"phx11111111", "phx22222222"},
	})
	want := `iifname { phx11111111, phx22222222 } oifname { phx11111111, phx22222222 } accept`
	if rendered != want {
		t.Fatalf("interface sets rendered as %q, want %q", rendered, want)
	}
}

func TestNFTDriverInlineHooksAreRenderedInPlannerOrder(t *testing.T) {
	runner := &fakeCommandRunner{}
	driver := &NFTDriver{Command: runner.run}
	desired, err := BuildDesiredState(FirewallInstanceSpec{
		ID: "photon", NetNS: "photon", Mode: ModeManaged, Backend: BackendNFT, OwnerPrefix: "photon",
		NativeHooks: NativeHooks{NFT: InlineHookRules{
			PreInput:  []string{`tcp dport 2222 accept comment "native-pre"`},
			PostInput: []string{`counter comment "native-post"`},
		}},
	}, FirewallPolicyInput{})
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if _, err := driver.Apply(context.Background(), desired); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var batch string
	for _, command := range runner.commands {
		if command.name == "nft" && command.input != "" {
			batch = command.input
		}
	}
	if batch == "" {
		t.Fatal("nft batch not captured")
	}
	invalid := strings.Index(batch, "ct state invalid drop")
	loopback := strings.Index(batch, `iifname lo accept`)
	pre := strings.Index(batch, `tcp dport 2222 accept comment "native-pre"`)
	babel := strings.Index(batch, "udp dport 6696 accept")
	post := strings.Index(batch, `counter comment "native-post"`)
	defaultDrop := strings.LastIndex(batch, "drop comment \"default policy\"")
	if !(invalid >= 0 && invalid < loopback && loopback < pre && pre < babel) {
		t.Fatalf("pre_input order incorrect: invalid=%d loopback=%d pre=%d babel=%d\n%s", invalid, loopback, pre, babel, batch)
	}
	if !(post >= 0 && defaultDrop >= 0 && post < defaultDrop) {
		t.Fatalf("post_input order incorrect: post=%d default=%d\n%s", post, defaultDrop, batch)
	}
}
