//go:build linux

package photonopenwrt

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type firewallFixture struct {
	f                     *Firewall
	doc                   map[string]any
	calls                 []string
	checks, commits       []string
	failCheck, failCommit bool
	failFW4Check          bool
	onCommit              func()
}

func ownedFirewallDocument() map[string]any {
	return map[string]any{"nftables": []any{
		map[string]any{"chain": map[string]any{"family": "inet", "table": "fw4", "name": firewallChain, "comment": firewallOwner}},
		map[string]any{"rule": map[string]any{"family": "inet", "table": "fw4", "chain": "input", "comment": firewallJumpOwner, "expr": []any{map[string]any{"jump": map[string]any{"target": firewallChain}}}}},
		map[string]any{"rule": map[string]any{"family": "inet", "table": "fw4", "chain": "input", "comment": "!fw4: foreign drop", "expr": []any{map[string]any{"drop": nil}}}},
		map[string]any{"chain": map[string]any{"family": "inet", "table": "fw4", "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
	}}
}

func newFirewallFixture(t *testing.T) *firewallFixture {
	t.Helper()
	dir := t.TempDir()
	x := &firewallFixture{doc: ownedFirewallDocument()}
	x.f = NewFirewall(FirewallOptions{
		RuntimeDir:        filepath.Join(dir, "fw4"),
		TableTemplatePath: filepath.Join(dir, "table.nft"),
		InputTemplatePath: filepath.Join(dir, "input.nft"),
		LockPath:          filepath.Join(dir, "fw4.lock"),
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			x.calls = append(x.calls, name+" "+strings.Join(args, " "))
			probe, err := os.OpenFile(x.f.options.LockPath, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			lockErr := unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB)
			if lockErr == nil {
				unix.Flock(int(probe.Fd()), unix.LOCK_UN)
			}
			probe.Close()
			if name == "nft" && !errors.Is(lockErr, unix.EWOULDBLOCK) {
				t.Fatalf("nft ran without fw4 lock: %v", lockErr)
			}
			if name == "fw4" && lockErr != nil {
				t.Fatalf("fw4 ran while holding its own lock: %v", lockErr)
			}
			if name == "fw4" {
				if slices.Equal(args, []string{"check"}) && x.failFW4Check {
					return nil, errors.New("transient fw4 check failure")
				}
				if slices.Equal(args, []string{"reload"}) {
					x.doc = ownedFirewallDocument()
				}
				return nil, nil
			}
			if name != "nft" {
				t.Fatalf("unexpected command %s", name)
			}
			if slices.Equal(args, []string{"-j", "list", "ruleset"}) {
				return json.Marshal(x.doc)
			}
			var path string
			if len(args) == 3 && args[0] == "-c" && args[1] == "-f" {
				path = args[2]
			} else if len(args) == 2 && args[0] == "-f" {
				path = args[1]
			} else {
				t.Fatalf("unexpected nft command %v", args)
			}
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if args[0] == "-c" {
				x.checks = append(x.checks, string(content))
				if x.failCheck {
					return []byte("check failed"), errors.New("exit 1")
				}
			} else {
				x.commits = append(x.commits, string(content))
				if x.onCommit != nil {
					x.onCommit()
				}
				if x.failCommit {
					return []byte("transaction failed"), errors.New("exit 1")
				}
			}
			return nil, nil
		},
	})
	for path, content := range map[string]string{x.f.options.TableTemplatePath: firewallTableTemplate, x.f.options.InputTemplatePath: firewallInputTemplate} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return x
}

func testFirewallDesired() FirewallDesired {
	return FirewallDesired{Devices: []string{"wan.2", "eth0", "wan.2"}, GossipPort: 20000, IKEPorts: []uint16{500}, NATTPorts: []uint16{4500}}
}

func TestFirewallRulesExactFixedAndRangeGrace(t *testing.T) {
	d := testFirewallDesired()
	d.IKEPorts = []uint16{31002, 31000, 31002}
	d.NATTPorts = []uint16{31003, 31001}
	for _, rangeMode := range []bool{false, true} {
		d.RangeMode = rangeMode
		rules, err := firewallRules(d)
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) != 4 {
			t.Fatalf("rules: %v", rules)
		}
		all := strings.Join(rules, "\n")
		for _, expected := range []string{`iifname { "eth0", "wan.2" } tcp dport 20000`, `iifname { "eth0", "wan.2" } udp dport 20000`, `ct state != invalid counter accept comment "photon-openwrt:allow"`} {
			if !strings.Contains(all, expected) {
				t.Fatalf("missing %q: %s", expected, all)
			}
		}
		for _, expected := range []string{`{ 31000, 31002 }`, `{ 31001, 31003 }`} {
			if !strings.Contains(all, expected) {
				t.Fatalf("missing exact grace set %s: %s", expected, all)
			}
		}
		if rangeMode {
			for _, expected := range []string{"udp dport 500 ct original proto-dst { 31000, 31002 }", "udp dport 4500 ct original proto-dst { 31001, 31003 }"} {
				if !strings.Contains(all, expected) {
					t.Fatalf("range filter missing %s: %s", expected, all)
				}
			}
		} else if strings.Contains(all, "ct original") {
			t.Fatal(all)
		}
	}
}

func TestFirewallRejectInvalidInputsBeforeIO(t *testing.T) {
	for _, device := range []string{"", ".", "..", "eth*", "a/b", "a:b", "has space", "0123456789abcdef", "x\" accept", "x\ny"} {
		t.Run(device, func(t *testing.T) {
			x := newFirewallFixture(t)
			if err := x.f.Apply(context.Background(), FirewallDesired{Devices: []string{device}, GossipPort: 20000}); err == nil {
				t.Fatal("invalid device accepted")
			}
			if len(x.calls) != 0 {
				t.Fatal(x.calls)
			}
		})
	}
	for _, d := range []FirewallDesired{{IKEPorts: []uint16{0}}, {NATTPorts: []uint16{4500, 0}}} {
		if _, err := firewallRules(d); err == nil {
			t.Fatal("zero port accepted")
		}
	}
	rules, err := firewallRules(FirewallDesired{GossipPort: 20000, IKEPorts: []uint16{500}})
	if err != nil || len(rules) != 0 {
		t.Fatalf("empty WAN set opened traffic: %v %v", rules, err)
	}
}

func TestFirewallApplyAtomicSnippetAndCleanup(t *testing.T) {
	x := newFirewallFixture(t)
	ctx := context.Background()
	if err := x.f.Apply(ctx, testFirewallDesired()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(x.f.options.RuntimeDir, "input.nft")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("snippet permissions: %v %v", info, err)
	}
	if !strings.HasPrefix(string(data), firewallSnippetHeader) || strings.Contains(string(data), "add rule") {
		t.Fatalf("snippet not chain-body include: %s", data)
	}
	if len(x.checks) != 1 || !slices.Equal(x.checks, x.commits) {
		t.Fatalf("check/transaction differ: %v %v", x.checks, x.commits)
	}
	if !strings.HasPrefix(x.commits[0], "flush chain inet fw4 photon_openwrt_input\n") {
		t.Fatal(x.commits)
	}
	if err := x.f.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snippet retained: %v", err)
	}
	if x.commits[1] != "flush chain inet fw4 photon_openwrt_input\n" {
		t.Fatal(x.commits[1])
	}
	for _, call := range x.calls {
		if strings.HasPrefix(call, "fw4 ") {
			t.Fatal("unnecessary fw4 reload", x.calls)
		}
	}
	if err := x.f.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestFirewallFailureKeepsOldSnippetAndTransaction(t *testing.T) {
	for _, failure := range []string{"check", "commit", "cleanup"} {
		t.Run(failure, func(t *testing.T) {
			x := newFirewallFixture(t)
			ctx := context.Background()
			if err := x.f.Apply(ctx, testFirewallDesired()); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(x.f.options.RuntimeDir, "input.nft")
			before, _ := os.ReadFile(path)
			d := testFirewallDesired()
			d.GossipPort = 21000
			x.failCheck = failure == "check"
			x.failCommit = !x.failCheck
			x.onCommit = func() {
				candidate, err := os.ReadFile(path)
				if failure == "cleanup" {
					if !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("cleanup did not remove candidate: %v", err)
					}
				} else if err != nil || !strings.Contains(string(candidate), "21000") {
					t.Fatalf("candidate not atomically visible before commit: %s %v", candidate, err)
				}
			}
			var err error
			if failure == "cleanup" {
				err = x.f.Cleanup(ctx)
			} else {
				err = x.f.Apply(ctx, d)
			}
			if err == nil {
				t.Fatal("failure hidden")
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil || string(after) != string(before) {
				t.Fatalf("old runtime not restored: %s %v", after, readErr)
			}
			if failure == "check" && len(x.commits) != 1 {
				t.Fatal("failed check committed", x.commits)
			}
		})
	}
	x := newFirewallFixture(t)
	x.failCommit = true
	if err := x.f.Apply(context.Background(), testFirewallDesired()); err == nil {
		t.Fatal("failed initial commit accepted")
	}
	if _, err := os.Stat(filepath.Join(x.f.options.RuntimeDir, "input.nft")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("first failed apply left snippet", err)
	}
}

func TestFirewallInitializeOnlyWithPackageTemplatesAndRetryNextApply(t *testing.T) {
	x := newFirewallFixture(t)
	x.doc = map[string]any{"nftables": []any{}}
	if err := x.f.Apply(context.Background(), testFirewallDesired()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(x.calls, "fw4 check") || !slices.Contains(x.calls, "fw4 reload") {
		t.Fatal(x.calls)
	}
	x.doc = map[string]any{"nftables": []any{}}
	if err := x.f.Apply(context.Background(), testFirewallDesired()); err != nil {
		t.Fatal("later reconcile could not recover missing fw4 hooks", err)
	}
	count := 0
	for _, call := range x.calls {
		if call == "fw4 reload" {
			count++
		}
	}
	if count != 2 {
		t.Fatal(x.calls)
	}
	for _, failure := range []string{"template", "foreign-snippet"} {
		t.Run(failure, func(t *testing.T) {
			x := newFirewallFixture(t)
			x.doc = map[string]any{"nftables": []any{}}
			if failure == "template" {
				if err := os.WriteFile(x.f.options.TableTemplatePath, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.MkdirAll(x.f.options.RuntimeDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(x.f.options.RuntimeDir, "other.nft"), []byte("accept"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := x.f.Apply(context.Background(), testFirewallDesired()); err == nil {
				t.Fatal("unsafe initialization accepted")
			}
			for _, call := range x.calls {
				if strings.HasPrefix(call, "fw4 ") || strings.HasPrefix(call, "nft -f") {
					t.Fatal("unsafe initialization mutated firewall", x.calls)
				}
			}
		})
	}
}

func TestFirewallTransientInitializationFailureCanRecover(t *testing.T) {
	x := newFirewallFixture(t)
	x.doc = map[string]any{"nftables": []any{}}
	x.failFW4Check = true
	if err := x.f.Apply(context.Background(), testFirewallDesired()); err == nil {
		t.Fatal("transient init failure hidden")
	}
	for _, call := range x.calls {
		if call == "fw4 reload" {
			t.Fatal("reload followed failed fw4 check")
		}
	}
	if len(x.commits) != 0 {
		t.Fatal("failed initialization committed rules")
	}
	x.failFW4Check = false
	if err := x.f.Apply(context.Background(), testFirewallDesired()); err != nil {
		t.Fatal("same backend failed later retry", err)
	}
	checks, reloads := 0, 0
	for _, call := range x.calls {
		if call == "fw4 check" {
			checks++
		}
		if call == "fw4 reload" {
			reloads++
		}
	}
	if checks != 2 || reloads != 1 {
		t.Fatalf("unexpected retry scope: %v", x.calls)
	}
}

func TestFirewallRefusesOccupiedChainOrJump(t *testing.T) {
	for _, kind := range []string{"chain-owner", "base-chain", "rule-owner", "jump-owner", "duplicate-jump", "conditional-jump", "goto", "other-chain-reference"} {
		t.Run(kind, func(t *testing.T) {
			x := newFirewallFixture(t)
			entries := x.doc["nftables"].([]any)
			chain := entries[0].(map[string]any)["chain"].(map[string]any)
			jump := entries[1].(map[string]any)["rule"].(map[string]any)
			switch kind {
			case "chain-owner":
				chain["comment"] = "foreign"
			case "base-chain":
				chain["hook"] = "input"
				chain["type"] = "filter"
			case "rule-owner":
				entries = append(entries, map[string]any{"rule": map[string]any{"family": "inet", "table": "fw4", "chain": firewallChain, "comment": "foreign"}})
			case "jump-owner":
				jump["comment"] = "foreign"
			case "duplicate-jump":
				entries = append(entries, entries[1])
			case "conditional-jump":
				jump["expr"] = append(jump["expr"].([]any), map[string]any{"match": map[string]any{}})
			case "goto":
				jump["expr"] = []any{map[string]any{"goto": map[string]any{"target": firewallChain}}}
			case "other-chain-reference":
				jump["chain"] = "input_wan"
			}
			x.doc["nftables"] = entries
			for _, action := range []func() error{func() error { return x.f.Apply(context.Background(), testFirewallDesired()) }, func() error { return x.f.Cleanup(context.Background()) }} {
				if err := action(); err == nil {
					t.Fatal("foreign ownership accepted")
				}
			}
			for _, call := range x.calls {
				if !strings.HasPrefix(call, "nft -j list ruleset") {
					t.Fatal("foreign ownership mutated", x.calls)
				}
			}
		})
	}
}

func TestFirewallCleanupAbsentDoesNotReload(t *testing.T) {
	x := newFirewallFixture(t)
	x.doc = map[string]any{"nftables": []any{}}
	if err := x.f.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(x.calls) != 1 || x.calls[0] != "nft -j list ruleset" {
		t.Fatal(x.calls)
	}
}

func TestFirewallPackageTemplatesMatch(t *testing.T) {
	for path, expected := range map[string]string{"../../contrib/openwrt/files/photon-fw4-table.nft": firewallTableTemplate, "../../contrib/openwrt/files/photon-fw4-input.nft": firewallInputTemplate} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != expected {
			t.Fatalf("%s differs from initialization guard: %v", path, err)
		}
	}
}

func TestFirewallSharedLockWaitIsCancellable(t *testing.T) {
	x := newFirewallFixture(t)
	file, err := os.OpenFile(x.f.options.LockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := x.f.Apply(ctx, testFirewallDesired()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked writer did not cancel: %v", err)
	}
	if len(x.calls) != 0 {
		t.Fatal("blocked writer invoked tools", x.calls)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := x.f.Apply(context.Background(), testFirewallDesired()); err != nil {
		t.Fatal("writer failed after external reload released lock", err)
	}
}

func TestFirewallRejectsUnhookedOrMalformedInput(t *testing.T) {
	for _, kind := range []string{"ordinary-input", "wrong-hook", "wrong-type", "malformed-document"} {
		t.Run(kind, func(t *testing.T) {
			x := newFirewallFixture(t)
			entries := x.doc["nftables"].([]any)
			input := entries[3].(map[string]any)["chain"].(map[string]any)
			switch kind {
			case "ordinary-input":
				delete(input, "type")
				delete(input, "hook")
			case "wrong-hook":
				input["hook"] = "forward"
			case "wrong-type":
				input["type"] = "nat"
			case "malformed-document":
				x.doc = map[string]any{}
			}
			if err := x.f.Apply(context.Background(), testFirewallDesired()); err == nil {
				t.Fatal("unhooked input reported success")
			}
			if len(x.calls) != 1 || x.calls[0] != "nft -j list ruleset" {
				t.Fatal("invalid input mutated fw4", x.calls)
			}
		})
	}
}
