//go:build linux

package photonopenwrt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	firewallChain         = "photon_openwrt_input"
	firewallOwner         = "photon-openwrt:input"
	firewallJumpOwner     = "photon-openwrt:jump"
	firewallRuleOwner     = "photon-openwrt:allow"
	firewallSnippetHeader = "# photon-openwrt managed input rules\n"
	firewallTableTemplate = "chain photon_openwrt_input {\n\tcomment \"photon-openwrt:input\"\n\tinclude \"/run/photon/fw4/*.nft\"\n}\n"
	firewallInputTemplate = "jump photon_openwrt_input comment \"photon-openwrt:jump\"\n"
)

// FirewallDesired contains local listening ports, including any signed grace
// ports. In range mode IKEPorts/NATTPorts are original, pre-DNAT UDP ports;
// their local destinations must also be 500/4500 respectively.
type FirewallDesired struct {
	Devices             []string
	GossipPort          uint16
	IKEPorts, NATTPorts []uint16
	RangeMode           bool
}

type FirewallOptions struct {
	Run               Runner
	RuntimeDir        string
	TableTemplatePath string
	InputTemplatePath string
	// LockPath must be the same inode used by fw4. Override only for isolated tests.
	LockPath string
}

// Firewall manages one ordinary chain reached from fw4's input chain. It must
// not use a separate base-chain accept: a later fw4 drop would override it.
// The daemon is the sole writer; fw4 can rebuild its table from the snippet.
type Firewall struct {
	mu      sync.Mutex
	options FirewallOptions
}

func NewFirewall(options FirewallOptions) *Firewall {
	if options.Run == nil {
		options.Run = runCommand
	}
	if options.RuntimeDir == "" {
		options.RuntimeDir = "/run/photon/fw4"
	}
	if options.TableTemplatePath == "" {
		options.TableTemplatePath = "/usr/share/nftables.d/table-pre/30-photon.nft"
	}
	if options.InputTemplatePath == "" {
		options.InputTemplatePath = "/usr/share/nftables.d/chain-pre/input/30-photon.nft"
	}
	if options.LockPath == "" {
		options.LockPath = "/var/run/fw4.lock"
	}
	return &Firewall{options: options}
}

var firewallDevicePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

func firewallRules(desired FirewallDesired) ([]string, error) {
	devices := slices.Clone(desired.Devices)
	for _, device := range devices {
		if len(device) == 0 || len(device) > 15 || device == "." || device == ".." || !firewallDevicePattern.MatchString(device) {
			return nil, fmt.Errorf("invalid firewall device %q", device)
		}
	}
	slices.Sort(devices)
	devices = slices.Compact(devices)
	ports := func(input []uint16) (string, error) {
		values := slices.Clone(input)
		slices.Sort(values)
		values = slices.Compact(values)
		out := make([]string, len(values))
		for i, value := range values {
			if value == 0 {
				return "", errors.New("firewall port must be nonzero")
			}
			out[i] = strconv.Itoa(int(value))
		}
		return "{ " + strings.Join(out, ", ") + " }", nil
	}
	ike, err := ports(desired.IKEPorts)
	if err != nil {
		return nil, err
	}
	natt, err := ports(desired.NATTPorts)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, nil
	}
	for i := range devices {
		devices[i] = strconv.Quote(devices[i])
	}
	prefix := "iifname { " + strings.Join(devices, ", ") + " } "
	suffix := " ct state != invalid counter accept comment " + strconv.Quote(firewallRuleOwner)
	var rules []string
	if desired.GossipPort != 0 {
		for _, protocol := range []string{"tcp", "udp"} {
			rules = append(rules, prefix+protocol+" dport "+strconv.Itoa(int(desired.GossipPort))+suffix)
		}
	}
	for _, group := range []struct {
		values []uint16
		set    string
		local  string
	}{
		{desired.IKEPorts, ike, "500"}, {desired.NATTPorts, natt, "4500"},
	} {
		if len(group.values) == 0 {
			continue
		}
		expression := "udp dport " + group.set
		if desired.RangeMode {
			expression = "udp dport " + group.local + " ct original proto-dst " + group.set
		}
		rules = append(rules, prefix+expression+suffix)
	}
	return rules, nil
}

func firewallTransaction(rules []string) []byte {
	var out strings.Builder
	fmt.Fprintf(&out, "flush chain inet fw4 %s\n", firewallChain)
	for _, rule := range rules {
		fmt.Fprintf(&out, "add rule inet fw4 %s %s\n", firewallChain, rule)
	}
	return []byte(out.String())
}

func (f *Firewall) Apply(ctx context.Context, desired FirewallDesired) error {
	rules, err := firewallRules(desired)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	snippet := firewallSnippetHeader + strings.Join(rules, "\n") + "\n"
	ready := false
	apply := func() error {
		// A first fw4 reload executes the include too: inspect snippet ownership
		// before initialization and again while holding fw4's shared lock.
		if _, _, err := f.oldSnippet(); err != nil {
			return err
		}
		present, attached, err := f.observe(ctx)
		if err != nil {
			return err
		}
		ready = present && attached
		if !ready {
			return nil
		}
		return f.replace(ctx, rules, []byte(snippet), false)
	}
	if err := f.withLock(ctx, apply); err != nil {
		return err
	}
	if ready {
		return nil
	}
	// fw4 takes this same lock itself. Never call it while holding the lock.
	if err := f.initialize(ctx); err != nil {
		return err
	}
	if err := f.withLock(ctx, apply); err != nil {
		return err
	}
	if !ready {
		return errors.New("fw4 reload did not attach the Photon input chain")
	}
	return nil
}

// Cleanup leaves the package-owned empty chain and jump in place. It never
// reloads fw4 and never flushes a table or another application's chain.
func (f *Firewall) Cleanup(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.withLock(ctx, func() error { return f.cleanupLocked(ctx) })
}

func (f *Firewall) cleanupLocked(ctx context.Context) error {
	present, _, err := f.observe(ctx)
	if err != nil {
		return err
	}
	if !present {
		if _, _, err := f.oldSnippet(); err != nil {
			return err
		}
		err := os.Remove(filepath.Join(f.options.RuntimeDir, "input.nft"))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return f.replace(ctx, nil, nil, true)
}

func (f *Firewall) initialize(ctx context.Context) error {
	for _, template := range []struct{ path, content string }{
		{f.options.TableTemplatePath, firewallTableTemplate}, {f.options.InputTemplatePath, firewallInputTemplate},
	} {
		info, err := os.Lstat(template.path)
		if err != nil {
			return fmt.Errorf("Photon fw4 template: %w", err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("Photon fw4 template %s is not a regular file", template.path)
		}
		content, err := os.ReadFile(template.path)
		if err != nil || string(content) != template.content {
			return fmt.Errorf("Photon fw4 template %s does not match the installed package", template.path)
		}
	}
	for _, action := range []string{"check", "reload"} {
		if output, err := f.options.Run(ctx, "fw4", action); err != nil {
			return fmt.Errorf("fw4 %s: %w: %s", action, err, output)
		}
	}
	return nil
}

func (f *Firewall) withLock(ctx context.Context, fn func() error) error {
	fd, err := unix.Open(f.options.LockPath, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("open fw4 lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), f.options.LockPath)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("fw4 lock is not a regular file")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return fmt.Errorf("lock fw4: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	return fn()
}

// observe rejects occupied names before any mutation. Counters and handles are
// intentionally ignored; ownership is attached to both chain and every rule.
func (f *Firewall) observe(ctx context.Context) (present, attached bool, err error) {
	output, err := f.options.Run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return false, false, fmt.Errorf("read fw4 ownership: %w: %s", err, output)
	}
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(output, &doc); err != nil {
		return false, false, fmt.Errorf("read fw4 JSON: %w", err)
	}
	if doc.NFTables == nil {
		return false, false, errors.New("read fw4 JSON: missing nftables array")
	}
	jumps := 0
	inputBase := false
	for _, entry := range doc.NFTables {
		for kind, raw := range entry {
			if kind != "chain" && kind != "rule" {
				continue
			}
			var object struct {
				Family, Table, Name, Chain, Comment, Type, Hook, Policy string
				Expr                                                    []map[string]json.RawMessage
			}
			if err := json.Unmarshal(raw, &object); err != nil {
				return false, false, err
			}
			if object.Family != "inet" || object.Table != "fw4" {
				continue
			}
			if kind == "chain" && object.Name == "input" {
				if inputBase || object.Type != "filter" || object.Hook != "input" {
					return false, false, errors.New("fw4 input is not its filter input base chain")
				}
				inputBase = true
			}
			if kind == "chain" && object.Name == firewallChain {
				if present || object.Comment != firewallOwner || object.Hook != "" || object.Type != "" || object.Policy != "" {
					return false, false, errors.New("Photon fw4 chain name is occupied by a foreign or base chain")
				}
				present = true
			}
			if kind != "rule" {
				continue
			}
			if object.Chain == firewallChain && object.Comment != firewallRuleOwner {
				return false, false, errors.New("Photon fw4 chain contains a foreign rule")
			}
			for _, expression := range object.Expr {
				for _, verdict := range []string{"jump", "goto"} {
					if len(expression[verdict]) == 0 {
						continue
					}
					var target struct{ Target string }
					if err := json.Unmarshal(expression[verdict], &target); err != nil {
						return false, false, err
					}
					if target.Target != firewallChain {
						continue
					}
					if object.Chain != "input" || object.Comment != firewallJumpOwner || verdict != "jump" || len(object.Expr) != 1 {
						return false, false, errors.New("Photon fw4 chain has a foreign reference")
					}
					jumps++
				}
			}
		}
	}
	if jumps > 1 {
		return false, false, errors.New("Photon fw4 input jump is duplicated")
	}
	return present, jumps == 1 && inputBase, nil
}

func (f *Firewall) oldSnippet() ([]byte, bool, error) {
	info, err := os.Lstat(f.options.RuntimeDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return nil, false, errors.New("Photon fw4 runtime directory is not a private directory")
	}
	entries, err := os.ReadDir(f.options.RuntimeDir)
	if err != nil {
		return nil, false, err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".nft") && entry.Name() != "input.nft" {
			return nil, false, errors.New("Photon fw4 runtime directory contains a foreign nft snippet")
		}
	}
	path := filepath.Join(f.options.RuntimeDir, "input.nft")
	info, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, false, errors.New("Photon fw4 snippet is not a private regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	if !strings.HasPrefix(string(data), firewallSnippetHeader) {
		return nil, false, errors.New("Photon fw4 snippet has a foreign owner")
	}
	return data, true, nil
}

func (f *Firewall) atomicSnippet(data []byte) error {
	file, err := os.CreateTemp(f.options.RuntimeDir, ".input-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(f.options.RuntimeDir, "input.nft"))
}

func (f *Firewall) replace(ctx context.Context, rules []string, snippet []byte, remove bool) error {
	old, existed, err := f.oldSnippet()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(f.options.RuntimeDir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(f.options.RuntimeDir, ".transaction-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(firewallTransaction(rules)); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if output, err := f.options.Run(ctx, "nft", "-c", "-f", file.Name()); err != nil {
		return fmt.Errorf("check Photon fw4 rules: %w: %s", err, output)
	}
	path := filepath.Join(f.options.RuntimeDir, "input.nft")
	if remove {
		err = os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	} else {
		err = f.atomicSnippet(snippet)
	}
	if err != nil {
		return err
	}
	if output, err := f.options.Run(ctx, "nft", "-f", file.Name()); err != nil {
		var restoreErr error
		if existed {
			restoreErr = f.atomicSnippet(old)
		} else {
			restoreErr = os.Remove(path)
			if errors.Is(restoreErr, os.ErrNotExist) {
				restoreErr = nil
			}
		}
		return errors.Join(fmt.Errorf("apply Photon fw4 transaction: %w: %s", err, output), restoreErr)
	}
	return nil
}
