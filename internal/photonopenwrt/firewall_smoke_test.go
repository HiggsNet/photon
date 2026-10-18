//go:build linux

package photonopenwrt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/firewall"
)

// This opt-in smoke uses the installed, real fw4 renderer and nft kernel API.
// All files fw4 may write, and all network objects, live in child namespaces.
// Run the compiled test on an OpenWrt/ImmortalWrt device with fw4, ip-full,
// mount and unshare available; ordinary go test never changes the machine.
func TestOpenWrtFW4IsolatedPackets(t *testing.T) {
	if os.Getenv("PHOTON_OPENWRT_FW4_SMOKE") != "1" {
		t.Skip("set PHOTON_OPENWRT_FW4_SMOKE=1 for isolated real fw4 packet acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if os.Getenv("PHOTON_FW4_SMOKE_CHILD") != "1" {
		for _, command := range []string{"unshare", "mount", "ip", "nft", "fw4"} {
			if _, err := exec.LookPath(command); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.CommandContext(ctx, "unshare", "-m", "--propagation", "private", "-n", os.Args[0], "-test.run=^TestOpenWrtFW4IsolatedPackets$", "-test.v")
		cmd.Env = append(os.Environ(), "PHOTON_FW4_SMOKE_CHILD=1", "PHOTON_FW4_HOST_NET="+fw4Namespace(t, "net"), "PHOTON_FW4_HOST_MNT="+fw4Namespace(t, "mnt"), "PHOTON_FW4_FIXTURE="+t.TempDir())
		output, err := cmd.CombinedOutput()
		t.Logf("isolated fw4:\n%s", output)
		if err != nil {
			t.Fatalf("isolated fw4 smoke: %v", err)
		}
		return
	}
	for _, kind := range []string{"net", "mnt"} {
		parent := os.Getenv("PHOTON_FW4_HOST_" + strings.ToUpper(kind))
		if parent == "" || parent == fw4Namespace(t, kind) {
			t.Fatalf("refusing mutation without a private %s namespace", kind)
		}
	}
	fw4PrivateFiles(t, ctx)
	fw4Command(t, ctx, "ip", "link", "set", "lo", "up")
	fw4Command(t, ctx, "ip", "netns", "add", "phfw-peer")
	for i := 0; i < 2; i++ {
		dev, peer := fmt.Sprintf("phfw%d", i), fmt.Sprintf("peer%d", i)
		fw4Command(t, ctx, "ip", "link", "add", dev, "type", "veth", "peer", "name", peer)
		fw4Command(t, ctx, "ip", "link", "set", peer, "netns", "phfw-peer")
		fw4Command(t, ctx, "ip", "link", "set", dev, "up")
		fw4Command(t, ctx, "ip", "netns", "exec", "phfw-peer", "ip", "link", "set", peer, "up")
		for family, prefix := range map[string]string{"-4": fmt.Sprintf("192.0.%d.", 2+i), "-6": fmt.Sprintf("2001:db8:%d::", 1+i)} {
			mask := "/30"
			if family == "-6" {
				mask = "/64"
			}
			fw4Command(t, ctx, "ip", family, "addr", "add", prefix+"1"+mask, "dev", dev)
			fw4Command(t, ctx, "ip", "netns", "exec", "phfw-peer", "ip", family, "addr", "add", prefix+"2"+mask, "dev", peer)
		}
	}
	// Wait for actual DAD, rather than suppressing it in a production-shaped test.
	for _, prefix := range [][]string{{"ip"}, {"ip", "netns", "exec", "phfw-peer", "ip"}} {
		deadline := time.Now().Add(8 * time.Second)
		for {
			args := append(append([]string{}, prefix[1:]...), "-j", "-6", "addr", "show")
			output := fw4Command(t, ctx, prefix[0], args...)
			if !strings.Contains(string(output), "tentative") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("IPv6 DAD did not complete")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	fw4Write(t, "/etc/config/firewall", `config defaults
	option input 'DROP'
	option output 'ACCEPT'
	option forward 'DROP'
	option drop_invalid '1'
	option auto_includes '1'
config zone
	option name 'wan'
	list device 'phfw0'
	list device 'phfw1'
	option input 'DROP'
	option output 'ACCEPT'
	option forward 'DROP'
config rule
	option name 'fixture-neighbor-discovery'
	option src 'wan'
	option family 'ipv6'
	option proto 'icmp'
	list icmp_type 'neighbour-solicitation'
	list icmp_type 'neighbour-advertisement'
	option target 'ACCEPT'
`)
	fw4Write(t, "/etc/config/network", "")
	fw4Write(t, "/etc/nftables.d/10-fixture.nft", "chain fixture_foreign { comment \"fixture:foreign\"; counter comment \"fixture:preserve\"; }\n")
	fw4Command(t, ctx, "fw4", "start")
	fw4Write(t, "/usr/share/nftables.d/table-pre/30-photon.nft", firewallTableTemplate)
	fw4Write(t, "/usr/share/nftables.d/chain-pre/input/30-photon.nft", firewallInputTemplate)
	fw4EchoServers(t)
	foreign := fw4Foreign(t, ctx)
	packets := 0
	check := func(dev int, port int, protocol string, want bool) {
		t.Helper()
		for _, address := range []string{fmt.Sprintf("192.0.%d.1", 2+dev), fmt.Sprintf("2001:db8:%d::1", 1+dev)} {
			cmd := exec.CommandContext(ctx, "ip", "netns", "exec", "phfw-peer", "/tmp/packet-helper", "-test.run=^TestOpenWrtFW4PacketHelper$")
			cmd.Env = append(os.Environ(), "PHOTON_FW4_PACKET_HELPER=1", "PHOTON_FW4_PACKET_PROTOCOL="+protocol, "PHOTON_FW4_PACKET_ADDRESS="+net.JoinHostPort(address, strconv.Itoa(port)))
			output, err := cmd.CombinedOutput()
			if (err == nil) != want {
				t.Fatalf("%s %s:%d allowed=%v want=%v: %s", protocol, address, port, err == nil, want, output)
			}
			if !want && !strings.Contains(string(output), "FW4_PACKET_BLOCKED") {
				t.Fatalf("packet helper failed without attempting a blocked socket: %s", output)
			}
			packets++
		}
	}
	check(0, 500, "udp", false)
	manager := NewFirewall(FirewallOptions{})
	desired := FirewallDesired{Devices: []string{"phfw0"}, GossipPort: 33434, IKEPorts: []uint16{500}, NATTPorts: []uint16{4500}}
	apply := func() {
		t.Helper()
		if err := manager.Apply(ctx, desired); err != nil {
			t.Fatal(err)
		}
	}
	apply() // Exercise initial real fw4 check/reload and re-observation.
	for _, port := range []int{500, 4500, 33434} {
		check(0, port, "udp", true)
		check(1, port, "udp", false)
	}
	check(0, 33434, "tcp", true)
	check(0, 7347, "tcp", false)
	check(0, 7347, "udp", false)
	t.Log("fixed ports: selected WAN accepts IPv4/IPv6 gossip and IPsec; other WAN and admin ports stay blocked")
	fw4Command(t, ctx, "fw4", "reload")
	check(0, 500, "udp", true)
	check(0, 33434, "tcp", true)
	desired.Devices = []string{"phfw1"}
	apply()
	check(0, 500, "udp", false)
	check(1, 500, "udp", true)
	check(1, 33434, "tcp", true)
	t.Log("real fw4 reload preserves allowances; WAN switch withdraws old device")

	// Range translation comes from the existing generic NAT planner/driver.
	// fw4 only accepts its exact current/grace original ports after translation.
	spec := firewall.FirewallInstanceSpec{ID: "wan", NetNS: "host", IsHost: true, Enabled: true, Mode: firewall.ModeManaged, Backend: firewall.BackendNFT, OwnerPrefix: "photon_fw4_smoke_nat", RedirectGrace: firewall.RedirectGrace{Enabled: true}, CharonIKEPort: 500, CharonNATTPort: 4500}
	input := firewall.FirewallPolicyInput{AdvertisedCurrentIKEPorts: []uint16{32001}, AdvertisedCurrentNATTPorts: []uint16{32002}, AdvertisedPreviousIKEPorts: []uint16{32011}, AdvertisedPreviousNATTPorts: []uint16{32012}}
	nat, err := firewall.BuildDesiredState(spec, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := firewall.NewNFTDriver().Apply(ctx, nat); err != nil {
		t.Fatal(err)
	}
	desired.RangeMode, desired.IKEPorts, desired.NATTPorts = true, []uint16{32001, 32011}, []uint16{32002, 32012}
	apply()
	for _, port := range []int{32001, 32002, 32011, 32012} {
		check(1, port, "udp", true)
	}
	for _, port := range []int{500, 4500, 32003} {
		check(1, port, "udp", false)
	}
	desired.IKEPorts, desired.NATTPorts = []uint16{32001}, []uint16{32002}
	apply()
	check(1, 32011, "udp", false)
	check(1, 32012, "udp", false)
	check(1, 32001, "udp", true)
	t.Log("range ports: exact current/grace DNAT works for IPv4/IPv6; direct, adjacent and expired original ports stay blocked")
	desired.Devices = nil // All selected WANs down: no listening fallback.
	apply()
	check(1, 32001, "udp", false)
	check(1, 33434, "tcp", false)
	if err := manager.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/run/photon/fw4/input.nft"); !os.IsNotExist(err) {
		t.Fatalf("cleanup retained runtime snippet: %v", err)
	}
	fw4Command(t, ctx, "fw4", "reload")
	check(1, 33434, "tcp", false)
	if got := fw4Foreign(t, ctx); !reflect.DeepEqual(got, foreign) {
		t.Fatalf("foreign fixture chain changed: before=%s after=%s", foreign, got)
	}
	fw4Command(t, ctx, "nft", "add", "rule", "inet", "fw4", firewallChain, "counter", "comment", `"fixture:foreign-rule"`)
	before := string(fw4Command(t, ctx, "nft", "-j", "list", "chain", "inet", "fw4", firewallChain))
	if err := manager.Apply(ctx, desired); err == nil {
		t.Fatal("accepted foreign rule in owned chain")
	}
	if err := manager.Cleanup(ctx); err == nil {
		t.Fatal("cleanup accepted foreign rule in owned chain")
	}
	if after := string(fw4Command(t, ctx, "nft", "-j", "list", "chain", "inet", "fw4", firewallChain)); after != before {
		t.Fatal("ownership conflict changed the existing chain")
	}
	t.Logf("all WAN down and cleanup/reload withdraw allowances; foreign resources preserved; %d real socket probes", packets)
}

func fw4Namespace(t *testing.T, kind string) string {
	t.Helper()
	value, err := os.Readlink("/proc/self/ns/" + kind)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func fw4Command(t *testing.T, ctx context.Context, name string, args ...string) []byte {
	t.Helper()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %q: %v: %s", name, args, err, output)
	}
	return output
}

func fw4Write(t *testing.T, path, content string) {
	t.Helper()
	if err := fw4WriteFile(path, content); err != nil {
		t.Fatal(err)
	}
}

// A mirror entry is a symlink to a read-only original mount. Refuse to follow
// even a single such ancestor (or leaf), before mkdir or file truncation.
func fw4WriteFile(path, content string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("fixture write requires a clean absolute path: %q", path)
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(path, current), string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing fixture write through symlink %s", current)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0600)
}

func fw4PrivateFiles(t *testing.T, ctx context.Context) {
	t.Helper()
	fixture := os.Getenv("PHOTON_FW4_FIXTURE")
	if !strings.HasPrefix(fixture, "/tmp/") {
		t.Fatal("private fixture must be under /tmp")
	}
	privateTmp := filepath.Join(fixture, "private-tmp")
	if err := os.MkdirAll(privateTmp, 0700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(privateTmp, "packet-helper"), binary, 0700); err != nil {
		t.Fatal(err)
	}
	fw4Command(t, ctx, "mount", "--bind", privateTmp, "/tmp")
	// OpenWrt normally aliases both runtime paths into /tmp; bind any physical
	// runtime mount separately on other supported fixture layouts.
	for i, runtime := range []string{"/run", "/var/run"} {
		if err := os.MkdirAll("/tmp/run", 0700); err != nil {
			t.Fatal(err)
		}
		resolved, err := filepath.EvalSymlinks(runtime)
		if err != nil {
			t.Fatal(err)
		}
		if resolved == "/tmp" || strings.HasPrefix(resolved, "/tmp/") {
			continue
		}
		privateRun := fmt.Sprintf("/tmp/private-run-%d", i)
		if err := os.Mkdir(privateRun, 0700); err != nil {
			t.Fatal(err)
		}
		fw4Command(t, ctx, "mount", "--bind", privateRun, resolved)
	}
	for _, tree := range []struct {
		path  string
		empty map[string]bool
	}{
		{"/etc", map[string]bool{"config": true, "photon": true, "nftables.d": true, "hotplug.d": true, "init.d": true, "rc.d": true}},
		{"/usr/share", map[string]bool{"nftables.d": true}},
	} {
		fw4PrivateMirror(t, ctx, tree.path, tree.empty)
	}
	fw4Command(t, ctx, "mount", "-t", "sysfs", "sysfs", "/sys")
	fw4AssertReadOnlyMirror(t, ctx)
}

func fw4PrivateMirror(t *testing.T, ctx context.Context, path string, empty map[string]bool) {
	t.Helper()
	name := strings.ReplaceAll(strings.Trim(path, "/"), "/", "-")
	original, mirror := "/tmp/original-"+name, "/tmp/private-"+name
	for _, dir := range []string{original, mirror} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	fw4Command(t, ctx, "mount", "--bind", path, original)
	// A missed empty entry must fail closed even if a test or an init script
	// bypasses fw4Write and follows its mirror symlink to the original tree.
	fw4Command(t, ctx, "mount", "-o", "remount,bind,ro", original, original)
	entries, err := os.ReadDir(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !empty[entry.Name()] {
			if err := os.Symlink(filepath.Join(original, entry.Name()), filepath.Join(mirror, entry.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	for dir := range empty {
		if err := os.Mkdir(filepath.Join(mirror, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	fw4Command(t, ctx, "mount", "--bind", mirror, path)
}

func TestFW4FixtureWriteRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(source, "existing")
	if err := os.WriteFile(file, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "unowned-directory")
	if err := os.Symlink(source, alias); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(root, "unowned-file")
	if err := os.Symlink(file, leaf); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{filepath.Join(alias, "existing"), filepath.Join(alias, "new", "nested"), leaf} {
		if err := fw4WriteFile(target, "clobber"); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("write %s did not reject symlink: %v", target, err)
		}
	}
	if got, err := os.ReadFile(file); err != nil || string(got) != "preserve" {
		t.Fatalf("source was modified: %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(source, "new")); !os.IsNotExist(err) {
		t.Fatalf("mkdir crossed the symlink: %v", err)
	}
	if err := fw4WriteFile(filepath.Join(root, "private", "safe"), "allowed"); err != nil {
		t.Fatal(err)
	}
}

func fw4AssertReadOnlyMirror(t *testing.T, ctx context.Context) {
	t.Helper()
	// Exercise both protections on a source created only in private /tmp. A
	// missed private-directory declaration must not be able to write its source
	// even through a raw writer that does not use the Go ancestor guard.
	source := "/tmp/isolation-source"
	fw4Write(t, source+"/keep", "preserve")
	fw4PrivateMirror(t, ctx, source, nil)
	if err := fw4WriteFile(source+"/keep", "clobber"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("mirror writer did not reject an unowned file: %v", err)
	}
	if err := os.WriteFile(source+"/keep", []byte("clobber"), 0600); !errors.Is(err, syscall.EROFS) {
		t.Fatalf("raw write through mirror was not blocked by readonly bind: %v", err)
	}
	if got, err := os.ReadFile(source + "/keep"); err != nil || string(got) != "preserve" {
		t.Fatalf("readonly mirror source changed: %q %v", got, err)
	}
	t.Log("isolation guard: symlink writer rejected and raw mirrored write blocked with EROFS")
}

func fw4Foreign(t *testing.T, ctx context.Context) string {
	t.Helper()
	var value any
	if err := json.Unmarshal(fw4Command(t, ctx, "nft", "-j", "list", "chain", "inet", "fw4", "fixture_foreign"), &value); err != nil {
		t.Fatal(err)
	}
	var normalize func(any)
	normalize = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for _, field := range []string{"handle", "packets", "bytes"} {
				delete(value, field)
			}
			for _, child := range value {
				normalize(child)
			}
		case []any:
			for _, child := range value {
				normalize(child)
			}
		}
	}
	normalize(value)
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func fw4EchoServers(t *testing.T) {
	t.Helper()
	for _, family := range []string{"4", "6"} {
		for _, port := range []string{"500", "4500", "33434", "7347"} {
			conn, err := net.ListenPacket("udp"+family, ":"+port)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })
			go func() {
				buffer := make([]byte, 256)
				for {
					n, address, err := conn.ReadFrom(buffer)
					if err != nil {
						return
					}
					_, _ = conn.WriteTo(buffer[:n], address)
				}
			}()
		}
		for _, port := range []string{"33434", "7347"} {
			listener, err := net.Listen("tcp"+family, ":"+port)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
				}
			}()
		}
	}
}

func TestOpenWrtFW4PacketHelper(t *testing.T) {
	if os.Getenv("PHOTON_FW4_PACKET_HELPER") != "1" {
		t.Skip("private packet helper")
	}
	conn, err := net.DialTimeout(os.Getenv("PHOTON_FW4_PACKET_PROTOCOL"), os.Getenv("PHOTON_FW4_PACKET_ADDRESS"), 750*time.Millisecond)
	if err != nil {
		t.Fatalf("FW4_PACKET_BLOCKED: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(750 * time.Millisecond))
	message := fmt.Sprintf("fw4-%d", time.Now().UnixNano())
	if _, err := io.WriteString(conn, message); err != nil {
		t.Fatalf("FW4_PACKET_BLOCKED: %v", err)
	}
	response := make([]byte, len(message))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("FW4_PACKET_BLOCKED: %v", err)
	}
	if string(response) != message {
		t.Fatalf("wrong echo %q", response)
	}
}
