//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonopenwrt"
)

// Exercise actual daemon startup after an unclean predecessor left marked
// rules, with all kernel and runtime effects confined to disposable namespaces.
func TestOpenWrtOptOutStartupIsolated(t *testing.T) {
	if os.Getenv("PHOTON_OPENWRT_STARTUP_SMOKE") != "1" {
		t.Skip("set PHOTON_OPENWRT_STARTUP_SMOKE=1 on the dedicated OpenWrt test device")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := func(name string, args ...string) []byte {
		t.Helper()
		output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v: %s", name, args, err, output)
		}
		return output
	}
	namespace := func(kind string) string {
		value, err := os.Readlink("/proc/self/ns/" + kind)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	if os.Getenv("PHOTON_OPENWRT_STARTUP_CHILD") != "1" {
		fixture := t.TempDir()
		child := exec.CommandContext(ctx, "unshare", "-m", "--propagation", "private", "-n", os.Args[0], "-test.run=^TestOpenWrtOptOutStartupIsolated$", "-test.v")
		child.Env = append(os.Environ(), "PHOTON_OPENWRT_STARTUP_CHILD=1", "PHOTON_OPENWRT_STARTUP_NET="+namespace("net"), "PHOTON_OPENWRT_STARTUP_MNT="+namespace("mnt"), "PHOTON_OPENWRT_STARTUP_TMP="+fixture)
		output, err := child.CombinedOutput()
		t.Logf("isolated startup:\n%s", output)
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, kind := range []string{"net", "mnt"} {
		parent := os.Getenv("PHOTON_OPENWRT_STARTUP_" + strings.ToUpper(kind))
		if parent == "" || parent == namespace(kind) {
			t.Fatal("refusing startup mutation outside private namespace", kind)
		}
	}
	privateTmp := os.Getenv("PHOTON_OPENWRT_STARTUP_TMP")
	if !strings.HasPrefix(privateTmp, "/tmp/") {
		t.Fatal("fixture outside /tmp")
	}
	command("mount", "--bind", privateTmp, "/tmp")
	if err := os.MkdirAll("/tmp/run", 0700); err != nil {
		t.Fatal(err)
	}
	for i, path := range []string{"/run", "/var/run"} {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			t.Fatal(err)
		}
		if resolved == "/tmp" || strings.HasPrefix(resolved, "/tmp/") {
			continue
		}
		privateRun := fmt.Sprintf("/tmp/runtime-%d", i)
		if err := os.Mkdir(privateRun, 0700); err != nil {
			t.Fatal(err)
		}
		command("mount", "--bind", privateRun, resolved)
	}
	command("ip", "link", "set", "lo", "up")
	batch := `add table inet fw4
add chain inet fw4 input { type filter hook input priority filter; policy accept; }
add chain inet fw4 photon_openwrt_input { comment "photon-openwrt:input"; }
add rule inet fw4 input jump photon_openwrt_input comment "photon-openwrt:jump"
`
	if err := os.WriteFile("/tmp/startup.nft", []byte(batch), 0600); err != nil {
		t.Fatal(err)
	}
	command("nft", "-f", "/tmp/startup.nft")
	t.Setenv("PHOTON_CONTROL_SOCKET_SCOPE", "data-dir")
	t.Setenv("PHOTON_CONTROL_SOCKET", "")
	for _, announceOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("announce-only=%v", announceOnly), func(t *testing.T) {
			if err := os.MkdirAll("/run/photon/fw4", 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile("/run/photon/fw4/input.nft", []byte("# photon-openwrt managed input rules\ncounter accept comment \"photon-openwrt:allow\"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			command("nft", "add", "rule", "inet", "fw4", "photon_openwrt_input", "counter", "accept", "comment", `"photon-openwrt:allow"`)
			verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
			verified.ManagedZone = "node-b.catofes."
			config.PeerID = string(verified.ManagedZone)
			local := defaultAppConfig()
			local.IPsec.LinkGroups = nil
			if announceOnly {
				local.OpenWrt = &photonopenwrt.Config{WANNetworks: []string{"wan"}, AnnounceIPsec: true}
			}
			rt := &testApp{Config: testConfigWithStatePath(local, filepath.Join(t.TempDir(), "photon.db")), Clock: time.Now}
			prepared, _ := newPersistedIPsecPublishTestService(t, rt, verified, checkpoint, runtime, config)
			prepared.Config.ListenAddr = "127.0.0.1:0"
			prepared.Config.Bootstrap = nil
			service := newDaemon(prepared.Config, prepared.State, time.Second, time.Now)
			service.openWrtRunner = func(context.Context, string, ...string) ([]byte, error) {
				return []byte(`{"interface":[{"interface":"wan","up":false}]}`), nil
			}
			runCtx, stop := context.WithCancel(ctx)
			defer stop()
			done := make(chan error, 1)
			go func() { done <- service.Run(runCtx) }()
			deadline := time.Now().Add(12 * time.Second)
			for {
				_, err := os.Lstat(controlSocketPath(service.Config))
				if err == nil {
					break
				}
				select {
				case err := <-done:
					t.Fatalf("daemon exited before cleanup: %v", err)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("daemon did not open its isolated control socket")
				}
				time.Sleep(25 * time.Millisecond)
			}
			// A queued event cannot be handled until startup recovery/cleanup has
			// completed. Do not cancel on the earlier snippet unlink: its nft
			// transaction may still be in flight and need rollback.
			var response controlResponse
			if err := exchangeControl(ctx, controlSocketPath(service.Config), controlRequest{Method: "sync_trigger"}, &response); err != nil || !response.OK {
				t.Fatalf("startup barrier: %+v %v", response, err)
			}
			if _, err := os.Lstat("/run/photon/fw4/input.nft"); !os.IsNotExist(err) {
				t.Fatalf("startup retained fw4 fragment: %v", err)
			}
			beforeStop := command("nft", "-j", "list", "chain", "inet", "fw4", "photon_openwrt_input")
			if strings.Contains(string(beforeStop), `"rule"`) {
				t.Fatalf("startup retained owned rules before stop: %s", beforeStop)
			}
			stop()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("daemon did not stop")
			}
			output := command("nft", "-j", "list", "chain", "inet", "fw4", "photon_openwrt_input")
			if strings.Contains(string(output), `"rule"`) {
				t.Fatalf("daemon retained stale owned rules: %s", output)
			}
		})
	}
}
