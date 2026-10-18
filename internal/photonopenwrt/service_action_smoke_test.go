//go:build linux

package photonopenwrt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The service manager and package init script are real. Only the daemon and
// cleanup executable are stand-ins, so a forced 30-second stop is repeatable
// without creating identity, BIRD, IPsec, or firewall state on the router.
func TestOpenWrtServiceActionIsolatedSlowStop(t *testing.T) {
	if os.Getenv("PHOTON_OPENWRT_SERVICE_SMOKE") != "1" {
		t.Skip("set PHOTON_OPENWRT_SERVICE_SMOKE=1 for private procd slow-stop acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if os.Getenv("PHOTON_SERVICE_SMOKE_CHILD") != "1" {
		for _, command := range []string{"unshare", "mount", "ubus", "ubusd", "procd"} {
			if _, err := exec.LookPath(command); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.CommandContext(ctx, "unshare", "-m", "--propagation", "private", "-n", "-p", "--fork", "--kill-child=SIGKILL", "--mount-proc", os.Args[0], "-test.run=^TestOpenWrtServiceActionIsolatedSlowStop$", "-test.v")
		cmd.Env = append(os.Environ(), "PHOTON_SERVICE_SMOKE_CHILD=1", "PHOTON_FW4_HOST_NET="+fw4Namespace(t, "net"), "PHOTON_FW4_HOST_MNT="+fw4Namespace(t, "mnt"), "PHOTON_SERVICE_HOST_PID="+fw4Namespace(t, "pid"), "PHOTON_FW4_FIXTURE="+t.TempDir())
		output, err := cmd.CombinedOutput()
		t.Logf("isolated procd:\n%s", output)
		if err != nil {
			t.Fatalf("isolated service action: %v", err)
		}
		return
	}
	for kind, parent := range map[string]string{"net": os.Getenv("PHOTON_FW4_HOST_NET"), "mnt": os.Getenv("PHOTON_FW4_HOST_MNT"), "pid": os.Getenv("PHOTON_SERVICE_HOST_PID")} {
		if parent == "" || parent == fw4Namespace(t, kind) {
			t.Fatalf("refusing procd without a private %s namespace", kind)
		}
	}
	if os.Getpid() != 1 {
		t.Fatal("fixture must be PID 1 in its own namespace; procd must be its child")
	}
	initScript, err := os.ReadFile(os.Getenv("PHOTON_SERVICE_INIT_SOURCE"))
	if err != nil || len(initScript) == 0 {
		t.Fatalf("provide copied contrib/openwrt/files/photon.init through PHOTON_SERVICE_INIT_SOURCE: %v", err)
	}
	fw4PrivateFiles(t, ctx)
	// The fresh sysfs mount must hide the host's cgroup mount before procd
	// creates children. Its optional cgroup integration must not reach hostfs.
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.subtree_control"); !os.IsNotExist(err) {
		t.Fatalf("refusing procd with a visible host cgroup mount: %v", err)
	}
	fw4PrivateMirror(t, ctx, "/usr/sbin", map[string]bool{"photon": true})
	if err := os.Remove("/usr/sbin/photon"); err != nil {
		t.Fatal(err)
	}
	fw4Write(t, "/usr/sbin/photon", `#!/bin/sh
case "$1:$2" in
 daemon:) exec /tmp/packet-helper -test.run=^TestOpenWrtSlowDaemonHelper$ ;;
 advanced:openwrt-cleanup)
  [ ! -e /tmp/cleanup-fail ] || exit 79
  pid=$(cat /tmp/slow-daemon.pid)
  if kill -0 "$pid" 2>/dev/null; then
   echo 'cleanup raced a live daemon' >&2
   exit 72
  fi
  echo "$pid" >> /tmp/cleanup-complete
  ;;
 *) exit 73 ;;
esac
`)
	if err := os.Chmod("/usr/sbin/photon", 0700); err != nil {
		t.Fatal(err)
	}
	fw4Write(t, "/etc/init.d/photon", string(initScript))
	if err := os.Chmod("/etc/init.d/photon", 0700); err != nil {
		t.Fatal(err)
	}
	fw4Write(t, "/etc/config/photon", "config photon 'main'\n option enabled '1'\n option config_file '/etc/photon/config.yaml'\n")
	fw4Write(t, "/etc/photon/config.yaml", "fixture: true\n")
	for _, dir := range []string{"/var/run/ubus", "/var/lock", "/tmp/empty-init", "/tmp/empty-rc"} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	start := func(name string, args ...string) {
		t.Helper()
		log, err := os.OpenFile("/tmp/"+name+".log", os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = log.Close() })
	}
	start("ubusd", "-s", "/var/run/ubus/ubus.sock")
	fw4Await(t, 5*time.Second, func() bool { _, err := os.Stat("/var/run/ubus/ubus.sock"); return err == nil })
	start("procd", "-s", "/var/run/ubus/ubus.sock", "-I", "/tmp/empty-init", "-R", "/tmp/empty-rc", "-S")
	fw4Await(t, 5*time.Second, func() bool { return exec.Command("ubus", "list", "service").Run() == nil })
	t.Cleanup(func() {
		for _, name := range []string{"procd", "ubusd"} {
			data, _ := os.ReadFile("/tmp/" + name + ".log")
			t.Logf("private %s log:\n%s", name, data)
		}
	})
	handler := New(Options{Validate: func(string) error { return nil }})
	service := func(action string) map[string]any {
		t.Helper()
		var output bytes.Buffer
		requestCtx, cancelRequest := context.WithTimeout(ctx, 5*time.Second)
		defer cancelRequest()
		began := time.Now()
		err := handler.Serve(requestCtx, []string{"call", "service"}, strings.NewReader(fmt.Sprintf(`{"action":%q}`, action)), &output)
		if err != nil {
			t.Fatal(err)
		}
		if time.Since(began) > 4*time.Second {
			t.Fatalf("service request waited for slow init: %s", output.String())
		}
		var result map[string]any
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	lastPID := 0
	for _, action := range []string{"stop", "restart"} {
		fw4Command(t, ctx, "/etc/init.d/photon", "start")
		fw4Await(t, 5*time.Second, func() bool { _, err := os.Stat("/tmp/slow-daemon.pid"); return err == nil })
		data, _ := os.ReadFile("/tmp/slow-daemon.pid")
		oldPID, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || oldPID <= 1 {
			t.Fatalf("invalid fixture daemon PID %q", data)
		}
		lastPID = oldPID
		began := time.Now()
		result := service(action)
		if result["ok"] != true || result["scheduled"] != true {
			t.Fatalf("action was not scheduled: %+v", result)
		}
		for _, concurrent := range []string{"stop", "restart", "start", "enable", "disable"} {
			if result := service(concurrent); result["ok"] != false {
				t.Fatalf("accepted %s while %s was running: %+v", concurrent, action, result)
			}
		}
		var final map[string]any
		fw4Await(t, 45*time.Second, func() bool {
			var services map[string]struct {
				Instances map[string]map[string]any `json:"instances"`
			}
			data := fw4Command(t, ctx, "ubus", "call", "service", "list", `{"name":"photon-action","verbose":true}`)
			if err := json.Unmarshal(data, &services); err != nil {
				t.Fatal(err)
			}
			for _, instance := range services["photon-action"].Instances {
				final = instance
				return instance["running"] == false
			}
			return false
		})
		if final["exit_code"] != float64(0) || final["respawn"] != nil {
			t.Fatalf("action did not finish once successfully: %+v", final)
		}
		if elapsed := time.Since(began); elapsed < 28*time.Second {
			t.Fatalf("slow daemon was not held through real term_timeout30: %s", elapsed)
		}
		if err := syscall.Kill(oldPID, 0); err == nil {
			t.Fatal("old daemon survived the completed action")
		}
		cleanup, _ := os.ReadFile("/tmp/cleanup-complete")
		if !strings.Contains(string(cleanup), strconv.Itoa(oldPID)+"\n") {
			t.Fatalf("init did not finish cleanup after daemon exit: %q", cleanup)
		}
		t.Logf("%s returned scheduled before RPC cancellation; real procd forced PID %d down and init cleanup completed in %s", action, oldPID, time.Since(began).Round(time.Millisecond))
		if action == "restart" {
			data, _ := os.ReadFile("/tmp/slow-daemon.pid")
			pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
			if pid <= 1 || pid == oldPID || syscall.Kill(pid, 0) != nil {
				t.Fatalf("restart did not start a new daemon: %q", data)
			}
			_ = syscall.Kill(pid, syscall.SIGKILL)
			fw4Await(t, 5*time.Second, func() bool { return syscall.Kill(pid, 0) != nil })
			fw4Command(t, ctx, "/etc/init.d/photon", "stop")
		}
		_ = os.Remove("/tmp/slow-daemon.pid")
	}
	// A real child failure remains observable, and an inactive failed job can
	// be retried without adopting a different command or respawning the child.
	for _, action := range []string{"stop", "restart"} {
		fw4Write(t, "/tmp/cleanup-fail", "injected cleanup failure\n")
		if result := service(action); result["ok"] != true || result["scheduled"] != true {
			t.Fatalf("failed to schedule failure fixture: %+v", result)
		}
		fw4Await(t, 5*time.Second, func() bool {
			state, err := handler.readServiceAction(ctx)
			return err == nil && state.Running != nil && !*state.Running && state.ExitCode != nil && *state.ExitCode == 79 && state.Error != ""
		})
		if got := fw4Command(t, ctx, "ubus", "call", "service", "list", `{"name":"photon"}`); strings.Contains(string(got), `"running": true`) {
			t.Fatalf("%s started a daemon despite cleanup failure: %s", action, got)
		}
		if err := os.Remove("/tmp/cleanup-fail"); err != nil {
			t.Fatal(err)
		}
		fw4Write(t, "/tmp/slow-daemon.pid", strconv.Itoa(lastPID)+"\n")
		if result := service(action); result["ok"] != true || result["scheduled"] != true {
			t.Fatalf("failed task could not be retried: %+v", result)
		}
		fw4Await(t, 5*time.Second, func() bool {
			state, err := handler.readServiceAction(ctx)
			return err == nil && state.Running != nil && !*state.Running && state.ExitCode != nil && *state.ExitCode == 0 && state.Error == ""
		})
		if action == "restart" {
			var pid int
			fw4Await(t, 5*time.Second, func() bool {
				data, _ := os.ReadFile("/tmp/slow-daemon.pid")
				pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
				return pid > 1 && pid != lastPID && syscall.Kill(pid, 0) == nil
			})
			_ = syscall.Kill(pid, syscall.SIGKILL)
			fw4Await(t, 5*time.Second, func() bool { return syscall.Kill(pid, 0) != nil })
			fw4Command(t, ctx, "/etc/init.d/photon", "stop")
		}
		t.Logf("%s cleanup failure is visible as exit_code=79, starts no daemon, and retry completes once with exit_code=0", action)
	}
}

func fw4Await(t *testing.T, limit time.Duration, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatalf("fixture condition did not converge within %s", limit)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestOpenWrtSlowDaemonHelper(t *testing.T) {
	if os.Getenv("PHOTON_SERVICE_SMOKE_CHILD") != "1" {
		t.Skip("private slow daemon helper")
	}
	if os.Getpid() <= 1 || fw4Namespace(t, "pid") == os.Getenv("PHOTON_SERVICE_HOST_PID") {
		t.Fatal("refusing slow helper outside isolated PID namespace")
	}
	signal.Ignore(syscall.SIGTERM)
	if err := os.WriteFile("/tmp/slow-daemon.pid", []byte(strconv.Itoa(os.Getpid())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Minute)
	t.Fatal("fixture daemon was not stopped")
}
