//go:build linux

package photonopenwrt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fixture(t *testing.T) (*Handler, string, *[]string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	var calls []string
	h := New(Options{
		DefaultConfigPath: path, ExamplePath: filepath.Join(dir, "example.yaml"),
		RuntimeDir: filepath.Join(dir, "run"), InitPath: filepath.Join(dir, "init-photon"),
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			if name == "uci" {
				if len(args) == 3 && args[2] == "photon.main.config_file" {
					return []byte(path), nil
				}
				return []byte("1"), nil
			}
			if name == "ubus" {
				return []byte(`{"photon":{"instances":{"main":{"running":true,"pid":123}}}}`), nil
			}
			return nil, nil
		},
		Validate: func(content string) error {
			if strings.Contains(content, "invalid") {
				return errors.New("invalid configuration")
			}
			return nil
		},
	})
	if err := os.WriteFile(h.options.ExamplePath, []byte("data_dir: /etc/photon\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return h, path, &calls
}

func invoke(t *testing.T, h *Handler, method string, arguments any) map[string]any {
	t.Helper()
	data, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := h.Serve(context.Background(), []string{"call", method}, bytes.NewReader(data), &output); err != nil {
		t.Fatal(err)
	}
	var reply map[string]any
	if err := json.Unmarshal(output.Bytes(), &reply); err != nil {
		t.Fatalf("invalid JSON reply: %v, %s", err, output.String())
	}
	return reply
}

func TestRPCListAndRejectedArgumentsHaveNoEffects(t *testing.T) {
	h, _, calls := fixture(t)
	var output bytes.Buffer
	if err := h.Serve(context.Background(), []string{"list"}, nil, &output); err != nil {
		t.Fatal(err)
	}
	var methods map[string]map[string]any
	if err := json.Unmarshal(output.Bytes(), &methods); err != nil || len(methods) != 6 {
		t.Fatalf("invalid method schema: %s, %v", output.String(), err)
	}
	for _, test := range []struct {
		method string
		args   any
	}{
		{"unknown", map[string]any{}},
		{"service", map[string]any{"action": "start; touch /tmp/injected"}},
		{"service", map[string]any{"action": nil}},
		{"service", map[string]any{"action": 1}},
		{"get_config", map[string]any{"path": "/etc/shadow"}},
		{"save_config", map[string]any{"content": "ok"}},
		{"snapshot", []string{}},
	} {
		if reply := invoke(t, h, test.method, test.args); reply["ok"] != false {
			t.Fatalf("accepted invalid request: %#v", reply)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("rejected arguments executed commands: %v", *calls)
	}
	if _, err := os.Stat(h.options.RuntimeDir); !os.IsNotExist(err) {
		t.Fatal("list/rejected requests created runtime state")
	}
}

func TestRPCSaveValidatesAndUsesOptimisticHash(t *testing.T) {
	h, path, calls := fixture(t)
	initial := invoke(t, h, "get_config", map[string]any{})
	if initial["ok"] != true || initial["exists"] != false || initial["sha256"] != "" || initial["content"] != "data_dir: /etc/photon\n" {
		t.Fatalf("missing config did not return example: %#v", initial)
	}
	if reply := invoke(t, h, "validate_config", map[string]any{"content": "valid"}); reply["ok"] != true {
		t.Fatal(reply)
	}
	if _, err := os.Stat(h.options.RuntimeDir); !os.IsNotExist(err) {
		t.Fatal("validation created state")
	}
	first := invoke(t, h, "save_config", map[string]any{"content": "first", "sha256": ""})
	if first["ok"] != true || first["sha256"] == "" {
		t.Fatal(first)
	}
	for _, request := range []map[string]any{
		{"content": "invalid", "sha256": first["sha256"]},
		{"content": "stale update", "sha256": ""},
		{"content": strings.Repeat("x", MaxConfigBytes+1), "sha256": first["sha256"]},
	} {
		if reply := invoke(t, h, "save_config", request); reply["ok"] != false {
			t.Fatalf("invalid or stale config was saved: %v", reply)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "first" {
		t.Fatalf("failed update changed file: %q, %v", data, err)
	}
	second := invoke(t, h, "save_config", map[string]any{"content": "second", "sha256": first["sha256"]})
	if second["ok"] != true || second["sha256"] == first["sha256"] {
		t.Fatal(second)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("configuration mode: %v, %v", info, err)
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".photon-config-*"))
	if len(matches) != 0 {
		t.Fatalf("temporary configuration files remain: %v", matches)
	}
	for _, call := range *calls {
		if strings.Contains(call, "init-photon") {
			t.Fatalf("saving config changed running service: %s", call)
		}
	}
}

func TestRPCSaveRejectsSymlinkAndConcurrentWriter(t *testing.T) {
	h, path, _ := fixture(t)
	target := filepath.Join(t.TempDir(), "other.yaml")
	if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if reply := invoke(t, h, "save_config", map[string]any{"content": "new", "sha256": ""}); reply["ok"] != false {
		t.Fatal("accepted symlink")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "untouched" {
		t.Fatal("modified symlink target")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(h.options.RuntimeDir, "config.lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if reply := invoke(t, h, "save_config", map[string]any{"content": "new", "sha256": ""}); reply["ok"] != false {
		t.Fatal("ignored existing configuration lock")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("locked save created config")
	}
}

func TestRPCConcurrentSavesAcceptOneVersion(t *testing.T) {
	h, path, _ := fixture(t)
	// Avoid a test-only race in the command recorder while two processes would
	// normally be serialized by flock in production.
	h.options.Run = func(context.Context, string, ...string) ([]byte, error) { return []byte(path), nil }
	var group sync.WaitGroup
	results := make(chan bool, 2)
	for _, content := range []string{"one", "two"} {
		group.Go(func() {
			_, err := h.saveConfig(context.Background(), content, "")
			results <- err == nil
		})
	}
	group.Wait()
	close(results)
	successes := 0
	for success := range results {
		if success {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("accepted %d simultaneous saves of the same version", successes)
	}
}

func TestRPCSnapshotDoesNotPretendProcdOrDaemonIsReady(t *testing.T) {
	h, path, _ := fixture(t)
	h.options.Views = func(_ context.Context, actual string) (Views, error) {
		if actual != path {
			t.Fatalf("wrong config passed to reader: %s", actual)
		}
		return Views{}, errors.New("control socket unavailable")
	}
	reply := invoke(t, h, "snapshot", map[string]any{"ubus_rpc_session": "session"})
	service := reply["service"].(map[string]any)
	if service["running"] != true || reply["daemon"] != nil || reply["summary"] != nil || reply["error"] == nil {
		t.Fatalf("running process was confused with network readiness: %#v", reply)
	}
	h.options.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("unavailable") }
	reply = invoke(t, h, "snapshot", map[string]any{})
	service = reply["service"].(map[string]any)
	if service["error"] == nil || service["enabled"] != nil || service["boot_enabled"] != nil {
		t.Fatal("procd failure must remain distinct from stopped")
	}
}

func TestRPCRejectsMalformedOrOversizedTransport(t *testing.T) {
	h, _, calls := fixture(t)
	for _, request := range []string{"{} {}", "null", "{", strings.Repeat(" ", 1<<20) + "{}"} {
		var output bytes.Buffer
		if err := h.Serve(t.Context(), []string{"call", "snapshot"}, strings.NewReader(request), &output); err != nil {
			t.Fatal(err)
		}
		var reply map[string]any
		if err := json.Unmarshal(output.Bytes(), &reply); err != nil || reply["ok"] != false {
			t.Fatalf("invalid request accepted: %v", reply)
		}
	}
	if len(*calls) != 0 {
		t.Fatal("invalid transport executed commands")
	}
}

func TestRPCServiceStartsOnlyConfiguredEnabledDaemon(t *testing.T) {
	h, path, calls := fixture(t)
	if reply := invoke(t, h, "service", map[string]any{"action": "start"}); reply["ok"] != false {
		t.Fatal("started without config")
	}
	if err := os.WriteFile(path, []byte("valid"), 0600); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	if reply := invoke(t, h, "service", map[string]any{"action": "start"}); reply["ok"] != true {
		t.Fatal(reply)
	}
	if last := (*calls)[len(*calls)-1]; last != h.options.InitPath+" start" {
		t.Fatalf("did not delegate to procd: %v", *calls)
	}
	*calls = nil
	if reply := invoke(t, h, "service", map[string]any{"action": "disable"}); reply["ok"] != true {
		t.Fatal(reply)
	}
	expected := []string{"uci set photon.main.enabled=0", "uci commit photon", h.options.InitPath + " disable"}
	if strings.Join(*calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("unexpected disable scope: %v", *calls)
	}
}

func TestCommandTimeoutTerminatesDiagnosticChildren(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	data, err := runCommand(ctx, "sh", "-c", "sleep 30 & printf '%s\\n' \"$!\"; wait")
	if err == nil {
		t.Fatal("blocked diagnostic did not time out")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		t.Fatalf("diagnostic did not start its child: %q, %v", data, err)
	}
	defer unix.Kill(pid, unix.SIGKILL)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if os.IsNotExist(err) {
			return
		}
		fields := strings.Fields(string(status))
		// A zombie is terminated and awaits the host init's reaper.
		if len(fields) > 2 && fields[2] == "Z" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("diagnostic child %d survived command timeout", pid)
}
