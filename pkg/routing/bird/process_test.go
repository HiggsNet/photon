package bird

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

type recordedCmd struct {
	name string
	args []string
}

type mockRunner struct {
	cmds     []recordedCmd
	fallback func(ctx context.Context, name string, args ...string) *exec.Cmd
}

func (m *mockRunner) run(ctx context.Context, name string, args ...string) *exec.Cmd {
	m.cmds = append(m.cmds, recordedCmd{
		name: name,
		args: slices.Clone(args),
	})
	if m.fallback != nil {
		return m.fallback(ctx, name, args...)
	}
	// Fail immediately so no real binary runs.
	return exec.CommandContext(ctx, "false")
}

func fakeBirdBinary(t *testing.T) string {
	t.Helper()
	birdPath := filepath.Join(t.TempDir(), "bird")
	script := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(birdPath, []byte(script), 0o755); err != nil {
		t.Fatalf("create fake bird binary: %v", err)
	}
	return birdPath
}

func managedSpec(tmp string) BirdInstanceSpec {
	owner := BirdResourceOwner{
		Manager:    "photon",
		InstanceID: "test-overlay",
		NetNSName:  "test-overlay",
	}
	owner.Token = OwnerToken(owner.InstanceID, owner.NetNSName)
	owner.ControlSocketToken = ResourceToken(owner, "control_socket")
	owner.PIDFileToken = ResourceToken(owner, "pid_file")
	owner.ConfigFileToken = ResourceToken(owner, "config_file")
	owner.RouteTableToken = ResourceToken(owner, "route_table")
	owner.RuleToken = ResourceToken(owner, "rule")
	return BirdInstanceSpec{
		Mode:              BirdModeManaged,
		NetNSName:         "test-overlay",
		RouterID:          1,
		ConfigPath:        filepath.Join(tmp, "bird.conf"),
		ControlSocketPath: filepath.Join(tmp, "bird.ctl"),
		PIDFilePath:       filepath.Join(tmp, "bird.pid"),
		Owner:             owner,
	}
}

func TestExecProcessManagerStartHostMode(t *testing.T) {
	tmp := t.TempDir()
	mr := &mockRunner{}
	pm := NewExecProcessManager(fakeBirdBinary(t))
	pm.runner = mr.run
	pm.socketWaitTimeout = 100 * time.Millisecond

	spec := managedSpec(tmp)
	spec.NetNS = NetNSSpec{Kind: "host"}

	// The fake bird exits immediately, so the socket wait will time out.
	if err := pm.Start(context.Background(), spec); err == nil {
		t.Fatal("expected Start to fail when socket does not appear")
	}

	if len(mr.cmds) != 1 {
		t.Fatalf("expected 1 recorded command, got %d: %+v", len(mr.cmds), mr.cmds)
	}
	cmd := mr.cmds[0]
	if filepath.Base(cmd.name) != "bird" {
		t.Errorf("expected bird command, got %s", cmd.name)
	}
	want := []string{"-c", spec.ConfigPath, "-s", spec.ControlSocketPath, "-P", spec.PIDFilePath}
	if !slices.Equal(cmd.args, want) {
		t.Errorf("expected args %v, got %v", want, cmd.args)
	}
}

func TestExecProcessManagerStartNamedNetNS(t *testing.T) {
	tmp := t.TempDir()
	mr := &mockRunner{
		fallback: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			if name == "ip" && len(args) >= 2 && args[0] == "netns" && args[1] == "add" {
				return exec.CommandContext(ctx, "true")
			}
			return exec.CommandContext(ctx, "false")
		},
	}
	pm := NewExecProcessManager(fakeBirdBinary(t))
	pm.runner = mr.run
	pm.socketWaitTimeout = 100 * time.Millisecond

	spec := managedSpec(tmp)
	spec.NetNS = NetNSSpec{Kind: "name", Name: "photon-test", Create: true}

	if err := pm.Start(context.Background(), spec); err == nil {
		t.Fatal("expected Start to fail when socket does not appear")
	}

	var foundAdd, foundExec bool
	for _, cmd := range mr.cmds {
		if cmd.name == "ip" && len(cmd.args) >= 3 && cmd.args[0] == "netns" && cmd.args[1] == "add" && cmd.args[2] == "photon-test" {
			foundAdd = true
		}
		if cmd.name == "ip" && len(cmd.args) >= 3 && cmd.args[0] == "netns" && cmd.args[1] == "exec" && cmd.args[2] == "photon-test" {
			foundExec = true
			want := []string{"netns", "exec", "photon-test", pm.birdBinary, "-c", spec.ConfigPath, "-s", spec.ControlSocketPath, "-P", spec.PIDFilePath}
			if !slices.Equal(cmd.args, want) {
				t.Errorf("expected exec args %v, got %v", want, cmd.args)
			}
		}
	}
	if !foundAdd {
		t.Errorf("expected ip netns add command, got %+v", mr.cmds)
	}
	if !foundExec {
		t.Errorf("expected ip netns exec command, got %+v", mr.cmds)
	}
}

func TestExecProcessManagerStartRejectsExitAfterSocketAppears(t *testing.T) {
	tmp := t.TempDir()
	pm := NewExecProcessManager(fakeBirdBinary(t))
	pm.socketWaitTimeout = 100 * time.Millisecond

	spec := managedSpec(tmp)
	spec.NetNS = NetNSSpec{Kind: "host"}
	// Simulate BIRD creating its control socket before failing to parse the
	// configuration. Start must not report this as a healthy daemon.
	if err := os.WriteFile(spec.ControlSocketPath, []byte{}, 0o644); err != nil {
		t.Fatalf("write socket: %v", err)
	}

	err := pm.Start(context.Background(), spec)
	if err == nil || !strings.Contains(err.Error(), "exited during startup") {
		t.Fatalf("Start error = %v, want startup exit", err)
	}
}

func TestExecProcessManagerStartRejectsNonManagedModes(t *testing.T) {
	pm := NewExecProcessManager("")

	for _, mode := range []BirdMode{BirdModeExternal, BirdModeDisabled} {
		spec := BirdInstanceSpec{Mode: mode, NetNSName: "x"}
		err := pm.Start(context.Background(), spec)
		if err == nil {
			t.Errorf("expected error for mode %q", mode)
		}
	}
}

func TestExecProcessManagerStartRejectsOverlongControlSocketPath(t *testing.T) {
	spec := managedSpec(t.TempDir())
	spec.ControlSocketPath = "/" + strings.Repeat("x", MaxControlSocketPathBytes)
	pm := NewExecProcessManager("")
	err := pm.Start(context.Background(), spec)
	if err == nil || !strings.Contains(err.Error(), "exceeds Linux limit") {
		t.Fatalf("Start overlong control socket error = %v", err)
	}
}

func TestExecProcessManagerStartAdoptsExistingPidfile(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		t.Run(fmt.Sprintf("reload_rejected=%v", rejected), func(t *testing.T) {
			commands := make(chan string, 1)
			server := newFakeServer(t, func(cmd string) string {
				commands <- cmd
				if rejected {
					return "8002 Configuration rejected\n0000 \n"
				}
				return "0002 Configuration OK\n0000 \n"
			})
			defer server.close()
			mr := &mockRunner{}
			pm := NewExecProcessManager(fakeBirdBinary(t))
			pm.runner = mr.run
			spec := managedSpec(t.TempDir())
			spec.NetNS = NetNSSpec{Kind: "host"}
			spec.ControlSocketPath = server.socket
			if err := os.WriteFile(spec.PIDFilePath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			err := pm.Start(context.Background(), spec)
			if (err != nil) != rejected {
				t.Fatalf("Start error = %v, rejected=%v", err, rejected)
			}
			select {
			case got := <-commands:
				if got != fmt.Sprintf("configure %q", spec.ConfigPath) {
					t.Fatalf("adopt command = %q", got)
				}
			case <-time.After(time.Second):
				t.Fatal("adopted BIRD did not reload configuration")
			}
			if pm.pid != os.Getpid() || len(mr.cmds) != 0 {
				t.Fatalf("adoption spawned a process or lost PID: pid=%d commands=%+v", pm.pid, mr.cmds)
			}
		})
	}
}

func TestEnsureNamedNetNSAcceptsExistingNamespace(t *testing.T) {
	runner := func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", `echo 'Cannot create namespace file "/run/netns/photon-test": File exists' >&2; exit 1`)
	}

	if err := ensureNamedNetNSWithRunner(context.Background(), "photon-test", runner); err != nil {
		t.Fatalf("expected existing netns to be accepted, got %v", err)
	}
}

func TestEnsureNamedNetNSIncludesCommandOutputOnFailure(t *testing.T) {
	runner := func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", `echo 'mount --make-shared /run/netns failed' >&2; exit 1`)
	}

	err := ensureNamedNetNSWithRunner(context.Background(), "photon-test", runner)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "mount --make-shared /run/netns failed") {
		t.Fatalf("expected command output in error, got %v", err)
	}
}

func TestExecProcessManagerStopIssuesCorrectCommands(t *testing.T) {
	tmp := t.TempDir()
	spec := managedSpec(tmp)

	// Create the managed files so Stop tries graceful shutdown and cleans up.
	if err := os.WriteFile(spec.ConfigPath, []byte("# config"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(spec.ControlSocketPath, []byte{}, 0o644); err != nil {
		t.Fatalf("write socket: %v", err)
	}
	if err := os.WriteFile(spec.PIDFilePath, []byte("99999\n"), 0o644); err != nil {
		t.Fatalf("write pidfile: %v", err)
	}

	mr := &mockRunner{
		fallback: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			if name == "birdc" {
				// Graceful shutdown fails.
				return exec.CommandContext(ctx, "false")
			}
			return exec.CommandContext(ctx, "false")
		},
	}
	pm := NewExecProcessManager("")
	pm.runner = mr.run
	pm.pid = 99999

	if err := pm.Stop(context.Background(), spec); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	var foundShutdown bool
	for _, cmd := range mr.cmds {
		if cmd.name == "birdc" {
			foundShutdown = true
			want := []string{"-s", spec.ControlSocketPath, "down"}
			if !slices.Equal(cmd.args, want) {
				t.Errorf("expected birdc args %v, got %v", want, cmd.args)
			}
		}
	}
	if !foundShutdown {
		t.Errorf("expected birdc shutdown command, got %+v", mr.cmds)
	}

	for _, p := range []string{spec.ConfigPath, spec.ControlSocketPath, spec.PIDFilePath} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected %s to be removed", p)
		}
	}
}

func TestExecProcessManagerStopSkipsCleanupWithoutOwnerTokens(t *testing.T) {
	tmp := t.TempDir()
	spec := managedSpec(tmp)
	spec.Owner = BirdResourceOwner{}

	for path, contents := range map[string]string{
		spec.ConfigPath:        "# config",
		spec.ControlSocketPath: "",
		spec.PIDFilePath:       "99999\n",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	pm := NewExecProcessManager("")
	pm.runner = (&mockRunner{fallback: func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "false")
	}}).run
	pm.pid = 99999

	if err := pm.Stop(context.Background(), spec); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	for _, p := range []string{spec.ConfigPath, spec.ControlSocketPath, spec.PIDFilePath} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s to remain without owner token: %v", p, err)
		}
	}
}

func TestExecProcessManagerIsRunning(t *testing.T) {
	tmp := t.TempDir()
	mr := &mockRunner{
		fallback: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			if filepath.Base(name) == "bird" {
				return exec.CommandContext(ctx, "sleep", "30")
			}
			return exec.CommandContext(ctx, "false")
		},
	}
	pm := NewExecProcessManager(fakeBirdBinary(t))
	pm.runner = mr.run
	pm.socketWaitTimeout = 100 * time.Millisecond

	spec := managedSpec(tmp)
	spec.NetNS = NetNSSpec{Kind: "host"}

	// Pre-create the socket so Start succeeds without a real BIRD daemon.
	if err := os.WriteFile(spec.ControlSocketPath, []byte{}, 0o644); err != nil {
		t.Fatalf("write socket: %v", err)
	}

	if err := pm.Start(context.Background(), spec); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	managedPID := func() int {
		pm.mu.Lock()
		defer pm.mu.Unlock()
		return pm.pid
	}
	t.Cleanup(func() {
		if pid := managedPID(); pid > 0 {
			if p, err := os.FindProcess(pid); err == nil {
				_ = p.Kill()
			}
		}
	})

	if !pm.IsRunning(context.Background()) {
		t.Fatal("expected process to be running")
	}

	proc, err := os.FindProcess(managedPID())
	if err != nil {
		t.Fatalf("find process: %v", err)
	}
	if err := proc.Kill(); err != nil {
		t.Fatalf("kill process: %v", err)
	}

	// Wait for the goroutine that reaps the child process.
	time.Sleep(100 * time.Millisecond)

	if pm.IsRunning(context.Background()) {
		t.Fatal("expected process to be stopped")
	}
}
