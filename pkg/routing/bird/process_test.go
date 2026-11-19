package bird

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

func TestExecProcessManagerRequiresReadyDaemon(t *testing.T) {
	pm := NewExecProcessManager(fakeBirdBinary(t))
	pm.socketWaitTimeout = 100 * time.Millisecond
	spec := managedSpec(t.TempDir())
	spec.NetNS = NetNSSpec{Kind: "host"}

	// A successful launcher is insufficient. The daemon must be identified
	// and answer on its own control socket.
	if err := pm.Start(t.Context(), spec); err == nil || !strings.Contains(err.Error(), "readiness") {
		t.Fatalf("Start error = %v, want readiness failure", err)
	}
	if pm.IsRunning(t.Context()) {
		t.Fatal("successful launcher was reported as a managed BIRD")
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

func TestExecProcessManagerRejectsReusedPID(t *testing.T) {
	spec := managedSpec(shortBirdTestDir(t))
	spec.NetNS = NetNSSpec{Kind: "host"}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: spec.ControlSocketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	if err := os.WriteFile(spec.PIDFilePath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pm := NewExecProcessManager(fakeBirdBinary(t))
	runner := &mockRunner{}
	pm.runner = runner.run

	if err := pm.Start(t.Context(), spec); err == nil || !strings.Contains(err.Error(), "without a matching PID file") {
		t.Fatalf("Start error = %v, want active socket conflict", err)
	}
	if pm.IsRunning(t.Context()) || len(runner.cmds) != 0 {
		t.Fatal("Start adopted the reused PID or launched a replacement over a live socket")
	}
	if err := pm.Stop(t.Context(), spec); err == nil {
		t.Fatal("Stop accepted an unrelated process and socket")
	}
	if _, err := os.Stat(spec.PIDFilePath); err != nil {
		t.Fatalf("Stop removed the PID file beside a live socket: %v", err)
	}
}

func shortBirdTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ph-bird-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
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

func TestExecProcessManagerStopPreservesLiveProcess(t *testing.T) {
	spec := managedSpec(shortBirdTestDir(t))
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: spec.ControlSocketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sh", "-c", "kill -STOP $$; exec sleep 30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	var status unix.WaitStatus
	if _, err := unix.Wait4(cmd.Process.Pid, &status, unix.WUNTRACED, nil); err != nil || !status.Stopped() {
		t.Fatalf("wait for process to stop: %v, status=%v", err, status)
	}
	pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	pm := NewExecProcessManager("")
	pm.rememberProcess(spec, &birdProcess{pid: cmd.Process.Pid, pidfd: pidfd})
	t.Cleanup(func() {
		if pm.process != nil {
			pm.process.close()
		}
	})
	for path, contents := range map[string]string{
		spec.ConfigPath:  "# config",
		spec.PIDFilePath: strconv.Itoa(cmd.Process.Pid),
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := pm.Stop(ctx, spec); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop error = %v, want deadline", err)
	}
	if !pm.IsRunning(t.Context()) {
		t.Fatal("lost live process after Stop timeout")
	}
	for _, path := range []string{spec.ConfigPath, spec.ControlSocketPath, spec.PIDFilePath} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("Stop timeout lost %s: %v", path, err)
		}
	}

	if err := cmd.Process.Signal(unix.SIGCONT); err != nil {
		t.Fatal(err)
	}
	if err := pm.Stop(t.Context(), spec); err != nil {
		t.Fatalf("retry Stop: %v", err)
	}
	if pm.IsRunning(t.Context()) {
		t.Fatal("process is still reported as running after Stop")
	}
	for _, path := range []string{spec.ConfigPath, spec.ControlSocketPath, spec.PIDFilePath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("expected %s to be removed after exit: %v", path, err)
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

	if err := pm.Stop(context.Background(), spec); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	for _, p := range []string{spec.ConfigPath, spec.ControlSocketPath, spec.PIDFilePath} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s to remain without owner token: %v", p, err)
		}
	}
}

func TestExecProcessManagerDaemonLifecycle(t *testing.T) {
	if os.Getenv("PHOTON_BIRD_SMOKE") != "1" {
		t.Skip("set PHOTON_BIRD_SMOKE=1 to run the BIRD lifecycle smoke")
	}
	if _, err := exec.LookPath("bird"); err != nil {
		t.Skip("BIRD is not installed")
	}
	spec := managedSpec(shortBirdTestDir(t))
	spec.NetNS = NetNSSpec{Kind: "host"}
	validConfig := []byte("router id 192.0.2.1;\nprotocol device {}\n")
	if err := os.WriteFile(spec.ConfigPath, validConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := spec
	legacy.PIDFilePath = filepath.Join(shortBirdTestDir(t), "old.pid")
	legacy.ControlSocketPath = filepath.Join(filepath.Dir(legacy.PIDFilePath), "old.ctl")

	previous := NewExecProcessManager("")
	t.Cleanup(func() { _ = previous.Stop(context.Background(), legacy) })
	if err := previous.Start(t.Context(), legacy); err != nil {
		t.Fatalf("start BIRD at legacy paths: %v", err)
	}
	oldPID, err := readPidFile(legacy.PIDFilePath)
	if err != nil {
		t.Fatal(err)
	}

	spec.LegacyPIDFilePath = legacy.PIDFilePath
	spec.LegacyControlSocketPath = legacy.ControlSocketPath
	manager := NewExecProcessManager("")
	t.Cleanup(func() { _ = manager.Stop(context.Background(), spec) })
	if err := manager.Start(t.Context(), spec); err != nil {
		t.Fatalf("start BIRD at new paths: %v", err)
	}
	if previous.IsRunning(t.Context()) {
		t.Fatal("legacy BIRD survived migration")
	}
	pid, err := readPidFile(spec.PIDFilePath)
	if err != nil || !manager.IsRunning(t.Context()) || pid == oldPID {
		t.Fatalf("BIRD after migration: pid=%d, old PID=%d, error=%v", pid, oldPID, err)
	}
	for _, path := range []string{legacy.PIDFilePath, legacy.ControlSocketPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("legacy runtime path %s still exists: %v", path, err)
		}
	}

	restarted := NewExecProcessManager("")
	t.Cleanup(func() { _ = restarted.Stop(context.Background(), spec) })
	if err := os.WriteFile(spec.ConfigPath, []byte("invalid config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Start(t.Context(), spec); err == nil || restarted.IsRunning(t.Context()) {
		t.Fatalf("rejected configuration was treated as a successful adoption: %v", err)
	}
	if err := os.WriteFile(spec.ConfigPath, validConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Start(t.Context(), spec); err != nil {
		t.Fatalf("adopt after fixing configuration: %v", err)
	}
	if !restarted.IsRunning(t.Context()) || restarted.process.pid != pid {
		t.Fatalf("restart failed to adopt the original BIRD process %d", pid)
	}
	if err := restarted.Stop(t.Context(), spec); err != nil {
		t.Fatalf("stop adopted BIRD: %v", err)
	}
	if manager.IsRunning(t.Context()) {
		t.Fatal("adopted BIRD did not exit")
	}
}
