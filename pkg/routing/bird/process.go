package bird

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ProcessManager owns the BIRD child process in managed mode.
type ProcessManager interface {
	// CheckConfig validates a candidate with the instance that will load it.
	CheckConfig(ctx context.Context, spec BirdInstanceSpec, candidatePath string) error

	// Start ensures the target netns exists and starts BIRD inside it.
	// If the instance's PID and control socket still exist, Start adopts the
	// process and applies the current configuration instead of spawning another.
	Start(ctx context.Context, spec BirdInstanceSpec) error

	// Stop gracefully stops the BIRD process and removes Photon-owned
	// pid/control-socket/config files when ownership checks pass.
	Stop(ctx context.Context, spec BirdInstanceSpec) error

	// IsRunning reports whether the currently managed BIRD process is alive.
	// The implementation is expected to hold the spec it was started with.
	IsRunning(ctx context.Context) bool

	// LastExit returns and clears the latest observed managed-process exit.
	LastExit() *ProcessExit
}

// ExecProcessManager implements ProcessManager by executing BIRD and ip
// binaries directly.
type ExecProcessManager struct {
	birdBinary string
	runner     func(ctx context.Context, cmd string, args ...string) *exec.Cmd

	mu      sync.Mutex
	process *birdProcess
	spec    BirdInstanceSpec
	exit    *ProcessExit

	// socketWaitTimeout bounds the BIRD launch and readiness checks.
	socketWaitTimeout time.Duration
}

// NewExecProcessManager returns an ExecProcessManager that uses birdBinary
// (or looks up "bird" on PATH if empty).
func NewExecProcessManager(birdBinary string) *ExecProcessManager {
	return &ExecProcessManager{
		birdBinary:        birdBinary,
		runner:            exec.CommandContext,
		socketWaitTimeout: 2 * time.Second,
	}
}

var _ ProcessManager = (*ExecProcessManager)(nil)

const gracefulTimeout = 5 * time.Second

// CheckConfig uses the live parser when Start would adopt an existing instance.
func (pm *ExecProcessManager) CheckConfig(ctx context.Context, spec BirdInstanceSpec, candidatePath string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.observeExit()

	process := pm.process
	if process != nil {
		if !sameBirdPaths(pm.spec, spec) {
			return errors.New("another BIRD instance is already managed")
		}
	} else {
		var err error
		process, err = pm.findProcess(spec)
		if err != nil {
			return err
		}
		if process != nil {
			defer process.close()
		}
	}
	if process != nil {
		if err := process.verifyControlSocket(spec.ControlSocketPath); err != nil {
			return err
		}
		return NewClient(spec.ControlSocketPath, 10*time.Second).CheckConfig(ctx, candidatePath)
	}

	binary, err := pm.resolveBinary()
	if err != nil {
		return err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := pm.runner(checkCtx, binary, "-p", "-c", candidatePath).CombinedOutput()
	if err != nil {
		if checkCtx.Err() != nil {
			return checkCtx.Err()
		}
		if message := strings.TrimSpace(string(output)); message != "" {
			return fmt.Errorf("parse config with %s: %s: %w", binary, message, err)
		}
		return fmt.Errorf("parse config with %s: %w", binary, err)
	}
	return nil
}

// Start ensures the target netns exists and starts BIRD inside it.
func (pm *ExecProcessManager) Start(ctx context.Context, spec BirdInstanceSpec) error {
	if spec.Mode != BirdModeManaged {
		return fmt.Errorf("bird process manager only supports mode %q, got %q", BirdModeManaged, spec.Mode)
	}
	if spec.NetNSName == "" {
		return errors.New("bird instance netns_name is required")
	}
	for _, p := range []string{spec.ConfigPath, spec.ControlSocketPath, spec.PIDFilePath} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("bird path must be absolute: %s", p)
		}
	}
	if len(spec.ControlSocketPath) > MaxControlSocketPathBytes {
		return fmt.Errorf("BIRD control socket path is %d bytes, exceeds Linux limit %d: %s", len(spec.ControlSocketPath), MaxControlSocketPathBytes, spec.ControlSocketPath)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.observeExit()
	if pm.process != nil {
		if !sameBirdPaths(pm.spec, spec) {
			return errors.New("another BIRD instance is already managed")
		}
		return pm.process.applyConfig(ctx, spec)
	}

	existing, err := pm.findProcess(spec)
	if err != nil {
		return err
	}
	if existing != nil {
		if err := existing.applyConfig(ctx, spec); err != nil {
			existing.close()
			return err
		}
		pm.rememberProcess(spec, existing)
		return nil
	}
	binary, err := pm.resolveBinary()
	if err != nil {
		return err
	}

	if legacy, ok := legacyBirdSpec(spec); ok {
		if err := pm.retireLegacy(ctx, legacy); err != nil {
			return err
		}
	}
	if err := prepareBirdSocket(ctx, spec, true); err != nil {
		return err
	}
	for _, path := range []string{spec.ControlSocketPath, spec.PIDFilePath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("create BIRD runtime directory: %w", err)
		}
	}

	if spec.NetNS.Kind == "name" {
		if spec.NetNS.Name == "" {
			return errors.New("netns name is required for named netns")
		}
		if spec.NetNS.Create {
			if err := pm.ensureNamedNetNS(ctx, spec.NetNS.Name); err != nil {
				return fmt.Errorf("ensure netns %q: %w", spec.NetNS.Name, err)
			}
		}
	}
	startCtx, cancel := context.WithTimeout(ctx, pm.socketWaitTimeout)
	defer cancel()
	args := birdArgs(spec)
	var cmd *exec.Cmd
	switch spec.NetNS.Kind {
	case "host":
		cmd = pm.runner(startCtx, binary, args...)
	case "name":
		wrapped := append([]string{"netns", "exec", spec.NetNS.Name, binary}, args...)
		cmd = pm.runner(startCtx, "ip", wrapped...)
	case "path":
		return errors.New("path netns is not yet supported")
	default:
		return fmt.Errorf("unsupported netns kind %q", spec.NetNS.Kind)
	}

	// Wait for the launcher. BIRD daemonizes, so only the process identified
	// by the PID file and control socket is eligible to become ready.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("BIRD launcher exited during startup: %w", err)
	}
	process, err := pm.waitForReady(startCtx, spec)
	if err != nil {
		return fmt.Errorf("waiting for BIRD readiness: %w", err)
	}
	pm.rememberProcess(spec, process)
	return nil
}

func birdArgs(spec BirdInstanceSpec) []string {
	return []string{"-c", spec.ConfigPath, "-s", spec.ControlSocketPath, "-P", spec.PIDFilePath}
}

func sameBirdPaths(a, b BirdInstanceSpec) bool {
	return a.ConfigPath == b.ConfigPath && a.ControlSocketPath == b.ControlSocketPath && a.PIDFilePath == b.PIDFilePath
}

func legacyBirdSpec(spec BirdInstanceSpec) (BirdInstanceSpec, bool) {
	if spec.LegacyControlSocketPath == "" || spec.LegacyPIDFilePath == "" {
		return BirdInstanceSpec{}, false
	}
	spec.ControlSocketPath = spec.LegacyControlSocketPath
	spec.PIDFilePath = spec.LegacyPIDFilePath
	return spec, true
}

func (process *birdProcess) applyConfig(ctx context.Context, spec BirdInstanceSpec) error {
	if err := process.verifyControlSocket(spec.ControlSocketPath); err != nil {
		return err
	}
	if err := NewClient(spec.ControlSocketPath, 10*time.Second).Configure(ctx, spec.ConfigPath); err != nil {
		return fmt.Errorf("configure existing BIRD process %d: %w", process.pid, err)
	}
	if process.exited() {
		return fmt.Errorf("BIRD process %d exited during adoption", process.pid)
	}
	return nil
}

func (pm *ExecProcessManager) rememberProcess(spec BirdInstanceSpec, process *birdProcess) {
	pm.process = process
	pm.spec = spec
	pm.exit = nil
}

func (pm *ExecProcessManager) retireLegacy(ctx context.Context, spec BirdInstanceSpec) error {
	process, err := pm.findProcess(spec)
	if err != nil {
		return err
	}
	if process == nil {
		return prepareBirdSocket(ctx, spec, false)
	}
	defer process.close()
	if err := process.stop(ctx); err != nil {
		return fmt.Errorf("stop legacy BIRD before moving runtime files: %w", err)
	}
	return cleanBirdFiles(ctx, spec, false)
}

// Stop gracefully stops the BIRD process and removes Photon-owned files.
func (pm *ExecProcessManager) Stop(ctx context.Context, spec BirdInstanceSpec) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.observeExit()
	if pm.process != nil && !sameBirdPaths(pm.spec, spec) {
		return errors.New("cannot stop a different BIRD instance")
	}

	process := pm.process
	if process == nil {
		var err error
		process, err = pm.findProcess(spec)
		if err != nil {
			return err
		}
		if process != nil {
			defer process.close()
		} else if legacy, ok := legacyBirdSpec(spec); ok {
			if err := pm.retireLegacy(ctx, legacy); err != nil {
				return err
			}
		}
	}
	if process != nil {
		if err := process.stop(ctx); err != nil {
			return err
		}
	}
	if pm.process != nil {
		pm.process.close()
		pm.process = nil
		pm.spec = BirdInstanceSpec{}
	}
	pm.exit = nil
	return cleanBirdFiles(ctx, spec, true)
}

// IsRunning reports whether the currently managed BIRD process is alive.
func (pm *ExecProcessManager) IsRunning(_ context.Context) bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.observeExit()
	return pm.process != nil
}

// LastExit returns and clears the latest observed managed BIRD process exit.
func (pm *ExecProcessManager) LastExit() *ProcessExit {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.observeExit()
	exit := pm.exit
	pm.exit = nil
	return exit
}

func (pm *ExecProcessManager) observeExit() {
	if pm.process != nil && pm.process.exited() {
		pm.exit = &ProcessExit{PID: pm.process.pid, Failure: errors.New("exited")}
		pm.process.close()
		pm.process = nil
		pm.spec = BirdInstanceSpec{}
	}
}

func (pm *ExecProcessManager) resolveBinary() (string, error) {
	if pm.birdBinary != "" {
		if _, err := os.Stat(pm.birdBinary); err != nil {
			return "", fmt.Errorf("bird binary %q: %w", pm.birdBinary, err)
		}
		return pm.birdBinary, nil
	}
	return findBirdBinary()
}

func cleanBirdFiles(ctx context.Context, spec BirdInstanceSpec, config bool) error {
	removePID := birdResourceCleanupAllowed(spec.Owner, "pid_file")
	removeSocket := birdResourceCleanupAllowed(spec.Owner, "control_socket")
	removeConfig := config && birdResourceCleanupAllowed(spec.Owner, "config_file")
	if !removePID && !removeSocket && !removeConfig {
		return nil
	}
	if err := prepareBirdSocket(ctx, spec, true); err != nil {
		return err
	}
	var err error
	if removePID {
		err = removeBirdFile(spec.PIDFilePath)
	}
	if removeConfig {
		err = errors.Join(err, removeBirdFile(spec.ConfigPath))
	}
	return err
}

func removeBirdFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove BIRD file %s: %w", path, err)
	}
	return nil
}

func prepareBirdSocket(ctx context.Context, spec BirdInstanceSpec, remove bool) error {
	path := spec.ControlSocketPath
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("BIRD control path %s is not a Unix socket", path)
	}
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(context.WithoutCancel(ctx), "unix", path)
	if err == nil {
		conn.Close()
		return fmt.Errorf("BIRD control socket %s already has a listener without a matching PID file", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("probe BIRD control socket %s: %w", path, err)
	}
	if remove && birdResourceCleanupAllowed(spec.Owner, "control_socket") {
		return removeBirdFile(path)
	}
	return nil
}

func (pm *ExecProcessManager) waitForReady(ctx context.Context, spec BirdInstanceSpec) (*birdProcess, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var readinessErr error
	for {
		process, err := pm.findProcess(spec)
		if err != nil {
			return nil, err
		}
		if process != nil {
			readinessErr = process.verifyControlSocket(spec.ControlSocketPath)
			if readinessErr == nil {
				var response string
				response, readinessErr = NewClient(spec.ControlSocketPath, pm.socketWaitTimeout).Raw(ctx, "show status")
				if readinessErr == nil && !strings.Contains(response, "\n0013 ") {
					readinessErr = errors.New("BIRD has not reported that the daemon is running")
				}
			}
			if readinessErr == nil && !process.exited() {
				return process, nil
			}
			process.close()
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), readinessErr)
		case <-ticker.C:
		}
	}
}

func birdResourceCleanupAllowed(owner BirdResourceOwner, resource string) bool {
	if owner.Manager != "photon" || owner.InstanceID == "" || owner.NetNSName == "" || owner.Token == "" {
		return false
	}
	switch resource {
	case "control_socket":
		return owner.ControlSocketToken == ResourceToken(owner, resource)
	case "pid_file":
		return owner.PIDFileToken == ResourceToken(owner, resource)
	case "config_file":
		return owner.ConfigFileToken == ResourceToken(owner, resource)
	case "route_table":
		return owner.RouteTableToken == ResourceToken(owner, resource)
	case "rule":
		return owner.RuleToken == ResourceToken(owner, resource)
	default:
		return false
	}
}

// OwnerToken derives the base token for one managed BIRD instance.
func OwnerToken(instanceID, netnsName string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"photon.bird.owner.v1",
		instanceID,
		netnsName,
		"owner",
	}, "\x00")))
	return hex.EncodeToString(sum[:8])
}

// ResourceToken derives a token for one concrete managed BIRD resource.
func ResourceToken(owner BirdResourceOwner, resource string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"photon.bird.owner.v1",
		owner.InstanceID,
		owner.NetNSName,
		owner.Token,
		resource,
	}, "\x00")))
	return hex.EncodeToString(sum[:8])
}

func (pm *ExecProcessManager) ensureNamedNetNS(ctx context.Context, name string) error {
	return ensureNamedNetNSWithRunner(ctx, name, pm.runner)
}

// findBirdBinary locates the BIRD binary on PATH.
func findBirdBinary() (string, error) {
	path, err := exec.LookPath("bird")
	if err != nil {
		return "", fmt.Errorf("bird binary not found on PATH: %w", err)
	}
	return path, nil
}

func ensureNamedNetNSWithRunner(
	ctx context.Context,
	name string,
	runner func(context.Context, string, ...string) *exec.Cmd,
) error {
	if name == "" {
		return errors.New("netns name is empty")
	}
	cmd := runner(ctx, "ip", "netns", "add", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "File exists") || strings.Contains(msg, "already exists") {
			return nil
		}
		if msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

func readPidFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return pid, nil
}
