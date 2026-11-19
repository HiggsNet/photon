package bird

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type birdProcess struct {
	pid   int
	pidfd int
}

// A PID file is only a hint. Open a handle before checking /proc, so a
// subsequent signal or exit check always refers to the same kernel process.
func (pm *ExecProcessManager) findProcess(spec BirdInstanceSpec) (*birdProcess, error) {
	pid, err := readPidFile(spec.PIDFilePath)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, strconv.ErrSyntax) || errors.Is(err, strconv.ErrRange) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read BIRD PID file %s: %w", spec.PIDFilePath, err)
	}
	if pid <= 1 || pid > 1<<31-1 {
		return nil, nil
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open process handle for BIRD PID %d: %w", pid, err)
	}
	process := &birdProcess{pid: pid, pidfd: pidfd}
	matches, err := pm.matchesProcess(process, spec)
	if err != nil || !matches || process.exited() {
		process.close()
		return nil, err
	}
	return process, nil
}

func (pm *ExecProcessManager) matchesProcess(process *birdProcess, spec BirdInstanceSpec) (bool, error) {
	proc := fmt.Sprintf("/proc/%d", process.pid)
	cmdline, err := os.ReadFile(filepath.Join(proc, "cmdline"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("read command line for BIRD PID %d: %w", process.pid, err)
	}
	args := strings.Split(strings.TrimSuffix(string(cmdline), "\x00"), "\x00")
	if !slices.Equal(args[1:], birdArgs(spec)) {
		return false, nil
	}

	exe := filepath.Join(proc, "exe")
	if pm.birdBinary != "" {
		expected, err := os.Stat(pm.birdBinary)
		if err != nil {
			return false, err
		}
		actual, err := os.Stat(exe)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return os.SameFile(expected, actual), nil
	}
	actual, err := os.Readlink(exe)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read executable for BIRD PID %d: %w", process.pid, err)
	}
	// A persisted daemon can still be running the previous package version.
	name := filepath.Base(strings.TrimSuffix(actual, " (deleted)"))
	return name == "bird" || name == ".bird-wrapped", nil
}

func (process *birdProcess) verifyControlSocket(path string) error {
	proc := fmt.Sprintf("/proc/%d", process.pid)
	sockets, err := os.ReadFile(filepath.Join(proc, "net/unix"))
	if err != nil {
		return fmt.Errorf("read Unix sockets for BIRD PID %d: %w", process.pid, err)
	}

	// BIRD binds before forking, so SO_PEERCRED identifies the launcher.
	// Match the listening socket inode to an fd held by the daemon itself.
	var inode string
	for line := range strings.SplitSeq(string(sockets), "\n") {
		fields := strings.SplitN(line, " ", 8)
		if len(fields) == 8 && fields[3] == "00010000" && fields[4] == "0001" && fields[5] == "01" && fields[7] == path {
			if inode != "" {
				return fmt.Errorf("multiple listeners for BIRD control socket %s", path)
			}
			inode = fields[6]
		}
	}
	if inode != "" {
		dir := filepath.Join(proc, "fd")
		entries, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("read descriptors for BIRD PID %d: %w", process.pid, err)
		}
		for _, entry := range entries {
			target, err := os.Readlink(filepath.Join(dir, entry.Name()))
			if err == nil && target == "socket:["+inode+"]" && !process.exited() {
				return nil
			}
		}
	}
	return fmt.Errorf("BIRD PID %d does not own a listener for %s", process.pid, path)
}

func (process *birdProcess) close() {
	_ = unix.Close(process.pidfd)
}

func (process *birdProcess) exited() bool {
	fds := []unix.PollFd{{Fd: int32(process.pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	if err != nil || n == 0 {
		return false
	}
	// If Photon is PID 1, the daemonized BIRD may have been reparented
	// to Photon. Reap that child without waiting on a reusable PID.
	var status unix.Siginfo
	_ = unix.Waitid(unix.P_PIDFD, process.pidfd, &status, unix.WEXITED|unix.WNOHANG, nil)
	return true
}

func (process *birdProcess) stop(ctx context.Context) error {
	if process.exited() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, gracefulTimeout)
	defer cancel()

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("stop BIRD process %d: %w", process.pid, err)
	}
	// BIRD handles SIGTERM as a graceful shutdown. Signal the process
	// directly, even if its control socket is unavailable.
	if err := unix.PidfdSendSignal(process.pidfd, unix.SIGTERM, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("signal BIRD process %d: %w", process.pid, err)
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for !process.exited() {
		select {
		case <-ctx.Done():
			if process.exited() {
				return nil
			}
			return fmt.Errorf("waiting for BIRD process %d to stop: %w", process.pid, ctx.Err())
		case <-ticker.C:
		}
	}
	return nil
}
